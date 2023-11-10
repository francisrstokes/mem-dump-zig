const std = @import("std");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const PidError = error{ NoPidProvided, PidNotValid };
const OutOfRangeError = error{OutOfRange};

const MapEntry = struct { start: usize, end: usize, read: bool, write: bool, execute: bool };

pub fn get_pid_arg(allocator: Allocator) !i32 {
    var args = try std.process.argsAlloc(allocator);
    defer allocator.free(args);
    if (args.len < 2) {
        return PidError.NoPidProvided;
    }
    const pid = try std.fmt.parseInt(i32, args[1], 10);
    return pid;
}

pub fn read_maps_file(allocator: Allocator, pid: i32) ![]u8 {
    const buf = try allocator.alloc(u8, 32);
    defer allocator.free(buf);

    const filepath = try std.fmt.bufPrint(buf, "/proc/{d}/maps", .{pid});
    const file = try std.fs.openFileAbsolute(filepath, .{});
    defer file.close();

    const max_file_size = 1024 * 1024;
    return file.readToEndAlloc(allocator, max_file_size);
}

pub fn get_hex_slice_at_position(str: []const u8, start_offset: usize) ![]const u8 {
    var offset: usize = 0;

    for (str[start_offset..]) |c| {
        if ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f')) {
            offset += 1;
            continue;
        }
        return str[start_offset .. start_offset + offset];
    }
    return OutOfRangeError.OutOfRange;
}

pub fn parse_maps_file(allocator: Allocator, file: []u8) !std.ArrayList(MapEntry) {
    var map_entries = std.ArrayList(MapEntry).init(allocator);

    var it = std.mem.split(u8, file, "\n");
    while (it.next()) |line| {
        if (std.mem.eql(u8, line, "")) {
            continue;
        }

        const start_addr = try get_hex_slice_at_position(line, 0);
        const end_addr = try get_hex_slice_at_position(line, start_addr.len + 1);

        const ustart_addr = try std.fmt.parseInt(usize, start_addr, 16);
        const uend_addr = try std.fmt.parseInt(usize, end_addr, 16);

        const perm_offset = start_addr.len + end_addr.len + 2;

        const read = line[perm_offset + 0] == 'r';
        const write = line[perm_offset + 1] == 'w';
        const execute = line[perm_offset + 2] == 'x';

        try map_entries.append(.{ .start = ustart_addr, .end = uend_addr, .read = read, .write = write, .execute = execute });
    }

    return map_entries;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Grab the pid
    const pid = try get_pid_arg(allocator);
    const pidt = @as(linux.pid_t, pid);

    // Open the maps file
    const maps_file = try read_maps_file(allocator, pid);
    defer allocator.free(maps_file);

    // Parse the relevent information
    const map_info = try parse_maps_file(allocator, maps_file);
    defer map_info.deinit();

    // Attach with ptrace
    _ = linux.ptrace(linux.PTRACE.ATTACH, pidt, 0, 0, 0);

    // Open the mem file
    const path_buffer = try allocator.alloc(u8, 256);
    defer allocator.free(path_buffer);

    const mem_path = try std.fmt.bufPrint(path_buffer, "/proc/{d}/mem", .{pid});
    const mem_file = try std.fs.openFileAbsolute(mem_path, .{ .mode = std.fs.File.OpenMode.read_only });
    defer mem_file.close();

    // Open the a file to the relative path of the pid concatenated with .dump
    const dump_path = try std.fmt.bufPrint(path_buffer, "{d}.dump", .{pid});
    const dump_file = try std.fs.cwd().createFile(dump_path, .{});
    defer dump_file.close();

    // For any given r/w region, read the memory to a buffer, and write it to the dump
    for (map_info.items) |info_item| {
        if (!info_item.read or !info_item.write) {
            continue;
        }

        const size = info_item.end - info_item.start;
        const buffer = try allocator.alloc(u8, size);
        try mem_file.seekTo(info_item.start);

        _ = try mem_file.read(buffer);
        _ = try dump_file.write(buffer);
    }

    // Detach with ptrace
    _ = linux.ptrace(linux.PTRACE.DETACH, pidt, 0, 0, 0);
}
