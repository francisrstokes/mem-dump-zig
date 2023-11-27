const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "mem-dump",
        .root_source_file = .{ .path = "src/mem-dump.zig" },
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    });

    exe.addAnonymousModule("zigex", .{
        .source_file = .{ .path = "libs/zigex/src/regex.zig" },
    });

    b.installArtifact(exe);
}
