const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // VirtualTap module
    const virtual_tap_mod = b.addModule("virtual_tap", .{
        .root_source_file = b.path("src/virtual_tap.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests
    const tests = b.addTest(.{
        .root_module = virtual_tap_mod,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run VirtualTap tests");
    test_step.dependOn(&run_tests.step);
}
