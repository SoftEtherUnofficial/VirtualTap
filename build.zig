const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Export VirtualTap module
    const virtualtap_module = b.addModule("virtualtap", .{
        .root_source_file = b.path("src/virtual_tap_integrated.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Export C FFI module
    const c_ffi_module = b.addModule("virtualtap_c_ffi", .{
        .root_source_file = b.path("src/c_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    c_ffi_module.addImport("virtualtap", virtualtap_module);

    // Create static library using Zig 0.15 API (compatible with module system)
    // Use Step.Compile.create which works with root_module
    const lib = std.Build.Step.Compile.create(b, .{
        .name = "virtualtap",
        .root_module = c_ffi_module,
        .kind = .lib,
        .linkage = .static,
    });
    lib.linkLibC();

    // Install library
    b.installArtifact(lib);

    // Install the header file
    const install_header = b.addInstallFile(
        b.path("include/virtual_tap.h"),
        "include/virtual_tap.h",
    );
    b.getInstallStep().dependOn(&install_header.step);

    // Build tests
    const tests = std.Build.Step.Compile.create(b, .{
        .name = "virtualtap_test",
        .root_module = virtualtap_module,
        .kind = .@"test",
        .linkage = null,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Default build step
    b.default_step.dependOn(&lib.step);
}
