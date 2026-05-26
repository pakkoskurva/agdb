const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/agdb.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "agdb",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/cli_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("agdb", lib_mod);

    const exe = b.addExecutable(.{
        .name = "agdb",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the agdb CLI");
    run_step.dependOn(&run_cmd.step);

    const runtime_mod = b.createModule(.{
        .root_source_file = b.path("src/runtime_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    runtime_mod.addImport("agdb", lib_mod);

    const runtime_exe = b.addExecutable(.{
        .name = "agdb-runtime",
        .root_module = runtime_mod,
    });
    b.installArtifact(runtime_exe);

    const lib_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const integration_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_mod.addImport("agdb", lib_mod);
    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit + integration tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    const integration_step = b.step("test-integration", "Run integration tests only");
    integration_step.dependOn(&run_integration_tests.step);
}
