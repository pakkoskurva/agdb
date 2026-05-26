const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const registry_path = b.option([]const u8, "AGDB_REGISTRY_PATH", "Path to registry database") orelse "/var/lib/agdb/registry.agdb";
    const data_root = b.option([]const u8, "AGDB_DATA_ROOT", "Path to tenant data root") orelse "/var/lib/agdb/tenants";
    const runner_install_path = b.option([]const u8, "sandbox_runner_path", "Install path of the sandbox runner") orelse "/usr/lib/agdb/sandbox_runner";

    const opts = b.addOptions();
    opts.addOption([]const u8, "AGDB_REGISTRY_PATH", registry_path);
    opts.addOption([]const u8, "AGDB_DATA_ROOT", data_root);
    opts.addOption([]const u8, "sandbox_runner_path", runner_install_path);
    const build_options_mod = opts.createModule();

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/agdb.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("build_options", build_options_mod);

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
    exe_mod.addImport("build_options", build_options_mod);

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
    runtime_mod.addImport("build_options", build_options_mod);

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
    integration_mod.addImport("build_options", build_options_mod);
    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit + integration tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    const integration_step = b.step("test-integration", "Run integration tests only");
    integration_step.dependOn(&run_integration_tests.step);

    const runner_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
    });

    const runner_mod = b.createModule(.{
        .root_source_file = b.path("src/cloud/sandbox_runner.zig"),
        .target = runner_target,
        .optimize = optimize,
    });
    runner_mod.addImport("agdb", lib_mod);
    runner_mod.addImport("build_options", build_options_mod);

    const runner_exe = b.addExecutable(.{
        .name = "sandbox_runner",
        .root_module = runner_mod,
    });
    runner_exe.linkage = .static;
    if (optimize == .ReleaseSafe or optimize == .ReleaseFast or optimize == .ReleaseSmall) {
        runner_exe.root_module.strip = true;
    }

    const runner_install_subpath = if (runner_install_path.len > 0 and runner_install_path[0] == '/')
        runner_install_path[1..]
    else
        runner_install_path;

    const install_runner_step = b.addInstallFile(runner_exe.getEmittedBin(), runner_install_subpath);

    const runner_step = b.step("install-runner", "Install the sandbox_runner");
    runner_step.dependOn(&install_runner_step.step);
    b.getInstallStep().dependOn(&install_runner_step.step);
}
