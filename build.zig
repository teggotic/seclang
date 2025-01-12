const std = @import("std");

fn qbeC(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Mode,
    path: []const u8,
) *std.Build.Step.TranslateC {
    const qbe_c = b.addTranslateC(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    qbe_c.addIncludePath(b.path("vendor"));

    return qbe_c;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const keystone_c = b.addTranslateC(.{
        .root_source_file = b.path("src/keystone.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const qbe_c = qbeC(b, target, optimize, "src/qbe.h");
    const qbe_c_amd64 = qbeC(b, target, optimize, "src/qbe_amd64.h");
    const qbe_c_arm64 = qbeC(b, target, optimize, "src/qbe_arm64.h");
    const qbe_c_rv64 = qbeC(b, target, optimize, "src/qbe_rv64.h");

    const qbe = b.addStaticLibrary(.{
        .name = "qbe",
        .optimize = optimize,
        .target = target,
        .link_libc = true,
    });

    qbe.addCSourceFiles(.{
        .root = b.path("vendor/qbe"),
        .files = &[_][]const u8{
            "abi.c",
            "alias.c",
            "cfg.c",
            "copy.c",
            "emit.c",
            "fold.c",
            "live.c",
            "load.c",
            "mem.c",
            "parse.c",
            "rega.c",
            "simpl.c",
            "spill.c",
            "ssa.c",
            "util.c",
            "amd64/emit.c",
            "amd64/isel.c",
            "amd64/sysv.c",
            "amd64/targ.c",
            "arm64/abi.c",
            "arm64/emit.c",
            "arm64/isel.c",
            "arm64/targ.c",
            "rv64/abi.c",
            "rv64/emit.c",
            "rv64/isel.c",
            "rv64/targ.c",
        },
        .flags = &[_][]const u8{
            "-std=c99",
        },
    });
    qbe.addCSourceFile(.{
        .file = b.path("src/qbe.c"),
        .flags = &[_][]const u8{
            "-std=c99",
        },
    });
    qbe.addIncludePath(b.path("vendor"));

    const exe = b.addExecutable(.{
        .name = "seclang",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibrary(qbe);
    exe.linkSystemLibrary("c");
    exe.linkSystemLibrary("keystone");

    const pretty = b.dependency("pretty", .{});

    exe.root_module.addImport("pretty", pretty.module("pretty"));
    exe.root_module.addImport("keystone", keystone_c.createModule());
    exe.root_module.addImport("qbe_amd64", qbe_c_amd64.createModule());
    exe.root_module.addImport("qbe_arm64", qbe_c_arm64.createModule());
    exe.root_module.addImport("qbe_rv64", qbe_c_rv64.createModule());
    exe.root_module.addImport("qbe_c", qbe_c.createModule());

    b.installArtifact(exe);

    const check_step = b.step("check", "Check build");
    check_step.dependOn(&exe.step);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
