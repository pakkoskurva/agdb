const std = @import("std");
const build_options = @import("build_options");
const registry = @import("registry.zig");

pub const SandboxHandle = struct {
    tenant_id: u64,
    pid: i32,
    cgroup_fd: i32,
    ipc_fd: i32,
    last_activity_ns: i64,
};

const CLONE_NEWNS: u64 = 0x00020000;
const CLONE_NEWUTS: u64 = 0x04000000;
const CLONE_NEWIPC: u64 = 0x08000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_INTO_CGROUP: u64 = 1 << 33;

const clone_args = extern struct {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
};

fn sys_clone3(args: *clone_args, size: usize) isize {
    return @bitCast(std.os.linux.syscall2(.clone3, @intFromPtr(args), size));
}

fn writeAll(fd: i32, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const rc = std.os.linux.write(fd, data[written..].ptr, data.len - written);
        const err = std.posix.errno(rc);
        if (err != .SUCCESS) {
            if (err == .INTR) continue;
            return error.WriteFailed;
        }
        if (rc == 0) return error.WriteFailed;
        written += @intCast(rc);
    }
}

fn writeCgroupFile(tenant_id: u64, file_name: []const u8, content: []const u8) !void {
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/agdb/tenant-{d}/{s}", .{ tenant_id, file_name });
    const fd_rc = std.os.linux.open(path.ptr, @as(std.os.linux.O, .{ .ACCMODE = .WRONLY }), 0);
    const open_err = std.posix.errno(fd_rc);
    if (open_err != .SUCCESS) return error.CgroupWriteOpenFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = std.os.linux.close(fd);
    try writeAll(fd, content);
}

fn cleanupCgroupDir(tenant_id: u64) void {
    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/agdb/tenant-{d}", .{tenant_id}) catch return;
    _ = std.os.linux.rmdir(path.ptr);
}

pub fn spawnTenantSandbox(tenant: registry.TenantRecord) !SandboxHandle {
    var path_buf: [512]u8 = undefined;

    _ = std.os.linux.mkdir("/sys/fs/cgroup/agdb\x00", 0o755);

    const cg_path = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/agdb/tenant-{d}", .{tenant.tenant_id});
    const mk_rc = std.os.linux.mkdir(cg_path.ptr, 0o755);
    const mk_err = std.posix.errno(mk_rc);
    if (mk_err != .SUCCESS and mk_err != .EXIST) return error.CgroupMkdirFailed;

    errdefer cleanupCgroupDir(tenant.tenant_id);

    try writeCgroupFile(tenant.tenant_id, "memory.max", "536870912");
    try writeCgroupFile(tenant.tenant_id, "memory.swap.max", "0");
    try writeCgroupFile(tenant.tenant_id, "pids.max", "64");
    try writeCgroupFile(tenant.tenant_id, "cpu.max", "500000 1000000");

    const cgroup_fd_rc = std.os.linux.open(cg_path.ptr, @as(std.os.linux.O, .{ .PATH = true }), 0);
    if (std.posix.errno(cgroup_fd_rc) != .SUCCESS) return error.CgroupOpenFailed;
    const cgroup_fd: i32 = @intCast(cgroup_fd_rc);
    errdefer _ = std.os.linux.close(cgroup_fd);

    var sv: [2]i32 = undefined;
    const sock_rc = std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC, 0, &sv);
    if (std.posix.errno(sock_rc) != .SUCCESS) return error.SocketpairFailed;
    errdefer {
        _ = std.os.linux.close(sv[0]);
        _ = std.os.linux.close(sv[1]);
    }

    var pipe_fds: [2]i32 = undefined;
    const pipe_rc = std.os.linux.pipe2(&pipe_fds, @as(std.os.linux.O, .{ .CLOEXEC = true }));
    if (std.posix.errno(pipe_rc) != .SUCCESS) return error.PipeFailed;
    errdefer {
        _ = std.os.linux.close(pipe_fds[0]);
        _ = std.os.linux.close(pipe_fds[1]);
    }

    var args = clone_args{
        .flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWUSER | CLONE_INTO_CGROUP,
        .pidfd = 0,
        .child_tid = 0,
        .parent_tid = 0,
        .exit_signal = 17,
        .stack = 0,
        .stack_size = 0,
        .tls = 0,
        .set_tid = 0,
        .set_tid_size = 0,
        .cgroup = @intCast(cgroup_fd),
    };

    const pid = sys_clone3(&args, @sizeOf(clone_args));
    if (pid < 0) return error.Clone3Failed;

    if (pid == 0) {
        _ = std.os.linux.close(sv[0]);
        _ = std.os.linux.close(pipe_fds[1]);

        _ = std.os.linux.fcntl(sv[1], std.os.linux.F.SETFD, 0);

        var val: [1]u8 = undefined;
        var read_done = false;
        while (!read_done) {
            const rrc = std.os.linux.read(pipe_fds[0], &val, 1);
            const rerr = std.posix.errno(rrc);
            if (rerr == .SUCCESS) {
                if (rrc == 0) std.os.linux.exit(1);
                read_done = true;
            } else if (rerr == .INTR) {
                continue;
            } else {
                std.os.linux.exit(1);
            }
        }
        _ = std.os.linux.close(pipe_fds[0]);

        var tenant_id_str: [24]u8 = undefined;
        const tid_s = std.fmt.bufPrintZ(&tenant_id_str, "{d}", .{tenant.tenant_id}) catch std.os.linux.exit(1);

        var ipc_fd_str: [16]u8 = undefined;
        const ifd_s = std.fmt.bufPrintZ(&ipc_fd_str, "{d}", .{sv[1]}) catch std.os.linux.exit(1);

        var data_path_term: [256]u8 = undefined;
        const sentinel_idx = std.mem.indexOfScalar(u8, &tenant.data_path, 0) orelse tenant.data_path.len;
        const usable = @min(sentinel_idx, data_path_term.len - 1);
        @memcpy(data_path_term[0..usable], tenant.data_path[0..usable]);
        data_path_term[usable] = 0;

        var path_term: [512]u8 = undefined;
        _ = std.fmt.bufPrintZ(&path_term, "{s}", .{build_options.sandbox_runner_path}) catch std.os.linux.exit(1);

        const argv = [_]?[*:0]const u8{
            @ptrCast(&path_term),
            @ptrCast(tid_s.ptr),
            @ptrCast(ifd_s.ptr),
            @ptrCast(&data_path_term),
            null,
        };
        const envp = [_]?[*:0]const u8{null};
        _ = std.os.linux.execve(@ptrCast(&path_term), @ptrCast(&argv), @ptrCast(&envp));
        std.os.linux.exit(1);
    }

    _ = std.os.linux.close(sv[1]);
    _ = std.os.linux.close(pipe_fds[0]);

    var setup_ok = true;
    var proc_path_buf: [128]u8 = undefined;

    const sg_path = try std.fmt.bufPrintZ(&proc_path_buf, "/proc/{d}/setgroups", .{pid});
    const sg_fd_rc = std.os.linux.open(sg_path.ptr, @as(std.os.linux.O, .{ .ACCMODE = .WRONLY }), 0);
    if (std.posix.errno(sg_fd_rc) == .SUCCESS) {
        const sg_fd: i32 = @intCast(sg_fd_rc);
        writeAll(sg_fd, "deny") catch {
            setup_ok = false;
        };
        _ = std.os.linux.close(sg_fd);
    } else {
        setup_ok = false;
    }

    const gid_path = try std.fmt.bufPrintZ(&proc_path_buf, "/proc/{d}/gid_map", .{pid});
    const gid_fd_rc = std.os.linux.open(gid_path.ptr, @as(std.os.linux.O, .{ .ACCMODE = .WRONLY }), 0);
    if (std.posix.errno(gid_fd_rc) == .SUCCESS) {
        const gid_fd: i32 = @intCast(gid_fd_rc);
        writeAll(gid_fd, "0 1000 1") catch {
            setup_ok = false;
        };
        _ = std.os.linux.close(gid_fd);
    } else {
        setup_ok = false;
    }

    const uid_path = try std.fmt.bufPrintZ(&proc_path_buf, "/proc/{d}/uid_map", .{pid});
    const uid_fd_rc = std.os.linux.open(uid_path.ptr, @as(std.os.linux.O, .{ .ACCMODE = .WRONLY }), 0);
    if (std.posix.errno(uid_fd_rc) == .SUCCESS) {
        const uid_fd: i32 = @intCast(uid_fd_rc);
        writeAll(uid_fd, "0 1000 1") catch {
            setup_ok = false;
        };
        _ = std.os.linux.close(uid_fd);
    } else {
        setup_ok = false;
    }

    const signal_byte: [1]u8 = if (setup_ok) [1]u8{1} else [1]u8{0};
    _ = std.os.linux.write(pipe_fds[1], &signal_byte, 1);
    _ = std.os.linux.close(pipe_fds[1]);

    if (!setup_ok) {
        _ = std.os.linux.kill(@intCast(pid), 9);
        var st: u32 = 0;
        _ = std.os.linux.wait4(@intCast(pid), &st, 0, null);
        _ = std.os.linux.close(sv[0]);
        _ = std.os.linux.close(cgroup_fd);
        cleanupCgroupDir(tenant.tenant_id);
        return error.SandboxSetupFailed;
    }

    return SandboxHandle{
        .tenant_id = tenant.tenant_id,
        .pid = @intCast(pid),
        .cgroup_fd = cgroup_fd,
        .ipc_fd = sv[0],
        .last_activity_ns = std.time.nanoTimestamp(),
    };
}

pub fn destroySandbox(handle: SandboxHandle) !void {
    var path_buf: [512]u8 = undefined;
    const kill_path = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/agdb/tenant-{d}/cgroup.kill", .{handle.tenant_id});
    const kfd_rc = std.os.linux.open(kill_path.ptr, @as(std.os.linux.O, .{ .ACCMODE = .WRONLY }), 0);
    if (std.posix.errno(kfd_rc) == .SUCCESS) {
        const kfd: i32 = @intCast(kfd_rc);
        _ = std.os.linux.write(kfd, "1", 1);
        _ = std.os.linux.close(kfd);
    } else {
        _ = std.os.linux.kill(handle.pid, 9);
    }

    const SYS_pidfd_open: usize = 434;
    const pidfd_rc = std.os.linux.syscall2(@enumFromInt(SYS_pidfd_open), @as(usize, @intCast(handle.pid)), 0);
    if (std.posix.errno(pidfd_rc) == .SUCCESS) {
        const pidfd: i32 = @intCast(pidfd_rc);
        var poll_fds = [1]std.os.linux.pollfd{.{
            .fd = pidfd,
            .events = std.os.linux.POLL.IN,
            .revents = 0,
        }};
        _ = std.os.linux.poll(@ptrCast(&poll_fds), 1, 10000);
        _ = std.os.linux.close(pidfd);
    }

    var status: u32 = 0;
    while (true) {
        const w_rc = std.os.linux.wait4(handle.pid, &status, 0, null);
        const w_err = std.posix.errno(w_rc);
        if (w_err == .SUCCESS) break;
        if (w_err == .INTR) continue;
        break;
    }

    const dir_path = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/agdb/tenant-{d}", .{handle.tenant_id});
    _ = std.os.linux.rmdir(dir_path.ptr);

    _ = std.os.linux.close(handle.ipc_fd);
    _ = std.os.linux.close(handle.cgroup_fd);
}
