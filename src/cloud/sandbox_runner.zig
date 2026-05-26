const std = @import("std");
const agdb = @import("agdb");
const database = agdb.database;
const record_mod = agdb.record;
const json_mod = agdb.json;
const ipc = agdb.cloud.ipc;

const BPF_LD = 0x00;
const BPF_W = 0x00;
const BPF_ABS = 0x20;
const BPF_JMP = 0x05;
const BPF_JEQ = 0x10;
const BPF_K = 0x00;
const BPF_RET = 0x06;

const AUDIT_ARCH_X86_64 = 3221225534;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub const sock_filter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

pub const sock_fprog = extern struct {
    len: u16,
    filter: [*]const sock_filter,
};

const allowed_syscalls = [_]u32{
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 32, 33, 39, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 60, 61, 62, 63, 72, 74, 75, 77, 96, 186, 202, 203, 204, 217, 228, 231, 232, 233, 234, 257, 258, 261, 263, 267, 269, 281, 285, 288, 290, 291, 293, 302, 309, 332, 425, 426, 427,
};

const seccomp_filter = blk: {
    const N = allowed_syscalls.len;
    var f: [4 + N + 2]sock_filter = undefined;
    f[0] = .{ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = 4 };
    f[1] = .{ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 1, .jf = 0, .k = AUDIT_ARCH_X86_64 };
    f[2] = .{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[3] = .{ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = 0 };

    var i: usize = 0;
    while (i < N) : (i += 1) {
        const target_offset = 4 + N + 1 - (4 + i + 1);
        f[4 + i] = .{
            .code = BPF_JMP | BPF_JEQ | BPF_K,
            .jt = @intCast(target_offset),
            .jf = 0,
            .k = allowed_syscalls[i],
        };
    }
    f[4 + N] = .{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[4 + N + 1] = .{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ALLOW };
    break :blk f;
};

fn mustSucceed(rc: usize) !void {
    const err = std.posix.errno(rc);
    if (err != .SUCCESS) return error.SyscallFailed;
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 4) {
        std.os.linux.exit(1);
    }

    const tenant_id_str = args[1];
    const ipc_fd_str = args[2];
    const data_path_str = args[3];

    try mustSucceed(std.os.linux.mount("none", "/", null, std.os.linux.MS.REC | std.os.linux.MS.PRIVATE, 0));

    var tmp_path_buf: [128]u8 = undefined;
    const tmp_path = try std.fmt.bufPrintZ(&tmp_path_buf, "/tmp/agdb-{s}", .{tenant_id_str});
    const mkdir_rc = std.os.linux.mkdir(tmp_path.ptr, 0o700);
    const mkdir_err = std.posix.errno(mkdir_rc);
    if (mkdir_err != .SUCCESS and mkdir_err != .EXIST) return error.MkdirFailed;

    try mustSucceed(std.os.linux.mount("none", tmp_path.ptr, "tmpfs", 0, @intFromPtr("size=128m,mode=0700")));

    var sub_buf: [512]u8 = undefined;
    const sub_paths = [_][]const u8{ "proc", "dev", "tmp", "data" };
    for (sub_paths) |sub| {
        const sub_path = try std.fmt.bufPrintZ(&sub_buf, "/tmp/agdb-{s}/{s}", .{ tenant_id_str, sub });
        const sub_rc = std.os.linux.mkdir(sub_path.ptr, 0o755);
        const sub_err = std.posix.errno(sub_rc);
        if (sub_err != .SUCCESS and sub_err != .EXIST) return error.MkdirFailed;
    }

    const sys_paths = [_][]const u8{ "/usr", "/lib", "/lib64", "/bin" };
    for (sys_paths) |sys_p| {
        var sys_p_terminated: [64]u8 = undefined;
        const sp = try std.fmt.bufPrintZ(&sys_p_terminated, "{s}", .{sys_p});
        const access_rc = std.os.linux.access(sp.ptr, 0);
        if (std.posix.errno(access_rc) == .SUCCESS) {
            const dest_path = try std.fmt.bufPrintZ(&sub_buf, "/tmp/agdb-{s}{s}", .{ tenant_id_str, sys_p });
            const dm_rc = std.os.linux.mkdir(dest_path.ptr, 0o755);
            const dm_err = std.posix.errno(dm_rc);
            if (dm_err != .SUCCESS and dm_err != .EXIST) return error.MkdirFailed;
            const mb_rc = std.os.linux.mount(sp.ptr, dest_path.ptr, null, std.os.linux.MS.BIND | std.os.linux.MS.REC, 0);
            if (std.posix.errno(mb_rc) != .SUCCESS) return error.MountFailed;
            const mr_rc = std.os.linux.mount(sp.ptr, dest_path.ptr, null, std.os.linux.MS.BIND | std.os.linux.MS.REMOUNT | std.os.linux.MS.RDONLY | std.os.linux.MS.REC, 0);
            if (std.posix.errno(mr_rc) != .SUCCESS) return error.MountRemountFailed;
        }
    }

    const dev_files = [_][]const u8{ "/dev/null", "/dev/zero", "/dev/urandom" };
    for (dev_files) |df| {
        var df_term: [32]u8 = undefined;
        const df_p = try std.fmt.bufPrintZ(&df_term, "{s}", .{df});
        const dest_path = try std.fmt.bufPrintZ(&sub_buf, "/tmp/agdb-{s}{s}", .{ tenant_id_str, df });
        const f_fd = std.os.linux.open(dest_path.ptr, @as(std.os.linux.O, .{ .ACCMODE = .WRONLY, .CREAT = true }), 0o644);
        if (std.posix.errno(f_fd) == .SUCCESS) _ = std.os.linux.close(@intCast(f_fd));
        const m_rc = std.os.linux.mount(df_p.ptr, dest_path.ptr, null, std.os.linux.MS.BIND, 0);
        if (std.posix.errno(m_rc) != .SUCCESS) return error.MountFailed;
    }

    var data_term: [256]u8 = undefined;
    if (data_path_str.len + 1 > data_term.len) return error.DataPathTooLong;
    const data_p = try std.fmt.bufPrintZ(&data_term, "{s}", .{data_path_str});
    const dest_data_path = try std.fmt.bufPrintZ(&sub_buf, "/tmp/agdb-{s}/data", .{tenant_id_str});
    try mustSucceed(std.os.linux.mount(data_p.ptr, dest_data_path.ptr, null, std.os.linux.MS.BIND | std.os.linux.MS.REC, 0));

    const old_root_path = try std.fmt.bufPrintZ(&sub_buf, "/tmp/agdb-{s}/tmp/old_root", .{tenant_id_str});
    const orm_rc = std.os.linux.mkdir(old_root_path.ptr, 0o755);
    const orm_err = std.posix.errno(orm_rc);
    if (orm_err != .SUCCESS and orm_err != .EXIST) return error.MkdirFailed;

    const sys_pivot_root: usize = 155;
    try mustSucceed(std.os.linux.syscall2(@enumFromInt(sys_pivot_root), @intFromPtr(tmp_path.ptr), @intFromPtr(old_root_path.ptr)));

    try mustSucceed(std.os.linux.chdir("/"));
    try mustSucceed(std.os.linux.umount2("/tmp/old_root", std.os.linux.MNT.DETACH));
    try mustSucceed(std.os.linux.mount("none", "/proc", "proc", std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV | std.os.linux.MS.NOEXEC, 0));

    const PR_SET_NO_NEW_PRIVS = 38;
    if (std.posix.errno(std.os.linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) != .SUCCESS) return error.PrctlFailed;

    const cap_user_header = extern struct {
        version: u32,
        pid: i32,
    };
    const cap_user_data = extern struct {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    };
    var cap_hdr = cap_user_header{
        .version = 0x20080522,
        .pid = 0,
    };
    var cap_data = [_]cap_user_data{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    const sys_capset: usize = 126;
    if (std.posix.errno(std.os.linux.syscall2(@enumFromInt(sys_capset), @intFromPtr(&cap_hdr), @intFromPtr(&cap_data))) != .SUCCESS) return error.CapsetFailed;

    const PR_CAP_AMBIENT = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL = 4;
    if (std.posix.errno(std.os.linux.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) != .SUCCESS) return error.PrctlFailed;

    const PR_SET_SECUREBITS = 28;
    const SECBIT_NOROOT = 1 << 0;
    const SECBIT_NOROOT_LOCKED = 1 << 1;
    const SECBIT_NO_SETUID_FIXUP = 1 << 2;
    const SECBIT_NO_SETUID_FIXUP_LOCKED = 1 << 3;
    if (std.posix.errno(std.os.linux.prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED, 0, 0, 0)) != .SUCCESS) return error.PrctlFailed;

    const prog = sock_fprog{
        .len = @intCast(seccomp_filter.len),
        .filter = &seccomp_filter,
    };
    const PR_SET_SECCOMP = 22;
    if (std.posix.errno(std.os.linux.prctl(PR_SET_SECCOMP, 2, @intFromPtr(&prog), 0, 0)) != .SUCCESS) return error.SeccompFailed;

    var db = try database.Database.open(gpa, .{
        .data_dir = "/data",
        .embedding_dim = 256,
    });

    const ipc_fd = try std.fmt.parseInt(i32, ipc_fd_str, 10);
    const epoll_fd_rc = std.os.linux.epoll_create1(0);
    if (std.posix.errno(epoll_fd_rc) != .SUCCESS) return error.EpollCreateFailed;
    const epoll_fd: i32 = @intCast(epoll_fd_rc);

    var event = std.os.linux.epoll_event{
        .events = std.os.linux.EPOLL.IN | std.os.linux.EPOLL.ERR | std.os.linux.EPOLL.HUP,
        .data = .{ .fd = ipc_fd },
    };
    if (std.posix.errno(std.os.linux.epoll_ctl(epoll_fd, std.os.linux.EPOLL.CTL_ADD, ipc_fd, &event)) != .SUCCESS) return error.EpollCtlFailed;

    var events: [1]std.os.linux.epoll_event = undefined;

    while (true) {
        const num_events_rc = std.os.linux.epoll_wait(epoll_fd, &events, 1, -1);
        const ne_err = std.posix.errno(num_events_rc);
        if (ne_err != .SUCCESS) {
            if (ne_err == .INTR) continue;
            return error.EpollWaitFailed;
        }
        const num_events: usize = @intCast(num_events_rc);
        if (num_events == 0) continue;

        var msg = ipc.recvMessage(gpa, ipc_fd) catch |err| {
            if (err == error.ConnectionClosed) {
                db.close();
                std.os.linux.exit(0);
            }
            continue;
        };
        defer msg.deinit(gpa);

        var status: u8 = 0;
        var resp_buf = std.ArrayList(u8).init(gpa);
        defer resp_buf.deinit();

        executeDatabaseQuery(db, msg, &resp_buf) catch {
            status = 1;
            resp_buf.clearRetainingCapacity();
            resp_buf.appendSlice("{\"error\":\"query execution failed\"}") catch {};
        };

        ipc.sendMessage(ipc_fd, msg.header.msg_type, status, msg.header.request_id, resp_buf.items) catch {};
    }
}

fn executeDatabaseQuery(db: *database.Database, msg: ipc.IpcMessage, resp_buf: *std.ArrayList(u8)) !void {
    const allocator = resp_buf.allocator;
    switch (msg.header.msg_type) {
        0x01 => {
            var value = try json_mod.parse(allocator, msg.payload);
            defer value.deinit(allocator);

            const query_field = value.getField("query") orelse return error.MissingQuery;
            const query_str = query_field.asString() orelse return error.InvalidQuery;

            var top_k_val: usize = 10;
            if (value.getField("top_k")) |k| {
                const kv = k.asInt() orelse return error.InvalidTopK;
                if (kv < 0) return error.InvalidTopK;
                const kuv: usize = @intCast(kv);
                top_k_val = @min(kuv, 1000);
            }

            var results = try db.searchText(query_str, top_k_val);
            defer results.deinit();

            var out_obj: json_mod.Value = .{ .object = .{} };
            defer out_obj.deinit(allocator);
            try json_mod.objectPut(allocator, &out_obj, "count", json_mod.makeInt(@intCast(results.items.len)));
            var hits_arr = try json_mod.makeArray(allocator, results.items.len);
            var i: usize = 0;
            while (i < results.items.len) : (i += 1) {
                var entry: json_mod.Value = .{ .object = .{} };
                try json_mod.objectPut(allocator, &entry, "id", json_mod.makeInt(@intCast(results.items[i].id)));
                try json_mod.objectPut(allocator, &entry, "score", json_mod.makeFloat(@floatCast(results.items[i].score)));
                const rec_json = try record_mod.toJson(allocator, results.items[i].record);
                try json_mod.objectPut(allocator, &entry, "record", rec_json);
                hits_arr.array[i] = entry;
            }
            try json_mod.objectPut(allocator, &out_obj, "hits", hits_arr);

            const body_out = try json_mod.stringify(allocator, out_obj);
            defer allocator.free(body_out);
            try resp_buf.appendSlice(body_out);
        },
        else => {
            try resp_buf.appendSlice("{\"status\":\"ok\"}");
        },
    }
}
