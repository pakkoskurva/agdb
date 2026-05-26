const std = @import("std");
const sandbox = @import("sandbox.zig");
const ipc = @import("ipc.zig");

pub const SandboxHandle = sandbox.SandboxHandle;

pub const WaitingRequest = struct {
    response_buf: []u8,
    response_len: usize,
    status: u8,
    sem: std.Thread.Semaphore,
    completed: std.atomic.Value(bool),
};

pub const ProcessTable = struct {
    slots: []?SandboxHandle,
    epoll_fd: i32,
    mu: std.Thread.Mutex,
    pending_requests: std.AutoHashMap(u64, *WaitingRequest),
    pending_mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*ProcessTable {
        const self = try allocator.create(ProcessTable);
        errdefer allocator.destroy(self);

        const slots = try allocator.alloc(?SandboxHandle, 4096);
        errdefer allocator.free(slots);
        @memset(slots, null);

        const epoll_fd_rc = std.os.linux.epoll_create1(0);
        if (std.posix.errno(epoll_fd_rc) != .SUCCESS) return error.EpollCreateFailed;

        self.* = ProcessTable{
            .slots = slots,
            .epoll_fd = @intCast(epoll_fd_rc),
            .mu = .{},
            .pending_requests = std.AutoHashMap(u64, *WaitingRequest).init(allocator),
            .pending_mutex = .{},
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *ProcessTable) void {
        var handles_to_destroy = std.ArrayList(SandboxHandle).init(self.allocator);
        defer handles_to_destroy.deinit();
        {
            self.mu.lock();
            defer self.mu.unlock();
            for (self.slots, 0..) |maybe_handle, i| {
                if (maybe_handle) |handle| {
                    handles_to_destroy.append(handle) catch {};
                    self.slots[i] = null;
                }
            }
        }
        for (handles_to_destroy.items) |h| {
            sandbox.destroySandbox(h) catch {};
        }
        self.allocator.free(self.slots);
        _ = std.os.linux.close(self.epoll_fd);
        self.pending_requests.deinit();
        self.allocator.destroy(self);
    }

    pub fn insertLocked(self: *ProcessTable, handle: SandboxHandle) !void {
        var free_slot: ?usize = null;
        for (self.slots, 0..) |maybe_handle, i| {
            if (maybe_handle == null) {
                free_slot = i;
                break;
            }
        }

        const idx = free_slot orelse return error.ProcessTableFull;
        self.slots[idx] = handle;

        var event = std.os.linux.epoll_event{
            .events = std.os.linux.EPOLL.IN | std.os.linux.EPOLL.ERR | std.os.linux.EPOLL.HUP,
            .data = .{ .u64 = handle.tenant_id },
        };
        const rc = std.os.linux.epoll_ctl(self.epoll_fd, std.os.linux.EPOLL.CTL_ADD, handle.ipc_fd, &event);
        if (std.posix.errno(rc) != .SUCCESS) {
            self.slots[idx] = null;
            return error.EpollCtlFailed;
        }
    }

    pub fn insert(self: *ProcessTable, handle: SandboxHandle) !void {
        self.mu.lock();
        defer self.mu.unlock();
        try self.insertLocked(handle);
    }

    pub fn lookupLocked(self: *ProcessTable, tenant_id: u64) ?*SandboxHandle {
        for (self.slots) |*maybe_handle| {
            if (maybe_handle.*) |*handle| {
                if (handle.tenant_id == tenant_id) return handle;
            }
        }
        return null;
    }

    pub fn getHandle(self: *ProcessTable, tenant_id: u64) ?SandboxHandle {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.lookupLocked(tenant_id)) |h| return h.*;
        return null;
    }

    pub fn updateActivity(self: *ProcessTable, tenant_id: u64) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.lookupLocked(tenant_id)) |h| {
            h.last_activity_ns = std.time.nanoTimestamp();
        }
    }

    pub fn removeLocked(self: *ProcessTable, tenant_id: u64) void {
        for (self.slots, 0..) |maybe_handle, i| {
            if (maybe_handle) |handle| {
                if (handle.tenant_id == tenant_id) {
                    _ = std.os.linux.epoll_ctl(self.epoll_fd, std.os.linux.EPOLL.CTL_DEL, handle.ipc_fd, null);
                    self.slots[i] = null;
                    return;
                }
            }
        }
    }

    pub fn remove(self: *ProcessTable, tenant_id: u64) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.removeLocked(tenant_id);
    }

    fn failPendingForTenant(self: *ProcessTable, tenant_id: u64) void {
        _ = tenant_id;
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();
        var it = self.pending_requests.iterator();
        while (it.next()) |entry| {
            const wr = entry.value_ptr.*;
            if (!wr.completed.load(.acquire)) {
                wr.status = 0xFF;
                wr.response_len = 0;
                wr.completed.store(true, .release);
                wr.sem.post();
            }
        }
    }

    fn reapZombies(self: *ProcessTable) void {
        var status: u32 = 0;
        while (true) {
            const pid_rc = std.os.linux.wait4(-1, &status, std.os.linux.W.NOHANG, null);
            const err = std.posix.errno(pid_rc);
            if (err != .SUCCESS) break;
            if (pid_rc <= 0) break;

            const pid: i32 = @intCast(pid_rc);
            self.mu.lock();
            var found_tenant: ?u64 = null;
            for (self.slots) |maybe_handle| {
                if (maybe_handle) |h| {
                    if (h.pid == pid) {
                        found_tenant = h.tenant_id;
                        break;
                    }
                }
            }
            if (found_tenant) |tid| {
                self.removeLocked(tid);
                self.failPendingForTenant(tid);
            }
            self.mu.unlock();
        }
    }

    fn reapIdleSandboxes(self: *ProcessTable, now: i64) void {
        var to_destroy = std.ArrayList(SandboxHandle).init(self.allocator);
        defer to_destroy.deinit();

        const idle_limit_ns = 10 * 60 * std.time.ns_per_s;

        self.mu.lock();
        for (self.slots, 0..) |maybe_handle, i| {
            if (maybe_handle) |h| {
                if (now - h.last_activity_ns > idle_limit_ns) {
                    to_destroy.append(h) catch {};
                    _ = std.os.linux.epoll_ctl(self.epoll_fd, std.os.linux.EPOLL.CTL_DEL, h.ipc_fd, null);
                    self.slots[i] = null;
                }
            }
        }
        self.mu.unlock();

        for (to_destroy.items) |h| {
            sandbox.destroySandbox(h) catch {};
        }
    }

    pub fn runDispatchLoop(self: *ProcessTable) !void {
        var events: [64]std.os.linux.epoll_event = undefined;
        var last_sweep_ns = std.time.nanoTimestamp();

        while (true) {
            const rc = std.os.linux.epoll_wait(self.epoll_fd, &events, 64, 5000);
            const err = std.posix.errno(rc);

            const now = std.time.nanoTimestamp();
            if (now - last_sweep_ns > 5 * std.time.ns_per_s) {
                self.reapZombies();
                self.reapIdleSandboxes(now);
                last_sweep_ns = now;
            }

            if (err != .SUCCESS) {
                if (err == .INTR) continue;
                return error.EpollWaitFailed;
            }
            const n: usize = @intCast(rc);
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const tenant_id = events[i].data.u64;

                var ipc_fd: i32 = -1;
                {
                    self.mu.lock();
                    if (self.lookupLocked(tenant_id)) |h| {
                        ipc_fd = h.ipc_fd;
                    }
                    self.mu.unlock();
                }
                if (ipc_fd < 0) continue;

                const ev_flags = events[i].events;
                if ((ev_flags & (std.os.linux.EPOLL.ERR | std.os.linux.EPOLL.HUP)) != 0 and (ev_flags & std.os.linux.EPOLL.IN) == 0) {
                    self.remove(tenant_id);
                    self.failPendingForTenant(tenant_id);
                    continue;
                }

                var msg = ipc.recvMessage(self.allocator, ipc_fd) catch |rerr| {
                    if (rerr == error.ConnectionClosed) {
                        self.remove(tenant_id);
                        self.failPendingForTenant(tenant_id);
                    }
                    continue;
                };
                defer msg.deinit(self.allocator);

                self.pending_mutex.lock();
                const wait_opt = self.pending_requests.get(msg.header.request_id);
                if (wait_opt) |wait_req| {
                    _ = self.pending_requests.remove(msg.header.request_id);
                    self.pending_mutex.unlock();

                    const copy_len = @min(wait_req.response_buf.len, msg.payload.len);
                    if (copy_len > 0) {
                        @memcpy(wait_req.response_buf[0..copy_len], msg.payload[0..copy_len]);
                    }
                    wait_req.response_len = copy_len;
                    wait_req.status = msg.header.status;
                    wait_req.completed.store(true, .release);
                    wait_req.sem.post();
                } else {
                    self.pending_mutex.unlock();
                }
            }
        }
    }
};
