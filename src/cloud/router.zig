const std = @import("std");
const registry = @import("registry.zig");
const process_table = @import("process_table.zig");
const sandbox = @import("sandbox.zig");
const ipc = @import("ipc.zig");

pub const Router = struct {
    reg: *registry.Registry,
    pt: *process_table.ProcessTable,
    allocator: std.mem.Allocator,
    next_request_id: std.atomic.Value(u64),
    spawn_mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, reg: *registry.Registry, pt: *process_table.ProcessTable) Router {
        return .{
            .reg = reg,
            .pt = pt,
            .allocator = allocator,
            .next_request_id = std.atomic.Value(u64).init(1),
            .spawn_mutex = .{},
        };
    }

    pub fn handleHttpRequest(self: *Router, auth_header: ?[]const u8, req_body: []const u8, resp_buf: *std.ArrayList(u8)) !void {
        if (auth_header == null) return error.Unauthorized;
        const header = auth_header.?;
        if (!std.mem.startsWith(u8, header, "Bearer ")) return error.Unauthorized;
        const api_key = header["Bearer ".len..];

        const tenant_rec = (try self.reg.lookupByApiKey(api_key)) orelse return error.Unauthorized;

        var active_handle: process_table.SandboxHandle = undefined;
        var have_handle = false;

        if (self.pt.getHandle(tenant_rec.tenant_id)) |h| {
            active_handle = h;
            have_handle = true;
        }

        if (!have_handle) {
            self.spawn_mutex.lock();
            if (self.pt.getHandle(tenant_rec.tenant_id)) |h2| {
                active_handle = h2;
                self.spawn_mutex.unlock();
            } else {
                const new_handle = sandbox.spawnTenantSandbox(tenant_rec) catch |err| {
                    self.spawn_mutex.unlock();
                    return err;
                };

                self.pt.mu.lock();
                if (self.pt.lookupLocked(tenant_rec.tenant_id)) |existing| {
                    active_handle = existing.*;
                    self.pt.mu.unlock();
                    self.spawn_mutex.unlock();
                    sandbox.destroySandbox(new_handle) catch {};
                } else {
                    self.pt.insertLocked(new_handle) catch |err| {
                        self.pt.mu.unlock();
                        self.spawn_mutex.unlock();
                        sandbox.destroySandbox(new_handle) catch {};
                        return err;
                    };
                    active_handle = new_handle;
                    self.pt.mu.unlock();
                    self.spawn_mutex.unlock();
                }
            }
        }

        self.pt.updateActivity(tenant_rec.tenant_id);

        const request_id = self.next_request_id.fetchAdd(1, .monotonic);

        const response_buf = try self.allocator.alloc(u8, 1024 * 1024 * 16);
        defer self.allocator.free(response_buf);

        var wait_req = process_table.WaitingRequest{
            .response_buf = response_buf,
            .response_len = 0,
            .status = 0,
            .sem = .{},
            .completed = std.atomic.Value(bool).init(false),
        };

        {
            self.pt.pending_mutex.lock();
            defer self.pt.pending_mutex.unlock();
            try self.pt.pending_requests.put(request_id, &wait_req);
        }

        var pending_removed = false;
        defer {
            if (!pending_removed) {
                self.pt.pending_mutex.lock();
                _ = self.pt.pending_requests.remove(request_id);
                self.pt.pending_mutex.unlock();
            }
        }

        ipc.sendMessage(active_handle.ipc_fd, 0x01, 0, request_id, req_body) catch |err| {
            return err;
        };

        const timeout_ns: u64 = 30 * std.time.ns_per_s;
        wait_req.sem.timedWait(timeout_ns) catch {
            {
                self.pt.pending_mutex.lock();
                _ = self.pt.pending_requests.remove(request_id);
                self.pt.pending_mutex.unlock();
                pending_removed = true;
            }
            var current_handle = process_table.SandboxHandle{ .tenant_id = 0, .pid = 0, .cgroup_fd = -1, .ipc_fd = -1, .last_activity_ns = 0 };
            if (self.pt.getHandle(tenant_rec.tenant_id)) |h| {
                if (h.pid == active_handle.pid and h.ipc_fd == active_handle.ipc_fd) {
                    current_handle = h;
                    self.pt.remove(tenant_rec.tenant_id);
                }
            }
            if (current_handle.tenant_id != 0) {
                sandbox.destroySandbox(current_handle) catch {};
            }
            return error.QueryTimeout;
        };

        pending_removed = true;

        if (!wait_req.completed.load(.acquire)) return error.QueryExecutionFailed;
        if (wait_req.status != 0) return error.QueryExecutionFailed;

        try resp_buf.appendSlice(wait_req.response_buf[0..wait_req.response_len]);
    }
};
