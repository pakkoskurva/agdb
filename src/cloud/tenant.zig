const std = @import("std");
const registry = @import("registry.zig");
const process_table = @import("process_table.zig");
const sandbox = @import("sandbox.zig");

pub const TenantLifecycle = struct {
    reg: *registry.Registry,
    pt: *process_table.ProcessTable,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, reg: *registry.Registry, pt: *process_table.ProcessTable) TenantLifecycle {
        return .{
            .reg = reg,
            .pt = pt,
            .allocator = allocator,
        };
    }

    pub fn createTenant(self: *TenantLifecycle, email: []const u8) !registry.TenantRecord {
        return self.reg.registerTenant(email);
    }

    pub fn lookupTenant(self: *TenantLifecycle, api_key: []const u8) !?registry.TenantRecord {
        return self.reg.lookupByApiKey(api_key);
    }

    pub fn destroyTenant(self: *TenantLifecycle, tenant_id: u64) !void {
        try self.reg.revokeTenant(tenant_id);

        var handle_copy: ?sandbox.SandboxHandle = null;
        {
            self.pt.mu.lock();
            defer self.pt.mu.unlock();
            if (self.pt.lookupLocked(tenant_id)) |handle| {
                handle_copy = handle.*;
                self.pt.removeLocked(tenant_id);
            }
        }

        if (handle_copy) |h| {
            try sandbox.destroySandbox(h);
        }
    }
};
