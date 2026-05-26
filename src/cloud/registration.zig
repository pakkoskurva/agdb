const std = @import("std");
const registry = @import("registry.zig");
const apikey = @import("apikey.zig");
const sandbox = @import("sandbox.zig");
const process_table = @import("process_table.zig");
const json = @import("../json.zig");

pub const RegistrationHandler = struct {
    reg: *registry.Registry,
    pt: *process_table.ProcessTable,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, reg: *registry.Registry, pt: *process_table.ProcessTable) RegistrationHandler {
        return .{
            .reg = reg,
            .pt = pt,
            .allocator = allocator,
        };
    }

    pub fn handleRegister(self: *RegistrationHandler, body: []const u8, resp_buf: *std.ArrayList(u8)) !void {
        if (body.len > 1024) return error.BodyTooLarge;
        var value = try json.parse(self.allocator, body);
        defer value.deinit(self.allocator);

        const email_val = value.getField("email") orelse return error.MissingEmail;
        const email = email_val.asString() orelse return error.InvalidEmail;

        if (email.len == 0 or email.len > 254) return error.InvalidEmail;
        var at_count: usize = 0;
        for (email) |c| {
            if (c == '@') at_count += 1;
            if (std.ascii.isControl(c)) return error.InvalidEmail;
            if (c == ' ') return error.InvalidEmail;
        }
        if (at_count != 1) return error.InvalidEmail;

        const record = try self.reg.registerTenant(email);
        const generated_key = try apikey.generateApiKey();
        const hash = apikey.hashApiKey(&generated_key);
        try self.reg.storeApiKeyHash(record.tenant_id, hash);

        var out_obj = json.makeObject(self.allocator);
        defer out_obj.deinit(self.allocator);

        var tenant_id_str: [24]u8 = undefined;
        const tid_slice = try std.fmt.bufPrint(&tenant_id_str, "{d}", .{record.tenant_id});

        try json.objectPut(self.allocator, &out_obj, "tenant_id", try json.makeString(self.allocator, tid_slice));
        try json.objectPut(self.allocator, &out_obj, "api_key", try json.makeString(self.allocator, &generated_key));

        const body_out = try json.stringify(self.allocator, out_obj);
        defer self.allocator.free(body_out);
        try resp_buf.appendSlice(body_out);
    }

    pub fn handleDeleteAccount(self: *RegistrationHandler, auth_header: ?[]const u8, resp_buf: *std.ArrayList(u8)) !void {
        if (auth_header == null) return error.Unauthorized;
        const header = auth_header.?;
        if (!std.mem.startsWith(u8, header, "Bearer ")) return error.Unauthorized;
        const api_key = header["Bearer ".len..];

        const tenant_rec = (try self.reg.lookupByApiKey(api_key)) orelse return error.Unauthorized;

        try self.reg.revokeTenant(tenant_rec.tenant_id);

        var handle_copy: ?sandbox.SandboxHandle = null;
        {
            self.pt.mu.lock();
            defer self.pt.mu.unlock();
            if (self.pt.lookupLocked(tenant_rec.tenant_id)) |handle| {
                handle_copy = handle.*;
                self.pt.removeLocked(tenant_rec.tenant_id);
            }
        }
        if (handle_copy) |h| {
            sandbox.destroySandbox(h) catch {};
        }

        const sentinel_idx = std.mem.indexOfScalar(u8, &tenant_rec.data_path, 0) orelse tenant_rec.data_path.len;
        const path_slice = tenant_rec.data_path[0..sentinel_idx];

        recursiveDelete(path_slice) catch {};

        try resp_buf.appendSlice("{\"status\":\"deleted\"}");
    }
};

fn deleteDirContents(dir_fd: i32) !void {
    var buf: [8192]u8 = undefined;
    while (true) {
        const rc = std.os.linux.syscall3(.getdents64, @intCast(dir_fd), @intFromPtr(&buf), buf.len);
        const err = std.posix.errno(rc);
        if (err != .SUCCESS) return error.GetdentsFailed;
        if (rc == 0) break;
        const limit: usize = @intCast(rc);
        var pos: usize = 0;
        while (pos < limit) {
            const reclen = std.mem.readInt(u16, buf[pos + 16 ..][0..2], .little);
            if (reclen == 0) break;
            const name_ptr: [*:0]const u8 = @ptrCast(&buf[pos + 19]);
            const name_slice = std.mem.sliceTo(name_ptr, 0);
            const next_pos = pos + reclen;
            if (!std.mem.eql(u8, name_slice, ".") and !std.mem.eql(u8, name_slice, "..")) {
                recursiveDeleteAt(dir_fd, name_ptr);
            }
            pos = next_pos;
        }
    }
}

fn recursiveDeleteAt(parent_fd: i32, name_z: [*:0]const u8) void {
    const fd_rc = std.os.linux.openat(parent_fd, name_z, @as(std.os.linux.O, .{ .DIRECTORY = true, .NOFOLLOW = true }), 0);
    const fd_err = std.posix.errno(fd_rc);
    if (fd_err == .SUCCESS) {
        const child_fd: i32 = @intCast(fd_rc);
        deleteDirContents(child_fd) catch {};
        _ = std.os.linux.close(child_fd);
        const AT_REMOVEDIR: u32 = 0x200;
        _ = std.os.linux.unlinkat(parent_fd, name_z, AT_REMOVEDIR);
    } else {
        _ = std.os.linux.unlinkat(parent_fd, name_z, 0);
    }
}

fn recursiveDelete(path: []const u8) !void {
    if (path.len == 0) return;
    var path_buf: [4096]u8 = undefined;
    if (path.len + 1 > path_buf.len) return error.PathTooLong;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);
    const AT_FDCWD: i32 = -100;
    recursiveDeleteAt(AT_FDCWD, path_z);
}
