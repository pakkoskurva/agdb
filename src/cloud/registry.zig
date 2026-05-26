const std = @import("std");
const database = @import("../database.zig");
const transaction = @import("../transaction.zig");
const record_mod = @import("../record.zig");
const apikey = @import("apikey.zig");
const build_options = @import("build_options");

pub const TenantRecord = extern struct {
    tenant_id: u64,
    email_hash: [32]u8,
    api_key_hash: [32]u8,
    created_at_unix: i64,
    active: u8,
    _pad: [7]u8 = [_]u8{0} ** 7,
    data_path: [256]u8,
};

pub const Registry = struct {
    db: *database.Database,
    allocator: std.mem.Allocator,
    mu: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) !Registry {
        var path_buf: [512]u8 = undefined;
        const env_path = std.process.getEnvVarOwned(allocator, "AGDB_REGISTRY_PATH") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try allocator.dupe(u8, build_options.AGDB_REGISTRY_PATH),
            else => return err,
        };
        defer allocator.free(env_path);

        if (env_path.len + 1 > path_buf.len) return error.RegistryPathTooLong;
        const path_terminated = try std.fmt.bufPrintZ(&path_buf, "{s}", .{env_path});

        const dir = std.fs.path.dirname(env_path);
        if (dir) |d| std.fs.cwd().makePath(d) catch {};

        const db = try database.Database.open(allocator, .{
            .data_dir = path_terminated[0 .. path_terminated.len - 1],
            .embedding_dim = 64,
        });

        return Registry{
            .db = db,
            .allocator = allocator,
            .mu = .{},
        };
    }

    pub fn deinit(self: *Registry) void {
        self.db.close();
    }

    fn normalizeEmail(buf: []u8, email: []const u8) ![]u8 {
        if (email.len > buf.len) return error.InvalidEmail;
        var i: usize = 0;
        while (i < email.len) : (i += 1) {
            buf[i] = std.ascii.toLower(email[i]);
        }
        return buf[0..email.len];
    }

    fn emailKey(buf: []u8, email_hash: [32]u8) ![]u8 {
        var hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&email_hash)});
        return try std.fmt.bufPrint(buf, "email:{s}", .{hex});
    }

    fn tenantKey(buf: []u8, tenant_id: u64) ![]u8 {
        return try std.fmt.bufPrint(buf, "tenant:{d}", .{tenant_id});
    }

    fn apiKeyKey(buf: []u8, key_hash: [32]u8) ![]u8 {
        var hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&key_hash)});
        return try std.fmt.bufPrint(buf, "apikey:{s}", .{hex});
    }

    pub fn registerTenant(self: *Registry, email: []const u8) !TenantRecord {
        self.mu.lock();
        defer self.mu.unlock();

        if (email.len == 0 or email.len > 254) return error.InvalidEmail;

        var norm_buf: [256]u8 = undefined;
        const normalized = try normalizeEmail(&norm_buf, email);

        var email_hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(normalized, &email_hash, .{});

        var email_key_buf: [128]u8 = undefined;
        const email_key = try emailKey(&email_key_buf, email_hash);

        if (try self.db.kv.get(self.allocator, email_key)) |val| {
            self.allocator.free(val);
            return error.EmailAlreadyRegistered;
        }

        var tenant_id: u64 = 0;
        var attempts: usize = 0;
        while (attempts < 64) : (attempts += 1) {
            tenant_id = std.crypto.random.int(u64);
            if (tenant_id == 0) continue;

            var tk_buf: [64]u8 = undefined;
            const tk = try tenantKey(&tk_buf, tenant_id);
            if (try self.db.kv.get(self.allocator, tk)) |existing| {
                self.allocator.free(existing);
                tenant_id = 0;
                continue;
            }
            break;
        }
        if (tenant_id == 0) return error.TenantIdAllocationFailed;

        var data_path: [256]u8 = [_]u8{0} ** 256;
        const data_root = build_options.AGDB_DATA_ROOT;
        const dp_written = std.fmt.bufPrint(&data_path, "{s}/{d}/", .{ data_root, tenant_id }) catch return error.DataPathTooLong;
        _ = dp_written;

        var dir_path_buf: [512]u8 = undefined;
        const dir_path = std.fmt.bufPrintZ(&dir_path_buf, "{s}/{d}", .{ data_root, tenant_id }) catch return error.DataPathTooLong;
        std.fs.cwd().makePath(dir_path[0 .. dir_path.len - 1]) catch |err| {
            return err;
        };

        var record = TenantRecord{
            .tenant_id = tenant_id,
            .email_hash = email_hash,
            .api_key_hash = [_]u8{0} ** 32,
            .created_at_unix = std.time.timestamp(),
            .active = 1,
            .data_path = data_path,
        };

        var tenant_key_buf: [64]u8 = undefined;
        const tenant_key = try tenantKey(&tenant_key_buf, tenant_id);

        var id_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_buf, tenant_id, .little);

        self.db.kv.put(tenant_key, std.mem.asBytes(&record)) catch |err| {
            std.fs.cwd().deleteTree(dir_path[0 .. dir_path.len - 1]) catch {};
            return err;
        };

        self.db.kv.put(email_key, &id_buf) catch |err| {
            self.db.kv.delete(tenant_key) catch {};
            std.fs.cwd().deleteTree(dir_path[0 .. dir_path.len - 1]) catch {};
            return err;
        };

        return record;
    }

    pub fn storeApiKeyHash(self: *Registry, tenant_id: u64, key_hash: [32]u8) !void {
        self.mu.lock();
        defer self.mu.unlock();

        var tenant_key_buf: [64]u8 = undefined;
        const tenant_key = try tenantKey(&tenant_key_buf, tenant_id);
        const val = try self.db.kv.get(self.allocator, tenant_key) orelse return error.TenantNotFound;
        defer self.allocator.free(val);

        if (val.len < @sizeOf(TenantRecord)) return error.CorruptTenantRecord;

        var record = std.mem.bytesToValue(TenantRecord, val[0..@sizeOf(TenantRecord)]);

        const old_hash = record.api_key_hash;
        const zero_hash: [32]u8 = [_]u8{0} ** 32;
        var was_set = false;
        for (old_hash, zero_hash) |a, b| {
            if (a != b) {
                was_set = true;
                break;
            }
        }

        if (was_set) {
            var old_ak_buf: [128]u8 = undefined;
            const old_ak = try apiKeyKey(&old_ak_buf, old_hash);
            self.db.kv.delete(old_ak) catch {};
        }

        record.api_key_hash = key_hash;
        try self.db.kv.put(tenant_key, std.mem.asBytes(&record));

        var apikey_key_buf: [128]u8 = undefined;
        const apikey_key = try apiKeyKey(&apikey_key_buf, key_hash);
        var id_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_buf, tenant_id, .little);
        try self.db.kv.put(apikey_key, &id_buf);
    }

    pub fn lookupByApiKey(self: *Registry, key: []const u8) !?TenantRecord {
        self.mu.lock();
        defer self.mu.unlock();

        const key_hash = apikey.hashApiKey(key);

        var apikey_key_buf: [128]u8 = undefined;
        const apikey_key = try apiKeyKey(&apikey_key_buf, key_hash);

        const id_val = try self.db.kv.get(self.allocator, apikey_key) orelse return null;
        defer self.allocator.free(id_val);

        if (id_val.len < 8) return null;

        const tenant_id = std.mem.readInt(u64, id_val[0..8], .little);

        var tenant_key_buf: [64]u8 = undefined;
        const tenant_key = try tenantKey(&tenant_key_buf, tenant_id);

        const rec_val = try self.db.kv.get(self.allocator, tenant_key) orelse return null;
        defer self.allocator.free(rec_val);

        if (rec_val.len < @sizeOf(TenantRecord)) return null;

        const record = std.mem.bytesToValue(TenantRecord, rec_val[0..@sizeOf(TenantRecord)]);
        if (record.active == 0) return null;
        return record;
    }

    pub fn revokeTenant(self: *Registry, tenant_id: u64) !void {
        self.mu.lock();
        defer self.mu.unlock();

        var tenant_key_buf: [64]u8 = undefined;
        const tenant_key = try tenantKey(&tenant_key_buf, tenant_id);
        const val = try self.db.kv.get(self.allocator, tenant_key) orelse return error.TenantNotFound;
        defer self.allocator.free(val);

        if (val.len < @sizeOf(TenantRecord)) return error.CorruptTenantRecord;

        var record = std.mem.bytesToValue(TenantRecord, val[0..@sizeOf(TenantRecord)]);

        const zero_hash: [32]u8 = [_]u8{0} ** 32;
        var was_set = false;
        for (record.api_key_hash, zero_hash) |a, b| {
            if (a != b) {
                was_set = true;
                break;
            }
        }
        if (was_set) {
            var ak_buf: [128]u8 = undefined;
            const ak = try apiKeyKey(&ak_buf, record.api_key_hash);
            self.db.kv.delete(ak) catch {};
        }

        record.active = 0;
        try self.db.kv.put(tenant_key, std.mem.asBytes(&record));
    }
};
