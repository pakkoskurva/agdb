const std = @import("std");
const builtin = @import("builtin");

pub const SchemaMagic: u32 = 0x53434841;
pub const SchemaVersion: u32 = 1;

pub const FieldKind = enum(u8) {
    int,
    uint,
    float,
    bool_,
    pointer,
    array,
    struct_,
    union_,
    enum_,
    optional,
    slice,
};

pub const FieldInfo = extern struct {
    name_offset: u32,
    name_len: u32,
    kind: FieldKind,
    flags: u8,
    offset: u16,
    size: u16,
    alignment: u8,
    reserved: [3]u8,
    type_info_offset: u32,
};

pub const StructInfo = extern struct {
    magic: u32,
    version: u32,
    schema_id: u32,
    size: u32,
    alignment: u32,
    field_count: u32,
    name_offset: u32,
    name_len: u32,
    checksum: u32,
    reserved: [12]u8,
};

pub const SchemaEntry = struct {
    id: u32,
    name: []const u8,
    info: StructInfo,
    fields: []FieldInfo,
    type_name: []const u8,
};

pub const MigrationFn = *const fn (*anyopaque, *anyopaque, u32, u32) void;

pub const Migration = struct {
    from_version: u32,
    to_version: u32,
    migrate_fn: MigrationFn,
};

pub const SchemaRegistry = struct {
    entries: std.AutoHashMap(u32, SchemaEntry),
    name_index: std.StringHashMap(u32),
    migrations: std.AutoHashMap(u64, Migration),
    next_schema_id: std.atomic.Value(u32),
    string_pool: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    lock: std.Thread.RwLock,

    const Self = @This();

    pub fn init(allocator_ptr: std.mem.Allocator) SchemaRegistry {
        return SchemaRegistry{
            .entries = std.AutoHashMap(u32, SchemaEntry).init(allocator_ptr),
            .name_index = std.StringHashMap(u32).init(allocator_ptr),
            .migrations = std.AutoHashMap(u64, Migration).init(allocator_ptr),
            .next_schema_id = std.atomic.Value(u32).init(1),
            .string_pool = std.ArrayList(u8).init(allocator_ptr),
            .allocator = allocator_ptr,
            .lock = std.Thread.RwLock{},
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.name);
            self.allocator.free(entry.value_ptr.fields);
            self.allocator.free(entry.value_ptr.type_name);
        }
        self.entries.deinit();
        self.name_index.deinit();
        self.migrations.deinit();
        self.string_pool.deinit();
    }

    pub fn registerSchema(
        self: *Self,
        comptime T: type,
        name: []const u8,
    ) !u32 {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.name_index.get(name)) |existing_id| {
            return existing_id;
        }

        const schema_id = self.next_schema_id.fetchAdd(1, .monotonic);

        const type_info = @typeInfo(T);
        const struct_info = switch (type_info) {
            .@"struct" => |s| s,
            else => return error.NotAStruct,
        };

        var info = StructInfo{
            .magic = SchemaMagic,
            .version = SchemaVersion,
            .schema_id = schema_id,
            .size = @intCast(@sizeOf(T)),
            .alignment = @intCast(@alignOf(T)),
            .field_count = @intCast(struct_info.fields.len),
            .name_offset = @intCast(self.string_pool.items.len),
            .name_len = @intCast(name.len),
            .checksum = 0,
            .reserved = [_]u8{0} ** 12,
        };

        try self.string_pool.appendSlice(name);

        var fields = std.ArrayList(FieldInfo).init(self.allocator);
        errdefer fields.deinit();

        inline for (struct_info.fields) |field| {
            const field_name_offset = self.string_pool.items.len;

            try self.string_pool.appendSlice(field.name);

            const field_info = FieldInfo{
                .name_offset = @intCast(field_name_offset),
                .name_len = @intCast(field.name.len),
                .kind = fieldTypeToKind(field.type),
                .flags = 0,
                .offset = @intCast(@offsetOf(T, field.name)),
                .size = @intCast(@sizeOf(field.type)),
                .alignment = @intCast(@alignOf(field.type)),
                .reserved = [_]u8{0} ** 3,
                .type_info_offset = 0,
            };

            try fields.append(field_info);
        }

        info.checksum = computeStructChecksum(&info, fields.items);

        const entry = SchemaEntry{
            .id = schema_id,
            .name = try self.allocator.dupe(u8, name),
            .info = info,
            .fields = try fields.toOwnedSlice(),
            .type_name = try self.allocator.dupe(u8, @typeName(T)),
        };

        try self.entries.put(schema_id, entry);
        try self.name_index.put(entry.name, schema_id);

        return schema_id;
    }

    pub fn getSchema(self: *Self, id: u32) ?SchemaEntry {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.entries.get(id);
    }

    pub fn getSchemaByName(self: *Self, name: []const u8) ?SchemaEntry {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const id = self.name_index.get(name) orelse return null;
        return self.entries.get(id);
    }

    pub fn hasSchema(self: *Self, id: u32) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.entries.contains(id);
    }

    pub fn validateObject(self: *Self, data: []const u8, schema_id: u32) !bool {
        const entry = self.getSchema(schema_id) orelse return error.SchemaNotFound;

        if (data.len < @as(usize, entry.info.size)) {
            return error.DataTooSmall;
        }

        for (entry.fields) |field| {
            const end_offset: usize = @as(usize, field.offset) + @as(usize, field.size);
            if (end_offset > data.len) {
                return error.FieldOutOfBounds;
            }
        }

        return true;
    }

    pub fn migrateObject(
        self: *Self,
        old_data: []const u8,
        old_schema_id: u32,
        new_schema_id: u32,
    ) ![]u8 {
        const old_entry = self.getSchema(old_schema_id) orelse return error.SchemaNotFound;
        const new_entry = self.getSchema(new_schema_id) orelse return error.SchemaNotFound;

        if (old_schema_id == new_schema_id) {
            const copy = try self.allocator.dupe(u8, old_data);
            return copy;
        }

        const migration_key = (@as(u64, old_schema_id) << 32) | @as(u64, new_schema_id);

        const new_data = try self.allocator.alloc(u8, new_entry.info.size);
        @memset(new_data, 0);

        const copy_len = @min(old_data.len, new_data.len);
        @memcpy(new_data[0..copy_len], old_data[0..copy_len]);

        if (self.migrations.get(migration_key)) |migration| {
            migration.migrate_fn(
                @constCast(@ptrCast(old_data.ptr)),
                @ptrCast(new_data.ptr),
                old_entry.info.size,
                new_entry.info.size,
            );
        }

        return new_data;
    }

    pub fn registerMigration(
        self: *Self,
        from_schema_id: u32,
        to_schema_id: u32,
        migration_fn: MigrationFn,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const key = (@as(u64, from_schema_id) << 32) | @as(u64, to_schema_id);

        const migration = Migration{
            .from_version = from_schema_id,
            .to_version = to_schema_id,
            .migrate_fn = migration_fn,
        };

        try self.migrations.put(key, migration);
    }

    pub fn getFieldOffset(self: *Self, schema_id: u32, field_name: []const u8) ?u16 {
        const entry = self.getSchema(schema_id) orelse return null;

        for (entry.fields) |field| {
            const name_start = self.string_pool.items[field.name_offset..];
            const name = name_start[0..field.name_len];
            if (std.mem.eql(u8, name, field_name)) {
                return field.offset;
            }
        }

        return null;
    }

    pub fn getFieldInfo(self: *Self, schema_id: u32, field_name: []const u8) ?FieldInfo {
        const entry = self.getSchema(schema_id) orelse return null;

        for (entry.fields) |field| {
            const name_start = self.string_pool.items[field.name_offset..];
            const name = name_start[0..field.name_len];
            if (std.mem.eql(u8, name, field_name)) {
                return field;
            }
        }

        return null;
    }

    pub fn getSchemaSize(self: *Self, schema_id: u32) ?u32 {
        const entry = self.getSchema(schema_id) orelse return null;
        return entry.info.size;
    }

    pub fn getSchemaAlignment(self: *Self, schema_id: u32) ?u32 {
        const entry = self.getSchema(schema_id) orelse return null;
        return entry.info.alignment;
    }

    pub fn compareSchemas(self: *Self, id1: u32, id2: u32) !SchemaComparison {
        const entry1 = self.getSchema(id1) orelse return error.SchemaNotFound;
        const entry2 = self.getSchema(id2) orelse return error.SchemaNotFound;

        var comparison = SchemaComparison{
            .compatible = true,
            .layout_changed = false,
            .fields_added = std.ArrayList([]const u8).init(self.allocator),
            .fields_removed = std.ArrayList([]const u8).init(self.allocator),
            .fields_modified = std.ArrayList([]const u8).init(self.allocator),
        };

        errdefer {
            comparison.fields_added.deinit();
            comparison.fields_removed.deinit();
            comparison.fields_modified.deinit();
        }

        if (entry1.info.size != entry2.info.size or
            entry1.info.alignment != entry2.info.alignment)
        {
            comparison.layout_changed = true;
        }

        for (entry1.fields) |field1| {
            const name1 = self.string_pool.items[field1.name_offset..][0..field1.name_len];
            var found = false;

            for (entry2.fields) |field2| {
                const name2 = self.string_pool.items[field2.name_offset..][0..field2.name_len];

                if (std.mem.eql(u8, name1, name2)) {
                    found = true;
                    if (field1.size != field2.size or
                        field1.offset != field2.offset or
                        field1.kind != field2.kind)
                    {
                        try comparison.fields_modified.append(name1);
                        comparison.compatible = false;
                    }
                    break;
                }
            }

            if (!found) {
                try comparison.fields_removed.append(name1);
            }
        }

        for (entry2.fields) |field2| {
            const name2 = self.string_pool.items[field2.name_offset..][0..field2.name_len];
            var found = false;

            for (entry1.fields) |field1| {
                const name1 = self.string_pool.items[field1.name_offset..][0..field1.name_len];
                if (std.mem.eql(u8, name1, name2)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                try comparison.fields_added.append(name2);
            }
        }

        return comparison;
    }

    pub fn serializeSchema(self: *Self, schema_id: u32) ![]u8 {
        const entry = self.getSchema(schema_id) orelse return error.SchemaNotFound;

        const total_size = @sizeOf(StructInfo) + entry.fields.len * @sizeOf(FieldInfo) + entry.name.len;
        const buffer = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(buffer);

        var offset: usize = 0;

        @memcpy(buffer[offset..][0..@sizeOf(StructInfo)], std.mem.asBytes(&entry.info));
        offset += @sizeOf(StructInfo);

        for (entry.fields) |field| {
            @memcpy(buffer[offset..][0..@sizeOf(FieldInfo)], std.mem.asBytes(&field));
            offset += @sizeOf(FieldInfo);
        }

        @memcpy(buffer[offset..][0..entry.name.len], entry.name);

        return buffer;
    }

    pub fn deserializeSchema(self: *Self, data: []const u8) !u32 {
        if (data.len < @sizeOf(StructInfo)) {
            return error.DataTooSmall;
        }

        var info_copy: StructInfo = undefined;
        @memcpy(std.mem.asBytes(&info_copy), data[0..@sizeOf(StructInfo)]);

        if (info_copy.magic != SchemaMagic) {
            return error.InvalidSchemaMagic;
        }

        const fields_size = @as(usize, info_copy.field_count) * @sizeOf(FieldInfo);
        if (data.len < @sizeOf(StructInfo) + fields_size) {
            return error.DataTooSmall;
        }

        const fields_copy = try self.allocator.alloc(FieldInfo, info_copy.field_count);
        errdefer self.allocator.free(fields_copy);

        @memcpy(
            std.mem.sliceAsBytes(fields_copy),
            data[@sizeOf(StructInfo)..][0..fields_size],
        );

        const name_offset = @sizeOf(StructInfo) + fields_size;
        if (data.len < name_offset + info_copy.name_len) {
            return error.DataTooSmall;
        }

        const name = data[name_offset..][0..info_copy.name_len];

        const schema_id = self.next_schema_id.fetchAdd(1, .monotonic);

        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);

        const type_name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(type_name_dup);

        const entry = SchemaEntry{
            .id = schema_id,
            .name = name_dup,
            .info = info_copy,
            .fields = fields_copy,
            .type_name = type_name_dup,
        };

        self.lock.lock();
        defer self.lock.unlock();

        try self.entries.put(schema_id, entry);
        try self.name_index.put(entry.name, schema_id);

        return schema_id;
    }
};

pub const SchemaComparison = struct {
    compatible: bool,
    layout_changed: bool,
    fields_added: std.ArrayList([]const u8),
    fields_removed: std.ArrayList([]const u8),
    fields_modified: std.ArrayList([]const u8),

    pub fn deinit(self: *SchemaComparison) void {
        self.fields_added.deinit();
        self.fields_removed.deinit();
        self.fields_modified.deinit();
    }
};

fn fieldTypeToKind(comptime T: type) FieldKind {
    return switch (@typeInfo(T)) {
        .int => |info| if (info.signedness == .unsigned) .uint else .int,
        .float => .float,
        .bool => .bool_,
        .pointer => |info| if (info.size == .slice) .slice else .pointer,
        .array => .array,
        .@"struct" => .struct_,
        .@"union" => .union_,
        .@"enum" => .enum_,
        .optional => .optional,
        else => .struct_,
    };
}

fn computeStructChecksum(info: *const StructInfo, fields: []const FieldInfo) u32 {
    var crc: u32 = 0xFFFFFFFF;

    const info_bytes = std.mem.asBytes(info);
    for (info_bytes[0..@offsetOf(StructInfo, "checksum")]) |byte| {
        crc ^= @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            crc = if ((crc & 1) != 0) (crc >> 1) ^ 0x82F63B78 else crc >> 1;
        }
    }

    for (fields) |field| {
        const field_bytes = std.mem.asBytes(&field);
        for (field_bytes) |byte| {
            crc ^= @as(u32, byte);
            var j: usize = 0;
            while (j < 8) : (j += 1) {
                crc = if ((crc & 1) != 0) (crc >> 1) ^ 0x82F63B78 else crc >> 1;
            }
        }
    }

    return crc ^ 0xFFFFFFFF;
}

comptime {
    _ = builtin;
}

test "schema registration" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var registry = SchemaRegistry.init(alloc);
    defer registry.deinit();

    const TestStruct = extern struct {
        id: u64,
        value: u32,
        flag: bool,
    };

    const schema_id = try registry.registerSchema(TestStruct, "TestStruct");
    try testing.expect(schema_id > 0);

    const entry = registry.getSchema(schema_id);
    try testing.expect(entry != null);
    try testing.expectEqual(@as(u32, 3), entry.?.info.field_count);
}

test "schema validation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var registry = SchemaRegistry.init(alloc);
    defer registry.deinit();

    const TestStruct = extern struct {
        id: u64,
        value: u32,
    };

    const schema_id = try registry.registerSchema(TestStruct, "TestStruct");

    const valid_data = [_]u8{0} ** @sizeOf(TestStruct);
    const result = try registry.validateObject(&valid_data, schema_id);
    try testing.expect(result);
}
