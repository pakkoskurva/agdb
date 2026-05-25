const std = @import("std");

pub const PersistentPtr = extern struct {
    pool_uuid: u128,
    offset: u64,

    pub const NULL = PersistentPtr{
        .pool_uuid = 0,
        .offset = 0,
    };

    pub fn isNull(self: PersistentPtr) bool {
        return self.offset == 0;
    }

    pub fn isValid(self: PersistentPtr) bool {
        return self.offset != 0 and self.pool_uuid != 0;
    }

    pub fn equals(self: PersistentPtr, other: PersistentPtr) bool {
        return self.pool_uuid == other.pool_uuid and self.offset == other.offset;
    }

    pub fn hash(self: PersistentPtr) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.pool_uuid));
        hasher.update(std.mem.asBytes(&self.offset));
        return hasher.final();
    }

    pub fn format(
        self: PersistentPtr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("PersistentPtr{{uuid={x}, offset={}}}", .{ self.pool_uuid, self.offset });
    }
};

pub fn RelativePtr(comptime T: type) type {
    return extern struct {
        offset: u64,
        pool_uuid_low: u64,
        pool_uuid_high: u64,
        tagged: u32,

        const Self = @This();
        pub const TAG_MASK: u32 = 0x7FFF0000;
        pub const TAG_SHIFT: u32 = 16;
        pub const INLINE_FLAG: u32 = 0x80000000;

        pub fn initNull() Self {
            return Self{
                .offset = 0,
                .pool_uuid_low = 0,
                .pool_uuid_high = 0,
                .tagged = 0,
            };
        }

        pub fn init(ptr: *T, base_addr: [*]const u8, pool_uuid: u128) Self {
            const ptr_addr = @intFromPtr(ptr);
            const base = @intFromPtr(base_addr);
            const offset = if (ptr_addr >= base) ptr_addr - base else 0;

            return Self{
                .offset = offset,
                .pool_uuid_low = @as(u64, @truncate(pool_uuid)),
                .pool_uuid_high = @as(u64, @truncate(pool_uuid >> 64)),
                .tagged = 0,
            };
        }

        pub fn initFromPersistent(pptr: PersistentPtr) Self {
            return Self{
                .offset = pptr.offset,
                .pool_uuid_low = @as(u64, @truncate(pptr.pool_uuid)),
                .pool_uuid_high = @as(u64, @truncate(pptr.pool_uuid >> 64)),
                .tagged = 0,
            };
        }

        pub fn toPersistent(self: Self) PersistentPtr {
            return PersistentPtr{
                .pool_uuid = (@as(u128, self.pool_uuid_high) << 64) | @as(u128, self.pool_uuid_low),
                .offset = self.offset,
            };
        }

        pub fn isNull(self: Self) bool {
            return self.offset == 0 and self.pool_uuid_low == 0 and self.pool_uuid_high == 0;
        }

        pub fn resolve(self: Self, base_addr: [*]const u8, expected_uuid: u128) !?*T {
            if (self.isNull()) {
                return null;
            }

            const ptr_uuid = (@as(u128, self.pool_uuid_high) << 64) | @as(u128, self.pool_uuid_low);
            if (ptr_uuid != expected_uuid) {
                return error.UUIDMismatch;
            }

            if (self.tagged & INLINE_FLAG != 0) {
                return error.InlineValueNotPointer;
            }

            const addr = @intFromPtr(base_addr) + self.offset;
            return @ptrFromInt(addr);
        }

        pub fn resolveConst(self: Self, base_addr: [*]const u8, expected_uuid: u128) !?*const T {
            if (self.isNull()) {
                return null;
            }

            const ptr_uuid = (@as(u128, self.pool_uuid_high) << 64) | @as(u128, self.pool_uuid_low);
            if (ptr_uuid != expected_uuid) {
                return error.UUIDMismatch;
            }

            const addr = @intFromPtr(base_addr) + self.offset;
            return @ptrFromInt(addr);
        }

        pub fn setTag(self: *Self, tag: u16) void {
            self.tagged = (self.tagged & ~TAG_MASK) | (@as(u32, tag) << TAG_SHIFT);
        }

        pub fn getTag(self: Self) u16 {
            return @truncate(self.tagged >> TAG_SHIFT);
        }

        pub fn setInlineValue(self: *Self, value: u15) void {
            self.offset = 0;
            self.pool_uuid_low = 0;
            self.pool_uuid_high = 0;
            self.tagged = INLINE_FLAG | @as(u32, value);
        }

        pub fn getInlineValue(self: Self) ?u15 {
            if (self.tagged & INLINE_FLAG != 0) {
                return @truncate(self.tagged & 0x7FFF);
            }
            return null;
        }

        pub fn isInline(self: Self) bool {
            return (self.tagged & INLINE_FLAG) != 0;
        }
    };
}

pub fn RelativeSlice(comptime T: type) type {
    return extern struct {
        ptr: RelativePtr(T),
        len: u64,

        const Self = @This();

        pub fn initNull() Self {
            return Self{
                .ptr = RelativePtr(T).initNull(),
                .len = 0,
            };
        }

        pub fn init(ptr: [*]T, len: u64, base_addr: [*]const u8, pool_uuid: u128) Self {
            return Self{
                .ptr = RelativePtr(T).init(ptr, base_addr, pool_uuid),
                .len = len,
            };
        }

        pub fn isNull(self: Self) bool {
            return self.ptr.isNull();
        }

        pub fn resolve(self: Self, base_addr: [*]const u8, expected_uuid: u128) !?[]T {
            const ptr = try self.ptr.resolve(base_addr, expected_uuid);
            if (ptr) |p| {
                return p[0..self.len];
            }
            return null;
        }

        pub fn resolveConst(self: Self, base_addr: [*]const u8, expected_uuid: u128) !?[]const T {
            const ptr = try self.ptr.resolveConst(base_addr, expected_uuid);
            if (ptr) |p| {
                return p[0..self.len];
            }
            return null;
        }
    };
}

pub fn RelativeString() type {
    return RelativeSlice(u8);
}

pub const PointerTable = struct {
    entries: []Entry,
    count: u64,
    capacity: u64,
    allocator: std.mem.Allocator,

    const Entry = struct {
        key: PersistentPtr,
        value: ?*anyopaque,
        used: bool,
    };

    pub fn init(allocator_ptr: std.mem.Allocator, initial_capacity: u64) !PointerTable {
        const entries = try allocator_ptr.alloc(Entry, initial_capacity);
        @memset(entries, Entry{
            .key = PersistentPtr.NULL,
            .value = null,
            .used = false,
        });

        return PointerTable{
            .entries = entries,
            .count = 0,
            .capacity = initial_capacity,
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *PointerTable) void {
        self.allocator.free(self.entries);
    }

    pub fn insert(self: *PointerTable, key: PersistentPtr, value: *anyopaque) !void {
        if (@as(f64, @floatFromInt(self.count)) / @as(f64, @floatFromInt(self.capacity)) > 0.7) {
            try self.resize();
        }

        var idx = key.hash() % self.capacity;
        while (self.entries[idx].used) {
            if (self.entries[idx].key.equals(key)) {
                self.entries[idx].value = value;
                return;
            }
            idx = (idx + 1) % self.capacity;
        }

        self.entries[idx] = Entry{
            .key = key,
            .value = value,
            .used = true,
        };
        self.count += 1;
    }

    pub fn get(self: *const PointerTable, key: PersistentPtr) ?*anyopaque {
        var idx = key.hash() % self.capacity;
        var iterations: u64 = 0;

        while (self.entries[idx].used and iterations < self.capacity) {
            if (self.entries[idx].key.equals(key)) {
                return self.entries[idx].value;
            }
            idx = (idx + 1) % self.capacity;
            iterations += 1;
        }

        return null;
    }

    pub fn remove(self: *PointerTable, key: PersistentPtr) ?*anyopaque {
        var idx = key.hash() % self.capacity;
        var iterations: u64 = 0;

        while (self.entries[idx].used and iterations < self.capacity) {
            if (self.entries[idx].key.equals(key)) {
                const value = self.entries[idx].value;
                self.entries[idx] = Entry{
                    .key = PersistentPtr.NULL,
                    .value = null,
                    .used = false,
                };
                self.count -= 1;
                return value;
            }
            idx = (idx + 1) % self.capacity;
            iterations += 1;
        }

        return null;
    }

    fn resize(self: *PointerTable) !void {
        const new_capacity = self.capacity * 2;
        const new_entries = try self.allocator.alloc(Entry, new_capacity);
        @memset(new_entries, Entry{
            .key = PersistentPtr.NULL,
            .value = null,
            .used = false,
        });

        const old_entries = self.entries;
        _ = self.capacity;

        self.entries = new_entries;
        self.capacity = new_capacity;
        self.count = 0;

        for (old_entries) |entry| {
            if (entry.used and entry.value != null) {
                try self.insert(entry.key, entry.value.?);
            }
        }

        self.allocator.free(old_entries);
    }
};

pub const ResidentObjectTable = struct {
    table: PointerTable,
    base_addr: [*]const u8,
    pool_uuid: u128,

    pub fn init(allocator_ptr: std.mem.Allocator, base_addr: [*]const u8, pool_uuid: u128, capacity: u64) !ResidentObjectTable {
        return ResidentObjectTable{
            .table = try PointerTable.init(allocator_ptr, capacity),
            .base_addr = base_addr,
            .pool_uuid = pool_uuid,
        };
    }

    pub fn deinit(self: *ResidentObjectTable) void {
        self.table.deinit();
    }

    pub fn getOrLoad(self: *ResidentObjectTable, comptime T: type, ptr: PersistentPtr) !?*T {
        if (ptr.isNull()) return null;

        const cached = self.table.get(ptr);
        if (cached) |c| {
            return @ptrCast(@alignCast(c));
        }

        const addr = @intFromPtr(self.base_addr) + ptr.offset;
        const native_ptr: *T = @ptrFromInt(addr);

        try self.table.insert(ptr, native_ptr);
        return native_ptr;
    }

    pub fn invalidate(self: *ResidentObjectTable, ptr: PersistentPtr) void {
        _ = self.table.remove(ptr);
    }

    pub fn clear(self: *ResidentObjectTable) void {
        var i: u64 = 0;
        while (i < self.table.capacity) : (i += 1) {
            self.table.entries[i] = PointerTable.Entry{
                .key = PersistentPtr.NULL,
                .value = null,
                .used = false,
            };
        }
        self.table.count = 0;
    }
};

test "persistent ptr operations" {
    const testing = std.testing;
    
    var ptr = PersistentPtr{ .pool_uuid = 12345, .offset = 100 };
    try testing.expect(!ptr.isNull());
    try testing.expect(ptr.isValid());
    
    var null_ptr = PersistentPtr.NULL;
    try testing.expect(null_ptr.isNull());
}

test "relative ptr" {
    const testing = std.testing;
    
    var buffer: [1024]u8 align(64) = undefined;
    var value: u64 = 42;
    
    const base: [*]const u8 = @ptrCast(&buffer);
    const value_ptr: *u64 = &value;
    
    var rel_ptr = RelativePtr(u64).init(value_ptr, base, 12345);
    
    const resolved = try rel_ptr.resolve(base, 12345);
    try testing.expect(resolved != null);
    try testing.expectEqual(@as(u64, 42), resolved.?.*);
}

test "pointer table" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    
    var table = try PointerTable.init(alloc, 16);
    defer table.deinit();
    
    var value1: u64 = 100;
    var value2: u64 = 200;
    
    const ptr1 = PersistentPtr{ .pool_uuid = 1, .offset = 100 };
    const ptr2 = PersistentPtr{ .pool_uuid = 1, .offset = 200 };
    
    try table.insert(ptr1, &value1);
    try table.insert(ptr2, &value2);
    
    const found1 = table.get(ptr1);
    const found2 = table.get(ptr2);
    
    try testing.expect(found1 != null);
    try testing.expect(found2 != null);
    try testing.expectEqual(@as(u64, 100), @as(*u64, @ptrCast(found1.?)).*);
}
