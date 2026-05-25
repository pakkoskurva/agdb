const std = @import("std");
const header = @import("header.zig");
const pointer = @import("pointer.zig");
const allocator_mod = @import("allocator.zig");
const transaction_mod = @import("transaction.zig");
const gc = @import("gc.zig");
const wal_mod = @import("wal.zig");

pub const EditMode = enum(u8) {
    read,
    write,
    exclusive,
};

pub fn Handle(comptime T: type) type {
    return struct {
        ptr: pointer.PersistentPtr,
        native: ?*T,
        store: *PersistentStore,
        mode: EditMode,
        dirty: bool,
        edit_count: u32,

        const Self = @This();

        pub fn init(store: *PersistentStore, ptr: pointer.PersistentPtr) Self {
            return Self{
                .ptr = ptr,
                .native = null,
                .store = store,
                .mode = .read,
                .dirty = false,
                .edit_count = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.dirty) {
                self.store.allocator.lock.lock();
                defer self.store.allocator.lock.unlock();

                var tx = self.store.tx_manager.begin() catch return;
                defer {
                    self.store.tx_manager.rollback(&tx) catch {};
                }

                self.store.tx_manager.commit(&tx) catch {};
                self.dirty = false;
            }
        }

        pub fn get(self: *Self) ?*T {
            if (self.native != null) {
                return self.native;
            }

            self.native = self.store.resolve(T, self.ptr) catch return null;
            return self.native;
        }

        pub fn getConst(self: *Self) ?*const T {
            return self.get();
        }

        pub fn edit(self: *Self) !*T {
            if (self.mode == .read) {
                self.mode = .write;
            }

            if (self.edit_count == 0) {
                var tx = try self.store.tx_manager.begin();
                try self.store.tx_manager.recordWrite(&tx, self.ptr.offset, @sizeOf(T), &[_]u8{});
                self.edit_count += 1;
            }

            self.dirty = true;

            if (self.native == null) {
                self.native = try self.store.resolve(T, self.ptr);
            }

            return self.native.?;
        }

        pub fn commit(self: *Self) !void {
            if (!self.dirty) return;

            if (self.native) |native| {
                try self.store.flush(self.ptr, std.mem.asBytes(native));
            }

            self.dirty = false;
            self.edit_count = 0;
        }

        pub fn rollback(self: *Self) void {
            self.dirty = false;
            self.edit_count = 0;
        }

        pub fn isDirty(self: *const Self) bool {
            return self.dirty;
        }

        pub fn getPtr(self: *const Self) pointer.PersistentPtr {
            return self.ptr;
        }
    };
}

pub fn PersistentArray(comptime T: type) type {
    return struct {
        ptr: pointer.PersistentPtr,
        len: u64,
        capacity: u64,
        store: *PersistentStore,

        const Self = @This();

        pub fn init(store: *PersistentStore, initial_capacity: u64) !Self {
            const size = initial_capacity * @sizeOf(T);
            const ptr = try store.allocate(size);
            return Self{
                .ptr = ptr,
                .len = 0,
                .capacity = initial_capacity,
                .store = store,
            };
        }

        pub fn deinit(self: *Self) void {
            self.store.deallocate(self.ptr) catch {};
        }

        pub fn get(self: *Self, idx: u64) ?*T {
            if (idx >= self.len) return null;

            const offset = self.ptr.offset + idx * @sizeOf(T);
            const elem_ptr = pointer.PersistentPtr{
                .pool_uuid = self.ptr.pool_uuid,
                .offset = offset,
            };

            return self.store.resolve(T, elem_ptr) catch null;
        }

        pub fn append(self: *Self, value: T) !void {
            if (self.len >= self.capacity) {
                try self.grow();
            }

            const idx = self.len;
            const offset = self.ptr.offset + idx * @sizeOf(T);
            const elem_ptr = pointer.PersistentPtr{
                .pool_uuid = self.ptr.pool_uuid,
                .offset = offset,
            };

            try self.store.write(elem_ptr, std.mem.asBytes(&value));
            self.len += 1;
        }

        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            self.len -= 1;

            const idx = self.len;
            if (self.get(idx)) |elem| {
                return elem.*;
            }
            return null;
        }

        pub fn set(self: *Self, idx: u64, value: T) !void {
            if (idx >= self.len) return error.OutOfBounds;

            const offset = self.ptr.offset + idx * @sizeOf(T);
            const elem_ptr = pointer.PersistentPtr{
                .pool_uuid = self.ptr.pool_uuid,
                .offset = offset,
            };

            try self.store.write(elem_ptr, std.mem.asBytes(&value));
        }

        fn grow(self: *Self) !void {
            const new_capacity = self.capacity * 2;
            const new_size = new_capacity * @sizeOf(T);

            const new_ptr = try self.store.reallocate(self.ptr, new_size);

            self.ptr = new_ptr;
            self.capacity = new_capacity;
        }

        pub fn length(self: *const Self) u64 {
            return self.len;
        }

        pub fn asSlice(self: *Self) ?[]T {
            if (self.len == 0) return null;

            const base = self.store.resolve(T, self.ptr) catch return null;
            if (base) |b| {
                return b[0..self.len];
            }
            return null;
        }
    };
}

pub fn PersistentMap(comptime K: type, comptime V: type) type {
    return struct {
        buckets_ptr: pointer.PersistentPtr,
        bucket_count: u64,
        entry_count: u64,
        store: *PersistentStore,

        const Entry = extern struct {
            key: K,
            value: V,
            next_offset: u64,
            hash: u64,
            occupied: u8,
            reserved: [7]u8,
        };

        const Self = @This();

        pub fn init(store: *PersistentStore, initial_buckets: u64) !Self {
            const bucket_size = initial_buckets * @sizeOf(u64);
            const buckets_ptr = try store.allocate(bucket_size);

            return Self{
                .buckets_ptr = buckets_ptr,
                .bucket_count = initial_buckets,
                .entry_count = 0,
                .store = store,
            };
        }

        pub fn deinit(self: *Self) void {
            self.store.deallocate(self.buckets_ptr) catch {};
        }

        pub fn get(self: *Self, key: K) ?V {
            const hash = self.hashKey(key);
            const bucket_idx = hash % self.bucket_count;

            const offset = self.buckets_ptr.offset + bucket_idx * @sizeOf(u64);
            const bucket_ptr = pointer.PersistentPtr{
                .pool_uuid = self.buckets_ptr.pool_uuid,
                .offset = offset,
            };

            const entry_offset_raw = self.store.read(u64, bucket_ptr) catch return null;
            if (entry_offset_raw) |entry_offset| {
                var current_offset = entry_offset;
                while (current_offset != 0) {
                    const entry_ptr = pointer.PersistentPtr{
                        .pool_uuid = self.buckets_ptr.pool_uuid,
                        .offset = current_offset,
                    };

                    const entry = self.store.resolve(Entry, entry_ptr) catch return null;
                    if (entry) |e| {
                        if (e.hash == hash and std.mem.eql(K, &e.key, &key)) {
                            return e.value;
                        }
                        current_offset = e.next_offset;
                    } else {
                        break;
                    }
                }
            }

            return null;
        }

        pub fn put(self: *Self, key: K, value: V) !void {
            const hash = self.hashKey(key);
            const bucket_idx = hash % self.bucket_count;

            const entry_size = @sizeOf(Entry);
            const entry_ptr = try self.store.allocate(entry_size);

            const entry = Entry{
                .key = key,
                .value = value,
                .next_offset = 0,
                .hash = hash,
                .occupied = 1,
                .reserved = [_]u8{0} ** 7,
            };

            try self.store.write(entry_ptr, std.mem.asBytes(&entry));

            const bucket_offset = self.buckets_ptr.offset + bucket_idx * @sizeOf(u64);
            const bucket_ptr = pointer.PersistentPtr{
                .pool_uuid = self.buckets_ptr.pool_uuid,
                .offset = bucket_offset,
            };

            _ = self.store.read(u64, bucket_ptr) catch null;
            try self.store.write(bucket_ptr, std.mem.asBytes(&entry_ptr.offset));

            self.entry_count += 1;
        }

        pub fn remove(self: *Self, key: K) !?V {
            const hash = self.hashKey(key);
            const bucket_idx = hash % self.bucket_count;

            const bucket_offset = self.buckets_ptr.offset + bucket_idx * @sizeOf(u64);
            const bucket_ptr = pointer.PersistentPtr{
                .pool_uuid = self.buckets_ptr.pool_uuid,
                .offset = bucket_offset,
            };

            var prev_offset: u64 = 0;
            const current_offset_raw = self.store.read(u64, bucket_ptr) catch return null;

            if (current_offset_raw) |current_offset| {
                var curr = current_offset;
                while (curr != 0) {
                    const entry_ptr = pointer.PersistentPtr{
                        .pool_uuid = self.buckets_ptr.pool_uuid,
                        .offset = curr,
                    };

                    const entry = self.store.resolve(Entry, entry_ptr) catch return null;
                    if (entry) |e| {
                        if (e.hash == hash and std.mem.eql(K, &e.key, &key)) {
                            const old_value = e.value;

                            if (prev_offset == 0) {
                                try self.store.write(bucket_ptr, std.mem.asBytes(&e.next_offset));
                            }

                            try self.store.deallocate(entry_ptr);
                            self.entry_count -= 1;

                            return old_value;
                        }
                        prev_offset = curr;
                        curr = e.next_offset;
                    } else {
                        break;
                    }
                }
            }

            return null;
        }

        pub fn contains(self: *Self, key: K) bool {
            return self.get(key) != null;
        }

        pub fn size(self: *const Self) u64 {
            return self.entry_count;
        }

        fn hashKey(self: *const Self, key: K) u64 {
            _ = self;
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(std.mem.asBytes(&key));
            return hasher.final();
        }
    };
}

pub const PersistentStore = struct {
    allocator: *allocator_mod.PersistentAllocator,
    tx_manager: *transaction_mod.TransactionManager,
    gc: *gc.RefCountGC,
    resident_objects: pointer.ResidentObjectTable,
    root: ?pointer.PersistentPtr,
    allocator_mem: std.mem.Allocator,

    pub fn init(
        allocator_ptr: std.mem.Allocator,
        alloc_inst: *allocator_mod.PersistentAllocator,
        tx_mgr: *transaction_mod.TransactionManager,
        gc_inst: *gc.RefCountGC,
    ) !*PersistentStore {
        const self = try allocator_ptr.create(PersistentStore);
        errdefer allocator_ptr.destroy(self);

        const base_addr = alloc_inst.heap.getBaseAddress();
        const pool_uuid = alloc_inst.heap.getPoolUUID();

        self.* = PersistentStore{
            .allocator = alloc_inst,
            .tx_manager = tx_mgr,
            .gc = gc_inst,
            .resident_objects = try pointer.ResidentObjectTable.init(allocator_ptr, base_addr, pool_uuid, 1024),
            .root = null,
            .allocator_mem = allocator_ptr,
        };

        return self;
    }

    pub fn deinit(self: *PersistentStore) void {
        self.resident_objects.deinit();
        self.allocator_mem.destroy(self);
    }

    pub fn allocate(self: *PersistentStore, size: u64) !pointer.PersistentPtr {
        const ptr = try self.allocator.alloc(size, 64);

        try self.gc.registerObject(ptr, gc.GCObjectInfo{
            .ref_count = 1,
            .flags = 0,
            .schema_id = 0,
            .first_ref_offset = 0,
            .scan_fn_offset = 0,
            .finalize_fn_offset = 0,
            .reserved = [_]u8{0} ** 32,
        });

        return ptr;
    }

    pub fn deallocate(self: *PersistentStore, ptr: pointer.PersistentPtr) !void {
        self.resident_objects.invalidate(ptr);
        try self.gc.unregisterObject(ptr);
        try self.allocator.free(ptr);
    }

    pub fn reallocate(self: *PersistentStore, ptr: pointer.PersistentPtr, new_size: u64) !pointer.PersistentPtr {
        self.resident_objects.invalidate(ptr);
        return try self.allocator.realloc(ptr, new_size, 64);
    }

    pub fn write(self: *PersistentStore, ptr: pointer.PersistentPtr, data: []const u8) !void {
        const base_addr = self.allocator.heap.getBaseAddress();
        const dest = base_addr + ptr.offset;
        @memcpy(dest[0..data.len], data);

        try self.allocator.heap.flushRange(ptr.offset + data.len);
    }

    pub fn read(self: *PersistentStore, comptime T: type, ptr: pointer.PersistentPtr) !?T {
        const native = try self.resolve(T, ptr);
        if (native) |n| {
            return n.*;
        }
        return null;
    }

    pub fn resolve(self: *PersistentStore, comptime T: type, ptr: pointer.PersistentPtr) !?*T {
        if (ptr.isNull()) return null;

        const cached = self.resident_objects.getOrLoad(T, ptr) catch return null;
        return cached;
    }

    pub fn flush(self: *PersistentStore, ptr: pointer.PersistentPtr, data: []const u8) !void {
        _ = ptr;
        _ = data;
        try self.allocator.heap.flush();
    }

    pub fn getRoot(self: *PersistentStore) ?pointer.PersistentPtr {
        return self.allocator.heap.getRoot();
    }

    pub fn setRoot(self: *PersistentStore, ptr: pointer.PersistentPtr) !void {
        const tx = try self.tx_manager.begin();
        errdefer self.tx_manager.rollback(tx) catch {};

        try self.tx_manager.recordRootUpdate(tx, self.root, ptr);
        try self.tx_manager.commit(tx);

        self.root = ptr;
    }

    pub fn beginTransaction(self: *PersistentStore) !*transaction_mod.Transaction {
        return try self.tx_manager.begin();
    }

    pub fn commitTransaction(self: *PersistentStore, tx: *transaction_mod.Transaction) !void {
        try self.tx_manager.commit(tx);
    }

    pub fn rollbackTransaction(self: *PersistentStore, tx: *transaction_mod.Transaction) !void {
        try self.tx_manager.rollback(tx);
    }

    pub fn editObject(self: *PersistentStore, comptime T: type, ptr: pointer.PersistentPtr) !Handle(T) {
        var handle = Handle(T).init(self, ptr);
        _ = try handle.edit();
        return handle;
    }

    pub fn createObject(self: *PersistentStore, comptime T: type, value: T) !Handle(T) {
        const ptr = try self.allocate(@sizeOf(T));
        errdefer self.deallocate(ptr) catch {};

        try self.write(ptr, std.mem.asBytes(&value));

        const handle = Handle(T).init(self, ptr);
        return handle;
    }

    pub fn refCount(self: *PersistentStore, ptr: pointer.PersistentPtr) !u32 {
        return try self.gc.getRefCount(ptr);
    }

    pub fn addRef(self: *PersistentStore, ptr: pointer.PersistentPtr) !void {
        try self.gc.incrementRefCount(ptr);
    }

    pub fn releaseRef(self: *PersistentStore, ptr: pointer.PersistentPtr) !void {
        try self.gc.decrementRefCount(ptr);
    }
};

test "persistent store allocation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_store.dat";
    const test_wal_path = "/tmp/test_store.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try @import("pheap.zig").PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit();

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var palloc = try allocator_mod.PersistentAllocator.init(alloc, heap, wal);
    defer palloc.deinit();

    var tx_mgr = try transaction_mod.TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    var gc_inst = try gc.RefCountGC.init(alloc, palloc, wal);
    defer gc_inst.deinit();

    var store = try PersistentStore.init(alloc, palloc, tx_mgr, gc_inst);
    defer store.deinit();

    const ptr = try store.allocate(128);
    try testing.expect(!ptr.isNull());

    const test_data = [_]u8{1, 2, 3, 4, 5, 6, 7, 8};
    try store.write(ptr, &test_data);

    const read_val = try store.read([8]u8, ptr);
    try testing.expect(read_val != null);
    try testing.expectEqualSlices(u8, &test_data, &read_val.?);
}

test "handle operations" {
    const testing = std.testing;

    const TestStruct = extern struct {
        value: u64,
        name: [16]u8,
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_handle.dat";
    const test_wal_path = "/tmp/test_handle.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try @import("pheap.zig").PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit();

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var palloc = try allocator_mod.PersistentAllocator.init(alloc, heap, wal);
    defer palloc.deinit();

    var tx_mgr = try transaction_mod.TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    var gc_inst = try gc.RefCountGC.init(alloc, palloc, wal);
    defer gc_inst.deinit();

    var store = try PersistentStore.init(alloc, palloc, tx_mgr, gc_inst);
    defer store.deinit();

    var obj = TestStruct{
        .value = 42,
        .name = [_]u8{0} ** 16,
    };
    @memcpy(obj.name[0..5], "hello");

    var handle = try store.createObject(TestStruct, obj);
    defer handle.deinit();

    const obj_ptr = handle.get();
    try testing.expect(obj_ptr != null);
    try testing.expectEqual(@as(u64, 42), obj_ptr.?.value);
}
