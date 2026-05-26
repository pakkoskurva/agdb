const std = @import("std");
const header = @import("header.zig");
const pointer = @import("pointer.zig");
const pheap = @import("pheap.zig");
const wal_mod = @import("wal.zig");
const mem_utils = @import("mem_utils.zig");
const topology_mod = @import("topology.zig");

pub const MIN_ALIGNMENT: u64 = 64;
pub const MIN_BLOCK_SIZE: u64 = 64;
pub const NUM_SIZE_CLASSES: usize = 32;
pub const MAX_SMALL_SIZE: u64 = 4096;

pub const CACHE_LINE_BYTES: usize = 64;
pub const SLAB_CACHE_LINES: usize = 8;
pub const SLAB_BYTES: usize = SLAB_CACHE_LINES * CACHE_LINE_BYTES;

pub const SlabLayout = struct {
    item_size: usize,
    items_per_slab: usize,
    slab_bytes: usize,
    header_bytes: usize,
    padding_bytes: usize,
};

pub fn computeSlabLayout(comptime item_size: usize) SlabLayout {
    const hdr = CACHE_LINE_BYTES;
    const data_bytes = SLAB_BYTES - hdr;
    const items = if (item_size == 0) 0 else data_bytes / item_size;
    const used = items * item_size;
    const pad = data_bytes - used;
    return SlabLayout{
        .item_size = item_size,
        .items_per_slab = items,
        .slab_bytes = SLAB_BYTES,
        .header_bytes = hdr,
        .padding_bytes = pad,
    };
}

pub const CacheLineSlabHeader = extern struct {
    count: u32,
    _p0: u32,
    next_slab: u64,
    _pad: [48]u8,

    comptime {
        if (@sizeOf(CacheLineSlabHeader) != CACHE_LINE_BYTES)
            @compileError("CacheLineSlabHeader must be exactly one cache line");
    }

    pub fn init() CacheLineSlabHeader {
        return .{
            .count = 0,
            ._p0 = 0,
            .next_slab = 0,
            ._pad = [_]u8{0} ** 48,
        };
    }
};

pub fn CacheLinePackedSlab(comptime T: type) type {
    const item_size = @max(1, @sizeOf(T));
    const data_bytes = SLAB_BYTES - CACHE_LINE_BYTES;
    const N = data_bytes / item_size;

    return struct {
        hdr: CacheLineSlabHeader align(CACHE_LINE_BYTES),
        items: [N]T,

        pub fn init() @This() {
            return .{
                .hdr = CacheLineSlabHeader.init(),
                .items = undefined,
            };
        }

        pub fn capacity() usize {
            return N;
        }

        pub fn slabLayout() SlabLayout {
            return computeSlabLayout(item_size);
        }
    };
}

pub const SizeClass = struct {
    size: u64,
    free_list_offset: u64,
    count: u64,
};

pub const AllocatorMetadata = extern struct {
    magic: u32,
    total_allocated: u64,
    total_freed: u64,
    allocation_count: u64,
    free_count: u64,
    num_size_classes: u64,
    free_heap_offset: u64,
    checksum: u32,
    reserved: [36]u8,

    pub const ALLOCATOR_MAGIC: u32 = 0x414C4F43;

    pub fn init() AllocatorMetadata {
        return AllocatorMetadata{
            .magic = ALLOCATOR_MAGIC,
            .total_allocated = 0,
            .total_freed = 0,
            .allocation_count = 0,
            .free_count = 0,
            .num_size_classes = NUM_SIZE_CLASSES,
            .free_heap_offset = 0,
            .checksum = 0,
            .reserved = [_]u8{0} ** 36,
        };
    }

    pub fn validate(self: *const AllocatorMetadata) !void {
        if (self.magic != ALLOCATOR_MAGIC) {
            return error.InvalidAllocatorMagic;
        }
    }

    pub fn canRepair(self: *const AllocatorMetadata) !bool {
        return self.magic == ALLOCATOR_MAGIC;
    }

    pub fn updateChecksum(self: *AllocatorMetadata) void {
        self.checksum = self.computeChecksum();
    }

    pub fn computeChecksum(self: *const AllocatorMetadata) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..@offsetOf(AllocatorMetadata, "checksum")]) |byte| {
            crc = crc32cByte(crc, byte);
        }
        return crc ^ 0xFFFFFFFF;
    }

    fn crc32cByte(crc: u32, byte: u8) u32 {
        const POLY: u32 = 0x82F63B78;
        var c = crc ^ @as(u32, byte);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            if ((c & 1) != 0) {
                c = (c >> 1) ^ POLY;
            } else {
                c = c >> 1;
            }
        }
        return c;
    }
};

pub const FreeListNode = extern struct {
    magic: u32,
    size: u64,
    prev: u64,
    next: u64,
    checksum: u32,
    reserved: u32,

    pub const NODE_MAGIC: u32 = 0x46524545;

    pub fn init(size: u64) FreeListNode {
        return FreeListNode{
            .magic = NODE_MAGIC,
            .size = size,
            .prev = 0,
            .next = 0,
            .checksum = 0,
            .reserved = 0,
        };
    }

    pub fn validate(self: *const FreeListNode) !void {
        if (self.magic != NODE_MAGIC) {
            return error.InvalidFreeListMagic;
        }
    }
};

pub const PersistentAllocator = struct {
    heap: *pheap.PersistentHeap,
    wal: *wal_mod.WAL,
    metadata: *AllocatorMetadata,
    size_classes: [NUM_SIZE_CLASSES]SizeClass,
    base_addr: [*]u8,
    allocator: std.mem.Allocator,
    free_list_heads: [NUM_SIZE_CLASSES]u64,
    large_free_list: u64,
    lock: std.Thread.Mutex,
    mpsc_lanes: [NUM_SIZE_CLASSES]*topology_mod.MPSCQueue(u64),

    const Self = @This();

    pub fn init(
        allocator_ptr: std.mem.Allocator,
        heap: *pheap.PersistentHeap,
        wal: *wal_mod.WAL,
    ) !*PersistentAllocator {
        const self = try allocator_ptr.create(PersistentAllocator);
        errdefer allocator_ptr.destroy(self);

        const base_addr = heap.getBaseAddress();
        const metadata_offset = header.HEADER_SIZE;

        const metadata_ptr: *AllocatorMetadata = @ptrCast(@alignCast(base_addr + metadata_offset));
        const needs_init = metadata_ptr.magic != AllocatorMetadata.ALLOCATOR_MAGIC;

        if (needs_init) {
            metadata_ptr.* = AllocatorMetadata.init();
            metadata_ptr.free_heap_offset = metadata_offset + @sizeOf(AllocatorMetadata) + @sizeOf([NUM_SIZE_CLASSES]u64);
            metadata_ptr.updateChecksum();
            try heap.flushRange(@sizeOf(header.HeapHeader) + @sizeOf(AllocatorMetadata));
        } else {
            try metadata_ptr.validate();
        }

        var size_classes: [NUM_SIZE_CLASSES]SizeClass = undefined;
        var current_size: u64 = MIN_BLOCK_SIZE;
        var i: usize = 0;
        while (i < NUM_SIZE_CLASSES) : (i += 1) {
            size_classes[i] = SizeClass{
                .size = current_size,
                .free_list_offset = 0,
                .count = 0,
            };
            current_size = @as(u64, @intFromFloat(@ceil(@as(f64, @floatFromInt(current_size)) * 1.25)));
        }

        var free_list_heads: [NUM_SIZE_CLASSES]u64 = undefined;
        @memset(&free_list_heads, 0);

        const free_list_storage_offset = metadata_offset + @sizeOf(AllocatorMetadata);
        const free_list_storage: *[NUM_SIZE_CLASSES]u64 = @ptrCast(@alignCast(base_addr + free_list_storage_offset));

        if (!needs_init) {
            i = 0;
            while (i < NUM_SIZE_CLASSES) : (i += 1) {
                free_list_heads[i] = free_list_storage[i];
            }
        }

        var mpsc_lanes: [NUM_SIZE_CLASSES]*topology_mod.MPSCQueue(u64) = undefined;
        var lanes_init: usize = 0;
        errdefer {
            var k: usize = 0;
            while (k < lanes_init) : (k += 1) {
                mpsc_lanes[k].deinit();
                allocator_ptr.destroy(mpsc_lanes[k]);
            }
        }
        while (lanes_init < NUM_SIZE_CLASSES) : (lanes_init += 1) {
            const q = try allocator_ptr.create(topology_mod.MPSCQueue(u64));
            q.initPtr(allocator_ptr);
            mpsc_lanes[lanes_init] = q;
        }

        self.* = PersistentAllocator{
            .heap = heap,
            .wal = wal,
            .metadata = metadata_ptr,
            .size_classes = size_classes,
            .base_addr = base_addr,
            .allocator = allocator_ptr,
            .free_list_heads = free_list_heads,
            .large_free_list = 0,
            .lock = std.Thread.Mutex{},
            .mpsc_lanes = mpsc_lanes,
        };

        return self;
    }

    pub fn deinit(self: *PersistentAllocator) void {
        for (&self.mpsc_lanes) |lane| {
            lane.deinit();
            self.allocator.destroy(lane);
        }
        self.allocator.destroy(self);
    }

    pub fn undoAllocation(self: *Self, offset: u64, size: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (offset < header.HEADER_SIZE + @sizeOf(AllocatorMetadata)) {
            return error.InvalidUndo;
        }

        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(self.base_addr + offset));
        if (!obj_header.isFreed()) {
            obj_header.setFreed(true);
            obj_header.checksum = obj_header.computeChecksum();
            try self.heap.flushRange(offset + @sizeOf(header.ObjectHeader));
        }

        if (self.metadata.allocation_count > 0) {
            self.metadata.allocation_count -= 1;
        }
        if (self.metadata.total_allocated >= size) {
            self.metadata.total_allocated -= size;
        }
        self.metadata.updateChecksum();
    }

    pub fn alloc(self: *Self, size: u64, alignment: u64) !pointer.PersistentPtr {
        self.lock.lock();
        defer self.lock.unlock();

        const actual_alignment = @max(alignment, MIN_ALIGNMENT);
        const actual_size = alignTo(@max(size, MIN_BLOCK_SIZE), actual_alignment);

        var tx = try self.wal.beginTransaction();
        defer {
            self.wal.endTransaction(&tx) catch {};
        }

        var offset: u64 = 0;

        if (actual_size <= MAX_SMALL_SIZE) {
            offset = try self.allocateFromSizeClass(actual_size, &tx);
        } else {
            offset = try self.allocateLarge(actual_size, &tx);
        }

        if (offset == 0) {
            offset = try self.allocateFromHeapEnd(actual_size, &tx);
        }

        if (offset == 0) {
            return error.OutOfMemory;
        }

        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(self.base_addr + offset));
        obj_header.* = header.ObjectHeader.init(actual_size, 0);
        obj_header.checksum = obj_header.computeChecksum();

        self.metadata.total_allocated += actual_size;
        self.metadata.allocation_count += 1;
        self.metadata.updateChecksum();

        try self.heap.flushRange(offset + @sizeOf(header.ObjectHeader));
        try self.wal.appendRecord(&tx, .allocate, offset, actual_size);

        return pointer.PersistentPtr{
            .pool_uuid = self.heap.getPoolUUID(),
            .offset = offset,
        };
    }

    fn freeLocked(self: *Self, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;

        if (ptr.pool_uuid != self.heap.getPoolUUID()) {
            return error.UUIDMismatch;
        }

        const offset = ptr.offset;
        if (offset < header.HEADER_SIZE + @sizeOf(AllocatorMetadata)) {
            return error.InvalidFree;
        }

        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(self.base_addr + offset));
        try obj_header.validate();

        if (obj_header.isFreed()) {
            return error.DoubleFree;
        }

        var tx = try self.wal.beginTransaction();
        defer {
            self.wal.endTransaction(&tx) catch {};
        }

        try self.wal.appendRecord(&tx, .free, offset, obj_header.size);

        const size = obj_header.size;

        const data_start = self.base_addr + offset + @sizeOf(header.ObjectHeader);
        if (size >= @sizeOf(header.ObjectHeader)) {
            const data_size = size - @sizeOf(header.ObjectHeader);
            if (data_size > 0) {
                mem_utils.secureZeroMemory(data_start, data_size);
            }
        }

        obj_header.setFreed(true);
        obj_header.checksum = obj_header.computeChecksum();

        if (size <= MAX_SMALL_SIZE) {
            try self.addToSizeClass(size, offset, &tx);
        } else {
            try self.addToLargeFreeList(offset, size, &tx);
        }

        self.metadata.total_freed += size;
        self.metadata.free_count += 1;
        self.metadata.updateChecksum();

        try self.heap.flushRange(offset + @sizeOf(header.ObjectHeader));
    }

    pub fn free(self: *Self, ptr: pointer.PersistentPtr) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.freeLocked(ptr);
    }

    pub fn realloc(self: *Self, ptr: pointer.PersistentPtr, new_size: u64, alignment: u64) !pointer.PersistentPtr {
        if (ptr.isNull()) {
            return self.alloc(new_size, alignment);
        }

        const offset = ptr.offset;
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(self.base_addr + offset));
        try obj_header.validate();

        const old_size = obj_header.size;

        if (new_size <= old_size) {
            return ptr;
        }

        const new_ptr = try self.alloc(new_size, alignment);
        errdefer self.free(new_ptr) catch {};

        const old_data_start = offset + @sizeOf(header.ObjectHeader);
        const new_data_start = new_ptr.offset + @sizeOf(header.ObjectHeader);

        const copy_size = @min(old_size, new_size);
        const src = self.base_addr + old_data_start;
        const dest = self.base_addr + new_data_start;
        @memcpy(dest[0..copy_size], src[0..copy_size]);

        try self.free(ptr);

        return new_ptr;
    }

    fn allocateFromSizeClass(self: *Self, size: u64, tx: *wal_mod.Transaction) !u64 {
        const class_idx = self.getSizeClassIndex(size);
        if (class_idx >= NUM_SIZE_CLASSES) return 0;

        var head_offset = self.free_list_heads[class_idx];
        while (head_offset != 0) {
            const node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + head_offset));
            node.validate() catch {
                head_offset = node.next;
                continue;
            };

            if (node.size >= size) {
                if (node.prev != 0) {
                    const prev_node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + node.prev));
                    prev_node.next = node.next;
                }
                if (node.next != 0) {
                    const next_node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + node.next));
                    next_node.prev = node.prev;
                }

                if (self.free_list_heads[class_idx] == head_offset) {
                    self.free_list_heads[class_idx] = node.next;
                }

                const free_list_storage_offset = header.HEADER_SIZE + @sizeOf(AllocatorMetadata);
                const free_list_storage: *[NUM_SIZE_CLASSES]u64 = @ptrCast(@alignCast(self.base_addr + free_list_storage_offset));
                free_list_storage[class_idx] = self.free_list_heads[class_idx];

                try self.wal.appendRecord(tx, .free_list_remove, head_offset, node.size);

                return head_offset;
            }

            head_offset = node.next;
        }

        return 0;
    }

    fn allocateLarge(self: *Self, size: u64, tx: *wal_mod.Transaction) !u64 {
        var best_offset: u64 = 0;
        var best_size: u64 = 0;
        var best_prev: u64 = 0;
        var prev_offset: u64 = 0;

        var current_offset = self.large_free_list;
        while (current_offset != 0) {
            const node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + current_offset));
            node.validate() catch break;

            if (node.size >= size and (best_offset == 0 or node.size < best_size)) {
                best_offset = current_offset;
                best_size = node.size;
                best_prev = prev_offset;
            }

            prev_offset = current_offset;
            current_offset = node.next;
        }

        if (best_offset == 0) return 0;

        const node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + best_offset));

        if (best_prev != 0) {
            const prev_node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + best_prev));
            prev_node.next = node.next;
        } else {
            self.large_free_list = node.next;
        }

        if (node.next != 0) {
            const next_node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + node.next));
            next_node.prev = best_prev;
        }

        try self.wal.appendRecord(tx, .free_list_remove, best_offset, node.size);

        return best_offset;
    }

    fn allocateFromHeapEnd(self: *Self, size: u64, tx: *wal_mod.Transaction) !u64 {
        const total_size = @sizeOf(header.ObjectHeader) + size;
        const aligned_offset = alignTo(self.metadata.free_heap_offset, MIN_ALIGNMENT);

        if (aligned_offset + total_size > self.heap.getSize()) {
            return 0;
        }

        self.metadata.free_heap_offset = aligned_offset + total_size;
        self.metadata.updateChecksum();

        try self.wal.appendRecord(tx, .heap_extend, aligned_offset, total_size);

        return aligned_offset;
    }

    fn addToSizeClass(self: *Self, size: u64, offset: u64, tx: *wal_mod.Transaction) !void {
        const class_idx = self.getSizeClassIndex(size);
        if (class_idx >= NUM_SIZE_CLASSES) return;

        const node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + offset));
        node.* = FreeListNode.init(size);
        node.next = self.free_list_heads[class_idx];
        node.prev = 0;

        if (self.free_list_heads[class_idx] != 0) {
            const old_head: *FreeListNode = @ptrCast(@alignCast(self.base_addr + self.free_list_heads[class_idx]));
            old_head.prev = offset;
        }

        self.free_list_heads[class_idx] = offset;

        const free_list_storage_offset = header.HEADER_SIZE + @sizeOf(AllocatorMetadata);
        const free_list_storage: *[NUM_SIZE_CLASSES]u64 = @ptrCast(@alignCast(self.base_addr + free_list_storage_offset));
        free_list_storage[class_idx] = offset;

        try self.wal.appendRecord(tx, .free_list_add, offset, size);
        try self.heap.flushRange(offset + @sizeOf(FreeListNode));
    }

    fn addToLargeFreeList(self: *Self, offset: u64, size: u64, tx: *wal_mod.Transaction) !void {
        const node: *FreeListNode = @ptrCast(@alignCast(self.base_addr + offset));
        node.* = FreeListNode.init(size);
        node.next = self.large_free_list;
        node.prev = 0;

        if (self.large_free_list != 0) {
            const old_head: *FreeListNode = @ptrCast(@alignCast(self.base_addr + self.large_free_list));
            old_head.prev = offset;
        }

        self.large_free_list = offset;

        try self.wal.appendRecord(tx, .free_list_add, offset, size);
        try self.heap.flushRange(offset + @sizeOf(FreeListNode));
    }

    fn getSizeClassIndex(self: *const Self, size: u64) usize {
        var i: usize = 0;
        while (i < NUM_SIZE_CLASSES) : (i += 1) {
            if (self.size_classes[i].size >= size) {
                return i;
            }
        }
        return NUM_SIZE_CLASSES - 1;
    }

    pub fn getUsedSize(self: *const Self) u64 {
        return self.metadata.total_allocated - self.metadata.total_freed;
    }

    pub fn getAllocationCount(self: *const Self) u64 {
        return self.metadata.allocation_count;
    }

    pub fn getFreeCount(self: *const Self) u64 {
        return self.metadata.free_count;
    }

    pub fn enqueueFree(self: *Self, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;
        const obj_hdr: *const header.ObjectHeader = @ptrCast(@alignCast(
            self.base_addr + @as(usize, @intCast(ptr.offset)),
        ));
        const size = obj_hdr.size;
        const class_idx = self.getSizeClassIndex(size);
        try self.mpsc_lanes[class_idx].enqueue(ptr.offset);
    }

    pub fn drainMPSCLanes(self: *Self) !usize {
        var drained: usize = 0;
        self.lock.lock();
        defer self.lock.unlock();

        const pool_uuid = self.heap.getPoolUUID();
        var class_idx: usize = 0;
        while (class_idx < NUM_SIZE_CLASSES) : (class_idx += 1) {
            const lane = self.mpsc_lanes[class_idx];
            while (lane.dequeue()) |offset| {
                const ptr = pointer.PersistentPtr{
                    .pool_uuid = pool_uuid,
                    .offset = offset,
                };
                self.freeLocked(ptr) catch {};
                drained += 1;
            }
        }
        return drained;
    }

    pub fn getPendingFreeCount(self: *const Self) usize {
        var total: usize = 0;
        for (self.mpsc_lanes) |lane| {
            if (!lane.isEmpty()) total += 1;
        }
        return total;
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocImpl,
        .resize = resizeImpl,
        .remap = remapImpl,
        .free = freeImpl,
    };

    pub fn getAllocator(self: *Self) std.mem.Allocator {
        return std.mem.Allocator{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    fn allocImpl(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        const self: *Self = @ptrCast(@alignCast(ctx));
        const alignment = @as(u64, 1) << @intFromEnum(ptr_align);
        const result = self.alloc(len, alignment) catch return null;
        return self.base_addr + result.offset;
    }

    fn resizeImpl(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn remapImpl(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    fn freeImpl(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        _ = buf_align;
        _ = ret_addr;
        const self: *Self = @ptrCast(@alignCast(ctx));
        const offset = @intFromPtr(buf.ptr) - @intFromPtr(self.base_addr);
        const ptr = pointer.PersistentPtr{
            .pool_uuid = self.heap.getPoolUUID(),
            .offset = offset,
        };
        self.free(ptr) catch {};
    }
};

fn alignTo(value: u64, alignment: u64) u64 {
    const mask = alignment - 1;
    return (value + mask) & ~mask;
}

test "persistent allocator" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_allocator.dat";
    std.fs.cwd().deleteFile(test_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal_file = try wal_mod.WAL.init(alloc, "/tmp/test_allocator.wal", null);
    defer wal_file.deinit();

    var palloc = try PersistentAllocator.init(alloc, heap, wal_file);
    defer palloc.deinit();

    const ptr1 = try palloc.alloc(128, 64);
    try testing.expect(!ptr1.isNull());

    const ptr2 = try palloc.alloc(256, 64);
    try testing.expect(!ptr2.isNull());
    try testing.expect(ptr1.offset != ptr2.offset);

    try palloc.free(ptr1);
    try testing.expectEqual(@as(u64, 1), palloc.getFreeCount());
}

test "cache line slab header is 64 bytes" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(CacheLineSlabHeader));
}

test "cache line packed slab capacity" {
    const Slab64 = CacheLinePackedSlab(u64);
    const cap = Slab64.capacity();
    const data_bytes = SLAB_BYTES - CACHE_LINE_BYTES;
    try std.testing.expectEqual(data_bytes / @sizeOf(u64), cap);
}

test "cache line packed slab init" {
    const Slab = CacheLinePackedSlab(u64);
    const s = Slab.init();
    try std.testing.expectEqual(@as(u32, 0), s.hdr.count);
    try std.testing.expectEqual(@as(u64, 0), s.hdr.next_slab);
}

test "compute slab layout" {
    const layout = computeSlabLayout(64);
    try std.testing.expectEqual(@as(usize, SLAB_BYTES), layout.slab_bytes);
    try std.testing.expectEqual(@as(usize, 64), layout.header_bytes);
    try std.testing.expectEqual(@as(usize, 64), layout.item_size);
    const data = SLAB_BYTES - CACHE_LINE_BYTES;
    try std.testing.expectEqual(data / 64, layout.items_per_slab);
}

test "mpsc lanes enqueue free" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_mpsc_free.dat";
    const wal_path = "/tmp/test_mpsc_free.wal";
    std.fs.cwd().deleteFile(test_path) catch {};
    std.fs.cwd().deleteFile(wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal_file = try wal_mod.WAL.init(alloc, wal_path, null);
    defer wal_file.deinit();

    var palloc = try PersistentAllocator.init(alloc, heap, wal_file);
    defer palloc.deinit();

    const ptr1 = try palloc.alloc(128, 64);
    try testing.expect(!ptr1.isNull());

    const ptr2 = try palloc.alloc(128, 64);
    try testing.expect(!ptr2.isNull());

    try palloc.enqueueFree(ptr1);
    try palloc.enqueueFree(ptr2);

    const drained = try palloc.drainMPSCLanes();
    try testing.expect(drained >= 2);
    try testing.expectEqual(@as(u64, 2), palloc.getFreeCount());
}
