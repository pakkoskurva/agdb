const std = @import("std");
const atomic = std.atomic;
const header = @import("header.zig");
const pointer = @import("pointer.zig");
const allocator_mod = @import("allocator.zig");
const wal_mod = @import("wal.zig");
const pheap = @import("pheap.zig");
const mem_utils = @import("mem_utils.zig");
const topology = @import("topology.zig");

pub const GC_MAGIC: u32 = 0x47434F4C;
pub const GC_VERSION: u32 = 1;

pub const GCStats = struct {
    objects_scanned: u64,
    objects_freed: u64,
    bytes_freed: u64,
    cycles_detected: u64,
    cycles_broken: u64,
    gc_cycles: u64,
    total_time_ns: u64,
};

pub const GCObjectInfo = extern struct {
    ref_count: u32,
    flags: u32,
    schema_id: u32,
    first_ref_offset: u32,
    scan_fn_offset: u64,
    finalize_fn_offset: u64,
    reserved: [32]u8,
};

pub const GCCallbacks = struct {
    scan_fn: ?*const fn (*anyopaque, *GCContext) void = null,
    finalize_fn: ?*const fn (*anyopaque) void = null,
};

pub const GCContext = struct {
    gc: *RefCountGC,
    marked: std.AutoHashMap(u64, void),
    worklist: std.ArrayList(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator_ptr: std.mem.Allocator) GCContext {
        return .{
            .gc = undefined,
            .marked = std.AutoHashMap(u64, void).init(allocator_ptr),
            .worklist = std.ArrayList(u64).init(allocator_ptr),
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *GCContext) void {
        self.marked.deinit();
        self.worklist.deinit();
    }

    pub fn mark(self: *GCContext, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;
        if (try self.marked.fetchPut(ptr.offset, {})) |_| return;
        try self.worklist.append(ptr.offset);
    }

    pub fn addReference(self: *GCContext, parent_offset: u64, child_ptr: pointer.PersistentPtr) !void {
        _ = parent_offset;
        try self.mark(child_ptr);
    }
};

pub const GCOperationDescriptor = extern struct {
    magic: u32,
    operation: u32,
    object_offset: u64,
    object_size: u64,
    parent_offset: u64,
    depth: u32,
    checksum: u32,
    reserved: [32]u8,

    pub const OP_FREE: u32 = 1;
    pub const OP_DEC_REF: u32 = 2;
    pub const OP_MARK: u32 = 3;

    pub const DESCRIPTOR_MAGIC: u32 = 0x47434453;

    pub fn init(operation: u32, object_offset: u64, object_size: u64, parent: u64, depth: u32) GCOperationDescriptor {
        return GCOperationDescriptor{
            .magic = DESCRIPTOR_MAGIC,
            .operation = operation,
            .object_offset = object_offset,
            .object_size = object_size,
            .parent_offset = parent,
            .depth = depth,
            .checksum = 0,
            .reserved = [_]u8{0} ** 32,
        };
    }

    pub fn computeChecksum(self: *const GCOperationDescriptor) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..@offsetOf(GCOperationDescriptor, "checksum")]) |byte| {
            crc ^= @as(u32, byte);
            var j: usize = 0;
            while (j < 8) : (j += 1) {
                crc = if ((crc & 1) != 0) (crc >> 1) ^ 0x82F63B78 else crc >> 1;
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *GCOperationDescriptor) void {
        self.checksum = self.computeChecksum();
    }
};

pub const RC_BATCH_INC: u8 = 1;
pub const RC_BATCH_DEC: u8 = 2;
pub const RC_BATCH_FLUSH_MAX: usize = 512;

pub const RCBatchOp = struct {
    kind: u8,
    offset: u64,
};

pub const RefCountGC = struct {
    allocator: std.mem.Allocator,
    alloc: *allocator_mod.PersistentAllocator,
    wal: *wal_mod.WAL,
    heap: *pheap.PersistentHeap,
    stats: GCStats,
    object_registry: std.AutoHashMap(u64, GCObjectInfo),
    cycle_breakers: std.ArrayList(pointer.PersistentPtr),
    enabled: atomic.Value(bool),
    lock: std.Thread.Mutex,
    max_depth: u32,
    deferred_frees: mem_utils.LockFreeStack,
    rc_batch: *topology.MPSCQueue(RCBatchOp),
    batch_lock: std.Thread.Mutex,

    const Self = @This();
    const MAX_RECURSION_DEPTH: u32 = 256;

    pub fn init(allocator_ptr: std.mem.Allocator, alloc_inst: *allocator_mod.PersistentAllocator, wal_inst: *wal_mod.WAL) !*RefCountGC {
        const self = try allocator_ptr.create(RefCountGC);
        errdefer allocator_ptr.destroy(self);

        const rc_batch = try allocator_ptr.create(topology.MPSCQueue(RCBatchOp));
        errdefer allocator_ptr.destroy(rc_batch);
        rc_batch.initPtr(allocator_ptr);

        self.* = RefCountGC{
            .allocator = allocator_ptr,
            .alloc = alloc_inst,
            .wal = wal_inst,
            .heap = alloc_inst.heap,
            .stats = GCStats{
                .objects_scanned = 0,
                .objects_freed = 0,
                .bytes_freed = 0,
                .cycles_detected = 0,
                .cycles_broken = 0,
                .gc_cycles = 0,
                .total_time_ns = 0,
            },
            .object_registry = std.AutoHashMap(u64, GCObjectInfo).init(allocator_ptr),
            .cycle_breakers = std.ArrayList(pointer.PersistentPtr).init(allocator_ptr),
            .enabled = atomic.Value(bool).init(true),
            .lock = std.Thread.Mutex{},
            .max_depth = MAX_RECURSION_DEPTH,
            .deferred_frees = mem_utils.LockFreeStack.init(allocator_ptr),
            .rc_batch = rc_batch,
            .batch_lock = std.Thread.Mutex{},
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.flushBatchedRefCounts() catch {};
        self.rc_batch.deinit();
        self.allocator.destroy(self.rc_batch);
        self.drainDeferredFrees() catch {};
        self.deferred_frees.deinit();
        self.object_registry.deinit();
        self.cycle_breakers.deinit();
        self.allocator.destroy(self);
    }

    pub fn incrementRefCount(self: *Self, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;

        self.lock.lock();
        defer self.lock.unlock();

        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr.offset));

        if (obj_header.isFreed()) {
            return error.ObjectAlreadyFreed;
        }

        var tx = try self.wal.beginTransaction();
        defer {
            self.wal.endTransaction(&tx) catch {};
        }

        const old_count = obj_header.ref_count;
        obj_header.ref_count +|= 1;
        obj_header.checksum = obj_header.computeChecksum();

        try self.wal.appendRecord(&tx, .ref_count_inc, ptr.offset, old_count);
        try self.heap.flushRange(ptr.offset + @sizeOf(header.ObjectHeader));
    }

    pub fn decrementRefCount(self: *Self, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;

        self.lock.lock();
        defer self.lock.unlock();

        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr.offset));

        if (obj_header.isFreed()) {
            return;
        }

        if (obj_header.ref_count == 0) {
            return error.InvalidRefCount;
        }

        var tx = try self.wal.beginTransaction();
        defer {
            self.wal.endTransaction(&tx) catch {};
        }

        const old_count = obj_header.ref_count;
        obj_header.ref_count -= 1;
        obj_header.checksum = obj_header.computeChecksum();

        try self.wal.appendRecord(&tx, .ref_count_dec, ptr.offset, old_count);
        try self.heap.flushRange(ptr.offset + @sizeOf(header.ObjectHeader));

        if (obj_header.ref_count == 0) {
            try self.freeObjectGraph(&tx, ptr, 0);
        }
    }

    pub fn getRefCount(self: *Self, ptr: pointer.PersistentPtr) !u32 {
        if (ptr.isNull()) return 0;

        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr.offset));

        try obj_header.validate();

        if (obj_header.isFreed()) {
            return 0;
        }

        return obj_header.ref_count;
    }

    fn freeObjectGraph(self: *Self, tx: *wal_mod.Transaction, ptr: pointer.PersistentPtr, depth: u32) !void {
        if (depth > self.max_depth) {
            try self.scheduleDeferredFree(ptr);
            return;
        }

        var descriptor = GCOperationDescriptor.init(GCOperationDescriptor.OP_FREE, ptr.offset, 0, 0, depth);
        descriptor.updateChecksum();

        try self.wal.appendRecord(tx, .gc_sweep, ptr.offset, @sizeOf(GCOperationDescriptor));

        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr.offset));
        const obj_size = obj_header.size;

        self.stats.objects_freed += 1;
        self.stats.bytes_freed += obj_size;

        obj_header.setFreed(true);
        obj_header.checksum = obj_header.computeChecksum();

        try self.alloc.free(ptr);
    }

    fn scheduleDeferredFree(self: *Self, ptr: pointer.PersistentPtr) !void {
        const entry = try self.allocator.create(pointer.PersistentPtr);
        errdefer self.allocator.destroy(entry);
        entry.* = ptr;
        try self.deferred_frees.push(@as(*anyopaque, @ptrCast(entry)));
    }

    fn drainDeferredFrees(self: *Self) !void {
        while (self.deferred_frees.pop()) |raw| {
            const ptr_entry: *pointer.PersistentPtr = @ptrCast(@alignCast(raw));
            const ptr = ptr_entry.*;
            self.allocator.destroy(ptr_entry);

            if (ptr.isNull()) continue;

            const base_addr = self.heap.getBaseAddress();
            const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + ptr.offset));
            if (obj_header.isFreed()) continue;

            var tx = self.wal.beginTransaction() catch continue;
            defer self.wal.endTransaction(&tx) catch {};

            const obj_size = obj_header.size;
            self.stats.objects_freed += 1;
            self.stats.bytes_freed += obj_size;

            obj_header.setFreed(true);
            obj_header.checksum = obj_header.computeChecksum();
            self.alloc.free(ptr) catch {};
        }
    }

    pub fn registerObject(self: *Self, ptr: pointer.PersistentPtr, info: GCObjectInfo) !void {
        if (ptr.isNull()) return;

        self.lock.lock();
        defer self.lock.unlock();

        try self.object_registry.put(ptr.offset, info);
    }

    pub fn unregisterObject(self: *Self, ptr: pointer.PersistentPtr) void {
        if (ptr.isNull()) return;

        self.lock.lock();
        defer self.lock.unlock();

        _ = self.object_registry.remove(ptr.offset);
    }

    pub fn addCycleBreaker(self: *Self, ptr: pointer.PersistentPtr) !void {
        self.lock.lock();
        defer self.lock.unlock();

        try self.cycle_breakers.append(ptr);
    }

    pub fn breakCycles(self: *Self) !usize {
        self.lock.lock();
        defer self.lock.unlock();

        var broken: usize = 0;

        for (self.cycle_breakers.items) |ptr| {
            if (try self.getRefCount(ptr) > 0) {
                try self.decrementRefCount(ptr);
                broken += 1;
                self.stats.cycles_broken += 1;
            }
        }

        return broken;
    }

    pub fn runCollection(self: *Self) !GCStats {
        if (!self.enabled.load(.monotonic)) {
            return self.stats;
        }

        const start_time = std.time.nanoTimestamp();

        self.lock.lock();
        defer self.lock.unlock();

        self.stats.gc_cycles += 1;

        try self.drainDeferredFrees();

        var ctx = GCContext.init(self.allocator);
        defer ctx.deinit();
        ctx.gc = self;

        const root = self.heap.getRoot();
        if (root) |r| {
            try ctx.mark(r);
        }

        while (ctx.worklist.pop()) |offset| {
            self.stats.objects_scanned += 1;

            if (self.object_registry.get(offset)) |info| {
                _ = info;
            }
        }

        var iter = self.object_registry.iterator();
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        while (iter.next()) |entry| {
            const offset = entry.key_ptr.*;
            if (!ctx.marked.contains(offset)) {
                try to_remove.append(offset);
            }
        }

        for (to_remove.items) |offset| {
            const ptr = pointer.PersistentPtr{
                .pool_uuid = self.heap.getPoolUUID(),
                .offset = offset,
            };
            var tx = try self.wal.beginTransaction();
            try self.freeObjectGraph(&tx, ptr, 0);
        }

        self.stats.total_time_ns = @as(u64, @intCast(std.time.nanoTimestamp() - start_time));

        return self.stats;
    }

    pub fn enable(self: *Self) void {
        self.enabled.store(true, .release);
    }

    pub fn disable(self: *Self) void {
        self.enabled.store(false, .release);
    }

    pub fn isEnabled(self: *Self) bool {
        return self.enabled.load(.monotonic);
    }

    pub fn getStats(self: *Self) GCStats {
        return self.stats;
    }

    pub fn resetStats(self: *Self) void {
        self.stats = GCStats{
            .objects_scanned = 0,
            .objects_freed = 0,
            .bytes_freed = 0,
            .cycles_detected = 0,
            .cycles_broken = 0,
            .gc_cycles = 0,
            .total_time_ns = 0,
        };
    }

    pub fn batchIncrementRefCount(self: *Self, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;
        try self.rc_batch.enqueue(.{ .kind = RC_BATCH_INC, .offset = ptr.offset });
    }

    pub fn batchDecrementRefCount(self: *Self, ptr: pointer.PersistentPtr) !void {
        if (ptr.isNull()) return;
        try self.rc_batch.enqueue(.{ .kind = RC_BATCH_DEC, .offset = ptr.offset });
    }

    pub fn flushBatchedRefCounts(self: *Self) !void {
        self.batch_lock.lock();
        defer self.batch_lock.unlock();

        var ops: [RC_BATCH_FLUSH_MAX]RCBatchOp = undefined;
        var count: usize = 0;

        while (count < RC_BATCH_FLUSH_MAX) {
            const op = self.rc_batch.dequeue() orelse break;
            ops[count] = op;
            count += 1;
        }
        if (count == 0) return;

        self.lock.lock();
        defer self.lock.unlock();

        var tx = try self.wal.beginTransaction();
        defer self.wal.endTransaction(&tx) catch {};

        const base_addr = self.heap.getBaseAddress();

        for (ops[0..count]) |op| {
            const ptr = pointer.PersistentPtr{ .pool_uuid = self.heap.getPoolUUID(), .offset = op.offset };
            if (ptr.isNull()) continue;
            const obj_hdr: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + op.offset));
            if (obj_hdr.isFreed()) continue;

            switch (op.kind) {
                RC_BATCH_INC => {
                    const old = obj_hdr.ref_count;
                    obj_hdr.ref_count +|= 1;
                    obj_hdr.checksum = obj_hdr.computeChecksum();
                    try self.wal.appendRecord(&tx, .ref_count_inc, op.offset, old);
                },
                RC_BATCH_DEC => {
                    if (obj_hdr.ref_count == 0) continue;
                    const old = obj_hdr.ref_count;
                    obj_hdr.ref_count -= 1;
                    obj_hdr.checksum = obj_hdr.computeChecksum();
                    try self.wal.appendRecord(&tx, .ref_count_dec, op.offset, old);
                    if (obj_hdr.ref_count == 0) {
                        try self.scheduleDeferredFree(ptr);
                    }
                },
                else => {},
            }
        }

        try self.wal.commitTransaction(&tx);
    }

    pub fn runConcurrentMark(self: *Self, n_workers: usize) !u64 {
        if (!self.enabled.load(.monotonic)) return 0;

        const worker_count = @max(1, @min(n_workers, 16));
        const cap_per_worker = 4096;

        const Deque = topology.WorkStealDeque(u64);
        const deques = try self.allocator.alloc(Deque, worker_count);
        defer self.allocator.free(deques);
        for (deques) |*d| {
            d.* = try Deque.init(self.allocator, cap_per_worker);
        }
        defer for (deques) |*d| d.deinit();

        var marked = std.AutoHashMap(u64, void).init(self.allocator);
        defer marked.deinit();

        var marked_lock = std.Thread.Mutex{};

        self.lock.lock();
        const root = self.heap.getRoot();
        self.lock.unlock();

        if (root) |r| {
            if (!r.isNull()) _ = deques[0].push(r.offset);
        }

        const Context = struct {
            deques: []Deque,
            marked: *std.AutoHashMap(u64, void),
            marked_lock: *std.Thread.Mutex,
            gc: *RefCountGC,
            worker_id: usize,
            total_workers: usize,

            fn run(ctx: *const @This()) void {
                var local_batch = std.ArrayList(u64).init(ctx.gc.allocator);
                defer local_batch.deinit();

                while (true) {
                    var got: ?u64 = ctx.deques[ctx.worker_id].pop();

                    if (got == null) {
                        var found_steal = false;
                        var attempt: usize = 0;
                        while (attempt < ctx.total_workers) : (attempt += 1) {
                            const victim = (ctx.worker_id + 1 + attempt) % ctx.total_workers;
                            if (ctx.deques[victim].steal()) |stolen| {
                                got = stolen;
                                found_steal = true;
                                break;
                            }
                        }
                        if (!found_steal) break;
                    }

                    const offset = got.?;

                    ctx.marked_lock.lock();
                    const already = ctx.marked.contains(offset);
                    if (!already) {
                        ctx.marked.put(offset, {}) catch {};
                    }
                    ctx.marked_lock.unlock();

                    if (already) continue;

                    ctx.gc.lock.lock();
                    if (ctx.gc.object_registry.get(offset)) |info| {
                        _ = info;
                    }
                    ctx.gc.lock.unlock();
                }
            }
        };

        var ctxs = try self.allocator.alloc(Context, worker_count);
        defer self.allocator.free(ctxs);
        for (ctxs, 0..) |*c, i| {
            c.* = .{
                .deques = deques,
                .marked = &marked,
                .marked_lock = &marked_lock,
                .gc = self,
                .worker_id = i,
                .total_workers = worker_count,
            };
        }

        if (worker_count == 1) {
            ctxs[0].run();
        } else {
            const threads = try self.allocator.alloc(std.Thread, worker_count);
            defer self.allocator.free(threads);
            for (threads, 0..) |*t, i| {
                t.* = try std.Thread.spawn(.{}, Context.run, .{&ctxs[i]});
            }
            for (threads) |t| t.join();
        }

        return @intCast(marked.count());
    }

    pub fn runVirtualCompaction(self: *Self) !u64 {
        self.lock.lock();
        defer self.lock.unlock();

        const base_addr = self.heap.getBaseAddress();
        const heap_size = self.heap.size;
        const hdr_size = @sizeOf(header.HeapHeader);

        var freed_count: u64 = 0;
        var offset: u64 = hdr_size;
        const obj_hdr_size = @as(u64, @intCast(@sizeOf(header.ObjectHeader)));

        while (offset + obj_hdr_size <= heap_size) {
            const obj_hdr: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));

            const valid = if (obj_hdr.validate()) |_| true else |_| false;
            if (!valid) {
                offset += obj_hdr_size;
                continue;
            }

            const obj_size = @as(u64, @intCast(obj_hdr.size));

            if (obj_hdr.isFreed() and obj_size > 0) {
                const ptr = pointer.PersistentPtr{
                    .pool_uuid = self.heap.getPoolUUID(),
                    .offset = offset,
                };
                _ = self.object_registry.remove(offset);
                self.alloc.free(ptr) catch {};
                freed_count += 1;
                self.stats.objects_freed += 1;
                self.stats.bytes_freed += obj_size;
            }

            const step = obj_hdr_size + obj_size;
            if (step == 0) break;
            offset += step;
        }

        return freed_count;
    }
};

pub const PartitionedGC = struct {
    allocator: std.mem.Allocator,
    partitions: []*GCPartition,
    partition_count: u32,
    current_partition: atomic.Value(u32),
    enabled: atomic.Value(bool),

    pub fn init(allocator_ptr: std.mem.Allocator, partition_count: u32, partition_size: u64) !*PartitionedGC {
        const self = try allocator_ptr.create(PartitionedGC);
        errdefer allocator_ptr.destroy(self);

        const partitions = try allocator_ptr.alloc(*GCPartition, partition_count);
        errdefer allocator_ptr.free(partitions);

        for (partitions, 0..) |*p, i| {
            const partition_id = @as(u32, @intCast(i));
            p.* = try GCPartition.init(allocator_ptr, partition_id, partition_size);
        }

        self.* = PartitionedGC{
            .allocator = allocator_ptr,
            .partitions = partitions,
            .partition_count = partition_count,
            .current_partition = atomic.Value(u32).init(0),
            .enabled = atomic.Value(bool).init(true),
        };

        return self;
    }

    pub fn deinit(self: *PartitionedGC) void {
        for (self.partitions) |p| {
            p.deinit();
            self.allocator.destroy(p);
        }
        self.allocator.free(self.partitions);
        self.allocator.destroy(self);
    }

    pub fn selectPartition(self: *PartitionedGC, offset: u64) *GCPartition {
        const idx = (offset / (1024 * 1024)) % self.partition_count;
        return self.partitions[idx];
    }

    pub fn runIncremental(self: *PartitionedGC) !void {
        const current = self.current_partition.fetchAdd(1, .monotonic) % self.partition_count;
        const partition = self.partitions[current];
        try partition.collect();
    }

    pub fn runFull(self: *PartitionedGC) !void {
        for (self.partitions) |partition| {
            try partition.collect();
        }
    }
};

pub const GCPartition = struct {
    id: u32,
    size: u64,
    objects: std.AutoHashMap(u64, GCObjectInfo),
    marked: std.AutoHashMap(u64, void),
    allocator: std.mem.Allocator,

    pub fn init(allocator_ptr: std.mem.Allocator, id: u32, size: u64) !*GCPartition {
        const self = try allocator_ptr.create(GCPartition);
        self.* = GCPartition{
            .id = id,
            .size = size,
            .objects = std.AutoHashMap(u64, GCObjectInfo).init(allocator_ptr),
            .marked = std.AutoHashMap(u64, void).init(allocator_ptr),
            .allocator = allocator_ptr,
        };
        return self;
    }

    pub fn deinit(self: *GCPartition) void {
        self.objects.deinit();
        self.marked.deinit();
    }

    pub fn addObject(self: *GCPartition, offset: u64, info: GCObjectInfo) !void {
        try self.objects.put(offset, info);
    }

    pub fn removeObject(self: *GCPartition, offset: u64) void {
        _ = self.objects.remove(offset);
    }

    pub fn mark(self: *GCPartition, offset: u64) !void {
        try self.marked.put(offset, {});
    }

    pub fn isMarked(self: *GCPartition, offset: u64) bool {
        return self.marked.contains(offset);
    }

    pub fn collect(self: *GCPartition) !void {
        var iter = self.objects.iterator();
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        while (iter.next()) |entry| {
            const offset = entry.key_ptr.*;
            if (!self.marked.contains(offset)) {
                try to_remove.append(offset);
            }
        }

        for (to_remove.items) |offset| {
            _ = self.objects.remove(offset);
        }

        self.marked.clearRetainingCapacity();
    }
};

test "ref count gc basic" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_gc.dat";
    const test_wal_path = "/tmp/test_gc.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var palloc = try allocator_mod.PersistentAllocator.init(alloc, heap, wal);
    defer palloc.deinit();

    var gc = try RefCountGC.init(alloc, palloc, wal);
    defer gc.deinit();

    const ptr = try palloc.alloc(64, 64);
    try testing.expect(!ptr.isNull());

    try gc.incrementRefCount(ptr);
    const count = try gc.getRefCount(ptr);
    try testing.expectEqual(@as(u32, 2), count);

    try gc.decrementRefCount(ptr);
    const count2 = try gc.getRefCount(ptr);
    try testing.expectEqual(@as(u32, 1), count2);
}
