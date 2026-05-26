const std = @import("std");
const pheap = @import("pheap.zig");
const allocator = @import("allocator.zig");
const wal = @import("wal.zig");
const transaction = @import("transaction.zig");
const recovery = @import("recovery.zig");
const pointer = @import("pointer.zig");
const concurrency = @import("concurrency.zig");
const gc = @import("gc.zig");
const snapshot = @import("snapshot.zig");
const gpu = @import("gpu.zig");
const security = @import("security.zig");
const api = @import("api.zig");
const schema = @import("schema.zig");
const mem_utils = @import("mem_utils.zig");

pub const PersistentHeap = pheap.PersistentHeap;
pub const PersistentAllocator = allocator.PersistentAllocator;
pub const WAL = wal.WAL;
pub const TransactionManager = transaction.TransactionManager;
pub const RecoveryEngine = recovery.RecoveryEngine;
pub const RelativePtr = pointer.RelativePtr;
pub const PersistentPtr = pointer.PersistentPtr;
pub const PMutex = concurrency.PMutex;
pub const PRWLock = concurrency.PRWLock;
pub const RefCountGC = gc.RefCountGC;
pub const SnapshotManager = snapshot.SnapshotManager;
pub const GPUContext = gpu.GPUContext;
pub const SecurityManager = security.SecurityManager;
pub const PersistentStore = api.PersistentStore;
pub const SchemaRegistry = schema.SchemaRegistry;

pub const Runtime = struct {
    heap: *PersistentHeap,
    alloc: *PersistentAllocator,
    wal: *WAL,
    tx_manager: *TransactionManager,
    recovery: *RecoveryEngine,
    gc: *RefCountGC,
    snapshots: *SnapshotManager,
    security: *SecurityManager,
    gpu_ctx: ?*GPUContext,
    store: *PersistentStore,
    arena: *std.heap.ArenaAllocator,
    parent_allocator: std.mem.Allocator,
    config: RuntimeConfig,

    pub const RuntimeConfig = struct {
        heap_path: []const u8,
        heap_size: u64,
        wal_path: []const u8,
        snapshot_dir: []const u8,
        enable_encryption: bool,
        master_key: ?[]const u8,
        enable_gpu: bool,
        gpu_kernel_path: ?[]const u8,
        gc_threshold: u64,
        snapshot_interval_ms: u64,
    };

    pub fn init(allocator_ptr: std.mem.Allocator, config: RuntimeConfig) !*Runtime {
        const arena_ptr = try allocator_ptr.create(std.heap.ArenaAllocator);
        errdefer allocator_ptr.destroy(arena_ptr);
        arena_ptr.* = std.heap.ArenaAllocator.init(allocator_ptr);
        errdefer arena_ptr.deinit();
        const arena_alloc = arena_ptr.allocator();

        const self = try allocator_ptr.create(Runtime);
        errdefer allocator_ptr.destroy(self);
        self.* = Runtime{
            .heap = undefined,
            .alloc = undefined,
            .wal = undefined,
            .tx_manager = undefined,
            .recovery = undefined,
            .gc = undefined,
            .snapshots = undefined,
            .security = undefined,
            .gpu_ctx = null,
            .store = undefined,
            .arena = arena_ptr,
            .parent_allocator = allocator_ptr,
            .config = config,
        };

        self.security = try arena_alloc.create(SecurityManager);
        self.security.* = try SecurityManager.init(arena_alloc, config.master_key, config.enable_encryption);

        const actual_size = if (config.heap_size == 0) 1024 * 1024 * 1024 else config.heap_size;
        const heap_path = try arena_alloc.dupe(u8, config.heap_path);
        const wal_path = try arena_alloc.dupe(u8, config.wal_path);

        self.heap = try PersistentHeap.init(arena_alloc, heap_path, actual_size, self.security);
        errdefer self.heap.deinit() catch {};

        self.wal = try WAL.init(arena_alloc, wal_path, self.security);
        errdefer self.wal.deinit();

        self.recovery = try arena_alloc.create(RecoveryEngine);
        self.recovery.* = RecoveryEngine.init(self.heap, self.wal, arena_alloc);
        try self.recovery.recover();

        self.alloc = try PersistentAllocator.init(arena_alloc, self.heap, self.wal);
        errdefer self.alloc.deinit();

        self.tx_manager = try TransactionManager.init(arena_alloc, self.wal, self.heap);
        errdefer self.tx_manager.deinit();
        self.tx_manager.setAllocatorHook(@ptrCast(self.alloc), undoAllocationThunk);

        self.gc = try RefCountGC.init(arena_alloc, self.alloc, self.wal);
        errdefer self.gc.deinit();

        var snapshot_path: ?[]const u8 = null;
        if (config.snapshot_dir.len > 0) {
            snapshot_path = try arena_alloc.dupe(u8, config.snapshot_dir);
        }
        self.snapshots = try SnapshotManager.init(arena_alloc, self.heap, snapshot_path);
        errdefer self.snapshots.deinit();

        if (config.enable_gpu and config.gpu_kernel_path != null) {
            const kernel_path = try arena_alloc.dupe(u8, config.gpu_kernel_path.?);
            self.gpu_ctx = try GPUContext.init(arena_alloc, kernel_path);
        }

        self.store = try PersistentStore.init(arena_alloc, self.alloc, self.tx_manager, self.gc);

        return self;
    }

    pub fn deinit(self: *Runtime) void {
        if (self.gpu_ctx) |ctx| {
            ctx.deinit();
        }
        self.snapshots.deinit();
        self.gc.deinit();
        self.tx_manager.deinit();
        self.alloc.deinit();
        self.wal.deinit();
        self.heap.deinit() catch {};
        self.security.deinit();
        const parent = self.parent_allocator;
        const arena_ptr = self.arena;
        arena_ptr.deinit();
        parent.destroy(arena_ptr);
        parent.destroy(self);
    }

    pub fn beginTransaction(self: *Runtime) !*transaction.Transaction {
        return self.tx_manager.begin();
    }

    fn undoAllocationThunk(ctx: *anyopaque, offset: u64, size: u64) anyerror!void {
        const alloc_ptr: *PersistentAllocator = @ptrCast(@alignCast(ctx));
        try alloc_ptr.undoAllocation(offset, size);
    }

    pub fn commit(self: *Runtime, tx: *transaction.Transaction) !void {
        try self.tx_manager.commit(tx);
    }

    pub fn rollback(self: *Runtime, tx: *transaction.Transaction) !void {
        try self.tx_manager.rollback(tx);
    }

    pub fn allocate(self: *Runtime, size: u64, alignment: u64) !pointer.PersistentPtr {
        const ptr = try self.alloc.alloc(size, alignment);
        if (self.tx_manager.active_transactions.count() > 0) {
            const latest_id = self.tx_manager.transaction_counter;
            if (self.tx_manager.active_transactions.getPtr(latest_id)) |tx| {
                tx.trackAllocation(ptr.offset, size) catch {};
            }
        }
        return ptr;
    }

    pub fn free(self: *Runtime, ptr: pointer.PersistentPtr) !void {
        try self.alloc.free(ptr);
    }

    pub fn getRoot(self: *Runtime) ?pointer.PersistentPtr {
        return self.heap.getRoot();
    }

    pub fn setRoot(self: *Runtime, tx: *transaction.Transaction, ptr: pointer.PersistentPtr) !void {
        try self.heap.setRoot(tx, ptr);
    }

    pub fn createSnapshot(self: *Runtime) !u64 {
        return self.snapshots.createSnapshot();
    }

    pub fn restoreSnapshot(self: *Runtime, snapshot_id: u64) !void {
        try self.snapshots.restoreSnapshot(snapshot_id);
    }

    pub fn runGC(self: *Runtime) !gc.GCStats {
        return self.gc.runCollection();
    }

    pub fn runGPUKernel(self: *Runtime, kernel_name: []const u8, inputs: []gpu.GPUValue, output_type: gpu.GPUValueType) !gpu.GPUValue {
        if (self.gpu_ctx) |ctx| {
            return ctx.runKernel(kernel_name, inputs, output_type);
        }
        return error.GPUNotEnabled;
    }

    pub fn getStats(self: *Runtime) RuntimeStats {
        return RuntimeStats{
            .heap_used = self.alloc.getUsedSize(),
            .heap_total = self.heap.getSize(),
            .allocation_count = self.alloc.getAllocationCount(),
            .free_count = self.alloc.getFreeCount(),
            .wal_size = self.wal.getSize(),
            .transaction_count = self.tx_manager.getTransactionCount(),
            .gc_stats = self.gc.getStats(),
            .snapshot_count = self.snapshots.getSnapshotCount(),
        };
    }

    pub fn flush(self: *Runtime) !void {
        try self.heap.flush();
        try self.wal.flush();
    }
};

pub const RuntimeStats = struct {
    heap_used: u64,
    heap_total: u64,
    allocation_count: u64,
    free_count: u64,
    wal_size: u64,
    transaction_count: u64,
    gc_stats: gc.GCStats,
    snapshot_count: u64,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var tracking = mem_utils.TrackingAllocator.init(gpa.allocator());
    const alloc = tracking.allocator();

    mem_utils.resetMemoryStats();

    const config = Runtime.RuntimeConfig{
        .heap_path = "/tmp/pheap.dat",
        .heap_size = 1024 * 1024 * 100,
        .wal_path = "/tmp/pheap.wal",
        .snapshot_dir = "/tmp/snapshots",
        .enable_encryption = false,
        .master_key = null,
        .enable_gpu = false,
        .gpu_kernel_path = null,
        .gc_threshold = 1000,
        .snapshot_interval_ms = 60000,
    };

    var runtime = try Runtime.init(alloc, config);
    defer runtime.deinit();

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Persistent Heap Runtime Initialized\n", .{});

    const tx = try runtime.beginTransaction();
    defer {
        runtime.rollback(tx) catch {};
    }

    const test_size: u64 = 256;
    const ptr = try runtime.allocate(test_size, 64);
    try stdout.print("Allocated {} bytes at offset {}\n", .{ test_size, ptr.offset });

    try runtime.setRoot(tx, ptr);

    const native_ptr = try runtime.heap.resolvePtr(ptr);
    if (native_ptr) |np| {
        const slice = @as([*]u8, @ptrCast(np))[0..test_size];
        @memset(slice, 0xAB);
    }

    try runtime.commit(tx);
    try stdout.print("Transaction committed\n", .{});

    const stats = runtime.getStats();
    try stdout.print("Heap: {}/{} bytes used\n", .{ stats.heap_used, stats.heap_total });
    try stdout.print("Allocations: {}, Frees: {}\n", .{ stats.allocation_count, stats.free_count });

    const ram = mem_utils.getMemoryStats();
    try stdout.print("RAM allocated: {} bytes, freed: {} bytes, peak live: {} bytes\n", .{
        ram.allocated,
        ram.freed,
        mem_utils.memoryFootprint(),
    });
}

test "runtime initialization" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    std.fs.deleteFileAbsolute("/tmp/test_pheap.dat") catch {};
    std.fs.deleteFileAbsolute("/tmp/test_pheap.wal") catch {};
    std.fs.deleteTreeAbsolute("/tmp/test_snapshots") catch {};

    const config = Runtime.RuntimeConfig{
        .heap_path = "/tmp/test_pheap.dat",
        .heap_size = 1024 * 1024 * 10,
        .wal_path = "/tmp/test_pheap.wal",
        .snapshot_dir = "/tmp/test_snapshots",
        .enable_encryption = false,
        .master_key = null,
        .enable_gpu = false,
        .gpu_kernel_path = null,
        .gc_threshold = 100,
        .snapshot_interval_ms = 60000,
    };

    var runtime = try Runtime.init(alloc, config);
    defer runtime.deinit();

    const stats = runtime.getStats();
    try testing.expect(stats.heap_total == config.heap_size);
}

test "allocation and persistence" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    std.fs.deleteFileAbsolute("/tmp/test_pheap2.dat") catch {};
    std.fs.deleteFileAbsolute("/tmp/test_pheap2.wal") catch {};
    std.fs.deleteTreeAbsolute("/tmp/test_snapshots2") catch {};

    const config = Runtime.RuntimeConfig{
        .heap_path = "/tmp/test_pheap2.dat",
        .heap_size = 1024 * 1024 * 10,
        .wal_path = "/tmp/test_pheap2.wal",
        .snapshot_dir = "/tmp/test_snapshots2",
        .enable_encryption = false,
        .master_key = null,
        .enable_gpu = false,
        .gpu_kernel_path = null,
        .gc_threshold = 100,
        .snapshot_interval_ms = 60000,
    };

    var runtime = try Runtime.init(alloc, config);
    defer runtime.deinit();

    const tx = try runtime.beginTransaction();
    const ptr = try runtime.allocate(128, 64);
    try runtime.setRoot(tx, ptr);
    try runtime.commit(tx);

    const tx2 = try runtime.beginTransaction();
    _ = try runtime.allocate(256, 64);
    try runtime.commit(tx2);

    const stats = runtime.getStats();
    try testing.expect(stats.allocation_count == 2);
}

test "transaction rollback" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    std.fs.deleteFileAbsolute("/tmp/test_pheap3.dat") catch {};
    std.fs.deleteFileAbsolute("/tmp/test_pheap3.wal") catch {};
    std.fs.deleteTreeAbsolute("/tmp/test_snapshots3") catch {};

    const config = Runtime.RuntimeConfig{
        .heap_path = "/tmp/test_pheap3.dat",
        .heap_size = 1024 * 1024 * 10,
        .wal_path = "/tmp/test_pheap3.wal",
        .snapshot_dir = "/tmp/test_snapshots3",
        .enable_encryption = false,
        .master_key = null,
        .enable_gpu = false,
        .gpu_kernel_path = null,
        .gc_threshold = 100,
        .snapshot_interval_ms = 60000,
    };

    var runtime = try Runtime.init(alloc, config);
    defer runtime.deinit();

    const tx = try runtime.beginTransaction();
    _ = try runtime.allocate(128, 64);
    try runtime.rollback(tx);

    const stats = runtime.getStats();
    try testing.expect(stats.allocation_count == 0);
}
