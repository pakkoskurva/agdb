const std = @import("std");
const pheap = @import("pheap.zig");
const allocator_mod = @import("allocator.zig");
const wal_mod = @import("wal.zig");
const transaction_mod = @import("transaction.zig");
const recovery_mod = @import("recovery.zig");
const pointer_mod = @import("pointer.zig");
const concurrency_mod = @import("concurrency.zig");
const gc_mod = @import("gc.zig");
const snapshot_mod = @import("snapshot.zig");
const security_mod = @import("security.zig");
const api_mod = @import("api.zig");
const schema_mod = @import("schema.zig");
const mem_utils_mod = @import("mem_utils.zig");

pub const PersistentHeap = pheap.PersistentHeap;
pub const PersistentAllocator = allocator_mod.PersistentAllocator;
pub const WAL = wal_mod.WAL;
pub const TransactionManager = transaction_mod.TransactionManager;
pub const Transaction = transaction_mod.Transaction;
pub const RecoveryEngine = recovery_mod.RecoveryEngine;
pub const RefCountGC = gc_mod.RefCountGC;
pub const SnapshotManager = snapshot_mod.SnapshotManager;
pub const SecurityManager = security_mod.SecurityManager;
pub const PersistentStore = api_mod.PersistentStore;
pub const SchemaRegistry = schema_mod.SchemaRegistry;
pub const PersistentPtr = pointer_mod.PersistentPtr;

pub const RuntimeConfig = struct {
    heap_path: []const u8,
    heap_size: u64,
    wal_path: []const u8,
    snapshot_dir: []const u8,
    enable_encryption: bool,
    master_key: ?[]const u8,
    gc_threshold: u64,
    snapshot_interval_ms: u64,

    pub fn default(base_dir: []const u8) RuntimeConfig {
        _ = base_dir;
        return .{
            .heap_path = "agdb.heap",
            .heap_size = 1024 * 1024 * 256,
            .wal_path = "agdb.wal",
            .snapshot_dir = "snapshots",
            .enable_encryption = false,
            .master_key = null,
            .gc_threshold = 1024,
            .snapshot_interval_ms = 60_000,
        };
    }
};

pub const RuntimeStats = struct {
    heap_used: u64,
    heap_total: u64,
    allocation_count: u64,
    free_count: u64,
    wal_size: u64,
    transaction_count: u64,
    gc_stats: gc_mod.GCStats,
    snapshot_count: u64,
};

pub const Runtime = struct {
    heap: *PersistentHeap,
    alloc: *PersistentAllocator,
    wal: *WAL,
    tx_manager: *TransactionManager,
    recovery: *RecoveryEngine,
    gc: *RefCountGC,
    snapshots: *SnapshotManager,
    security: *SecurityManager,
    store: *PersistentStore,
    arena: *std.heap.ArenaAllocator,
    parent_allocator: std.mem.Allocator,
    config: RuntimeConfig,

    pub fn init(parent_alloc: std.mem.Allocator, config: RuntimeConfig) !*Runtime {
        const arena_ptr = try parent_alloc.create(std.heap.ArenaAllocator);
        errdefer parent_alloc.destroy(arena_ptr);
        arena_ptr.* = std.heap.ArenaAllocator.init(parent_alloc);
        errdefer arena_ptr.deinit();
        const arena_alloc = arena_ptr.allocator();

        const self = try parent_alloc.create(Runtime);
        errdefer parent_alloc.destroy(self);

        self.* = Runtime{
            .heap = undefined,
            .alloc = undefined,
            .wal = undefined,
            .tx_manager = undefined,
            .recovery = undefined,
            .gc = undefined,
            .snapshots = undefined,
            .security = undefined,
            .store = undefined,
            .arena = arena_ptr,
            .parent_allocator = parent_alloc,
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

        self.store = try PersistentStore.init(arena_alloc, self.alloc, self.tx_manager, self.gc);

        return self;
    }

    pub fn deinit(self: *Runtime) void {
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

    pub fn beginTransaction(self: *Runtime) !*Transaction {
        return self.tx_manager.begin();
    }

    fn undoAllocationThunk(ctx: *anyopaque, offset: u64, size: u64) anyerror!void {
        const alloc_ptr: *PersistentAllocator = @ptrCast(@alignCast(ctx));
        try alloc_ptr.undoAllocation(offset, size);
    }

    pub fn commit(self: *Runtime, tx: *Transaction) !void {
        try self.tx_manager.commit(tx);
    }

    pub fn rollback(self: *Runtime, tx: *Transaction) !void {
        try self.tx_manager.rollback(tx);
    }

    pub fn allocate(self: *Runtime, size: u64, alignment: u64) !PersistentPtr {
        const ptr = try self.alloc.alloc(size, alignment);
        if (self.tx_manager.active_transactions.count() > 0) {
            const latest_id = self.tx_manager.transaction_counter;
            if (self.tx_manager.active_transactions.getPtr(latest_id)) |tx| {
                tx.trackAllocation(ptr.offset, size) catch {};
            }
        }
        return ptr;
    }

    pub fn free(self: *Runtime, ptr: PersistentPtr) !void {
        try self.alloc.free(ptr);
    }

    pub fn getRoot(self: *Runtime) ?PersistentPtr {
        return self.heap.getRoot();
    }

    pub fn setRoot(self: *Runtime, tx: *Transaction, ptr: PersistentPtr) !void {
        try self.heap.setRoot(tx, ptr);
    }

    pub fn createSnapshot(self: *Runtime) !u64 {
        return self.snapshots.createSnapshot();
    }

    pub fn restoreSnapshot(self: *Runtime, snapshot_id: u64) !void {
        try self.snapshots.restoreSnapshot(snapshot_id);
    }

    pub fn runGC(self: *Runtime) !gc_mod.GCStats {
        return self.gc.runCollection();
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

test "runtime smoke" {
    const testing = std.testing;
    const tmp_root = "agdb-test-runtime";
    std.fs.cwd().deleteTree(tmp_root) catch {};
    try std.fs.cwd().makePath(tmp_root);
    defer std.fs.cwd().deleteTree(tmp_root) catch {};

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const heap_path = try std.fmt.allocPrint(alloc, "{s}/heap.dat", .{tmp_root});
    defer alloc.free(heap_path);
    const wal_path = try std.fmt.allocPrint(alloc, "{s}/wal.dat", .{tmp_root});
    defer alloc.free(wal_path);
    const snap_path = try std.fmt.allocPrint(alloc, "{s}/snapshots", .{tmp_root});
    defer alloc.free(snap_path);

    const config = RuntimeConfig{
        .heap_path = heap_path,
        .heap_size = 1024 * 1024 * 4,
        .wal_path = wal_path,
        .snapshot_dir = snap_path,
        .enable_encryption = false,
        .master_key = null,
        .gc_threshold = 64,
        .snapshot_interval_ms = 60_000,
    };

    var rt = try Runtime.init(alloc, config);
    defer rt.deinit();

    const tx = try rt.beginTransaction();
    const ptr = try rt.allocate(128, 64);
    try rt.setRoot(tx, ptr);
    try rt.commit(tx);

    const stats = rt.getStats();
    try testing.expect(stats.allocation_count >= 1);
    try testing.expect(stats.heap_total >= 1024 * 1024);
}
