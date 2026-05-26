const std = @import("std");
const wal_mod = @import("wal.zig");
const pheap = @import("pheap.zig");
const pointer = @import("pointer.zig");
const header = @import("header.zig");
const mem_utils = @import("mem_utils.zig");
const htm = @import("htm.zig");
const seqlock = @import("seqlock.zig");
const tsc = @import("tsc.zig");

pub const TransactionState = enum(u8) {
    inactive,
    active,
    prepared,
    committed,
    rolled_back,
    failed,
};

pub const TX_FLAG_IN_HTM: u8 = 0x01;
pub const TX_FLAG_READ_VALIDATED: u8 = 0x02;
pub const TX_FLAG_PREFETCHED: u8 = 0x04;

pub const RegisterResidentTxState = extern struct {
    id: u64,
    start_tsc: u64,
    read_hash: u64,
    write_hash: u64,
    state: u8,
    flags: u8,
    htm_retries: u16,
    read_count: u16,
    write_count: u16,
    _pad: [24]u8,

    comptime {
        if (@sizeOf(RegisterResidentTxState) != 64)
            @compileError("RegisterResidentTxState must be exactly 64 bytes (one cache line)");
    }

    pub fn init(id: u64, start: u64) RegisterResidentTxState {
        return .{
            .id = id,
            .start_tsc = start,
            .read_hash = 0,
            .write_hash = 0,
            .state = @intFromEnum(TransactionState.active),
            .flags = 0,
            .htm_retries = 0,
            .read_count = 0,
            .write_count = 0,
            ._pad = [_]u8{0} ** 24,
        };
    }

    pub fn hashOffset(self: *RegisterResidentTxState, offset: u64, is_write: bool) void {
        const mix = offset ^ (offset >> 33) ^ 0xff51afd7ed558ccd;
        if (is_write) {
            self.write_hash ^= mix;
            if (self.write_count < std.math.maxInt(u16)) self.write_count += 1;
        } else {
            self.read_hash ^= mix;
            if (self.read_count < std.math.maxInt(u16)) self.read_count += 1;
        }
    }

    pub fn setFlag(self: *RegisterResidentTxState, flag: u8) void {
        self.flags |= flag;
    }

    pub fn clearFlag(self: *RegisterResidentTxState, flag: u8) void {
        self.flags &= ~flag;
    }

    pub fn hasFlag(self: *const RegisterResidentTxState, flag: u8) bool {
        return (self.flags & flag) != 0;
    }

    pub fn syncState(self: *RegisterResidentTxState, s: TransactionState) void {
        self.state = @intFromEnum(s);
    }
};

pub const OperationType = enum(u8) {
    read,
    write,
    allocate,
    free,
    root_update,
};

pub const ConflictType = enum(u8) {
    write_write,
    write_read,
    read_write,
};

pub const ConflictInfo = struct {
    conflicting_tx_id: u64,
    conflict_type: ConflictType,
    conflicting_offset: u64,
};

pub const RetryConfig = struct {
    max_attempts: u32,
    base_delay_ns: u64,
    max_delay_ns: u64,
    jitter: bool,

    pub fn default() RetryConfig {
        return RetryConfig{
            .max_attempts = 5,
            .base_delay_ns = 1_000_000,
            .max_delay_ns = 100_000_000,
            .jitter = true,
        };
    }
};

pub const Operation = struct {
    op_type: OperationType,
    offset: u64,
    size: u64,
    old_data: ?[]const u8,
    new_data: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator_ptr: std.mem.Allocator, op_type: OperationType, offset: u64, size: u64) Operation {
        return Operation{
            .op_type = op_type,
            .offset = offset,
            .size = size,
            .old_data = null,
            .new_data = null,
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *Operation) void {
        if (self.old_data) |data| {
            self.allocator.free(data);
        }
        if (self.new_data) |data| {
            self.allocator.free(data);
        }
    }

    pub fn setOldData(self: *Operation, data: []const u8) !void {
        if (self.old_data) |old| {
            self.allocator.free(old);
        }
        self.old_data = try self.allocator.dupe(u8, data);
    }

    pub fn setNewData(self: *Operation, data: []const u8) !void {
        if (self.new_data) |old| {
            self.allocator.free(old);
        }
        self.new_data = try self.allocator.dupe(u8, data);
    }
};

pub const PendingAllocation = struct {
    offset: u64,
    size: u64,
};

pub const Transaction = struct {
    id: u64,
    state: TransactionState,
    operations: std.ArrayList(Operation),
    wal_tx: ?wal_mod.Transaction,
    start_time: i64,
    start_tsc: u64,
    allocator: std.mem.Allocator,
    read_set: std.ArrayList(u64),
    write_set: std.ArrayList(u64),
    pending_allocations: std.ArrayList(PendingAllocation),
    parent_tx: ?u64,
    tx_arena: mem_utils.ArenaAllocator,
    reg_state: RegisterResidentTxState,
    seq_lock: seqlock.SeqLock,

    pub fn init(allocator_ptr: std.mem.Allocator, id: u64, wal_tx: wal_mod.Transaction) Transaction {
        const start = tsc.rdtsc();
        return Transaction{
            .id = id,
            .state = .active,
            .operations = undefined,
            .wal_tx = wal_tx,
            .start_time = std.time.timestamp(),
            .start_tsc = start,
            .allocator = undefined,
            .read_set = undefined,
            .write_set = undefined,
            .pending_allocations = undefined,
            .parent_tx = null,
            .tx_arena = mem_utils.ArenaAllocator.init(allocator_ptr, 8192),
            .reg_state = RegisterResidentTxState.init(id, start),
            .seq_lock = seqlock.SeqLock.init(),
        };
    }

    pub fn deinit(self: *Transaction) void {
        for (self.operations.items) |*op| {
            op.deinit();
        }
        self.operations.deinit();
        self.read_set.deinit();
        self.write_set.deinit();
        self.pending_allocations.deinit();
        if (self.wal_tx) |*wal_tx| {
            wal_tx.deinit();
        }
        self.tx_arena.deinit();
    }

    pub fn trackAllocation(self: *Transaction, offset: u64, size: u64) !void {
        try self.pending_allocations.append(.{ .offset = offset, .size = size });
    }

    pub fn addOperation(self: *Transaction, op: Operation) !void {
        try self.operations.append(op);
    }

    pub fn addRead(self: *Transaction, offset: u64) !void {
        self.seq_lock.beginWrite();
        errdefer self.seq_lock.endWrite();
        try self.read_set.append(offset);
        self.reg_state.hashOffset(offset, false);
        self.seq_lock.endWrite();
    }

    pub fn addWrite(self: *Transaction, offset: u64) !void {
        self.seq_lock.beginWrite();
        errdefer self.seq_lock.endWrite();
        try self.write_set.append(offset);
        self.reg_state.hashOffset(offset, true);
        self.seq_lock.endWrite();
    }

    pub fn getOperationCount(self: *const Transaction) usize {
        return self.operations.items.len;
    }

    pub fn hasConflict(self: *const Transaction, other: *const Transaction) bool {
        for (self.write_set.items) |ws| {
            for (other.read_set.items) |rs| {
                if (ws == rs) return true;
            }
            for (other.write_set.items) |ows| {
                if (ws == ows) return true;
            }
        }
        for (self.read_set.items) |rs| {
            for (other.write_set.items) |ws| {
                if (rs == ws) return true;
            }
        }
        return false;
    }
};

pub const TransactionManager = struct {
    wal: *wal_mod.WAL,
    heap: *pheap.PersistentHeap,
    allocator_ref: ?*anyopaque,
    undo_allocation_fn: ?*const fn (ctx: *anyopaque, offset: u64, size: u64) anyerror!void,
    active_transactions: std.AutoHashMap(u64, Transaction),
    transaction_counter: u64,
    lock: std.Thread.RwLock,
    allocator: std.mem.Allocator,
    max_active_transactions: usize,
    htm_fallback: std.Thread.Mutex,
    htm_stats: htm.HTMStats,

    pub fn setAllocatorHook(
        self: *@This(),
        ctx: *anyopaque,
        undo_fn: *const fn (ctx: *anyopaque, offset: u64, size: u64) anyerror!void,
    ) void {
        self.allocator_ref = ctx;
        self.undo_allocation_fn = undo_fn;
    }

    const Self = @This();

    pub fn init(allocator_ptr: std.mem.Allocator, wal: *wal_mod.WAL, heap: *pheap.PersistentHeap) !*TransactionManager {
        const self = try allocator_ptr.create(TransactionManager);
        errdefer allocator_ptr.destroy(self);

        self.* = TransactionManager{
            .wal = wal,
            .heap = heap,
            .allocator_ref = null,
            .undo_allocation_fn = null,
            .active_transactions = std.AutoHashMap(u64, Transaction).init(allocator_ptr),
            .transaction_counter = 0,
            .lock = std.Thread.RwLock{},
            .allocator = allocator_ptr,
            .max_active_transactions = 1024,
            .htm_fallback = std.Thread.Mutex{},
            .htm_stats = htm.HTMStats{},
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.active_transactions.iterator();
        while (iter.next()) |entry| {
            var tx = entry.value_ptr;
            tx.deinit();
        }
        self.active_transactions.deinit();
        self.allocator.destroy(self);
    }

    pub fn begin(self: *Self) !*Transaction {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.active_transactions.count() >= self.max_active_transactions) {
            return error.TooManyActiveTransactions;
        }

        self.transaction_counter += 1;
        const id = self.transaction_counter;

        const wal_tx = try self.wal.beginTransaction();

        const tx = Transaction.init(self.allocator, id, wal_tx);
        try self.active_transactions.put(id, tx);

        const entry = self.active_transactions.getPtr(id).?;
        entry.state = .active;

        const arena_alloc = entry.tx_arena.allocator();
        entry.allocator = arena_alloc;
        entry.operations = std.ArrayList(Operation).init(arena_alloc);
        entry.read_set = std.ArrayList(u64).init(arena_alloc);
        entry.write_set = std.ArrayList(u64).init(arena_alloc);
        entry.pending_allocations = std.ArrayList(PendingAllocation).init(arena_alloc);

        return entry;
    }

    fn checkConflictsLocked(self: *const Self, tx: *const Transaction) ?ConflictInfo {
        var iter = self.active_transactions.iterator();
        while (iter.next()) |entry| {
            const other = entry.value_ptr;
            if (other.id == tx.id) continue;
            if (other.state != .active and other.state != .prepared) continue;

            for (tx.write_set.items) |ws| {
                for (other.write_set.items) |ows| {
                    if (ws == ows) return ConflictInfo{
                        .conflicting_tx_id = other.id,
                        .conflict_type = .write_write,
                        .conflicting_offset = ws,
                    };
                }
                for (other.read_set.items) |rs| {
                    if (ws == rs) return ConflictInfo{
                        .conflicting_tx_id = other.id,
                        .conflict_type = .write_read,
                        .conflicting_offset = ws,
                    };
                }
            }

            for (tx.read_set.items) |rs| {
                for (other.write_set.items) |ws| {
                    if (rs == ws) return ConflictInfo{
                        .conflicting_tx_id = other.id,
                        .conflict_type = .read_write,
                        .conflicting_offset = rs,
                    };
                }
            }
        }
        return null;
    }

    pub fn checkConflicts(self: *Self, tx: *const Transaction) ?ConflictInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.checkConflictsLocked(tx);
    }

    pub fn commit(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.state != .active) {
            return error.TransactionNotActive;
        }

        if (self.checkConflictsLocked(tx)) |_| {
            tx.state = .failed;
            return error.TransactionConflict;
        }

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.commitTransaction(wal_tx);
        }

        tx.state = .committed;

        if (self.active_transactions.fetchRemove(tx.id)) |entry| {
            var removed_tx = entry.value;
            removed_tx.deinit();
        }

        try self.heap.flush();
    }

    pub fn rollback(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.state != .active and tx.state != .failed) {
            return error.TransactionNotActive;
        }

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.rollbackTransaction(wal_tx);
        }

        if (self.undo_allocation_fn) |undo_fn| {
            if (self.allocator_ref) |ctx| {
                for (tx.pending_allocations.items) |pa| {
                    undo_fn(ctx, pa.offset, pa.size) catch {};
                }
            }
        }

        tx.state = .rolled_back;

        if (self.active_transactions.fetchRemove(tx.id)) |entry| {
            var removed_tx = entry.value;
            removed_tx.deinit();
        }
    }

    pub fn prepare(self: *Self, tx: *Transaction) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (tx.state != .active) {
            return error.TransactionNotActive;
        }

        tx.state = .prepared;
    }

    pub fn getActiveTransactionCount(self: *Self) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.active_transactions.count();
    }

    pub fn getTransaction(self: *Self, id: u64) ?*Transaction {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.active_transactions.getPtr(id);
    }

    pub fn recordRead(self: *Self, tx: *Transaction, offset: u64) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        try tx.addRead(offset);
    }

    pub fn recordWrite(self: *Self, tx: *Transaction, offset: u64, size: u64, old_data: []const u8) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var op = Operation.init(self.allocator, .write, offset, size);
        try op.setOldData(old_data);
        try tx.addOperation(op);
        try tx.addWrite(offset);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecordWithData(wal_tx, .write, offset, size, old_data);
        }
    }

    pub fn recordAllocate(self: *Self, tx: *Transaction, offset: u64, size: u64) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const op = Operation.init(self.allocator, .allocate, offset, size);
        try tx.addOperation(op);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecord(wal_tx, .allocate, offset, size);
        }
    }

    pub fn recordFree(self: *Self, tx: *Transaction, offset: u64, size: u64, old_data: []const u8) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var op = Operation.init(self.allocator, .free, offset, size);
        try op.setOldData(old_data);
        try tx.addOperation(op);
        try tx.addWrite(offset);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecordWithData(wal_tx, .free, offset, size, old_data);
        }
    }

    pub fn recordRootUpdate(self: *Self, tx: *Transaction, old_root: ?pointer.PersistentPtr, new_root: pointer.PersistentPtr) !void {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var op = Operation.init(self.allocator, .root_update, new_root.offset, @sizeOf(pointer.PersistentPtr));
        if (old_root) |root| {
            try op.setOldData(std.mem.asBytes(&root));
        }
        try op.setNewData(std.mem.asBytes(&new_root));
        try tx.addOperation(op);

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.appendRecord(wal_tx, .root_update, new_root.offset, @sizeOf(pointer.PersistentPtr));
        }
    }

    pub fn getTransactionCount(self: *Self) u64 {
        return self.transaction_counter;
    }

    pub fn timeoutTransactions(self: *Self, timeout_ms: u64) !usize {
        self.lock.lock();
        defer self.lock.unlock();

        const current_time = std.time.timestamp();
        var timed_out: usize = 0;

        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.active_transactions.iterator();
        while (iter.next()) |entry| {
            const tx = entry.value_ptr;
            const elapsed_ms = @as(u64, @intCast((current_time - tx.start_time) * 1000));
            if (elapsed_ms > timeout_ms) {
                try to_remove.append(entry.key_ptr.*);
                timed_out += 1;
            }
        }

        for (to_remove.items) |id| {
            if (self.active_transactions.fetchRemove(id)) |entry| {
                var tx = entry.value;
                if (tx.wal_tx) |*wal_tx| {
                    try self.wal.rollbackTransaction(wal_tx);
                }
                tx.deinit();
            }
        }

        return timed_out;
    }

    pub fn retryableCommit(
        self: *Self,
        context: anytype,
        comptime work_fn: fn (ctx: @TypeOf(context), tx: *Transaction) anyerror!void,
        config: RetryConfig,
    ) !void {
        var attempt: u32 = 0;
        while (attempt < config.max_attempts) : (attempt += 1) {
            const tx = try self.begin();

            work_fn(context, tx) catch |work_err| {
                self.rollback(tx) catch {};
                return work_err;
            };

            self.commit(tx) catch |commit_err| {
                if (commit_err == error.TransactionConflict) {
                    self.rollback(tx) catch {};
                    if (attempt + 1 < config.max_attempts) {
                        var delay = config.base_delay_ns;
                        var i: u32 = 0;
                        while (i < attempt) : (i += 1) {
                            delay = @min(delay *| 2, config.max_delay_ns);
                        }
                        if (config.jitter) {
                            var prng = std.Random.DefaultPrng.init(@as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))));
                            const jitter_ns = prng.random().intRangeAtMost(u64, 0, delay / 2);
                            delay = @min(delay +| jitter_ns, config.max_delay_ns);
                        }
                        std.time.sleep(delay);
                        continue;
                    }
                    return error.MaxRetriesExceeded;
                }
                return commit_err;
            };

            return;
        }
        return error.MaxRetriesExceeded;
    }

    pub fn htmCommitTx(self: *Self, tx: *Transaction) !void {
        if (tx.state != .active) {
            return error.TransactionNotActive;
        }

        var found_conflict: ?ConflictInfo = null;
        var validated_via_htm = false;

        var attempts: u32 = 0;
        const max_htm_attempts: u32 = 6;

        while (attempts < max_htm_attempts) : (attempts += 1) {
            const htm_result = htm.htmBegin();
            switch (htm_result) {
                .success => {
                    found_conflict = self.checkConflictsLocked(tx);
                    htm.htmCommit();
                    validated_via_htm = true;
                    _ = @atomicRmw(u64, &self.htm_stats.htm_commits, .Add, 1, .seq_cst);
                    break;
                },
                .aborted => |code| {
                    _ = @atomicRmw(u64, &self.htm_stats.htm_aborts, .Add, 1, .seq_cst);
                    if (code & htm.HTM_ABORT_CONFLICT != 0) {
                        _ = @atomicRmw(u64, &self.htm_stats.conflict_aborts, .Add, 1, .seq_cst);
                    }
                    if (code & htm.HTM_ABORT_CAPACITY != 0) {
                        _ = @atomicRmw(u64, &self.htm_stats.capacity_aborts, .Add, 1, .seq_cst);
                    }
                    if (!htm.shouldRetry(code, .{})) break;
                    std.atomic.spinLoopHint();
                },
                .not_supported => break,
            }
        }

        if (!validated_via_htm) {
            self.lock.lockShared();
            found_conflict = self.checkConflictsLocked(tx);
            self.lock.unlockShared();
            _ = @atomicRmw(u64, &self.htm_stats.fallback_commits, .Add, 1, .seq_cst);
        }

        if (found_conflict != null) {
            tx.state = .failed;
            tx.reg_state.syncState(.failed);
            return error.TransactionConflict;
        }

        if (tx.wal_tx) |*wal_tx| {
            try self.wal.commitTransaction(wal_tx);
        }

        self.lock.lock();
        defer self.lock.unlock();

        tx.state = .committed;
        tx.reg_state.syncState(.committed);

        if (self.active_transactions.fetchRemove(tx.id)) |entry| {
            var removed_tx = entry.value;
            removed_tx.deinit();
        }

        try self.heap.flush();
    }

    pub fn seqlockReadSet(
        self: *Self,
        tx: *const Transaction,
        out_set: *std.ArrayList(u64),
    ) !void {
        _ = self;
        const max_retries: u32 = 32;
        var retry: u32 = 0;
        while (retry < max_retries) : (retry += 1) {
            const seq = tx.seq_lock.beginRead();

            out_set.clearRetainingCapacity();
            for (tx.read_set.items) |offset| {
                try out_set.append(offset);
            }
            asm volatile ("" ::: "memory");

            if (tx.seq_lock.endRead(seq)) return;

            std.atomic.spinLoopHint();
        }
        return error.SeqlockReadRetryExhausted;
    }

    pub fn prefetchReadSet(self: *const Self, tx: *const Transaction) void {
        const base_addr = self.heap.getBaseAddress();
        for (tx.read_set.items) |offset| {
            const ptr: *const u8 = @ptrCast(base_addr + @as(usize, @intCast(offset)));
            @prefetch(ptr, .{ .rw = .read, .locality = 3, .cache = .data });
        }
    }

    pub fn getHtmStats(self: *const Self) htm.HTMStats {
        return self.htm_stats;
    }

    pub fn snapshotRegState(self: *Self, tx_id: u64) ?RegisterResidentTxState {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const tx = self.active_transactions.getPtr(tx_id) orelse return null;
        const seq = tx.seq_lock.beginRead();
        const snap = tx.reg_state;
        asm volatile ("" ::: "memory");
        if (!tx.seq_lock.endRead(seq)) return null;
        return snap;
    }
};

test "register resident tx state size is 64 bytes" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(RegisterResidentTxState));
}

test "register resident tx state hash" {
    var reg = RegisterResidentTxState.init(42, 0);
    reg.hashOffset(0x100, false);
    reg.hashOffset(0x200, true);
    try std.testing.expectEqual(@as(u16, 1), reg.read_count);
    try std.testing.expectEqual(@as(u16, 1), reg.write_count);
    try std.testing.expect(reg.read_hash != 0);
    try std.testing.expect(reg.write_hash != 0);
}

test "register resident tx state flags" {
    var reg = RegisterResidentTxState.init(1, 0);
    try std.testing.expect(!reg.hasFlag(TX_FLAG_IN_HTM));
    reg.setFlag(TX_FLAG_IN_HTM);
    try std.testing.expect(reg.hasFlag(TX_FLAG_IN_HTM));
    reg.clearFlag(TX_FLAG_IN_HTM);
    try std.testing.expect(!reg.hasFlag(TX_FLAG_IN_HTM));
}

test "htm commit tx no conflict" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const heap_path = "/tmp/test_htm_commit.dat";
    const wal_path = "/tmp/test_htm_commit.wal";
    std.fs.cwd().deleteFile(heap_path) catch {};
    std.fs.cwd().deleteFile(wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try tx.addWrite(1024);
    try tx_mgr.htmCommitTx(tx);
    try testing.expectEqual(@as(usize, 0), tx_mgr.getActiveTransactionCount());
}

test "htm commit tx conflict" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const heap_path = "/tmp/test_htm_conflict.dat";
    const wal_path = "/tmp/test_htm_conflict.wal";
    std.fs.cwd().deleteFile(heap_path) catch {};
    std.fs.cwd().deleteFile(wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx1 = try tx_mgr.begin();
    try tx1.addWrite(2048);

    const tx2 = try tx_mgr.begin();
    try tx2.addWrite(2048);

    const result = tx_mgr.htmCommitTx(tx2);
    try testing.expectError(error.TransactionConflict, result);

    try tx_mgr.rollback(tx1);
}

test "seqlock read set" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const heap_path = "/tmp/test_seqlock_rs.dat";
    const wal_path = "/tmp/test_seqlock_rs.wal";
    std.fs.cwd().deleteFile(heap_path) catch {};
    std.fs.cwd().deleteFile(wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try tx.addRead(100);
    try tx.addRead(200);
    try tx.addRead(300);

    var snapshot = std.ArrayList(u64).init(alloc);
    defer snapshot.deinit();

    try tx_mgr.seqlockReadSet(tx, &snapshot);
    try testing.expectEqual(@as(usize, 3), snapshot.items.len);
    try testing.expectEqual(@as(u64, 100), snapshot.items[0]);
    try testing.expectEqual(@as(u64, 200), snapshot.items[1]);
    try testing.expectEqual(@as(u64, 300), snapshot.items[2]);

    try tx_mgr.rollback(tx);
}

test "prefetch read set does not crash" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const heap_path = "/tmp/test_prefetch_rs.dat";
    const wal_path = "/tmp/test_prefetch_rs.wal";
    std.fs.cwd().deleteFile(heap_path) catch {};
    std.fs.cwd().deleteFile(wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try tx.addRead(512);
    try tx.addRead(1024);

    tx_mgr.prefetchReadSet(tx);

    try tx_mgr.rollback(tx);
}

test "snapshot reg state" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const heap_path = "/tmp/test_snapreg.dat";
    const wal_path = "/tmp/test_snapreg.wal";
    std.fs.cwd().deleteFile(heap_path) catch {};
    std.fs.cwd().deleteFile(wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    const tx_id = tx.id;
    try tx.addWrite(4096);

    const snap = tx_mgr.snapshotRegState(tx_id);
    try testing.expect(snap != null);
    try testing.expectEqual(tx_id, snap.?.id);
    try testing.expectEqual(@as(u16, 1), snap.?.write_count);

    try tx_mgr.rollback(tx);
}

test "transaction manager lifecycle" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_mgr.dat";
    const test_wal_path = "/tmp/test_tx_mgr.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try testing.expect(tx.state == .active);
    try testing.expect(tx.id > 0);
    try tx_mgr.rollback(tx);
}

test "transaction commit" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_commit.dat";
    const test_wal_path = "/tmp/test_tx_commit.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx = try tx_mgr.begin();
    try tx_mgr.recordAllocate(tx, 100, 64);
    try tx_mgr.commit(tx);

    try testing.expectEqual(@as(usize, 0), tx_mgr.getActiveTransactionCount());
}

test "transaction conflict detection" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_conflict.dat";
    const test_wal_path = "/tmp/test_tx_conflict.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx1 = try tx_mgr.begin();
    try tx1.addWrite(200);

    const tx2 = try tx_mgr.begin();
    try tx2.addWrite(200);

    const conflict = tx_mgr.checkConflicts(tx2);
    try testing.expect(conflict != null);
    try testing.expectEqual(tx1.id, conflict.?.conflicting_tx_id);
    try testing.expectEqual(ConflictType.write_write, conflict.?.conflict_type);
    try testing.expectEqual(@as(u64, 200), conflict.?.conflicting_offset);

    try tx_mgr.rollback(tx1);

    const no_conflict = tx_mgr.checkConflicts(tx2);
    try testing.expect(no_conflict == null);

    try tx_mgr.rollback(tx2);
}

test "transaction read-write conflict detection" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_rw_conflict.dat";
    const test_wal_path = "/tmp/test_tx_rw_conflict.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx1 = try tx_mgr.begin();
    try tx1.addRead(300);

    const tx2 = try tx_mgr.begin();
    try tx2.addWrite(300);

    const conflict = tx_mgr.checkConflicts(tx2);
    try testing.expect(conflict != null);
    try testing.expectEqual(tx1.id, conflict.?.conflicting_tx_id);
    try testing.expectEqual(ConflictType.write_read, conflict.?.conflict_type);
    try testing.expectEqual(@as(u64, 300), conflict.?.conflicting_offset);

    try tx_mgr.rollback(tx1);
    try tx_mgr.rollback(tx2);
}

test "commit blocked by conflict returns error" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_commit_conflict.dat";
    const test_wal_path = "/tmp/test_tx_commit_conflict.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx1 = try tx_mgr.begin();
    try tx1.addWrite(400);

    const tx2 = try tx_mgr.begin();
    try tx2.addWrite(400);

    const result = tx_mgr.commit(tx2);
    try testing.expectError(error.TransactionConflict, result);
    try testing.expectEqual(TransactionState.failed, tx2.state);

    try tx_mgr.rollback(tx1);
    try tx_mgr.rollback(tx2);
}

test "retryable commit succeeds on first attempt" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_retry_ok.dat";
    const test_wal_path = "/tmp/test_tx_retry_ok.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const Ctx = struct { offset: u64 };
    const work = struct {
        fn do(ctx: Ctx, tx: *Transaction) anyerror!void {
            try tx.addWrite(ctx.offset);
        }
    }.do;

    const config = RetryConfig{
        .max_attempts = 3,
        .base_delay_ns = 1,
        .max_delay_ns = 1,
        .jitter = false,
    };

    try tx_mgr.retryableCommit(Ctx{ .offset = 500 }, work, config);
    try testing.expectEqual(@as(usize, 0), tx_mgr.getActiveTransactionCount());
}

test "retryable commit returns MaxRetriesExceeded when permanently blocked" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_tx_retry_exhaust.dat";
    const test_wal_path = "/tmp/test_tx_retry_exhaust.wal";
    std.fs.cwd().deleteFile(test_heap_path) catch {};
    std.fs.cwd().deleteFile(test_wal_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var tx_mgr = try TransactionManager.init(alloc, wal, heap);
    defer tx_mgr.deinit();

    const tx1 = try tx_mgr.begin();
    try tx1.addWrite(600);

    const Ctx = struct {};
    const work = struct {
        fn do(ctx: Ctx, tx: *Transaction) anyerror!void {
            _ = ctx;
            try tx.addWrite(600);
        }
    }.do;

    const config = RetryConfig{
        .max_attempts = 2,
        .base_delay_ns = 1,
        .max_delay_ns = 1,
        .jitter = false,
    };

    const result = tx_mgr.retryableCommit(Ctx{}, work, config);
    try testing.expectError(error.MaxRetriesExceeded, result);

    try tx_mgr.rollback(tx1);
    try testing.expectEqual(@as(usize, 0), tx_mgr.getActiveTransactionCount());
}
