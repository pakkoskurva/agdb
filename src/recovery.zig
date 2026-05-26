const std = @import("std");
const wal_mod = @import("wal.zig");
const pheap = @import("pheap.zig");
const header = @import("header.zig");
const allocator_mod = @import("allocator.zig");

pub const RecoveryPhase = enum(u8) {
    none,
    analysis,
    redo,
    undo,
    complete,
    failed,
};

pub const RecoveryStats = struct {
    transactions_analyzed: u64,
    transactions_committed: u64,
    transactions_rolled_back: u64,
    records_redone: u64,
    records_undone: u64,
    errors: u64,
    start_time_ns: i128,
    end_time_ns: i128,

    pub fn durationNs(self: *const RecoveryStats) i128 {
        if (self.end_time_ns == 0 or self.end_time_ns < self.start_time_ns) return 0;
        return self.end_time_ns - self.start_time_ns;
    }

    pub fn durationMs(self: *const RecoveryStats) i128 {
        return @divTrunc(self.durationNs(), 1_000_000);
    }
};

pub const RecoveryError = error{
    CorruptedWAL,
    IncompleteTransaction,
    InvalidRecord,
    HeapCorruption,
    UndoFailed,
    RedoFailed,
    DuplicateTransactionId,
    AlreadyRecovered,
    OutOfBounds,
    GenerationMismatch,
};

pub const CrashPhaseTag = enum {
    analysis,
    redo,
    undo,
    finalize,
};

pub const TransactionRecord = struct {
    tx: wal_mod.Transaction,
    lsn: u64,
};

fn ascendingLsn(_: void, a: TransactionRecord, b: TransactionRecord) bool {
    return a.lsn < b.lsn;
}

fn descendingLsn(_: void, a: TransactionRecord, b: TransactionRecord) bool {
    return a.lsn > b.lsn;
}

pub const RecoveryEngine = struct {
    heap: *pheap.PersistentHeap,
    wal: *wal_mod.WAL,
    phase: RecoveryPhase,
    stats: RecoveryStats,
    allocator: std.mem.Allocator,
    incomplete_transactions: std.ArrayList(TransactionRecord),
    committed_transactions: std.ArrayList(TransactionRecord),
    seen_ids: std.AutoHashMap(u64, void),
    last_checkpoint_lsn: u64,
    crash_simulator: ?*CrashSimulator,

    const Self = @This();

    pub fn init(heap: *pheap.PersistentHeap, wal: *wal_mod.WAL, allocator_param: std.mem.Allocator) RecoveryEngine {
        return RecoveryEngine{
            .heap = heap,
            .wal = wal,
            .phase = .none,
            .stats = RecoveryStats{
                .transactions_analyzed = 0,
                .transactions_committed = 0,
                .transactions_rolled_back = 0,
                .records_redone = 0,
                .records_undone = 0,
                .errors = 0,
                .start_time_ns = 0,
                .end_time_ns = 0,
            },
            .allocator = allocator_param,
            .incomplete_transactions = std.ArrayList(TransactionRecord).init(allocator_param),
            .committed_transactions = std.ArrayList(TransactionRecord).init(allocator_param),
            .seen_ids = std.AutoHashMap(u64, void).init(allocator_param),
            .last_checkpoint_lsn = 0,
            .crash_simulator = null,
        };
    }

    pub fn setCrashSimulator(self: *Self, sim: *CrashSimulator) void {
        self.crash_simulator = sim;
    }

    pub fn clearCrashSimulator(self: *Self) void {
        self.crash_simulator = null;
    }

    pub fn deinit(self: *Self) void {
        for (self.incomplete_transactions.items) |*entry| {
            entry.tx.deinit();
        }
        self.incomplete_transactions.deinit();

        for (self.committed_transactions.items) |*entry| {
            entry.tx.deinit();
        }
        self.committed_transactions.deinit();

        self.seen_ids.deinit();
    }

    fn maybeCrash(self: *Self, phase_tag: CrashPhaseTag) !void {
        if (self.crash_simulator) |sim| {
            if (sim.shouldCrash()) {
                self.stats.errors += 1;
                return switch (phase_tag) {
                    .analysis => error.CorruptedWAL,
                    .redo => error.RedoFailed,
                    .undo => error.UndoFailed,
                    .finalize => error.HeapCorruption,
                };
            }
        }
    }

    pub fn recover(self: *Self) !void {
        if (self.phase != .none and self.phase != .failed) {
            return error.AlreadyRecovered;
        }

        self.stats.start_time_ns = std.time.nanoTimestamp();

        errdefer {
            self.phase = .failed;
            self.stats.end_time_ns = std.time.nanoTimestamp();
        }

        if (!try self.needsRecoveryChecked()) {
            self.phase = .complete;
            self.stats.end_time_ns = std.time.nanoTimestamp();
            return;
        }

        self.last_checkpoint_lsn = self.wal.getLastCheckpoint();

        self.phase = .analysis;
        try self.maybeCrash(.analysis);
        try self.runAnalysisPhase();

        std.mem.sort(TransactionRecord, self.committed_transactions.items, {}, ascendingLsn);
        std.mem.sort(TransactionRecord, self.incomplete_transactions.items, {}, descendingLsn);

        self.phase = .redo;
        try self.runRedoPhase();

        self.phase = .undo;
        try self.runUndoPhase();

        try self.maybeCrash(.finalize);
        try self.finalizeRecovery();

        self.phase = .complete;
        self.stats.end_time_ns = std.time.nanoTimestamp();
    }

    fn needsRecoveryChecked(self: *Self) !bool {
        if (self.heap.header.isDirty()) {
            return true;
        }

        const transactions = self.wal.getTransactions() catch {
            self.stats.errors += 1;
            return true;
        };
        defer {
            for (transactions.items) |*tx| {
                tx.deinit();
            }
            transactions.deinit();
        }

        for (transactions.items) |tx| {
            if (tx.state == .active or tx.state == .prepared) {
                return true;
            }
        }

        return false;
    }

    fn cloneTransaction(self: *Self, src: *const wal_mod.Transaction) !wal_mod.Transaction {
        var new_records = std.ArrayList(wal_mod.WALRecord).init(self.allocator);
        errdefer {
            if (comptime @hasDecl(wal_mod.WALRecord, "deinit")) {
                for (new_records.items) |*r| {
                    r.deinit(self.allocator);
                }
            }
            new_records.deinit();
        }
        try new_records.ensureTotalCapacityPrecise(src.records.items.len);
        for (src.records.items) |rec| {
            const cloned = if (comptime @hasDecl(wal_mod.WALRecord, "clone"))
                try rec.clone(self.allocator)
            else
                rec;
            new_records.appendAssumeCapacity(cloned);
        }

        var cloned = wal_mod.Transaction.init(self.allocator, src.id);
        cloned.state = src.state;
        cloned.records.deinit();
        cloned.records = new_records;
        cloned.start_offset = src.start_offset;
        return cloned;
    }

    fn runAnalysisPhase(self: *Self) !void {
        const transactions = try self.wal.getTransactions();
        defer {
            for (transactions.items) |*tx| {
                tx.deinit();
            }
            transactions.deinit();
        }

        for (transactions.items) |*tx| {
            const lsn = self.wal.getTransactionLsn(tx) catch {
                self.stats.errors += 1;
                return error.CorruptedWAL;
            };

            if (lsn <= self.last_checkpoint_lsn and tx.state == .committed) {
                continue;
            }

            self.stats.transactions_analyzed += 1;

            switch (tx.state) {
                .committed => {
                    if (self.seen_ids.contains(tx.id)) {
                        self.stats.errors += 1;
                        return error.DuplicateTransactionId;
                    }
                    var cloned = try self.cloneTransaction(tx);
                    {
                        errdefer cloned.deinit();
                        try self.seen_ids.put(tx.id, {});
                        try self.committed_transactions.append(.{ .tx = cloned, .lsn = lsn });
                    }
                    self.stats.transactions_committed += 1;
                },
                .active, .prepared => {
                    if (self.seen_ids.contains(tx.id)) {
                        self.stats.errors += 1;
                        return error.DuplicateTransactionId;
                    }
                    var cloned = try self.cloneTransaction(tx);
                    {
                        errdefer cloned.deinit();
                        try self.seen_ids.put(tx.id, {});
                        try self.incomplete_transactions.append(.{ .tx = cloned, .lsn = lsn });
                    }
                },
                .rolled_back => {},
            }
        }
    }

    fn runRedoPhase(self: *Self) !void {
        for (self.committed_transactions.items) |*entry| {
            try self.redoTransaction(&entry.tx);
        }
    }

    fn redoTransaction(self: *Self, tx: *const wal_mod.Transaction) !void {
        try self.maybeCrash(.redo);
        for (tx.records.items) |record| {
            switch (try record.getType()) {
                .allocate, .write, .free, .free_list_add, .free_list_remove, .heap_extend, .root_update => {
                    try self.redoRecord(&record);
                    self.stats.records_redone += 1;
                },
                else => {
                    self.stats.errors += 1;
                    return error.InvalidRecord;
                },
            }
        }
        try self.maybeCrash(.redo);
    }

    fn boundsCheck(self: *Self, offset: u64, size: u64) !void {
        const heap_size = self.heap.getSize();
        if (offset > heap_size) {
            self.stats.errors += 1;
            return error.OutOfBounds;
        }
        if (size > heap_size - offset) {
            self.stats.errors += 1;
            return error.OutOfBounds;
        }
    }

    fn freeWalData(self: *Self, data: []const u8) void {
        if (comptime @hasDecl(wal_mod, "freeData")) {
            wal_mod.freeData(self.allocator, data);
        } else if (data.len > 0) {
            self.allocator.free(data);
        }
    }

    fn redoRecord(self: *Self, record: *const wal_mod.WALRecord) !void {
        switch (try record.getType()) {
            .allocate => {
                try self.boundsCheck(record.offset, @sizeOf(header.ObjectHeader));
                const base_addr = self.heap.getBaseAddress();
                const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
                obj_header.checksum = 0;
                obj_header.setFreed(false);
                obj_header.checksum = obj_header.computeChecksum();
                try self.heap.flushRangeAt(record.offset, @sizeOf(header.ObjectHeader));
                try self.heap.markAllocated(record.offset, record.size);
            },
            .write => {
                const new_data = try self.wal.getRedoData(record);
                defer self.freeWalData(new_data);
                if (new_data.len > 0) {
                    try self.boundsCheck(record.offset, new_data.len);
                    try self.verifyGeneration(record);
                    try self.heap.write(record.offset, new_data);
                }
            },
            .free => {
                try self.boundsCheck(record.offset, @sizeOf(header.ObjectHeader));
                const base_addr = self.heap.getBaseAddress();
                const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
                obj_header.checksum = 0;
                obj_header.setFreed(true);
                obj_header.checksum = obj_header.computeChecksum();
                try self.heap.flushRangeAt(record.offset, @sizeOf(header.ObjectHeader));
                try self.heap.markFreed(record.offset, record.size);
            },
            .heap_extend => {
                if (record.size > 0) {
                    const current_size = self.heap.getSize();
                    const target_size = record.offset + record.size;
                    if (current_size < target_size) {
                        try self.heap.expand(target_size - current_size);
                    }
                }
            },
            .root_update => {
                const base_addr = self.heap.getBaseAddress();
                const root_header: *header.HeapHeader = @ptrCast(@alignCast(base_addr));
                root_header.root_offset = record.offset;
                root_header.checksum = 0;
                root_header.updateChecksum();
                try self.heap.flushRangeAt(0, @sizeOf(header.HeapHeader));
            },
            .free_list_add => {
                try self.boundsCheck(record.offset, record.size);
                try self.heap.freeListInsert(record.offset, record.size);
                try self.heap.flushFreeListMetadata();
                try self.heap.flushRangeAt(record.offset, record.size);
            },
            .free_list_remove => {
                try self.boundsCheck(record.offset, record.size);
                try self.heap.freeListRemove(record.offset, record.size);
                try self.heap.flushFreeListMetadata();
                try self.heap.flushRangeAt(record.offset, record.size);
            },
            else => {
                self.stats.errors += 1;
                return error.InvalidRecord;
            },
        }
    }

    fn verifyGeneration(self: *Self, record: *const wal_mod.WALRecord) !void {
        if (comptime !@hasField(wal_mod.WALRecord, "generation")) return;
        if (comptime !@hasField(header.ObjectHeader, "generation")) return;
        if (record.offset < @sizeOf(header.HeapHeader)) return;
        const base_addr = self.heap.getBaseAddress();
        const obj_offset = self.heap.findObjectHeaderOffset(record.offset) catch return;
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + obj_offset));
        const rec_gen = @field(record.*, "generation");
        const obj_gen = @field(obj_header.*, "generation");
        if (rec_gen != obj_gen) {
            return error.GenerationMismatch;
        }
    }

    fn runUndoPhase(self: *Self) !void {
        for (self.incomplete_transactions.items) |*entry| {
            try self.undoTransaction(&entry.tx);
            self.stats.transactions_rolled_back += 1;
        }
    }

    fn undoTransaction(self: *Self, tx: *const wal_mod.Transaction) !void {
        try self.maybeCrash(.undo);
        var i: usize = tx.records.items.len;
        while (i > 0) {
            i -= 1;
            const record = tx.records.items[i];

            switch (try record.getType()) {
                .allocate => {
                    try self.undoAllocate(&record);
                    self.stats.records_undone += 1;
                },
                .write => {
                    try self.undoWrite(&record);
                    self.stats.records_undone += 1;
                },
                .free => {
                    try self.undoFree(&record);
                    self.stats.records_undone += 1;
                },
                .heap_extend => {
                    try self.undoHeapExtend(&record);
                    self.stats.records_undone += 1;
                },
                .root_update => {
                    try self.undoRootUpdate(&record);
                    self.stats.records_undone += 1;
                },
                .free_list_add => {
                    try self.undoFreeListAdd(&record);
                    self.stats.records_undone += 1;
                },
                .free_list_remove => {
                    try self.undoFreeListRemove(&record);
                    self.stats.records_undone += 1;
                },
                else => {
                    self.stats.errors += 1;
                    return error.IncompleteTransaction;
                },
            }
        }
        try self.maybeCrash(.undo);
    }

    fn undoAllocate(self: *Self, record: *const wal_mod.WALRecord) !void {
        try self.boundsCheck(record.offset, @sizeOf(header.ObjectHeader));
        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
        obj_header.checksum = 0;
        obj_header.setFreed(true);
        obj_header.checksum = obj_header.computeChecksum();
        try self.heap.flushRangeAt(record.offset, @sizeOf(header.ObjectHeader));
        if (!self.heap.isInFreeList(record.offset, record.size)) {
            try self.heap.freeListInsert(record.offset, record.size);
            try self.heap.flushFreeListMetadata();
        }
        try self.heap.markFreed(record.offset, record.size);
    }

    fn undoWrite(self: *Self, record: *const wal_mod.WALRecord) !void {
        const old_data = try self.wal.getUndoData(record);
        defer self.freeWalData(old_data);
        if (old_data.len > 0) {
            try self.boundsCheck(record.offset, old_data.len);
            try self.verifyGeneration(record);
            try self.heap.write(record.offset, old_data);
        }
    }

    fn undoFree(self: *Self, record: *const wal_mod.WALRecord) !void {
        try self.boundsCheck(record.offset, @sizeOf(header.ObjectHeader));
        const base_addr = self.heap.getBaseAddress();
        const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + record.offset));
        obj_header.checksum = 0;
        obj_header.setFreed(false);
        obj_header.checksum = obj_header.computeChecksum();
        try self.heap.flushRangeAt(record.offset, @sizeOf(header.ObjectHeader));
        if (self.heap.isInFreeList(record.offset, record.size)) {
            try self.heap.freeListRemove(record.offset, record.size);
            try self.heap.flushFreeListMetadata();
        }
        try self.heap.markAllocated(record.offset, record.size);
    }

    fn undoHeapExtend(self: *Self, record: *const wal_mod.WALRecord) !void {
        const current_size = self.heap.getSize();
        if (current_size > record.offset) {
            try self.heap.shrink(record.offset);
        }
    }

    fn undoRootUpdate(self: *Self, record: *const wal_mod.WALRecord) !void {
        const old_root = try self.wal.getUndoRootOffset(record);
        const base_addr = self.heap.getBaseAddress();
        const root_header: *header.HeapHeader = @ptrCast(@alignCast(base_addr));
        root_header.root_offset = old_root;
        root_header.checksum = 0;
        root_header.updateChecksum();
        try self.heap.flushRangeAt(0, @sizeOf(header.HeapHeader));
    }

    fn undoFreeListAdd(self: *Self, record: *const wal_mod.WALRecord) !void {
        try self.boundsCheck(record.offset, record.size);
        if (self.heap.isInFreeList(record.offset, record.size)) {
            try self.heap.freeListRemove(record.offset, record.size);
            try self.heap.flushFreeListMetadata();
        }
        try self.heap.flushRangeAt(record.offset, record.size);
    }

    fn undoFreeListRemove(self: *Self, record: *const wal_mod.WALRecord) !void {
        try self.boundsCheck(record.offset, record.size);
        if (!self.heap.isInFreeList(record.offset, record.size)) {
            try self.heap.freeListInsert(record.offset, record.size);
            try self.heap.flushFreeListMetadata();
        }
        try self.heap.flushRangeAt(record.offset, record.size);
    }

    fn finalizeRecovery(self: *Self) !void {
        var dirty_restored = false;
        errdefer {
            if (!dirty_restored) {
                self.heap.header.setDirty(true);
                self.heap.header.checksum = 0;
                self.heap.header.updateChecksum();
                self.heap.flushRangeAt(0, @sizeOf(header.HeapHeader)) catch |flush_err| {
                    std.log.err("recovery: failed to restore dirty flag on flush: {s}", .{@errorName(flush_err)});
                };
                self.heap.sync() catch |sync_err| {
                    std.log.err("recovery: failed to restore dirty flag on sync: {s}", .{@errorName(sync_err)});
                };
            }
        }

        try self.heap.sync();
        try self.wal.checkpoint();

        self.heap.header.setDirty(false);
        self.heap.header.checksum = 0;
        self.heap.header.updateChecksum();
        try self.heap.flushRangeAt(0, @sizeOf(header.HeapHeader));
        try self.heap.sync();
        dirty_restored = true;
    }

    pub fn getStats(self: *const Self) RecoveryStats {
        return self.stats;
    }

    pub fn getPhase(self: *const Self) RecoveryPhase {
        return self.phase;
    }

    fn nextScanOffset(current: u64) u64 {
        const align_v: u64 = @alignOf(header.ObjectHeader);
        return std.mem.alignForward(u64, current + 1, align_v);
    }

    fn scanHeap(self: *Self, comptime repair: bool) !if (repair) usize else bool {
        var result: if (repair) usize else bool = if (repair) 0 else true;

        if (repair) {
            const heap_header_expected = self.heap.header.computeChecksum();
            if (self.heap.header.checksum != heap_header_expected) {
                const can_repair = self.heap.header.canRepair() catch false;
                if (can_repair) {
                    self.heap.header.checksum = 0;
                    self.heap.header.updateChecksum();
                    try self.heap.flushRangeAt(0, @sizeOf(header.HeapHeader));
                    result += 1;
                } else {
                    self.stats.errors += 1;
                    return error.HeapCorruption;
                }
            }
        } else {
            self.heap.header.validate() catch {
                result = false;
            };
        }

        const base_addr = self.heap.getBaseAddress();
        const alloc_metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        if (repair) {
            const meta_expected = alloc_metadata.computeChecksum();
            if (alloc_metadata.checksum != meta_expected) {
                const can_repair = alloc_metadata.canRepair() catch false;
                if (can_repair) {
                    alloc_metadata.checksum = 0;
                    alloc_metadata.updateChecksum();
                    try self.heap.flushRangeAt(header.HEADER_SIZE, @sizeOf(allocator_mod.AllocatorMetadata));
                    result += 1;
                } else {
                    self.stats.errors += 1;
                    return error.HeapCorruption;
                }
            }
        } else {
            alloc_metadata.validate() catch {
                result = false;
            };
        }

        var offset: u64 = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata);
        const heap_size = self.heap.getSize();
        while (offset + @sizeOf(header.ObjectHeader) <= heap_size) {
            const obj_header: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));
            if (!obj_header.hasValidMagic()) {
                if (!repair) result = false;
                offset = nextScanOffset(offset);
                continue;
            }
            const expected = obj_header.computeChecksum();
            if (obj_header.checksum != expected) {
                if (repair) {
                    obj_header.checksum = 0;
                    obj_header.updateChecksum();
                    try self.heap.flushRangeAt(offset, @sizeOf(header.ObjectHeader));
                    result += 1;
                } else {
                    result = false;
                    offset = nextScanOffset(offset);
                    continue;
                }
            }
            const advance_result = @addWithOverflow(@as(u64, @sizeOf(header.ObjectHeader)), obj_header.size);
            if (advance_result[1] != 0) {
                if (!repair) result = false;
                offset = nextScanOffset(offset);
                continue;
            }
            const advance = advance_result[0];
            if (advance == 0 or offset + advance > heap_size) {
                if (!repair) result = false;
                offset = nextScanOffset(offset);
                continue;
            }
            offset += advance;
        }

        return result;
    }

    pub fn verifyHeapConsistency(self: *Self) !bool {
        return self.scanHeap(false);
    }

    pub fn repairHeap(self: *Self) !usize {
        return self.scanHeap(true);
    }
};

pub const CrashSimulator = struct {
    allocator: std.mem.Allocator,
    crash_points: std.ArrayList(usize),
    current_step: usize,
    triggered: bool,
    overflow_seen: bool,

    pub fn init(allocator_param: std.mem.Allocator) CrashSimulator {
        return CrashSimulator{
            .allocator = allocator_param,
            .crash_points = std.ArrayList(usize).init(allocator_param),
            .current_step = 0,
            .triggered = false,
            .overflow_seen = false,
        };
    }

    pub fn deinit(self: *CrashSimulator) void {
        self.crash_points.deinit();
    }

    pub fn addCrashPoint(self: *CrashSimulator, point: usize) !void {
        const lo = binarySearchInsertPos(self.crash_points.items, point) orelse return;
        try self.crash_points.insert(lo, point);
    }

    fn binarySearchInsertPos(items: []const usize, target: usize) ?usize {
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const v = items[mid];
            if (v == target) {
                return null;
            } else if (v < target) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    fn binarySearch(items: []const usize, target: usize) bool {
        return binarySearchInsertPos(items, target) == null;
    }

    pub fn shouldCrash(self: *CrashSimulator) bool {
        const add_result = @addWithOverflow(self.current_step, @as(usize, 1));
        if (add_result[1] != 0) {
            self.overflow_seen = true;
            return false;
        }
        self.current_step = add_result[0];
        if (binarySearch(self.crash_points.items, self.current_step)) {
            self.triggered = true;
            return true;
        }
        return false;
    }

    pub fn wasTriggered(self: *const CrashSimulator) bool {
        return self.triggered;
    }

    pub fn hadOverflow(self: *const CrashSimulator) bool {
        return self.overflow_seen;
    }

    fn resetState(self: *CrashSimulator) void {
        self.current_step = 0;
        self.triggered = false;
        self.overflow_seen = false;
    }

    pub fn reset(self: *CrashSimulator) void {
        self.resetState();
    }

    pub fn clear(self: *CrashSimulator) void {
        self.crash_points.clearRetainingCapacity();
        self.resetState();
    }
};

fn assertNoLeak(status: std.heap.Check) void {
    if (status != .ok) {
        std.debug.panic("memory leak detected: {s}", .{@tagName(status)});
    }
}

test "recovery engine initialization" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer assertNoLeak(gpa.deinit());
    const alloc = gpa.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &path_buf);

    const test_heap_path = try std.fs.path.join(alloc, &.{ tmp_path, "heap.dat" });
    defer alloc.free(test_heap_path);
    const test_wal_path = try std.fs.path.join(alloc, &.{ tmp_path, "wal.log" });
    defer alloc.free(test_wal_path);

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var wal = try wal_mod.WAL.init(alloc, test_wal_path, null);
    defer wal.deinit();

    var recovery = RecoveryEngine.init(heap, wal, alloc);
    defer recovery.deinit();

    try recovery.recover();
    try testing.expect(recovery.phase == .complete);
    try testing.expectEqual(@as(u64, 0), recovery.stats.errors);
    try testing.expectEqual(@as(u64, 0), recovery.stats.transactions_analyzed);
    try testing.expectEqual(@as(u64, 0), recovery.stats.transactions_committed);
    try testing.expectEqual(@as(u64, 0), recovery.stats.transactions_rolled_back);
    try testing.expectEqual(@as(u64, 0), recovery.stats.records_redone);
    try testing.expectEqual(@as(u64, 0), recovery.stats.records_undone);

    try testing.expectError(error.AlreadyRecovered, recovery.recover());
}

test "crash simulator semantics" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer assertNoLeak(gpa.deinit());
    const alloc = gpa.allocator();

    var sim = CrashSimulator.init(alloc);
    defer sim.deinit();

    try sim.addCrashPoint(2);
    try sim.addCrashPoint(2);
    try sim.addCrashPoint(5);
    try testing.expectEqual(@as(usize, 2), sim.crash_points.items.len);
    try testing.expectEqual(@as(usize, 2), sim.crash_points.items[0]);
    try testing.expectEqual(@as(usize, 5), sim.crash_points.items[1]);

    try testing.expect(!sim.shouldCrash());
    try testing.expect(sim.shouldCrash());
    try testing.expect(!sim.shouldCrash());
    try testing.expect(!sim.shouldCrash());
    try testing.expect(sim.shouldCrash());
    try testing.expect(sim.wasTriggered());

    sim.reset();
    try testing.expect(!sim.wasTriggered());
    try testing.expectEqual(@as(usize, 0), sim.current_step);
    try testing.expect(!sim.hadOverflow());
}

test "crash simulator binary search" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer assertNoLeak(gpa.deinit());
    const alloc = gpa.allocator();

    var sim = CrashSimulator.init(alloc);
    defer sim.deinit();

    try sim.addCrashPoint(10);
    try sim.addCrashPoint(3);
    try sim.addCrashPoint(7);
    try sim.addCrashPoint(1);
    try sim.addCrashPoint(5);

    try testing.expectEqual(@as(usize, 5), sim.crash_points.items.len);
    try testing.expectEqual(@as(usize, 1), sim.crash_points.items[0]);
    try testing.expectEqual(@as(usize, 3), sim.crash_points.items[1]);
    try testing.expectEqual(@as(usize, 5), sim.crash_points.items[2]);
    try testing.expectEqual(@as(usize, 7), sim.crash_points.items[3]);
    try testing.expectEqual(@as(usize, 10), sim.crash_points.items[4]);
}

test "recovery stats duration safety" {
    const testing = std.testing;
    const stats = RecoveryStats{
        .transactions_analyzed = 0,
        .transactions_committed = 0,
        .transactions_rolled_back = 0,
        .records_redone = 0,
        .records_undone = 0,
        .errors = 0,
        .start_time_ns = 1000,
        .end_time_ns = 0,
    };
    try testing.expectEqual(@as(i128, 0), stats.durationNs());
    try testing.expectEqual(@as(i128, 0), stats.durationMs());

    const stats2 = RecoveryStats{
        .transactions_analyzed = 0,
        .transactions_committed = 0,
        .transactions_rolled_back = 0,
        .records_redone = 0,
        .records_undone = 0,
        .errors = 0,
        .start_time_ns = 1000,
        .end_time_ns = 5_000_000_000,
    };
    try testing.expectEqual(@as(i128, 4_999_999_000), stats2.durationNs());
    try testing.expectEqual(@as(i128, 4999), stats2.durationMs());
}
