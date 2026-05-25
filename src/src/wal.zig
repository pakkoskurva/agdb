const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const header = @import("header.zig");
const pointer = @import("pointer.zig");
const security = @import("security.zig");
const mem_utils = @import("mem_utils.zig");
const iouring = @import("iouring.zig");

pub const WAL_MAGIC: u32 = 0x57414C46;
pub const WAL_VERSION: u32 = 1;
pub const WAL_BLOCK_SIZE: u64 = 4096;
pub const MAX_RECORDS_PER_TRANSACTION: usize = 1024;

const INITIAL_WAL_SIZE: u64 = 1024 * 1024 * 64;
const RECORD_FLAG_HAS_UNDO: u8 = 1;
const RECORD_FLAG_UNDO_COMPRESSED: u8 = 2;
const ASYNC_QUEUE_CAPACITY: usize = 256;

pub const RecordType = enum(u8) {
    begin = 1,
    commit = 2,
    rollback = 3,
    allocate = 4,
    free = 5,
    write = 6,
    free_list_add = 7,
    free_list_remove = 8,
    heap_extend = 9,
    root_update = 10,
    ref_count_inc = 11,
    ref_count_dec = 12,
    gc_mark = 13,
    gc_sweep = 14,
    checkpoint = 15,
};

pub const WALHeader = extern struct {
    magic: u32,
    version: u32,
    file_size: u64,
    last_checkpoint: u64,
    transaction_counter: u64,
    head_offset: u64,
    tail_offset: u64,
    checksum: u32,
    reserved: [28]u8,

    pub fn init(file_size: u64) WALHeader {
        return WALHeader{
            .magic = WAL_MAGIC,
            .version = WAL_VERSION,
            .file_size = file_size,
            .last_checkpoint = 0,
            .transaction_counter = 0,
            .head_offset = headerSize(),
            .tail_offset = headerSize(),
            .checksum = 0,
            .reserved = [_]u8{0} ** 28,
        };
    }

    pub fn validate(self: *const WALHeader, actual_file_size: u64) !void {
        if (self.magic != WAL_MAGIC) return error.InvalidWALMagic;
        if (self.version != WAL_VERSION) return error.UnsupportedWALVersion;
        if (self.file_size != actual_file_size) return error.InvalidWALFileSize;
        if (self.file_size < headerSize()) return error.InvalidWALFileSize;
        if (self.head_offset < headerSize()) return error.InvalidWALHeadOffset;
        if (self.tail_offset < headerSize()) return error.InvalidWALTailOffset;
        if (self.head_offset > self.tail_offset) return error.InvalidWALHeadOffset;
        if (self.tail_offset > self.file_size) return error.InvalidWALTailOffset;
        if (self.last_checkpoint > self.tail_offset) return error.InvalidWALCheckpoint;
        if ((self.head_offset - headerSize()) % recordAlignment() != 0) return error.InvalidWALHeadOffset;
        if (self.computeChecksum() != self.checksum) return error.HeaderChecksumMismatch;
    }

    pub fn computeChecksum(self: *const WALHeader) u32 {
        const bytes = std.mem.asBytes(self);
        const checksum_offset = @offsetOf(WALHeader, "checksum");
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..checksum_offset]) |byte| {
            crc = crc32cByte(crc, byte);
        }
        for (bytes[checksum_offset + @sizeOf(u32) ..]) |byte| {
            crc = crc32cByte(crc, byte);
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *WALHeader) void {
        self.checksum = 0;
        self.checksum = self.computeChecksum();
    }
};

pub const WALRecord = extern struct {
    record_type: u8,
    flags: u8,
    padding: [6]u8,
    transaction_id: u64,
    sequence: u64,
    offset: u64,
    size: u64,
    old_value_offset: u64,
    old_value_size: u64,
    data_checksum: u32,
    record_checksum: u32,

    pub fn init(
        record_type: RecordType,
        tx_id: u64,
        seq: u64,
        offset: u64,
        size: u64,
    ) WALRecord {
        return WALRecord{
            .record_type = @intFromEnum(record_type),
            .flags = 0,
            .padding = [_]u8{0} ** 6,
            .transaction_id = tx_id,
            .sequence = seq,
            .offset = offset,
            .size = size,
            .old_value_offset = 0,
            .old_value_size = 0,
            .data_checksum = 0,
            .record_checksum = 0,
        };
    }

    pub fn getType(self: *const WALRecord) !RecordType {
        return std.meta.intToEnum(RecordType, self.record_type) catch error.InvalidRecordType;
    }

    pub fn hasUndoData(self: *const WALRecord) bool {
        return (self.flags & RECORD_FLAG_HAS_UNDO) != 0;
    }

    pub fn isUndoCompressed(self: *const WALRecord) bool {
        return (self.flags & RECORD_FLAG_UNDO_COMPRESSED) != 0;
    }

    pub fn setUndoData(self: *WALRecord, old_value_offset: u64, data: []const u8) void {
        self.flags |= RECORD_FLAG_HAS_UNDO;
        self.old_value_offset = old_value_offset;
        self.old_value_size = @as(u64, @intCast(data.len));
        self.data_checksum = computeDataChecksum(data);
    }

    pub fn clearUndoData(self: *WALRecord) void {
        self.flags &= ~@as(u8, RECORD_FLAG_HAS_UNDO | RECORD_FLAG_UNDO_COMPRESSED);
        self.old_value_offset = 0;
        self.old_value_size = 0;
        self.data_checksum = 0;
    }

    pub fn computeChecksum(self: *const WALRecord) u32 {
        const bytes = std.mem.asBytes(self);
        const checksum_offset = @offsetOf(WALRecord, "record_checksum");
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..checksum_offset]) |byte| {
            crc = crc32cByte(crc, byte);
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *WALRecord) void {
        self.record_checksum = 0;
        self.record_checksum = self.computeChecksum();
    }

    pub fn validate(self: *const WALRecord) !void {
        _ = try self.getType();
        const known_flags: u8 = RECORD_FLAG_HAS_UNDO | RECORD_FLAG_UNDO_COMPRESSED;
        if ((self.flags & ~known_flags) != 0) return error.InvalidRecordFlags;
        if (!std.mem.eql(u8, self.padding[0..], &[_]u8{ 0, 0, 0, 0, 0, 0 })) return error.InvalidRecordPadding;
        if (!self.hasUndoData()) {
            if (self.old_value_offset != 0) return error.InvalidUndoOffset;
            if (self.old_value_size != 0) return error.InvalidUndoSize;
            if (self.data_checksum != 0) return error.DataChecksumMismatch;
        }
        if (self.computeChecksum() != self.record_checksum) return error.RecordChecksumMismatch;
    }

    pub fn validateWithoutChecksumForPending(self: *const WALRecord) !void {
        _ = try self.getType();
        const known_flags: u8 = RECORD_FLAG_HAS_UNDO | RECORD_FLAG_UNDO_COMPRESSED;
        if ((self.flags & ~known_flags) != 0) return error.InvalidRecordFlags;
        if (!std.mem.eql(u8, self.padding[0..], &[_]u8{ 0, 0, 0, 0, 0, 0 })) return error.InvalidRecordPadding;
    }
};

pub const Transaction = struct {
    id: u64,
    state: State,
    records: std.ArrayList(WALRecord),
    undo_data: std.ArrayList([]u8),
    start_offset: u64,
    allocator: std.mem.Allocator,
    deinitialized: bool,

    pub const State = enum(u8) {
        active,
        committed,
        rolled_back,
        prepared,
    };

    pub fn init(allocator_ptr: std.mem.Allocator, id: u64) Transaction {
        return Transaction{
            .id = id,
            .state = .active,
            .records = std.ArrayList(WALRecord).init(allocator_ptr),
            .undo_data = std.ArrayList([]u8).init(allocator_ptr),
            .start_offset = 0,
            .allocator = allocator_ptr,
            .deinitialized = false,
        };
    }

    pub fn deinit(self: *Transaction) void {
        if (self.deinitialized) return;
        for (self.undo_data.items) |data| {
            self.allocator.free(data);
        }
        self.undo_data.deinit();
        self.records.deinit();
        self.deinitialized = true;
    }

    pub fn addRecord(self: *Transaction, record: WALRecord) !void {
        if (self.deinitialized) return error.TransactionDeinitialized;
        if (self.records.items.len >= MAX_RECORDS_PER_TRANSACTION) return error.TooManyRecords;
        try self.records.append(record);
    }

    pub fn addUndoData(self: *Transaction, data: []const u8) !void {
        if (self.deinitialized) return error.TransactionDeinitialized;
        const copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(copy);
        try self.undo_data.append(copy);
    }

    pub fn addRecordWithUndoData(self: *Transaction, record: WALRecord, data: []const u8) !void {
        if (self.deinitialized) return error.TransactionDeinitialized;
        if (self.records.items.len >= MAX_RECORDS_PER_TRANSACTION) return error.TooManyRecords;
        const copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(copy);
        try self.undo_data.append(copy);
        errdefer {
            const idx = self.undo_data.items.len - 1;
            self.allocator.free(self.undo_data.items[idx]);
            _ = self.undo_data.pop();
        }
        try self.records.append(record);
    }

    pub fn getRecordCount(self: *const Transaction) usize {
        if (self.deinitialized) return 0;
        return self.records.items.len;
    }
};

pub const AsyncEntry = struct {
    wal_tx: Transaction,
    completed: std.atomic.Value(bool),
    result: anyerror!void,

    pub fn init(allocator: std.mem.Allocator, id: u64) AsyncEntry {
        return .{
            .wal_tx = Transaction.init(allocator, id),
            .completed = std.atomic.Value(bool).init(false),
            .result = {},
        };
    }

    pub fn deinit(self: *AsyncEntry, allocator: std.mem.Allocator) void {
        self.wal_tx.deinit();
        allocator.destroy(self);
    }
};

pub const PipelineBatch = struct {
    entries: [PIPELINE_BATCH_MAX]*AsyncEntry,
    count: usize,

    pub fn init() PipelineBatch {
        return .{ .entries = undefined, .count = 0 };
    }
};

pub const PIPELINE_BATCH_MAX: usize = 64;
pub const FUZZY_CHECKPOINT_INTERVAL_BYTES: u64 = 64 * 1024 * 1024;

pub const WAL = struct {
    file: std.fs.File,
    file_path: []const u8,
    header: *WALHeader,
    mapping: []align(4096) u8,
    mapped_size: u64,
    security: ?*security.SecurityManager,
    allocator: std.mem.Allocator,
    lock: std.Thread.Mutex,
    sequence_counter: u64,
    async_queue: mem_utils.LockFreeQueue,
    writer_thread: ?std.Thread,
    shutdown_flag: std.atomic.Value(bool),
    fuzzy_checkpoint_watermark: std.atomic.Value(u64),
    fuzzy_checkpoint_active: std.atomic.Value(bool),
    bytes_since_checkpoint: std.atomic.Value(u64),
    pipeline_lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(
        allocator_ptr: std.mem.Allocator,
        file_path: []const u8,
        security_mgr: ?*security.SecurityManager,
    ) !*WAL {
        const self = try allocator_ptr.create(WAL);
        errdefer allocator_ptr.destroy(self);

        const path_copy = try allocator_ptr.dupe(u8, file_path);
        errdefer allocator_ptr.free(path_copy);

        const file = std.fs.cwd().openFile(file_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try std.fs.cwd().createFile(file_path, .{ .read = true, .truncate = false, .exclusive = false }),
            else => return err,
        };
        errdefer file.close();

        const stat = try file.stat();
        const file_size: u64 = if (stat.size == 0) INITIAL_WAL_SIZE else stat.size;
        if (file_size < headerSize()) return error.InvalidWALFileSize;

        if (stat.size == 0) {
            try file.setEndPos(file_size);
        }

        const map_len = try toUsize(file_size);
        const mapping = try posix.mmap(
            null,
            map_len,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            file.handle,
            0,
        );
        errdefer posix.munmap(mapping);

        const header_ptr: *WALHeader = @ptrCast(@alignCast(mapping.ptr));

        var async_queue = try mem_utils.LockFreeQueue.init(allocator_ptr, ASYNC_QUEUE_CAPACITY);
        errdefer async_queue.deinit();

        self.* = WAL{
            .file = file,
            .file_path = path_copy,
            .header = header_ptr,
            .mapping = mapping,
            .mapped_size = file_size,
            .security = security_mgr,
            .allocator = allocator_ptr,
            .lock = std.Thread.Mutex{},
            .sequence_counter = 0,
            .async_queue = async_queue,
            .writer_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
            .fuzzy_checkpoint_watermark = std.atomic.Value(u64).init(0),
            .fuzzy_checkpoint_active = std.atomic.Value(bool).init(false),
            .bytes_since_checkpoint = std.atomic.Value(u64).init(0),
            .pipeline_lock = std.Thread.Mutex{},
        };

        if (stat.size == 0) {
            self.header.* = WALHeader.init(file_size);
            try self.flushHeader();
        } else {
            try self.header.validate(file_size);
            self.sequence_counter = try self.recoverSequenceCounter();
        }

        self.writer_thread = try std.Thread.spawn(.{}, writerThreadFn, .{self});

        return self;
    }

    pub fn deinit(self: *WAL) void {
        self.shutdown_flag.store(true, .release);

        if (self.writer_thread) |thread| {
            thread.join();
            self.writer_thread = null;
        }

        self.flushAsyncQueue() catch {};
        self.async_queue.deinit();

        self.flush() catch {};
        posix.munmap(self.mapping);
        self.file.close();
        self.allocator.free(self.file_path);
        self.allocator.destroy(self);
    }

    fn writerThreadFn(self: *WAL) void {
        while (!self.shutdown_flag.load(.acquire)) {
            self.drainAsyncQueueOnce() catch {};
            std.time.sleep(1 * std.time.ns_per_ms);
        }
        self.drainAsyncQueueOnce() catch {};
    }

    fn drainAsyncQueueOnce(self: *WAL) !void {
        while (self.async_queue.dequeue()) |raw| {
            const entry: *AsyncEntry = @ptrCast(@alignCast(raw));
            self.lock.lock();
            const write_result = self.writeTransactionRecordsLocked(&entry.wal_tx);
            if (write_result) |_| {
                entry.wal_tx.state = .committed;
                self.sync() catch {};
            } else |err| {
                entry.result = err;
            }
            self.lock.unlock();
            entry.completed.store(true, .release);
        }
    }

    pub fn flushAsyncQueue(self: *WAL) !void {
        try self.drainAsyncQueueOnce();
    }

    pub fn enqueueAsyncTransaction(self: *WAL, tx: *Transaction) !*AsyncEntry {
        if (tx.deinitialized) return error.TransactionDeinitialized;
        if (tx.state != .active) return error.TransactionNotActive;

        var commit_record = WALRecord.init(.commit, tx.id, self.getNextSequenceLocked(), 0, 0);
        commit_record.updateChecksum();
        try tx.addRecord(commit_record);

        const entry = try self.allocator.create(AsyncEntry);
        entry.wal_tx = tx.*;
        entry.completed = std.atomic.Value(bool).init(false);
        entry.result = {};

        tx.deinitialized = true;

        if (!self.async_queue.enqueue(@as(*anyopaque, @ptrCast(entry)))) {
            entry.wal_tx.deinitialized = false;
            tx.deinitialized = false;
            _ = tx.records.pop();
            self.allocator.destroy(entry);
            return error.AsyncQueueFull;
        }

        return entry;
    }

    pub fn waitAsync(self: *WAL, entry: *AsyncEntry) !void {
        while (!entry.completed.load(.acquire)) {
            std.atomic.spinLoopHint();
        }
        const r = entry.result;
        entry.wal_tx.deinit();
        self.allocator.destroy(entry);
        return r;
    }

    pub fn beginTransaction(self: *Self) !Transaction {
        self.lock.lock();
        defer self.lock.unlock();

        const next_id = try checkedAdd(self.header.transaction_counter, 1);
        var tx = Transaction.init(self.allocator, next_id);
        errdefer tx.deinit();

        tx.start_offset = self.header.tail_offset;
        var begin_record = WALRecord.init(.begin, tx.id, self.getNextSequenceLocked(), 0, 0);
        begin_record.updateChecksum();
        try tx.addRecord(begin_record);

        self.header.transaction_counter = next_id;
        try self.flushHeader();

        return tx;
    }

    pub fn endTransaction(self: *Self, tx: *Transaction) !void {
        if (!tx.deinitialized and tx.state == .active) {
            self.rollbackTransaction(tx) catch |err| {
                tx.deinit();
                return err;
            };
        }
        tx.deinit();
    }

    pub fn appendRecord(self: *Self, tx: *Transaction, record_type: RecordType, offset: u64, size: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.deinitialized) return error.TransactionDeinitialized;
        if (tx.state != .active) return error.TransactionNotActive;
        _ = try checkedAdd(offset, size);

        var record = WALRecord.init(record_type, tx.id, self.getNextSequenceLocked(), offset, size);
        record.updateChecksum();
        try tx.addRecord(record);
    }

    pub fn appendRecordWithData(self: *Self, tx: *Transaction, record_type: RecordType, offset: u64, size: u64, old_data: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.deinitialized) return error.TransactionDeinitialized;
        if (tx.state != .active) return error.TransactionNotActive;
        _ = try checkedAdd(offset, size);
        if (old_data.len == 0) return error.EmptyUndoData;
        if (old_data.len != size) return error.UndoSizeMismatch;

        var record = WALRecord.init(record_type, tx.id, self.getNextSequenceLocked(), offset, size);
        record.flags |= RECORD_FLAG_HAS_UNDO;

        const compressed = try mem_utils.compressMemory(old_data, self.allocator);
        defer self.allocator.free(compressed);

        const use_compression = compressed.len + 8 < old_data.len;

        if (use_compression) {
            var stored_buf = try self.allocator.alloc(u8, 8 + compressed.len);
            defer self.allocator.free(stored_buf);
            std.mem.writeInt(u64, stored_buf[0..8], @as(u64, @intCast(old_data.len)), .little);
            @memcpy(stored_buf[8..], compressed);
            record.flags |= RECORD_FLAG_UNDO_COMPRESSED;
            record.old_value_size = @as(u64, @intCast(stored_buf.len));
            record.data_checksum = computeDataChecksum(stored_buf);
            record.updateChecksum();
            try tx.addRecordWithUndoData(record, stored_buf);
        } else {
            record.old_value_size = @as(u64, @intCast(old_data.len));
            record.data_checksum = computeDataChecksum(old_data);
            record.updateChecksum();
            try tx.addRecordWithUndoData(record, old_data);
        }
    }

    pub fn commitTransaction(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.deinitialized) return error.TransactionDeinitialized;
        if (tx.state != .active and tx.state != .prepared) return error.TransactionNotActive;

        var commit_record = WALRecord.init(.commit, tx.id, self.getNextSequenceLocked(), 0, 0);
        commit_record.updateChecksum();
        try tx.addRecord(commit_record);
        errdefer _ = tx.records.pop();

        try self.writeTransactionRecordsLocked(tx);
        tx.state = .committed;
        try self.sync();
    }

    pub fn rollbackTransaction(self: *Self, tx: *Transaction) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (tx.deinitialized) return error.TransactionDeinitialized;
        if (tx.state == .committed) return error.TransactionAlreadyCommitted;
        if (tx.state == .rolled_back) return;

        var rollback_record = WALRecord.init(.rollback, tx.id, self.getNextSequenceLocked(), 0, 0);
        rollback_record.updateChecksum();
        try tx.addRecord(rollback_record);
        errdefer _ = tx.records.pop();

        try self.writeTransactionRecordsLocked(tx);
        tx.state = .rolled_back;
        try self.sync();
    }

    fn writeTransactionRecordsLocked(self: *Self, tx: *Transaction) !void {
        if (tx.records.items.len == 0) return error.EmptyTransaction;

        const start_offset = self.header.tail_offset;
        var total_size: u64 = 0;
        var undo_count: usize = 0;

        for (tx.records.items) |record| {
            try record.validateWithoutChecksumForPending();
            total_size = try checkedAdd(total_size, recordSize());
            if (record.hasUndoData()) {
                if (undo_count >= tx.undo_data.items.len) return error.UndoDataCountMismatch;
                total_size = try checkedAdd(total_size, @as(u64, @intCast(tx.undo_data.items[undo_count].len)));
                undo_count += 1;
            }
        }

        if (undo_count != tx.undo_data.items.len) return error.UndoDataCountMismatch;

        const buffer_len = try toUsize(total_size);
        var buffer = try self.allocator.alloc(u8, buffer_len);
        defer self.allocator.free(buffer);
        @memset(buffer, 0);

        var rel: usize = 0;
        var undo_index: usize = 0;

        for (tx.records.items, 0..) |*record_slot, idx| {
            var record = record_slot.*;
            const record_start = try checkedAdd(start_offset, @as(u64, @intCast(rel)));

            if (record.hasUndoData()) {
                const data = tx.undo_data.items[undo_index];
                const data_offset = try checkedAdd(record_start, recordSize());
                record.setUndoData(data_offset, data);
                if (record_slot.isUndoCompressed()) {
                    record.flags |= RECORD_FLAG_UNDO_COMPRESSED;
                }
                undo_index += 1;
            } else {
                record.clearUndoData();
            }

            try validateRecordSemantics(&record, idx == 0);
            record.updateChecksum();

            const rec_len = try toUsize(recordSize());
            @memcpy(buffer[rel .. rel + rec_len], std.mem.asBytes(&record));
            rel += rec_len;

            if (record.hasUndoData()) {
                const data = tx.undo_data.items[undo_index - 1];
                @memcpy(buffer[rel .. rel + data.len], data);
                rel += data.len;
            }

            record_slot.* = record;
        }

        if (rel != buffer.len) return error.InternalWALEncodingError;

        const end_offset = try checkedAdd(start_offset, total_size);
        try self.ensureMappedCapacity(end_offset);
        try self.writeAt(start_offset, buffer);

        self.header.tail_offset = end_offset;
        self.header.file_size = self.mapped_size;
        try self.flushHeader();
    }

    pub fn getRecords(self: *Self, start_offset: u64, max_records: usize) !std.ArrayList(WALRecord) {
        self.lock.lock();
        defer self.lock.unlock();

        if (start_offset < headerSize()) return error.InvalidStartOffset;
        if (start_offset > self.header.tail_offset) return error.InvalidStartOffset;

        var records = std.ArrayList(WALRecord).init(self.allocator);
        errdefer records.deinit();

        var offset = start_offset;
        var count: usize = 0;

        while (offset < self.header.tail_offset and count < max_records) {
            const parsed = try self.readRecordAtLocked(offset);
            try records.append(parsed.record);
            offset = parsed.next_offset;
            count += 1;
        }

        return records;
    }

    pub fn getTransactions(self: *Self) !std.ArrayList(Transaction) {
        self.lock.lock();
        defer self.lock.unlock();

        var transactions = std.ArrayList(Transaction).init(self.allocator);
        errdefer {
            for (transactions.items) |*tx| {
                tx.deinit();
            }
            transactions.deinit();
        }

        var offset = self.header.head_offset;
        var current_tx: ?Transaction = null;
        errdefer {
            if (current_tx) |*tx| {
                tx.deinit();
            }
        }

        while (offset < self.header.tail_offset) {
            const parsed = try self.readRecordAtLocked(offset);
            const record_type = try parsed.record.getType();

            switch (record_type) {
                .begin => {
                    if (current_tx != null) return error.NestedTransaction;
                    current_tx = Transaction.init(self.allocator, parsed.record.transaction_id);
                    current_tx.?.start_offset = offset;
                    try current_tx.?.addRecord(parsed.record);
                },
                .commit => {
                    if (current_tx) |*tx| {
                        if (tx.id != parsed.record.transaction_id) return error.TransactionIdMismatch;
                        try tx.addRecord(parsed.record);
                        tx.state = .committed;
                        try transactions.append(tx.*);
                        current_tx = null;
                    } else {
                        return error.CommitWithoutBegin;
                    }
                },
                .rollback => {
                    if (current_tx) |*tx| {
                        if (tx.id != parsed.record.transaction_id) return error.TransactionIdMismatch;
                        try tx.addRecord(parsed.record);
                        tx.state = .rolled_back;
                        try transactions.append(tx.*);
                        current_tx = null;
                    } else {
                        return error.RollbackWithoutBegin;
                    }
                },
                .checkpoint => {},
                else => {
                    if (current_tx) |*tx| {
                        if (tx.id != parsed.record.transaction_id) return error.TransactionIdMismatch;
                        try tx.addRecord(parsed.record);
                        if (parsed.record.hasUndoData()) {
                            const undo_data = try self.getUndoDataOwnedLocked(&parsed.record);
                            defer self.allocator.free(undo_data);
                            try tx.addUndoData(undo_data);
                        }
                    } else {
                        return error.RecordWithoutBegin;
                    }
                },
            }

            offset = parsed.next_offset;
        }

        if (current_tx) |*tx| {
            tx.state = .active;
            try transactions.append(tx.*);
            current_tx = null;
        }

        return transactions;
    }

    pub fn checkpoint(self: *Self) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const offset = self.header.tail_offset;
        const end_offset = try checkedAdd(offset, recordSize());
        try self.ensureMappedCapacity(end_offset);

        var record = WALRecord.init(.checkpoint, 0, self.getNextSequenceLocked(), offset, 0);
        record.updateChecksum();

        try self.writeAt(offset, std.mem.asBytes(&record));

        self.header.tail_offset = end_offset;
        self.header.head_offset = end_offset;
        self.header.last_checkpoint = offset;
        self.header.file_size = self.mapped_size;
        try self.flushHeader();
        try self.sync();
    }

    pub fn fuzzyCheckpointBegin(self: *Self) !u64 {
        if (self.fuzzy_checkpoint_active.load(.acquire)) return error.FuzzyCheckpointAlreadyActive;
        self.lock.lock();
        const watermark = self.header.tail_offset;
        self.lock.unlock();
        self.fuzzy_checkpoint_watermark.store(watermark, .release);
        self.fuzzy_checkpoint_active.store(true, .release);
        return watermark;
    }

    pub fn fuzzyCheckpointEnd(self: *Self) !void {
        if (!self.fuzzy_checkpoint_active.load(.acquire)) return error.NoActiveFuzzyCheckpoint;

        self.lock.lock();
        defer self.lock.unlock();

        const start_watermark = self.fuzzy_checkpoint_watermark.load(.acquire);
        const end_watermark = self.header.tail_offset;

        const record_offset = end_watermark;
        const end_offset = try checkedAdd(record_offset, recordSize());
        try self.ensureMappedCapacity(end_offset);

        var record = WALRecord.init(.checkpoint, 0, self.getNextSequenceLocked(), start_watermark, 0);
        record.updateChecksum();
        try self.writeAt(record_offset, std.mem.asBytes(&record));

        self.header.tail_offset = end_offset;
        self.header.last_checkpoint = record_offset;
        self.header.file_size = self.mapped_size;
        try self.flushHeader();
        try self.sync();

        self.bytes_since_checkpoint.store(0, .release);
        self.fuzzy_checkpoint_active.store(false, .release);
        self.fuzzy_checkpoint_watermark.store(0, .release);
    }

    pub fn checkpointIfNeeded(self: *Self) !bool {
        const bytes = self.bytes_since_checkpoint.load(.acquire);
        if (bytes < FUZZY_CHECKPOINT_INTERVAL_BYTES) return false;
        _ = try self.fuzzyCheckpointBegin();
        try self.fuzzyCheckpointEnd();
        return true;
    }

    pub fn getFuzzyCheckpointWatermark(self: *Self) ?u64 {
        if (!self.fuzzy_checkpoint_active.load(.acquire)) return null;
        return self.fuzzy_checkpoint_watermark.load(.acquire);
    }

    pub fn commitBatch(self: *Self, transactions: []*Transaction) !void {
        if (transactions.len == 0) return;
        if (transactions.len > PIPELINE_BATCH_MAX) return error.BatchTooLarge;

        var total_size: u64 = 0;
        for (transactions) |tx| {
            if (tx.deinitialized) return error.TransactionDeinitialized;
            if (tx.state != .active and tx.state != .prepared) return error.TransactionNotActive;
            var undo_seq: usize = 0;
            for (tx.records.items) |rec| {
                total_size = try checkedAdd(total_size, recordSize());
                if (rec.hasUndoData()) {
                    if (undo_seq < tx.undo_data.items.len) {
                        total_size = try checkedAdd(total_size, @as(u64, @intCast(tx.undo_data.items[undo_seq].len)));
                    }
                    undo_seq += 1;
                }
            }
            total_size = try checkedAdd(total_size, recordSize());
        }

        self.lock.lock();
        defer self.lock.unlock();

        const batch_start = self.header.tail_offset;
        const buffer_len = try toUsize(total_size);
        var buffer = try self.allocator.alloc(u8, buffer_len);
        defer self.allocator.free(buffer);
        @memset(buffer, 0);

        var write_off: usize = 0;
        var wal_off: u64 = batch_start;

        for (transactions) |tx| {
            var undo_idx: usize = 0;

            for (tx.records.items, 0..) |*record_slot, i| {
                var record = record_slot.*;
                const rec_start = wal_off;

                if (record.hasUndoData()) {
                    const data = tx.undo_data.items[undo_idx];
                    const data_off = try checkedAdd(rec_start, recordSize());
                    record.setUndoData(data_off, data);
                    if (record_slot.isUndoCompressed()) record.flags |= RECORD_FLAG_UNDO_COMPRESSED;
                    undo_idx += 1;
                } else {
                    record.clearUndoData();
                }

                try validateRecordSemantics(&record, i == 0);
                record.updateChecksum();

                const rec_bytes = std.mem.asBytes(&record);
                const rec_len = rec_bytes.len;
                @memcpy(buffer[write_off .. write_off + rec_len], rec_bytes);
                write_off += rec_len;
                wal_off = try checkedAdd(wal_off, recordSize());

                if (record.hasUndoData()) {
                    const data = tx.undo_data.items[undo_idx - 1];
                    @memcpy(buffer[write_off .. write_off + data.len], data);
                    write_off += data.len;
                    wal_off = try checkedAdd(wal_off, @as(u64, @intCast(data.len)));
                }

                record_slot.* = record;
            }

            var commit_rec = WALRecord.init(.commit, tx.id, self.getNextSequenceLocked(), 0, 0);
            commit_rec.updateChecksum();
            const commit_bytes = std.mem.asBytes(&commit_rec);
            @memcpy(buffer[write_off .. write_off + commit_bytes.len], commit_bytes);
            write_off += commit_bytes.len;
            wal_off = try checkedAdd(wal_off, recordSize());
            tx.state = .committed;
        }

        const end_offset = try checkedAdd(batch_start, @as(u64, @intCast(write_off)));
        try self.ensureMappedCapacity(end_offset);
        try self.writeAt(batch_start, buffer[0..write_off]);

        self.header.tail_offset = end_offset;
        self.header.file_size = self.mapped_size;
        try self.flushHeader();
        try self.sync();

        _ = self.bytes_since_checkpoint.fetchAdd(@as(u64, @intCast(write_off)), .acq_rel);
    }

    pub fn pipelinedCommit(self: *Self, tx: *Transaction) !void {
        self.pipeline_lock.lock();
        defer self.pipeline_lock.unlock();

        if (tx.deinitialized) return error.TransactionDeinitialized;
        if (tx.state != .active and tx.state != .prepared) return error.TransactionNotActive;

        var commit_record = WALRecord.init(.commit, tx.id, blk: {
            self.lock.lock();
            const seq = self.getNextSequenceLocked();
            self.lock.unlock();
            break :blk seq;
        }, 0, 0);
        commit_record.updateChecksum();
        try tx.addRecord(commit_record);
        errdefer _ = tx.records.pop();

        try self.ioUringWrite(tx);
        tx.state = .committed;
    }

    fn ioUringWrite(self: *Self, tx: *Transaction) !void {
        if (!comptime (builtin.os.tag == .linux)) {
            self.lock.lock();
            defer self.lock.unlock();
            try self.writeTransactionRecordsLocked(tx);
            try self.sync();
            return;
        }

        self.lock.lock();
        const start_off = self.header.tail_offset;
        var total: u64 = 0;
        var undo_cnt: usize = 0;
        for (tx.records.items) |rec| {
            total = try checkedAdd(total, recordSize());
            if (rec.hasUndoData()) {
                total = try checkedAdd(total, @as(u64, @intCast(tx.undo_data.items[undo_cnt].len)));
                undo_cnt += 1;
            }
        }
        const end_off = try checkedAdd(start_off, total);
        try self.ensureMappedCapacity(end_off);
        self.lock.unlock();

        const buf_len = try toUsize(total);
        var buf = try self.allocator.alloc(u8, buf_len);
        defer self.allocator.free(buf);
        @memset(buf, 0);

        var rel: usize = 0;
        var undo_idx: usize = 0;
        var wal_cur: u64 = start_off;

        for (tx.records.items, 0..) |*slot, idx| {
            var rec = slot.*;
            if (rec.hasUndoData()) {
                const data = tx.undo_data.items[undo_idx];
                const data_off = try checkedAdd(wal_cur, recordSize());
                rec.setUndoData(data_off, data);
                if (slot.isUndoCompressed()) rec.flags |= RECORD_FLAG_UNDO_COMPRESSED;
                undo_idx += 1;
            } else {
                rec.clearUndoData();
            }
            try validateRecordSemantics(&rec, idx == 0);
            rec.updateChecksum();
            const rb = std.mem.asBytes(&rec);
            @memcpy(buf[rel .. rel + rb.len], rb);
            rel += rb.len;
            wal_cur = try checkedAdd(wal_cur, recordSize());
            if (rec.hasUndoData()) {
                const data = tx.undo_data.items[undo_idx - 1];
                @memcpy(buf[rel .. rel + data.len], data);
                rel += data.len;
                wal_cur = try checkedAdd(wal_cur, @as(u64, @intCast(data.len)));
            }
            slot.* = rec;
        }

        var writer = try iouring.WALIOUringWriter.init(self.allocator, self.file.handle, 64);
        defer writer.deinit();

        writer.write_offset = start_off;
        _ = try writer.enqueueWrite(buf[0..rel], 1);
        try writer.enqueueFsync(true);
        _ = try writer.flush();

        self.lock.lock();
        self.header.tail_offset = end_off;
        self.header.file_size = self.mapped_size;
        try self.flushHeader();
        self.lock.unlock();

        _ = self.bytes_since_checkpoint.fetchAdd(@as(u64, @intCast(rel)), .acq_rel);
    }

    pub fn truncate(self: *Self, new_offset: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (new_offset < headerSize()) return error.InvalidTruncateOffset;
        if (new_offset > self.header.tail_offset) return error.InvalidTruncateOffset;

        var offset = headerSize();
        while (offset < new_offset) {
            const parsed = try self.readRecordAtLocked(offset);
            offset = parsed.next_offset;
        }
        if (offset != new_offset) return error.InvalidTruncateOffset;

        self.header.head_offset = new_offset;
        if (self.header.last_checkpoint < new_offset) {
            self.header.last_checkpoint = new_offset;
        }
        try self.flushHeader();
    }

    pub fn flush(self: *Self) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.flushHeaderLocked();
        try posix.msync(self.mapping, posix.MSF.SYNC);
    }

    fn flushHeader(self: *Self) !void {
        self.header.updateChecksum();
        try posix.msync(self.mapping[0..try toUsize(headerSize())], posix.MSF.SYNC);
    }

    fn flushHeaderLocked(self: *Self) !void {
        self.header.updateChecksum();
        try posix.msync(self.mapping[0..try toUsize(headerSize())], posix.MSF.SYNC);
    }

    pub fn sync(self: *Self) !void {
        try posix.msync(self.mapping, posix.MSF.SYNC);
        try posix.fsync(self.file.handle);
    }

    pub fn getSize(self: *Self) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.header.tail_offset;
    }

    pub fn getTransactionCount(self: *Self) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.header.transaction_counter;
    }

    pub fn getLastCheckpoint(self: *Self) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.header.last_checkpoint;
    }

    fn getNextSequenceLocked(self: *Self) u64 {
        self.sequence_counter += 1;
        return self.sequence_counter;
    }

    fn recoverSequenceCounter(self: *Self) !u64 {
        var max_sequence: u64 = 0;
        var offset = self.header.head_offset;

        while (offset < self.header.tail_offset) {
            const parsed = try self.readRecordAtLocked(offset);
            if (parsed.record.sequence > max_sequence) {
                max_sequence = parsed.record.sequence;
            }
            offset = parsed.next_offset;
        }

        return max_sequence;
    }

    fn ensureMappedCapacity(self: *Self, required_size: u64) !void {
        if (required_size <= self.mapped_size) return;

        var new_size = self.mapped_size;
        while (new_size < required_size) {
            if (new_size > std.math.maxInt(u64) / 2) return error.WALFileTooLarge;
            new_size *= 2;
        }

        try posix.msync(self.mapping, posix.MSF.SYNC);
        try self.file.setEndPos(new_size);

        const new_len = try toUsize(new_size);
        const new_mapping = try posix.mmap(
            null,
            new_len,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.file.handle,
            0,
        );
        errdefer posix.munmap(new_mapping);

        posix.munmap(self.mapping);

        self.mapping = new_mapping;
        self.mapped_size = new_size;
        self.header = @ptrCast(@alignCast(self.mapping.ptr));
        self.header.file_size = new_size;
        self.header.updateChecksum();
        try self.flushHeaderLocked();
    }

    fn writeAt(self: *Self, offset: u64, data: []const u8) !void {
        const start = try toUsize(offset);
        const end_u64 = try checkedAdd(offset, @as(u64, @intCast(data.len)));
        const end = try toUsize(end_u64);
        if (end_u64 > self.mapped_size) return error.WritePastMapping;
        @memcpy(self.mapping[start..end], data);
    }

    const ParsedRecord = struct {
        record: WALRecord,
        next_offset: u64,
    };

    fn readRecordAtLocked(self: *Self, offset: u64) !ParsedRecord {
        if (offset < headerSize()) return error.InvalidRecordOffset;
        const record_end = try checkedAdd(offset, recordSize());
        if (record_end > self.header.tail_offset) return error.TruncatedRecord;

        const start = try toUsize(offset);
        const end = try toUsize(record_end);
        var record: WALRecord = undefined;
        @memcpy(std.mem.asBytes(&record), self.mapping[start..end]);

        try record.validate();
        try validateRecordSemantics(&record, false);

        var next_offset = record_end;
        if (record.hasUndoData()) {
            if (record.old_value_offset != record_end) return error.InvalidUndoOffset;
            const undo_end = try checkedAdd(record.old_value_offset, record.old_value_size);
            if (undo_end > self.header.tail_offset) return error.InvalidUndoOffset;
            const undo_data = self.mapping[try toUsize(record.old_value_offset)..try toUsize(undo_end)];
            if (computeDataChecksum(undo_data) != record.data_checksum) return error.DataChecksumMismatch;
            next_offset = undo_end;
        }

        return ParsedRecord{
            .record = record,
            .next_offset = next_offset,
        };
    }

    pub fn getUndoData(self: *Self, record: *const WALRecord) ![]u8 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.getUndoDataOwnedLocked(record);
    }

    fn getUndoDataOwnedLocked(self: *Self, record: *const WALRecord) ![]u8 {
        if (!record.hasUndoData()) return &[_]u8{};
        if (record.old_value_size == 0) return error.InvalidUndoSize;
        if (record.old_value_offset < headerSize()) return error.InvalidUndoOffset;

        const data_start = record.old_value_offset;
        const data_end = try checkedAdd(data_start, record.old_value_size);

        if (data_end > self.header.tail_offset) return error.InvalidUndoOffset;
        if (data_end > self.mapped_size) return error.InvalidUndoOffset;

        const stored = self.mapping[try toUsize(data_start)..try toUsize(data_end)];
        if (computeDataChecksum(stored) != record.data_checksum) return error.DataChecksumMismatch;

        if (record.isUndoCompressed()) {
            if (stored.len < 8) return error.InvalidUndoSize;
            const uncompressed_size = std.mem.readInt(u64, stored[0..8], .little);
            _ = uncompressed_size;
            const compressed_payload = stored[8..];
            const decompressed = try mem_utils.decompressMemory(compressed_payload, self.allocator);
            return decompressed;
        }

        return try self.allocator.dupe(u8, stored);
    }

    pub fn getRedoData(self: *Self, record: *const WALRecord) ![]const u8 {
        _ = self;
        _ = record;
        return &[_]u8{};
    }

    pub fn getUndoRootOffset(self: *Self, record: *const WALRecord) !u64 {
        const undo_bytes = try self.getUndoData(record);
        defer if (undo_bytes.len > 0) self.allocator.free(undo_bytes);
        if (undo_bytes.len < 8) return error.InvalidUndoData;
        return std.mem.readInt(u64, undo_bytes[0..8], .little);
    }

    pub fn getTransactionLsn(self: *Self, tx: *const Transaction) !u64 {
        _ = self;
        if (tx.start_offset == 0) return error.InvalidTransactionOffset;
        return tx.start_offset;
    }
};

fn validateRecordSemantics(record: *const WALRecord, must_be_begin: bool) !void {
    const record_type = try record.getType();

    if (must_be_begin and record_type != .begin) return error.TransactionMustStartWithBegin;

    switch (record_type) {
        .begin, .commit, .rollback => {
            if (record.offset != 0) return error.InvalidRecordOffset;
            if (record.size != 0) return error.InvalidRecordSize;
            if (record.hasUndoData()) return error.InvalidUndoDataForRecordType;
        },
        .checkpoint => {
            if (record.transaction_id != 0) return error.InvalidTransactionId;
            if (record.size != 0) return error.InvalidRecordSize;
            if (record.hasUndoData()) return error.InvalidUndoDataForRecordType;
        },
        .write, .free, .root_update, .ref_count_dec, .free_list_remove, .heap_extend => {
            _ = try checkedAdd(record.offset, record.size);
        },
        .allocate, .free_list_add, .ref_count_inc, .gc_mark, .gc_sweep => {
            _ = try checkedAdd(record.offset, record.size);
        },
    }

    if (!record.hasUndoData()) {
        if (record.old_value_offset != 0) return error.InvalidUndoOffset;
        if (record.old_value_size != 0) return error.InvalidUndoSize;
        if (record.data_checksum != 0) return error.DataChecksumMismatch;
    } else {
        if (record.old_value_size == 0) return error.InvalidUndoSize;
        if (record.old_value_offset < headerSize()) return error.InvalidUndoOffset;
    }
}

fn computeDataChecksum(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        crc = crc32cByte(crc, byte);
    }
    return crc ^ 0xFFFFFFFF;
}

fn crc32cByte(crc: u32, byte: u8) u32 {
    const POLY: u32 = 0x82F63B78;
    var c = crc ^ @as(u32, byte);
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        c = if ((c & 1) != 0) (c >> 1) ^ POLY else c >> 1;
    }
    return c;
}

fn checkedAdd(a: u64, b: u64) !u64 {
    const result = @addWithOverflow(a, b);
    if (result[1] != 0) return error.IntegerOverflow;
    return result[0];
}

fn toUsize(value: u64) !usize {
    if (value > std.math.maxInt(usize)) return error.ValueTooLarge;
    return @as(usize, @intCast(value));
}

fn headerSize() u64 {
    return @as(u64, @intCast(@sizeOf(WALHeader)));
}

fn recordSize() u64 {
    return @as(u64, @intCast(@sizeOf(WALRecord)));
}

fn recordAlignment() u64 {
    return @as(u64, @intCast(@alignOf(WALRecord)));
}

test "wal initialization" {
    const testing = std.testing;
    _ = header;
    _ = pointer;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_wal.wal";
    std.fs.cwd().deleteFile(test_path) catch {};

    var wal = try WAL.init(alloc, test_path, null);
    defer wal.deinit();

    try testing.expect(wal.header.magic == WAL_MAGIC);
    try testing.expect(wal.header.version == WAL_VERSION);
    try testing.expect(wal.header.tail_offset == headerSize());

    std.fs.cwd().deleteFile(test_path) catch {};
}

test "transaction lifecycle" {
    const testing = std.testing;
    _ = header;
    _ = pointer;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_wal_tx.wal";
    std.fs.cwd().deleteFile(test_path) catch {};

    var wal = try WAL.init(alloc, test_path, null);
    defer wal.deinit();

    var tx = try wal.beginTransaction();
    defer wal.endTransaction(&tx) catch {};

    try wal.appendRecord(&tx, .write, 100, 64);
    try testing.expect(tx.getRecordCount() == 2);

    try wal.commitTransaction(&tx);
    try testing.expect(tx.state == .committed);

    const records = try wal.getRecords(headerSize(), 16);
    defer records.deinit();

    try testing.expect(records.items.len == 3);

    std.fs.cwd().deleteFile(test_path) catch {};
}

test "transaction with undo data" {
    const testing = std.testing;
    _ = header;
    _ = pointer;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_path = "/tmp/test_wal_undo.wal";
    std.fs.cwd().deleteFile(test_path) catch {};

    var wal = try WAL.init(alloc, test_path, null);
    defer wal.deinit();

    var tx = try wal.beginTransaction();
    defer wal.endTransaction(&tx) catch {};

    const old_data = "previous-value";
    try wal.appendRecordWithData(&tx, .write, 128, old_data.len, old_data);
    try wal.commitTransaction(&tx);

    const records = try wal.getRecords(headerSize(), 16);
    defer records.deinit();

    try testing.expect(records.items.len == 3);
    try testing.expect(records.items[1].hasUndoData());

    const undo = try wal.getUndoData(&records.items[1]);
    defer alloc.free(undo);
    try testing.expect(std.mem.eql(u8, undo, old_data));

    std.fs.cwd().deleteFile(test_path) catch {};
}
