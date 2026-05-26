const std = @import("std");
const tsc = @import("tsc.zig");

pub const REPLAY_MAGIC: u64 = 0x52455041595F4C47;
pub const REPLAY_VERSION: u32 = 1;

pub const EventType = enum(u8) {
    alloc = 1,
    free = 2,
    read = 3,
    write = 4,
    tx_begin = 5,
    tx_commit = 6,
    tx_rollback = 7,
    checkpoint = 8,
    gc_cycle = 9,
    wal_append = 10,
    wal_sync = 11,
    ref_inc = 12,
    ref_dec = 13,
    schema_create = 14,
    schema_drop = 15,
    barrier = 255,
};

pub const ReplayEvent = extern struct {
    magic: u32,
    event_type: u8,
    thread_id: u16 align(1),
    flags: u8,
    timestamp_ns: u64 align(1),
    tsc_value: u64 align(1),
    sequence: u64 align(1),
    arg0: u64 align(1),
    arg1: u64 align(1),
    arg2: u64 align(1),
    arg3: u64 align(1),
    checksum: u32 align(1),
    _pad: [4]u8,

    pub const MAGIC: u32 = 0x52455650;

    pub fn init(etype: EventType, thread_id: u16) ReplayEvent {
        var ev = std.mem.zeroes(ReplayEvent);
        ev.magic = MAGIC;
        ev.event_type = @intFromEnum(etype);
        ev.thread_id = thread_id;
        const now = std.time.nanoTimestamp();
        ev.timestamp_ns = if (now < 0) 0 else @intCast(now);
        ev.tsc_value = tsc.rdtsc();
        return ev;
    }

    pub fn computeChecksum(self: *const ReplayEvent) u32 {
        const bytes = std.mem.asBytes(self);
        const checksum_offset = @offsetOf(ReplayEvent, "checksum");
        var hash: u32 = 0x811c9dc5;
        for (bytes[0..checksum_offset]) |b| {
            hash ^= @as(u32, b);
            hash *%= 0x01000193;
        }
        for (bytes[checksum_offset + 4 ..]) |b| {
            hash ^= @as(u32, b);
            hash *%= 0x01000193;
        }
        return hash;
    }

    pub fn setChecksum(self: *ReplayEvent) void {
        self.checksum = self.computeChecksum();
    }

    pub fn validateChecksum(self: *const ReplayEvent) bool {
        return self.checksum == self.computeChecksum();
    }
};

comptime {
    std.debug.assert(@sizeOf(ReplayEvent) % 8 == 0);
}

pub const ReplayFileHeader = extern struct {
    magic: u64,
    version: u32,
    flags: u32,
    created_ns: u64,
    event_count: u64,
    checksum: u32,
    _pad: [4]u8,

    pub fn init() ReplayFileHeader {
        var h = std.mem.zeroes(ReplayFileHeader);
        h.magic = REPLAY_MAGIC;
        h.version = REPLAY_VERSION;
        const now = std.time.nanoTimestamp();
        h.created_ns = if (now < 0) 0 else @intCast(now);
        return h;
    }
};

pub const TraceWriter = struct {
    file: std.fs.File,
    mutex: std.Thread.Mutex,
    sequence: std.atomic.Value(u64),
    buf: std.ArrayList(u8),
    flush_threshold: usize,
    event_count: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8, flush_threshold: usize) !TraceWriter {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        errdefer file.close();

        var self = TraceWriter{
            .file = file,
            .mutex = .{},
            .sequence = std.atomic.Value(u64).init(0),
            .buf = std.ArrayList(u8).init(allocator),
            .flush_threshold = flush_threshold,
            .event_count = 0,
        };
        errdefer self.buf.deinit();

        var header = ReplayFileHeader.init();
        try self.buf.appendSlice(std.mem.asBytes(&header));

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.flushLocked() catch {};
        self.updateHeaderEventCount() catch {};
        self.file.close();
        self.buf.deinit();
    }

    pub fn record(self: *Self, comptime etype: EventType, thread_id: u16, arg0: u64, arg1: u64, arg2: u64, arg3: u64) !void {
        var ev = ReplayEvent.init(etype, thread_id);
        ev.sequence = self.sequence.fetchAdd(1, .acq_rel);
        ev.arg0 = arg0;
        ev.arg1 = arg1;
        ev.arg2 = arg2;
        ev.arg3 = arg3;
        ev.setChecksum();

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.buf.appendSlice(std.mem.asBytes(&ev));
        self.event_count += 1;
        if (self.buf.items.len >= self.flush_threshold) {
            try self.flushLocked();
        }
    }

    pub fn recordAlloc(self: *Self, thread_id: u16, offset: u64, size: u64) !void {
        try self.record(.alloc, thread_id, offset, size, 0, 0);
    }

    pub fn recordFree(self: *Self, thread_id: u16, offset: u64, size: u64) !void {
        try self.record(.free, thread_id, offset, size, 0, 0);
    }

    pub fn recordWrite(self: *Self, thread_id: u16, offset: u64, size: u64, checksum: u64) !void {
        try self.record(.write, thread_id, offset, size, checksum, 0);
    }

    pub fn recordTxBegin(self: *Self, thread_id: u16, tx_id: u64) !void {
        try self.record(.tx_begin, thread_id, tx_id, 0, 0, 0);
    }

    pub fn recordTxCommit(self: *Self, thread_id: u16, tx_id: u64, lsn: u64) !void {
        try self.record(.tx_commit, thread_id, tx_id, lsn, 0, 0);
    }

    pub fn recordTxRollback(self: *Self, thread_id: u16, tx_id: u64) !void {
        try self.record(.tx_rollback, thread_id, tx_id, 0, 0, 0);
    }

    pub fn recordBarrier(self: *Self) !void {
        try self.record(.barrier, 0, 0, 0, 0, 0);
    }

    pub fn flush(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.flushLocked();
    }

    fn flushLocked(self: *Self) !void {
        if (self.buf.items.len == 0) return;
        try self.file.writeAll(self.buf.items);
        self.buf.clearRetainingCapacity();
    }

    fn updateHeaderEventCount(self: *Self) !void {
        try self.file.seekTo(@offsetOf(ReplayFileHeader, "event_count"));
        var count_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &count_bytes, self.event_count, .little);
        try self.file.writeAll(&count_bytes);
    }
};

pub const ReplayStats = struct {
    total_events: u64 = 0,
    alloc_events: u64 = 0,
    free_events: u64 = 0,
    write_events: u64 = 0,
    tx_begin_events: u64 = 0,
    tx_commit_events: u64 = 0,
    tx_rollback_events: u64 = 0,
    checksum_failures: u64 = 0,
    replay_duration_ns: u64 = 0,
};

pub const ReplayReader = struct {
    file: std.fs.File,
    header: ReplayFileHeader,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn open(allocator: std.mem.Allocator, path: []const u8) !ReplayReader {
        const file = try std.fs.cwd().openFile(path, .{});
        errdefer file.close();

        var header: ReplayFileHeader = undefined;
        const n = try file.readAll(std.mem.asBytes(&header));
        if (n < @sizeOf(ReplayFileHeader)) return error.InvalidTraceFile;
        if (header.magic != REPLAY_MAGIC) return error.InvalidTraceMagic;
        if (header.version != REPLAY_VERSION) return error.UnsupportedTraceVersion;

        return Self{
            .file = file,
            .header = header,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.file.close();
    }

    pub fn nextEvent(self: *Self) !?ReplayEvent {
        var ev: ReplayEvent = undefined;
        const n = try self.file.readAll(std.mem.asBytes(&ev));
        if (n == 0) return null;
        if (n < @sizeOf(ReplayEvent)) return error.TruncatedEvent;
        if (ev.magic != ReplayEvent.MAGIC) return error.InvalidEventMagic;
        return ev;
    }

    pub fn validate(self: *Self, stats: *ReplayStats) !void {
        try self.file.seekTo(@sizeOf(ReplayFileHeader));
        stats.* = .{};
        const start_ns = std.time.nanoTimestamp();

        while (try self.nextEvent()) |ev| {
            stats.total_events += 1;
            if (!ev.validateChecksum()) {
                stats.checksum_failures += 1;
                continue;
            }
            const etype: EventType = @enumFromInt(ev.event_type);
            switch (etype) {
                .alloc => stats.alloc_events += 1,
                .free => stats.free_events += 1,
                .write => stats.write_events += 1,
                .tx_begin => stats.tx_begin_events += 1,
                .tx_commit => stats.tx_commit_events += 1,
                .tx_rollback => stats.tx_rollback_events += 1,
                else => {},
            }
        }

        const end_ns = std.time.nanoTimestamp();
        const diff = end_ns - start_ns;
        stats.replay_duration_ns = if (diff < 0) 0 else @intCast(diff);
    }

    pub fn loadAll(self: *Self) ![]ReplayEvent {
        try self.file.seekTo(@sizeOf(ReplayFileHeader));
        var events = std.ArrayList(ReplayEvent).init(self.allocator);
        errdefer events.deinit();

        while (try self.nextEvent()) |ev| {
            try events.append(ev);
        }

        return events.toOwnedSlice();
    }
};

pub const DeterministicReplayer = struct {
    allocator: std.mem.Allocator,
    events: []ReplayEvent,
    pos: usize,
    virtual_time_ns: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, events: []ReplayEvent) Self {
        return .{
            .allocator = allocator,
            .events = events,
            .pos = 0,
            .virtual_time_ns = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.events);
    }

    pub fn step(self: *Self) ?*const ReplayEvent {
        if (self.pos >= self.events.len) return null;
        const ev = &self.events[self.pos];
        self.virtual_time_ns = ev.timestamp_ns;
        self.pos += 1;
        return ev;
    }

    pub fn stepUntil(self: *Self, event_type: EventType) ?*const ReplayEvent {
        while (self.pos < self.events.len) {
            const ev = &self.events[self.pos];
            self.pos += 1;
            if (@as(EventType, @enumFromInt(ev.event_type)) == event_type) return ev;
        }
        return null;
    }

    pub fn reset(self: *Self) void {
        self.pos = 0;
        self.virtual_time_ns = 0;
    }

    pub fn remaining(self: *const Self) usize {
        if (self.pos >= self.events.len) return 0;
        return self.events.len - self.pos;
    }

    pub fn progress(self: *const Self) f64 {
        if (self.events.len == 0) return 1.0;
        return @as(f64, @floatFromInt(self.pos)) / @as(f64, @floatFromInt(self.events.len));
    }
};

test "replay event checksum" {
    const testing = std.testing;
    var ev = ReplayEvent.init(.write, 1);
    ev.arg0 = 0x1000;
    ev.arg1 = 64;
    ev.setChecksum();
    try testing.expect(ev.validateChecksum());
    ev.arg0 ^= 1;
    try testing.expect(!ev.validateChecksum());
}

test "replay event size aligned" {
    try std.testing.expect(@sizeOf(ReplayEvent) % 8 == 0);
}

test "trace writer and reader" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const path = "/tmp/test_replay.bin";
    defer std.fs.cwd().deleteFile(path) catch {};

    {
        var writer = try TraceWriter.init(alloc, path, 64 * 1024);
        defer writer.deinit();
        try writer.recordAlloc(0, 0x1000, 128);
        try writer.recordWrite(0, 0x1000, 64, 0xDEAD);
        try writer.recordTxBegin(0, 1);
        try writer.recordTxCommit(0, 1, 100);
        try writer.flush();
    }

    {
        var reader = try ReplayReader.open(alloc, path);
        defer reader.deinit();
        var stats = ReplayStats{};
        try reader.validate(&stats);
        try testing.expectEqual(@as(u64, 4), stats.total_events);
        try testing.expectEqual(@as(u64, 0), stats.checksum_failures);
        try testing.expectEqual(@as(u64, 1), stats.alloc_events);
        try testing.expectEqual(@as(u64, 1), stats.write_events);
        try testing.expectEqual(@as(u64, 1), stats.tx_begin_events);
        try testing.expectEqual(@as(u64, 1), stats.tx_commit_events);
    }
}
