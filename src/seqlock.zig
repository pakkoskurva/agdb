const std = @import("std");
const atomic = std.atomic;

pub const SeqLock = struct {
    sequence: atomic.Value(u64) align(64),
    _pad: [56]u8,

    pub fn init() SeqLock {
        return .{
            .sequence = atomic.Value(u64).init(0),
            ._pad = [_]u8{0} ** 56,
        };
    }

    pub fn beginRead(self: *const SeqLock) u64 {
        while (true) {
            const seq = self.sequence.load(.acquire);
            if (seq & 1 == 0) return seq;
            std.atomic.spinLoopHint();
        }
    }

    pub fn endRead(self: *const SeqLock, seq: u64) bool {
        const current = self.sequence.load(.acquire);
        return current == seq;
    }

    pub fn retryRead(self: *const SeqLock, seq: u64) ?u64 {
        const current = self.sequence.load(.acquire);
        if (current != seq) return null;
        return seq;
    }

    pub fn beginWrite(self: *SeqLock) void {
        const old = self.sequence.fetchAdd(1, .acq_rel);
        std.debug.assert(old & 1 == 0);
    }

    pub fn endWrite(self: *SeqLock) void {
        _ = self.sequence.fetchAdd(1, .release);
    }

    pub fn readLocked(self: *const SeqLock) u64 {
        return self.sequence.load(.acquire);
    }
};

pub fn SeqLockData(comptime T: type) type {
    return struct {
        lock: SeqLock align(64),
        data: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{
                .lock = SeqLock.init(),
                .data = value,
            };
        }

        pub fn read(self: *const Self) T {
            while (true) {
                const seq = self.lock.beginRead();
                const snapshot = self.data;
                asm volatile ("" ::: "memory");
                if (self.lock.endRead(seq)) return snapshot;
                std.atomic.spinLoopHint();
            }
        }

        pub fn write(self: *Self, value: T) void {
            self.lock.beginWrite();
            self.data = value;
            self.lock.endWrite();
        }

        pub fn modify(self: *Self, comptime F: fn (*T) void) void {
            self.lock.beginWrite();
            F(&self.data);
            self.lock.endWrite();
        }
    };
}

pub const SeqLockU64 = struct {
    lock: SeqLock align(64),
    value: u64,

    pub fn init(v: u64) SeqLockU64 {
        return .{
            .lock = SeqLock.init(),
            .value = v,
        };
    }

    pub fn load(self: *const SeqLockU64) u64 {
        while (true) {
            const seq = self.lock.beginRead();
            const v = @atomicLoad(u64, &self.value, .acquire);
            if (self.lock.endRead(seq)) return v;
            std.atomic.spinLoopHint();
        }
    }

    pub fn store(self: *SeqLockU64, v: u64) void {
        self.lock.beginWrite();
        @atomicStore(u64, &self.value, v, .release);
        self.lock.endWrite();
    }

    pub fn fetchAdd(self: *SeqLockU64, delta: u64) u64 {
        self.lock.beginWrite();
        const old = self.value;
        self.value +%= delta;
        self.lock.endWrite();
        return old;
    }
};

pub const SeqLockBytes = struct {
    lock: SeqLock align(64),
    buf: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, size: usize) !SeqLockBytes {
        const buf = try allocator.alloc(u8, size);
        @memset(buf, 0);
        return .{
            .lock = SeqLock.init(),
            .buf = buf,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SeqLockBytes) void {
        self.allocator.free(self.buf);
        self.buf = &[_]u8{};
    }

    pub fn readInto(self: *const SeqLockBytes, out: []u8) bool {
        if (out.len != self.buf.len) return false;
        while (true) {
            const seq = self.lock.beginRead();
            @memcpy(out, self.buf);
            asm volatile ("" ::: "memory");
            if (self.lock.endRead(seq)) return true;
            std.atomic.spinLoopHint();
        }
    }

    pub fn write(self: *SeqLockBytes, data: []const u8) void {
        const n = @min(data.len, self.buf.len);
        self.lock.beginWrite();
        @memcpy(self.buf[0..n], data[0..n]);
        self.lock.endWrite();
    }
};

test "seqlock basic read/write" {
    const testing = std.testing;
    var sl = SeqLockU64.init(42);
    try testing.expectEqual(@as(u64, 42), sl.load());
    sl.store(99);
    try testing.expectEqual(@as(u64, 99), sl.load());
}

test "seqlock begin/end read" {
    const testing = std.testing;
    const sl = SeqLock.init();
    const seq = sl.beginRead();
    try testing.expect(seq & 1 == 0);
    try testing.expect(sl.endRead(seq));
}

test "seqlock typed data" {
    const testing = std.testing;
    const Point = struct { x: i32, y: i32 };
    var sld = SeqLockData(Point).init(.{ .x = 1, .y = 2 });
    const val = sld.read();
    try testing.expectEqual(@as(i32, 1), val.x);
    try testing.expectEqual(@as(i32, 2), val.y);
    sld.write(.{ .x = 10, .y = 20 });
    const val2 = sld.read();
    try testing.expectEqual(@as(i32, 10), val2.x);
    try testing.expectEqual(@as(i32, 20), val2.y);
}
