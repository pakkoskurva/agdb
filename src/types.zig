const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Error = error{
    InvalidShape,
    InvalidAxis,
    OutOfBounds,
    ShapeMismatch,
    DivideByZero,
    Overflow,
    MustBeSquare,
    SingularMatrix,
    LengthMismatch,
    InvalidParameter,
    InvalidNodeState,
    InvalidData,
    ScoringFailed,
    InvalidVersion,
    InvalidSize,
    InvalidAlignment,
    OutOfMemory,
    EndOfStream,
};

pub const Fixed32_32 = struct {
    raw: i64,

    pub fn fromFloat(value: f64) Fixed32_32 {
        const scaled = value * 4294967296.0;
        return .{ .raw = @intFromFloat(@round(scaled)) };
    }

    pub fn toFloat(self: Fixed32_32) f64 {
        return @as(f64, @floatFromInt(self.raw)) / 4294967296.0;
    }

    pub fn add(self: Fixed32_32, other: Fixed32_32) Fixed32_32 {
        return .{ .raw = self.raw +% other.raw };
    }

    pub fn sub(self: Fixed32_32, other: Fixed32_32) Fixed32_32 {
        return .{ .raw = self.raw -% other.raw };
    }

    pub fn mul(self: Fixed32_32, other: Fixed32_32) Fixed32_32 {
        const product: i128 = @as(i128, self.raw) * @as(i128, other.raw);
        return .{ .raw = @intCast(product >> 32) };
    }

    pub fn div(self: Fixed32_32, other: Fixed32_32) !Fixed32_32 {
        if (other.raw == 0) return Error.DivideByZero;
        const numerator: i128 = @as(i128, self.raw) << 32;
        return .{ .raw = @intCast(@divTrunc(numerator, @as(i128, other.raw))) };
    }
};

pub const PRNG = struct {
    state: u64,

    pub fn init(seed: u64) PRNG {
        var state = seed;
        if (state == 0) state = 0x9E3779B97F4A7C15;
        return .{ .state = state };
    }

    pub fn next(self: *PRNG) u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        return self.state;
    }

    pub fn float(self: *PRNG) f32 {
        const bits: u32 = @intCast((self.next() >> 41) & 0x7FFFFF);
        return @as(f32, @floatFromInt(bits)) / 8388608.0;
    }

    pub fn floatRange(self: *PRNG, min_value: f32, max_value: f32) f32 {
        return min_value + self.float() * (max_value - min_value);
    }

    pub fn intRange(self: *PRNG, min_value: u64, max_value: u64) u64 {
        if (max_value <= min_value) return min_value;
        const span = max_value - min_value;
        return min_value + (self.next() % span);
    }
};

pub const BitSet = struct {
    bits: []u64,
    capacity: usize,
    allocator: Allocator,

    pub fn init(allocator: Allocator, capacity: usize) !BitSet {
        const words = (capacity + 63) / 64;
        const buf = try allocator.alloc(u64, @max(words, 1));
        @memset(buf, 0);
        return .{ .bits = buf, .capacity = capacity, .allocator = allocator };
    }

    pub fn deinit(self: *BitSet) void {
        self.allocator.free(self.bits);
        self.bits = &[_]u64{};
        self.capacity = 0;
    }

    pub fn set(self: *BitSet, index: usize) void {
        if (index >= self.capacity) return;
        const word = index >> 6;
        const bit = index & 63;
        self.bits[word] |= @as(u64, 1) << @intCast(bit);
    }

    pub fn clear(self: *BitSet, index: usize) void {
        if (index >= self.capacity) return;
        const word = index >> 6;
        const bit = index & 63;
        self.bits[word] &= ~(@as(u64, 1) << @intCast(bit));
    }

    pub fn get(self: *const BitSet, index: usize) bool {
        if (index >= self.capacity) return false;
        const word = index >> 6;
        const bit = index & 63;
        return (self.bits[word] >> @intCast(bit)) & 1 == 1;
    }

    pub fn count(self: *const BitSet) usize {
        var total: usize = 0;
        for (self.bits) |word| total += @popCount(word);
        return total;
    }

    pub fn resetAll(self: *BitSet) void {
        @memset(self.bits, 0);
    }
};

pub const RankedSegment = struct {
    tokens: []u32,
    score: f32,
    position: u64,
    anchor: bool,

    pub fn init(allocator: Allocator, tokens: []const u32, score: f32, position: u64, anchor: bool) !RankedSegment {
        return .{
            .tokens = try allocator.dupe(u32, tokens),
            .score = score,
            .position = position,
            .anchor = anchor,
        };
    }

    pub fn deinit(self: *RankedSegment, allocator: Allocator) void {
        if (self.tokens.len > 0) allocator.free(self.tokens);
        self.tokens = &[_]u32{};
    }
};

test "PRNG deterministic" {
    var p1 = PRNG.init(42);
    var p2 = PRNG.init(42);
    try std.testing.expectEqual(p1.next(), p2.next());
}

test "BitSet basic set/get/count" {
    var bs = try BitSet.init(std.testing.allocator, 128);
    defer bs.deinit();
    bs.set(0);
    bs.set(64);
    bs.set(127);
    try std.testing.expect(bs.get(0));
    try std.testing.expect(bs.get(64));
    try std.testing.expect(bs.get(127));
    try std.testing.expectEqual(@as(usize, 3), bs.count());
    bs.clear(64);
    try std.testing.expect(!bs.get(64));
    try std.testing.expectEqual(@as(usize, 2), bs.count());
}

test "RankedSegment lifecycle" {
    var s = try RankedSegment.init(std.testing.allocator, &.{ 1, 2, 3 }, 0.5, 10, true);
    defer s.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), s.tokens.len);
    try std.testing.expectEqual(@as(u64, 10), s.position);
    try std.testing.expect(s.anchor);
}

test "Fixed32_32 round-trip" {
    const v = Fixed32_32.fromFloat(1.5);
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), v.toFloat(), 1e-9);
}
