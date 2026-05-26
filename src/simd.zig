const std = @import("std");
const builtin = @import("builtin");

pub const CACHE_LINE: usize = 64;
pub const AVX2_WIDTH: usize = 32;
pub const AVX2_U64_LANES: usize = 4;

pub const is_x86_64 = builtin.cpu.arch == .x86_64;
pub const has_avx2 = is_x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

pub const Vec4u64 = @Vector(4, u64);
pub const Vec8u32 = @Vector(8, u32);
pub const Vec16u16 = @Vector(16, u16);
pub const Vec32u8 = @Vector(32, u8);

pub const Vec2u64 = @Vector(2, u64);
pub const Vec4u32 = @Vector(4, u32);

pub inline fn loadVec4u64(ptr: *const [4]u64) Vec4u64 {
    return @as(Vec4u64, ptr.*);
}

pub inline fn storeVec4u64(ptr: *[4]u64, v: Vec4u64) void {
    const arr: [4]u64 = v;
    ptr.* = arr;
}

pub inline fn vec4u64Broadcast(val: u64) Vec4u64 {
    return @splat(val);
}

pub inline fn vec4u64Eq(a: Vec4u64, b: Vec4u64) @Vector(4, bool) {
    return a == b;
}

pub inline fn anyTrue4(mask: @Vector(4, bool)) bool {
    return @reduce(.Or, mask);
}

pub inline fn allTrue4(mask: @Vector(4, bool)) bool {
    return @reduce(.And, mask);
}

pub const ConflictScanResult = struct {
    conflict_found: bool,
    conflict_lane: u8,
};

pub fn simdConflictScan(needles: []const u64, haystack: []const u64) ConflictScanResult {
    var hi: usize = 0;
    while (hi + 4 <= haystack.len) : (hi += 4) {
        const hv: Vec4u64 = haystack[hi..][0..4].*;
        for (needles) |needle| {
            const nv: Vec4u64 = @splat(needle);
            const mask = vec4u64Eq(hv, nv);
            if (anyTrue4(mask)) {
                const lane: u8 = blk: {
                    inline for (0..4) |idx| {
                        if (mask[idx]) break :blk @as(u8, @intCast(idx));
                    }
                    break :blk 0;
                };
                return .{ .conflict_found = true, .conflict_lane = lane };
            }
        }
    }
    while (hi < haystack.len) : (hi += 1) {
        for (needles) |needle| {
            if (haystack[hi] == needle) {
                return .{ .conflict_found = true, .conflict_lane = 0 };
            }
        }
    }
    return .{ .conflict_found = false, .conflict_lane = 0 };
}

pub fn simdWriteSetIntersects(write_set_a: []const u64, write_set_b: []const u64) bool {
    const result = simdConflictScan(write_set_a, write_set_b);
    return result.conflict_found;
}

pub const BloomFilter256 = struct {
    bits: [4]u64,

    pub fn init() BloomFilter256 {
        return .{ .bits = [_]u64{0} ** 4 };
    }

    pub fn hash1(key: u64) u8 {
        const h = key *% 0x9e3779b97f4a7c15;
        return @intCast(h & 0xFF);
    }

    pub fn hash2(key: u64) u8 {
        const h = (key >> 17) *% 0x6c62272e07bb0142;
        return @intCast(h & 0xFF);
    }

    pub fn hash3(key: u64) u8 {
        const h = (key ^ (key >> 31)) *% 0xbf58476d1ce4e5b9;
        return @intCast((h >> 8) & 0xFF);
    }

    pub fn insert(self: *BloomFilter256, key: u64) void {
        const h1 = hash1(key);
        const h2 = hash2(key);
        const h3 = hash3(key);

        const w1 = h1 / 64;
        const b1: u6 = @intCast(h1 % 64);
        const w2 = h2 / 64;
        const b2: u6 = @intCast(h2 % 64);
        const w3 = h3 / 64;
        const b3: u6 = @intCast(h3 % 64);

        self.bits[w1 % 4] |= @as(u64, 1) << b1;
        self.bits[w2 % 4] |= @as(u64, 1) << b2;
        self.bits[w3 % 4] |= @as(u64, 1) << b3;
    }

    pub fn mightContain(self: *const BloomFilter256, key: u64) bool {
        const h1 = hash1(key);
        const h2 = hash2(key);
        const h3 = hash3(key);

        const w1 = h1 / 64;
        const b1: u6 = @intCast(h1 % 64);
        const w2 = h2 / 64;
        const b2: u6 = @intCast(h2 % 64);
        const w3 = h3 / 64;
        const b3: u6 = @intCast(h3 % 64);

        const bit1 = (self.bits[w1 % 4] >> b1) & 1;
        const bit2 = (self.bits[w2 % 4] >> b2) & 1;
        const bit3 = (self.bits[w3 % 4] >> b3) & 1;

        return (bit1 & bit2 & bit3) != 0;
    }

    pub fn simdMightContainBatch(self: *const BloomFilter256, keys: []const u64, results: []bool) void {
        std.debug.assert(results.len >= keys.len);
        const filter_vec: Vec4u64 = loadVec4u64(&self.bits);

        var i: usize = 0;
        while (i + 4 <= keys.len) : (i += 4) {
            inline for (0..4) |lane| {
                results[i + lane] = simdBloomCheck(filter_vec, keys[i + lane]);
            }
        }
        while (i < keys.len) : (i += 1) {
            results[i] = self.mightContain(keys[i]);
        }
    }

    fn simdBloomCheck(filter_vec: Vec4u64, key: u64) bool {
        const h1 = hash1(key);
        const h2 = hash2(key);
        const h3 = hash3(key);

        const w1 = h1 / 64;
        const b1: u6 = @intCast(h1 % 64);
        const w2 = h2 / 64;
        const b2: u6 = @intCast(h2 % 64);
        const w3 = h3 / 64;
        const b3: u6 = @intCast(h3 % 64);

        const bit1 = (filter_vec[w1 % 4] >> b1) & 1;
        const bit2 = (filter_vec[w2 % 4] >> b2) & 1;
        const bit3 = (filter_vec[w3 % 4] >> b3) & 1;

        return (bit1 & bit2 & bit3) != 0;
    }

    pub fn reset(self: *BloomFilter256) void {
        self.bits = [_]u64{0} ** 4;
    }

    pub fn unionWith(self: *BloomFilter256, other: *const BloomFilter256) void {
        const a: Vec4u64 = loadVec4u64(&self.bits);
        const b: Vec4u64 = loadVec4u64(&other.bits);
        const result = a | b;
        storeVec4u64(&self.bits, result);
    }

    pub fn intersectsWith(self: *const BloomFilter256, other: *const BloomFilter256) bool {
        const a: Vec4u64 = loadVec4u64(&self.bits);
        const b: Vec4u64 = loadVec4u64(&other.bits);
        const result = a & b;
        const zero: Vec4u64 = @splat(0);
        return @reduce(.Or, result != zero);
    }
};

pub fn simdMemcmp32(a: *const [32]u8, b: *const [32]u8) bool {
    const va: Vec32u8 = a.*;
    const vb: Vec32u8 = b.*;
    const eq = va == vb;
    return @reduce(.And, eq);
}

pub fn simdSum64(data: []const u64) u64 {
    var acc: Vec4u64 = @splat(0);
    var i: usize = 0;
    while (i + 4 <= data.len) : (i += 4) {
        const v: Vec4u64 = data[i..][0..4].*;
        acc += v;
    }
    var sum: u64 = @reduce(.Add, acc);
    while (i < data.len) : (i += 1) {
        sum +%= data[i];
    }
    return sum;
}

pub fn simdZero(buf: []u8) void {
    var i: usize = 0;
    const zero32: Vec32u8 = @splat(0);
    while (i + 32 <= buf.len) : (i += 32) {
        const p: *align(1) Vec32u8 = @ptrCast(buf.ptr + i);
        p.* = zero32;
    }
    while (i < buf.len) : (i += 1) {
        buf[i] = 0;
    }
}

pub fn prefetchForRead(ptr: *const anyopaque) void {
    @prefetch(ptr, .{ .rw = .read, .locality = 3, .cache = .data });
}

pub fn prefetchForWrite(ptr: *anyopaque) void {
    @prefetch(ptr, .{ .rw = .write, .locality = 3, .cache = .data });
}

pub fn prefetchNTA(ptr: *const anyopaque) void {
    @prefetch(ptr, .{ .rw = .read, .locality = 0, .cache = .data });
}

test "bloom filter basic" {
    const testing = std.testing;
    var bf = BloomFilter256.init();
    bf.insert(0xDEADBEEF_CAFEBABE);
    bf.insert(0x12345678_9ABCDEF0);
    try testing.expect(bf.mightContain(0xDEADBEEF_CAFEBABE));
    try testing.expect(bf.mightContain(0x12345678_9ABCDEF0));
}

test "bloom filter batch simd" {
    const testing = std.testing;
    var bf = BloomFilter256.init();
    const keys = [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    for (keys) |k| bf.insert(k);

    var results = [_]bool{false} ** 8;
    bf.simdMightContainBatch(&keys, &results);
    for (results) |r| {
        try testing.expect(r);
    }
}

test "simd conflict scan" {
    const testing = std.testing;
    const needles = [_]u64{ 10, 20, 30 };
    const haystack = [_]u64{ 1, 2, 3, 4, 5, 20, 7, 8 };
    const result = simdConflictScan(&needles, &haystack);
    try testing.expect(result.conflict_found);

    const haystack2 = [_]u64{ 1, 2, 3, 4 };
    const result2 = simdConflictScan(&needles, &haystack2);
    try testing.expect(!result2.conflict_found);
}
