const std = @import("std");

pub fn stableHash(data: []const u8, seed: u64) u64 {
    var hash: u64 = seed ^ 0xCBF29CE484222325;
    for (data) |byte| {
        hash ^= @as(u64, byte);
        hash *%= 0x100000001B3;
        hash ^= hash >> 33;
    }
    hash ^= @as(u64, @intCast(data.len)) *% 0x9E3779B97F4A7C15;
    hash ^= hash >> 32;
    hash *%= 0xFF51AFD7ED558CCD;
    hash ^= hash >> 32;
    hash *%= 0xC4CEB9FE1A85EC53;
    hash ^= hash >> 32;
    return hash;
}

pub fn stableHashU32(data: []const u8, seed: u64) u32 {
    return @intCast(stableHash(data, seed) & 0xFFFFFFFF);
}

pub fn combineHashes(a: u64, b: u64) u64 {
    var h: u64 = a;
    h ^= b +% 0x9E3779B97F4A7C15 +% (h << 6) +% (h >> 2);
    return h;
}

test "stableHash deterministic" {
    const data = "hello agdb";
    try std.testing.expectEqual(stableHash(data, 42), stableHash(data, 42));
}

test "stableHash differs by seed" {
    const data = "hello agdb";
    try std.testing.expect(stableHash(data, 1) != stableHash(data, 2));
}

test "stableHash differs by data" {
    try std.testing.expect(stableHash("a", 0) != stableHash("b", 0));
}

test "combineHashes deterministic" {
    try std.testing.expectEqual(combineHashes(1, 2), combineHashes(1, 2));
}
