const std = @import("std");

pub const ApiKey = extern struct {
    tenant_id: u64,
    hash: [32]u8,
    created_at_unix: i64,
    revoked: u8,
    _pad: [7]u8 = [_]u8{0} ** 7,
};

pub fn generateApiKey() ![64]u8 {
    var key: [64]u8 = undefined;
    @memcpy(key[0..5], "agdb_");
    var rand_bytes: [29]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    var i: usize = 0;
    while (i < rand_bytes.len) : (i += 1) {
        const byte = rand_bytes[i];
        const high = (byte >> 4) & 0x0F;
        const low = byte & 0x0F;
        const hex_chars = "0123456789abcdef";
        key[5 + i * 2] = hex_chars[high];
        key[5 + i * 2 + 1] = hex_chars[low];
    }
    key[63] = 0;
    return key;
}

pub fn hashApiKey(key: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    var len = key.len;
    if (len > 0 and key[len - 1] == 0) {
        len -= 1;
    }
    std.crypto.hash.Blake3.hash(key[0..len], &hash, .{});
    return hash;
}

pub fn verifyApiKey(key: []const u8, stored_hash: [32]u8) bool {
    const computed = hashApiKey(key);
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < computed.len) : (i += 1) {
        diff |= computed[i] ^ stored_hash[i];
    }
    return diff == 0;
}
