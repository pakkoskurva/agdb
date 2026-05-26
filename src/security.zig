const std = @import("std");
const crypto = std.crypto;
const builtin = @import("builtin");
const tsc = @import("tsc.zig");

pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;
pub const AES_TAG_SIZE: usize = 16;
pub const CHACHA_KEY_SIZE: usize = 32;
pub const CHACHA_NONCE_SIZE: usize = 12;
pub const CHACHA_TAG_SIZE: usize = 16;

pub const EncryptionAlgorithm = enum(u8) {
    aes_gcm,
    chacha20_poly1305,
};

pub const EncryptionKey = struct {
    data: [32]u8,
    algorithm: EncryptionAlgorithm,
    key_id: u64,
    created_at: i64,

    pub fn init(algorithm: EncryptionAlgorithm) EncryptionKey {
        var key = EncryptionKey{
            .data = undefined,
            .algorithm = algorithm,
            .key_id = 0,
            .created_at = std.time.timestamp(),
        };
        crypto.random.bytes(&key.data);
        crypto.random.bytes(std.mem.asBytes(&key.key_id));
        return key;
    }

    pub fn fromBytes(data: [32]u8, algorithm: EncryptionAlgorithm) EncryptionKey {
        return EncryptionKey{
            .data = data,
            .algorithm = algorithm,
            .key_id = @as(u64, @bitCast(std.time.timestamp())),
            .created_at = std.time.timestamp(),
        };
    }

    pub fn zero() EncryptionKey {
        return EncryptionKey{
            .data = [_]u8{0} ** 32,
            .algorithm = .aes_gcm,
            .key_id = 0,
            .created_at = 0,
        };
    }

    pub fn isZero(self: *const EncryptionKey) bool {
        for (self.data) |byte| {
            if (byte != 0) return false;
        }
        return true;
    }
};

pub const EncryptedRegion = struct {
    ciphertext: []u8,
    nonce: [12]u8,
    tag: [16]u8,
    key_id: u64,
    algorithm: EncryptionAlgorithm,
    associated_data: []const u8,

    pub fn init(allocator_ptr: std.mem.Allocator, plaintext_len: usize) EncryptedRegion {
        return EncryptedRegion{
            .ciphertext = allocator_ptr.alloc(u8, plaintext_len) catch &[_]u8{},
            .nonce = [_]u8{0} ** 12,
            .tag = [_]u8{0} ** 16,
            .key_id = 0,
            .algorithm = .aes_gcm,
            .associated_data = &[_]u8{},
        };
    }

    pub fn deinit(self: *EncryptedRegion, allocator_ptr: std.mem.Allocator) void {
        allocator_ptr.free(self.ciphertext);
    }
};

pub const HKDFParams = struct {
    salt: [32]u8,
    info: []const u8,
    output_len: usize,

    pub fn init(info: []const u8) HKDFParams {
        var params = HKDFParams{
            .salt = undefined,
            .info = info,
            .output_len = 32,
        };
        crypto.random.bytes(&params.salt);
        return params;
    }
};

pub const SecurityManager = struct {
    master_key: ?EncryptionKey,
    region_keys: std.AutoHashMap(u64, EncryptionKey),
    enabled: bool,
    use_hardware_accel: bool,
    nonce_counter: std.atomic.Value(u64),
    allocator: std.mem.Allocator,
    lock: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator_ptr: std.mem.Allocator, master_key_data: ?[]const u8, enabled: bool) !SecurityManager {
        var master_key: ?EncryptionKey = null;

        if (enabled and master_key_data != null) {
            var key_bytes: [32]u8 = [_]u8{0} ** 32;
            const copy_len = @min(master_key_data.?.len, 32);
            @memcpy(key_bytes[0..copy_len], master_key_data.?[0..copy_len]);
            master_key = EncryptionKey.fromBytes(key_bytes, .aes_gcm);
        } else if (enabled) {
            master_key = EncryptionKey.init(.aes_gcm);
        }

        return SecurityManager{
            .master_key = master_key,
            .region_keys = std.AutoHashMap(u64, EncryptionKey).init(allocator_ptr),
            .enabled = enabled,
            .use_hardware_accel = hasAESNI(),
            .nonce_counter = std.atomic.Value(u64).init(0),
            .allocator = allocator_ptr,
            .lock = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.region_keys.deinit();
        if (self.master_key) |*key| {
            crypto.utils.secureZero(u8, &key.data);
        }
    }

    pub fn encrypt(self: *Self, plaintext: []const u8, associated_data: []const u8) !EncryptedRegion {
        if (!self.enabled) {
            const region = EncryptedRegion.init(self.allocator, plaintext.len);
            @memcpy(region.ciphertext, plaintext);
            return region;
        }

        const key = self.master_key orelse return error.NoMasterKey;

        var region = EncryptedRegion.init(self.allocator, plaintext.len);
        errdefer region.deinit(self.allocator);

        region.algorithm = key.algorithm;
        region.key_id = key.key_id;
        region.associated_data = associated_data;

        self.generateNonce(&region.nonce);

        switch (key.algorithm) {
            .aes_gcm => {
                try self.encryptAESGCM(plaintext, region.ciphertext, &region.tag, key.data, region.nonce, associated_data);
            },
            .chacha20_poly1305 => {
                try self.encryptChaCha20(plaintext, region.ciphertext, &region.tag, key.data, region.nonce, associated_data);
            },
        }

        return region;
    }

    pub fn decrypt(self: *Self, region: *const EncryptedRegion) ![]u8 {
        if (!self.enabled) {
            const plaintext = try self.allocator.alloc(u8, region.ciphertext.len);
            @memcpy(plaintext, region.ciphertext);
            return plaintext;
        }

        const key = self.master_key orelse return error.NoMasterKey;

        const plaintext = try self.allocator.alloc(u8, region.ciphertext.len);
        errdefer self.allocator.free(plaintext);

        switch (region.algorithm) {
            .aes_gcm => {
                try self.decryptAESGCM(region.ciphertext, plaintext, &region.tag, key.data, region.nonce, region.associated_data);
            },
            .chacha20_poly1305 => {
                try self.decryptChaCha20(region.ciphertext, plaintext, &region.tag, key.data, region.nonce, region.associated_data);
            },
        }

        return plaintext;
    }

    fn encryptAESGCM(
        self: *Self,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
        key: [32]u8,
        nonce: [12]u8,
        ad: []const u8,
    ) !void {
        _ = self;
        if (ciphertext.len != plaintext.len) return error.BufferSizeMismatch;
        crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, tag, plaintext, ad, nonce, key);
    }

    fn decryptAESGCM(
        self: *Self,
        ciphertext: []const u8,
        plaintext: []u8,
        tag: *const [16]u8,
        key: [32]u8,
        nonce: [12]u8,
        ad: []const u8,
    ) !void {
        _ = self;
        if (ciphertext.len != plaintext.len) return error.BufferSizeMismatch;
        try crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag.*, ad, nonce, key);
    }

    fn encryptChaCha20(
        self: *Self,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
        key: [32]u8,
        nonce: [12]u8,
        ad: []const u8,
    ) !void {
        _ = self;
        if (ciphertext.len != plaintext.len) return error.BufferSizeMismatch;
        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(ciphertext, tag, plaintext, ad, nonce, key);
    }

    fn decryptChaCha20(
        self: *Self,
        ciphertext: []const u8,
        plaintext: []u8,
        tag: *const [16]u8,
        key: [32]u8,
        nonce: [12]u8,
        ad: []const u8,
    ) !void {
        _ = self;
        if (ciphertext.len != plaintext.len) return error.BufferSizeMismatch;
        try crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag.*, ad, nonce, key);
    }

    fn generateNonce(self: *Self, nonce: *[12]u8) void {
        const counter = self.nonce_counter.fetchAdd(1, .monotonic);
        crypto.random.bytes(nonce[0..4]);
        std.mem.writeInt(u64, nonce[4..12], counter, .little);
    }

    pub fn deriveKey(self: *Self, salt: []const u8, info: []const u8, region_id: u64) !EncryptionKey {
        if (!self.enabled) {
            return EncryptionKey.zero();
        }

        const master = self.master_key orelse return error.NoMasterKey;

        const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, &master.data);

        var okm: [32]u8 = undefined;
        crypto.kdf.hkdf.HkdfSha256.expand(&okm, info, prk);

        var key = EncryptionKey.fromBytes(okm, master.algorithm);
        key.key_id = region_id;

        self.lock.lock();
        defer self.lock.unlock();
        try self.region_keys.put(region_id, key);

        return key;
    }

    pub fn getRegionKey(self: *Self, region_id: u64) ?EncryptionKey {
        self.lock.lock();
        defer self.lock.unlock();
        return self.region_keys.get(region_id);
    }

    pub fn rotateMasterKey(self: *Self, new_key_data: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.master_key) |*old| {
            crypto.utils.secureZero(u8, &old.data);
        }

        var key_bytes: [32]u8 = [_]u8{0} ** 32;
        const copy_len = @min(new_key_data.len, 32);
        @memcpy(key_bytes[0..copy_len], new_key_data[0..copy_len]);

        self.master_key = EncryptionKey.fromBytes(key_bytes, .aes_gcm);

        self.region_keys.clearRetainingCapacity();
    }

    pub fn isEnabled(self: *const Self) bool {
        return self.enabled;
    }

    pub fn hasHardwareAccel(self: *const Self) bool {
        return self.use_hardware_accel;
    }

    pub fn generateRdrandBlake3Nonce(self: *Self, nonce: *[12]u8) void {
        var hw_rng = tsc.HardwareRng.init();
        var entropy: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            const word = hw_rng.next64();
            std.mem.writeInt(u64, entropy[i * 8 ..][0..8], word, .little);
        }
        const counter = self.nonce_counter.fetchAdd(1, .monotonic);
        std.mem.writeInt(u64, entropy[24..32], counter, .little);

        const Blake3 = crypto.hash.Blake3;
        var h = Blake3.init(.{});
        h.update(&entropy);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        @memcpy(nonce[0..12], digest[0..12]);
    }

    pub fn encryptAesXts(
        self: *const Self,
        plaintext: []const u8,
        ciphertext: []u8,
        key1: [32]u8,
        key2: [32]u8,
        sector_num: u64,
    ) !void {
        _ = self;
        if (plaintext.len != ciphertext.len) return error.LengthMismatch;
        if (plaintext.len % 16 != 0) return error.MustBeBlockAligned;
        if (plaintext.len == 0) return;
        try aesXtsEncrypt(plaintext, ciphertext, key1, key2, sector_num);
    }

    pub fn decryptAesXts(
        self: *const Self,
        ciphertext: []const u8,
        plaintext: []u8,
        key1: [32]u8,
        key2: [32]u8,
        sector_num: u64,
    ) !void {
        _ = self;
        if (ciphertext.len != plaintext.len) return error.LengthMismatch;
        if (ciphertext.len % 16 != 0) return error.MustBeBlockAligned;
        if (ciphertext.len == 0) return;
        try aesXtsDecrypt(ciphertext, plaintext, key1, key2, sector_num);
    }

    pub fn encryptCacheLine(
        self: *const Self,
        line_addr: u64,
        plaintext: *const [64]u8,
        ciphertext: *[64]u8,
        key1: [32]u8,
        key2: [32]u8,
    ) !void {
        const sector = line_addr / 64;
        try self.encryptAesXts(plaintext[0..], ciphertext[0..], key1, key2, sector);
    }

    pub fn decryptCacheLine(
        self: *const Self,
        line_addr: u64,
        ciphertext: *const [64]u8,
        plaintext: *[64]u8,
        key1: [32]u8,
        key2: [32]u8,
    ) !void {
        const sector = line_addr / 64;
        try self.decryptAesXts(ciphertext[0..], plaintext[0..], key1, key2, sector);
    }
};

fn hasAESNI() bool {
    return true;
}

fn gfMulX(t: *[16]u8) void {
    var carry: u8 = 0;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const next_carry: u8 = t[i] >> 7;
        t[i] = (t[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry != 0) {
        t[0] ^= 0x87;
    }
}

fn aesXtsEncrypt(
    plaintext: []const u8,
    ciphertext: []u8,
    key1: [32]u8,
    key2: [32]u8,
    sector_num: u64,
) !void {
    const Aes256 = crypto.core.aes.Aes256;

    var sector_le: [16]u8 = [_]u8{0} ** 16;
    std.mem.writeInt(u64, sector_le[0..8], sector_num, .little);

    const enc2 = Aes256.initEnc(key2);
    var tweak: [16]u8 = undefined;
    enc2.encrypt(&tweak, &sector_le);

    const enc1 = Aes256.initEnc(key1);

    const block_count = plaintext.len / 16;
    var b: usize = 0;
    while (b < block_count) : (b += 1) {
        const offset = b * 16;
        var pp: [16]u8 = undefined;
        @memcpy(&pp, plaintext[offset..][0..16]);
        for (&pp, tweak) |*p, tw| p.* ^= tw;
        var cc: [16]u8 = undefined;
        enc1.encrypt(&cc, &pp);
        for (&cc, tweak) |*c, tw| c.* ^= tw;
        @memcpy(ciphertext[offset..][0..16], &cc);
        gfMulX(&tweak);
    }
}

fn aesXtsDecrypt(
    ciphertext: []const u8,
    plaintext: []u8,
    key1: [32]u8,
    key2: [32]u8,
    sector_num: u64,
) !void {
    const Aes256 = crypto.core.aes.Aes256;

    var sector_le: [16]u8 = [_]u8{0} ** 16;
    std.mem.writeInt(u64, sector_le[0..8], sector_num, .little);

    const enc2 = Aes256.initEnc(key2);
    var tweak: [16]u8 = undefined;
    enc2.encrypt(&tweak, &sector_le);

    const dec1 = Aes256.initDec(key1);

    const block_count = ciphertext.len / 16;
    var b: usize = 0;
    while (b < block_count) : (b += 1) {
        const offset = b * 16;
        var cc: [16]u8 = undefined;
        @memcpy(&cc, ciphertext[offset..][0..16]);
        for (&cc, tweak) |*c, tw| c.* ^= tw;
        var pp: [16]u8 = undefined;
        dec1.decrypt(&pp, &cc);
        for (&pp, tweak) |*p, tw| p.* ^= tw;
        @memcpy(plaintext[offset..][0..16], &pp);
        gfMulX(&tweak);
    }
}

pub const TPM2Interface = struct {
    handle: ?*anyopaque,
    tcti: []const u8,
    pcr_values: [24][32]u8,
    nv_counter: u64,
    initialized: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator_ptr: std.mem.Allocator, tcti: []const u8) TPM2Interface {
        return TPM2Interface{
            .handle = null,
            .tcti = tcti,
            .pcr_values = [_][32]u8{[_]u8{0} ** 32} ** 24,
            .nv_counter = 0,
            .initialized = false,
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *TPM2Interface) void {
        _ = self;
    }

    pub fn initialize(self: *TPM2Interface) !void {
        _ = self;
    }

    pub fn readPCR(self: *TPM2Interface, pcr_index: u8) ![32]u8 {
        _ = self;
        _ = pcr_index;
        return [_]u8{0} ** 32;
    }

    pub fn readAllPCRs(self: *TPM2Interface) !void {
        var i: u8 = 0;
        while (i < 24) : (i += 1) {
            self.pcr_values[i] = try self.readPCR(i);
        }
    }

    pub fn seal(self: *TPM2Interface, data: []const u8, pcr_mask: u32) ![]u8 {
        _ = pcr_mask;
        const sealed = try self.allocator.alloc(u8, data.len + 256);
        @memcpy(sealed[0..data.len], data);
        return sealed;
    }

    pub fn unseal(self: *TPM2Interface, sealed_data: []const u8, pcr_mask: u32) ![]u8 {
        _ = pcr_mask;
        const unsealed = try self.allocator.alloc(u8, sealed_data.len - 256);
        @memcpy(unsealed, sealed_data[0..unsealed.len]);
        return unsealed;
    }

    pub fn incrementNVCounter(self: *TPM2Interface) !u64 {
        self.nv_counter += 1;
        return self.nv_counter;
    }

    pub fn readNVCounter(self: *TPM2Interface) !u64 {
        return self.nv_counter;
    }

    pub fn verifyPCRPolicy(self: *TPM2Interface, expected_pcrs: []const [32]u8, pcr_mask: u32) !bool {
        _ = pcr_mask;
        var i: usize = 0;
        while (i < expected_pcrs.len) : (i += 1) {
            if (!std.mem.eql(u8, &self.pcr_values[i], &expected_pcrs[i])) {
                return false;
            }
        }
        return true;
    }
    pub fn quote(self: *TPM2Interface, qualifying_data: []const u8, pcr_mask: u32) ![]u8 {
        _ = pcr_mask;
        const quote_buf = try self.allocator.alloc(u8, qualifying_data.len + 512);
        @memcpy(quote_buf[0..qualifying_data.len], qualifying_data);
        return quote_buf;
    }
};

pub const IntegrityVerifier = struct {
    merkle_tree: []MerkleNode,
    page_hashes: std.AutoHashMap(u64, [32]u8),
    allocator: std.mem.Allocator,

    const MerkleNode = struct {
        hash: [32]u8,
        left: ?usize,
        right: ?usize,
    };

    pub fn init(allocator_ptr: std.mem.Allocator) IntegrityVerifier {
        return IntegrityVerifier{
            .merkle_tree = &[_]MerkleNode{},
            .page_hashes = std.AutoHashMap(u64, [32]u8).init(allocator_ptr),
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *IntegrityVerifier) void {
        self.allocator.free(self.merkle_tree);
        self.page_hashes.deinit();
    }

    pub fn computePageHash(self: *IntegrityVerifier, page_data: []const u8, page_idx: u64) [32]u8 {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(page_data);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        self.page_hashes.put(page_idx, hash) catch {};
        return hash;
    }

    pub fn verifyPageHash(self: *IntegrityVerifier, page_data: []const u8, page_idx: u64) !bool {
        const expected = self.page_hashes.get(page_idx) orelse return error.HashNotFound;
        const computed = self.computePageHash(page_data, page_idx);

        if (!std.mem.eql(u8, &expected, &computed)) {
            return error.HashMismatch;
        }

        return true;
    }

    pub fn buildMerkleTree(self: *IntegrityVerifier, page_count: u64) !void {
        const node_count = page_count * 2 - 1;
        self.merkle_tree = try self.allocator.alloc(MerkleNode, node_count);

        var i: u64 = 0;
        while (i < page_count) : (i += 1) {
            const hash = self.page_hashes.get(i) orelse [_]u8{0} ** 32;
            self.merkle_tree[i] = MerkleNode{
                .hash = hash,
                .left = null,
                .right = null,
            };
        }

        var level_size = page_count;
        var level_start: u64 = 0;

        while (level_size > 1) {
            const next_start = level_start + level_size;
            const next_size = level_size / 2;

            i = 0;
            while (i < next_size) : (i += 1) {
                const left_idx = level_start + i * 2;
                const right_idx = left_idx + 1;

                var combined: [64]u8 = undefined;
                @memcpy(combined[0..32], &self.merkle_tree[left_idx].hash);
                @memcpy(combined[32..64], &self.merkle_tree[right_idx].hash);

                var hasher = crypto.hash.sha2.Sha256.init(.{});
                hasher.update(&combined);
                var hash: [32]u8 = undefined;
                hasher.final(&hash);

                self.merkle_tree[next_start + i] = MerkleNode{
                    .hash = hash,
                    .left = left_idx,
                    .right = right_idx,
                };
            }

            level_start = next_start;
            level_size = next_size;
        }
    }

    pub fn getMerkleRoot(self: *const IntegrityVerifier) ?[32]u8 {
        if (self.merkle_tree.len == 0) return null;
        return self.merkle_tree[self.merkle_tree.len - 1].hash;
    }

    pub fn verifyMerkleProof(self: *const IntegrityVerifier, page_idx: u64, proof: []const [32]u8) bool {
        _ = self;
        _ = page_idx;
        _ = proof;
        return true;
    }
};

test "security manager encryption" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const key = "test_master_key_12345678901234567";
    var sec_mgr = try SecurityManager.init(alloc, key, true);
    defer sec_mgr.deinit();

    const plaintext = "Hello, encrypted world!";
    var region = try sec_mgr.encrypt(plaintext, "associated_data");
    defer region.deinit(alloc);

    try testing.expect(region.ciphertext.len == plaintext.len);
    try testing.expect(!std.mem.eql(u8, plaintext, region.ciphertext));
}

test "encryption key derivation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const key = "test_master_key_12345678901234567";
    var sec_mgr = try SecurityManager.init(alloc, key, true);
    defer sec_mgr.deinit();

    const derived1 = try sec_mgr.deriveKey("salt1", "info1", 1);
    const derived2 = try sec_mgr.deriveKey("salt2", "info2", 2);

    try testing.expect(!std.mem.eql(u8, &derived1.data, &derived2.data));
}
