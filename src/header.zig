const std = @import("std");
const builtin = @import("builtin");

pub const HEAP_MAGIC = [8]u8{ 'Z', 'I', 'G', 'P', 'H', 'E', 'A', 'P' };
pub const HEAP_VERSION: u32 = 1;
pub const HEADER_SIZE: u64 = 256;
pub const CACHE_LINE_SIZE: u64 = 64;

fn crc32cByte(crc: u32, byte: u8) u32 {
    const POLY: u32 = 0x82F63B78;
    var c = crc ^ @as(u32, byte);
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        if ((c & 1) != 0) {
            c = (c >> 1) ^ POLY;
        } else {
            c = c >> 1;
        }
    }
    return c;
}

pub const Endianness = enum(u32) {
    little = 0x01234567,
    big = 0x76543210,
};

pub const HeapHeader = extern struct {
    magic: [8]u8 align(8),
    version: u32 align(8),
    flags: u32 align(8),
    pool_uuid_low: u64 align(8),
    pool_uuid_high: u64 align(8),
    endianness: Endianness align(8),
    checksum: u32 align(8),
    reserved1: u32 align(8),
    heap_size: u64 align(8),
    used_size: u64 align(8),
    root_offset: u64 align(8),
    root_uuid_low: u64 align(8),
    root_uuid_high: u64 align(8),
    allocator_offset: u64 align(8),
    transaction_id: u64 align(8),
    last_checkpoint: u64 align(8),
    reserved2: [256 - 128]u8 align(8),

    pub fn init(heap_size: u64) HeapHeader {
        var uuid_low: u64 = undefined;
        var uuid_high: u64 = undefined;

        var seed: u64 = @bitCast(std.time.timestamp());
        var stack_anchor: u64 = heap_size;
        seed ^= @as(u64, @intFromPtr(&stack_anchor));
        seed ^= heap_size;

        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();
        uuid_low = rand.int(u64);
        uuid_high = rand.int(u64);

        var header = HeapHeader{
            .magic = HEAP_MAGIC,
            .version = HEAP_VERSION,
            .flags = 0,
            .pool_uuid_low = uuid_low,
            .pool_uuid_high = uuid_high,
            .endianness = if (builtin.cpu.arch.endian() == .little) Endianness.little else Endianness.big,
            .checksum = 0,
            .reserved1 = 0,
            .heap_size = heap_size,
            .used_size = HEADER_SIZE,
            .root_offset = 0,
            .root_uuid_low = 0,
            .root_uuid_high = 0,
            .allocator_offset = 0,
            .transaction_id = 0,
            .last_checkpoint = 0,
            .reserved2 = [_]u8{0} ** (256 - 128),
        };

        header.checksum = header.computeChecksum();
        return header;
    }

    pub fn computeChecksum(self: *const HeapHeader) u32 {
        const bytes = std.mem.asBytes(self);
        const checksum_offset = @offsetOf(HeapHeader, "checksum");
        const checksum_size = @sizeOf(u32);

        var crc: u32 = 0xFFFFFFFF;

        var i: usize = 0;
        while (i < checksum_offset) : (i += 1) {
            crc = crc32cByte(crc, bytes[i]);
        }

        i = checksum_offset + checksum_size;
        while (i < bytes.len) : (i += 1) {
            crc = crc32cByte(crc, bytes[i]);
        }

        return crc ^ 0xFFFFFFFF;
    }

    pub fn validate(self: *const HeapHeader) !void {
        if (!std.mem.eql(u8, self.magic[0..], HEAP_MAGIC[0..])) {
            return error.InvalidMagic;
        }

        if (self.version > HEAP_VERSION) {
            return error.UnsupportedVersion;
        }

        const expected_endianness = if (builtin.cpu.arch.endian() == .little) Endianness.little else Endianness.big;
        if (self.endianness != expected_endianness) {
            return error.EndiannessMismatch;
        }

        const computed = self.computeChecksum();
        if (computed != self.checksum) {
            return error.ChecksumMismatch;
        }
    }

    pub fn getPoolUUID(self: *const HeapHeader) u128 {
        return (@as(u128, self.pool_uuid_high) << 64) | @as(u128, self.pool_uuid_low);
    }

    pub fn setPoolUUID(self: *HeapHeader, uuid: u128) void {
        self.pool_uuid_low = @as(u64, @truncate(uuid));
        self.pool_uuid_high = @as(u64, @truncate(uuid >> 64));
    }

    pub fn getRootPtr(self: *const HeapHeader) ?struct { offset: u64, uuid: u128 } {
        if (self.root_offset == 0) {
            return null;
        }
        return .{
            .offset = self.root_offset,
            .uuid = (@as(u128, self.root_uuid_high) << 64) | @as(u128, self.root_uuid_low),
        };
    }

    pub fn setRootPtr(self: *HeapHeader, offset: u64, uuid: u128) void {
        self.root_offset = offset;
        self.root_uuid_low = @as(u64, @truncate(uuid));
        self.root_uuid_high = @as(u64, @truncate(uuid >> 64));
    }

    pub fn updateChecksum(self: *HeapHeader) void {
        self.checksum = self.computeChecksum();
    }

    pub fn canRepair(self: *const HeapHeader) !bool {
        if (!std.mem.eql(u8, self.magic[0..], HEAP_MAGIC[0..])) return false;
        if (self.version > HEAP_VERSION) return false;
        const expected_endianness = if (builtin.cpu.arch.endian() == .little) Endianness.little else Endianness.big;
        if (self.endianness != expected_endianness) return false;
        return true;
    }

    pub fn isDirty(self: *const HeapHeader) bool {
        return (self.flags & 0x01) != 0;
    }

    pub fn setDirty(self: *HeapHeader, dirty: bool) void {
        if (dirty) {
            self.flags |= 0x01;
        } else {
            self.flags &= ~@as(u32, 0x01);
        }
    }
};

comptime {
    if (@sizeOf(HeapHeader) != HEADER_SIZE) @compileError("HeapHeader size does not match HEADER_SIZE");
}

pub const ObjectHeader = extern struct {
    magic: u32,
    flags: u32,
    size: u64,
    ref_count: u32,
    schema_id: u32,
    checksum: u32,
    reserved: u32,

    pub const OBJECT_MAGIC: u32 = 0xDEADBEEF;
    pub const FLAG_FREED: u32 = 0x01;
    pub const FLAG_PINNED: u32 = 0x02;
    pub const FLAG_ARRAY: u32 = 0x04;

    pub fn init(size: u64, schema_id: u32) ObjectHeader {
        var obj = ObjectHeader{
            .magic = OBJECT_MAGIC,
            .flags = 0,
            .size = size,
            .ref_count = 1,
            .schema_id = schema_id,
            .checksum = 0,
            .reserved = 0,
        };
        obj.checksum = obj.computeChecksum();
        return obj;
    }

    pub fn validate(self: *const ObjectHeader) !void {
        if (self.magic != OBJECT_MAGIC) {
            return error.InvalidObjectMagic;
        }
    }

    pub fn hasValidMagic(self: *const ObjectHeader) bool {
        return self.magic == OBJECT_MAGIC;
    }

    pub fn isFreed(self: *const ObjectHeader) bool {
        return (self.flags & FLAG_FREED) != 0;
    }

    pub fn isPinned(self: *const ObjectHeader) bool {
        return (self.flags & FLAG_PINNED) != 0;
    }

    pub fn isArray(self: *const ObjectHeader) bool {
        return (self.flags & FLAG_ARRAY) != 0;
    }

    pub fn setFreed(self: *ObjectHeader, freed: bool) void {
        if (freed) {
            self.flags |= FLAG_FREED;
        } else {
            self.flags &= ~@as(u32, FLAG_FREED);
        }
    }

    pub fn setPinned(self: *ObjectHeader, pinned: bool) void {
        if (pinned) {
            self.flags |= FLAG_PINNED;
        } else {
            self.flags &= ~@as(u32, FLAG_PINNED);
        }
    }

    pub fn computeChecksum(self: *const ObjectHeader) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        const skip_start = @offsetOf(ObjectHeader, "checksum");
        const skip_end = skip_start + @sizeOf(u32);

        for (bytes, 0..) |byte, i| {
            if (i >= skip_start and i < skip_end) continue;
            crc = crc32cByte(crc, byte);
        }

        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *ObjectHeader) void {
        self.checksum = self.computeChecksum();
    }
};

pub const FreeBlock = extern struct {
    magic: u32,
    size: u64,
    prev_offset: u64,
    next_offset: u64,
    checksum: u32,
    reserved: u32,

    pub const FREE_MAGIC: u32 = 0xFEEDFACE;

    pub fn init(size: u64) FreeBlock {
        var block = FreeBlock{
            .magic = FREE_MAGIC,
            .size = size,
            .prev_offset = 0,
            .next_offset = 0,
            .checksum = 0,
            .reserved = 0,
        };
        block.checksum = block.computeChecksum();
        return block;
    }

    pub fn validate(self: *const FreeBlock) !void {
        if (self.magic != FREE_MAGIC) {
            return error.InvalidFreeBlockMagic;
        }
    }

    pub fn computeChecksum(self: *const FreeBlock) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        const skip_start = @offsetOf(FreeBlock, "checksum");
        const skip_end = skip_start + @sizeOf(u32);

        for (bytes, 0..) |byte, i| {
            if (i >= skip_start and i < skip_end) continue;
            crc = crc32cByte(crc, byte);
        }

        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *FreeBlock) void {
        self.checksum = self.computeChecksum();
    }
};

test "header initialization and validation" {
    const testing = std.testing;
    const header = HeapHeader.init(1024 * 1024);
    try testing.expect(std.mem.eql(u8, header.magic[0..], HEAP_MAGIC[0..]));
    try testing.expect(header.version == HEAP_VERSION);
    try header.validate();
}

test "checksum computation" {
    const testing = std.testing;
    var header = HeapHeader.init(1024 * 1024);
    const original_checksum = header.checksum;
    header.heap_size = 2048 * 1024;
    header.updateChecksum();
    try testing.expect(header.checksum != original_checksum);
    try header.validate();
}

test "object header" {
    const testing = std.testing;
    var obj = ObjectHeader.init(256, 42);
    try testing.expect(obj.magic == ObjectHeader.OBJECT_MAGIC);
    try testing.expect(obj.size == 256);
    try testing.expect(obj.ref_count == 1);
    try testing.expect(!obj.isFreed());
    obj.setFreed(true);
    try testing.expect(obj.isFreed());
}
