const std = @import("std");

pub const ANS_SCALE_BITS: u32 = 12;
pub const ANS_SCALE: u32 = 1 << ANS_SCALE_BITS;
pub const ANS_LOWER_BOUND: u64 = 1 << 23;
pub const ANS_UPPER_BOUND: u64 = ANS_LOWER_BOUND << 8;

pub const MAX_SYMBOLS: usize = 256;

pub const SymbolStats = struct {
    freq: [MAX_SYMBOLS]u32,
    cum_freq: [MAX_SYMBOLS + 1]u32,
    symbol_count: u32,

    pub fn init() SymbolStats {
        return std.mem.zeroes(SymbolStats);
    }

    pub fn countFrequencies(self: *SymbolStats, data: []const u8) void {
        var raw_freq = [_]u64{0} ** MAX_SYMBOLS;
        for (data) |b| raw_freq[b] += 1;

        var total: u64 = 0;
        for (raw_freq) |f| total += f;

        if (total == 0) {
            @memset(&self.freq, 0);
            @memset(&self.cum_freq, 0);
            self.symbol_count = 0;
            return;
        }

        var active: u32 = 0;
        for (raw_freq, 0..) |f, i| {
            if (f > 0) {
                self.freq[i] = @max(1, @as(u32, @intCast((@as(u128, f) * ANS_SCALE) / total)));
                active += 1;
            } else {
                self.freq[i] = 0;
            }
        }
        self.symbol_count = active;

        var sum: u32 = 0;
        for (&self.freq) |*f| sum += f.*;

        if (sum > ANS_SCALE) {
            var excess: u32 = sum - ANS_SCALE;
            var i: usize = MAX_SYMBOLS;
            while (i > 0 and excess > 0) {
                i -= 1;
                if (self.freq[i] > 1) {
                    const reduce = @min(self.freq[i] - 1, excess);
                    self.freq[i] -= reduce;
                    excess -= reduce;
                }
            }
        } else if (sum < ANS_SCALE) {
            var deficit: u32 = ANS_SCALE - sum;
            var i: usize = 0;
            while (i < MAX_SYMBOLS and deficit > 0) : (i += 1) {
                if (self.freq[i] > 0) {
                    self.freq[i] += deficit;
                    deficit = 0;
                }
            }
        }

        self.buildCumFreq();
    }

    pub fn buildCumFreq(self: *SymbolStats) void {
        self.cum_freq[0] = 0;
        for (0..MAX_SYMBOLS) |i| {
            self.cum_freq[i + 1] = self.cum_freq[i] + self.freq[i];
        }
    }

    pub fn serialize(self: *const SymbolStats, out: []u8) usize {
        var pos: usize = 0;
        for (self.freq) |f| {
            if (pos + 2 > out.len) break;
            std.mem.writeInt(u16, out[pos..][0..2], @intCast(@min(f, 0xFFFF)), .little);
            pos += 2;
        }
        return pos;
    }

    pub fn deserialize(self: *SymbolStats, data: []const u8) bool {
        if (data.len < MAX_SYMBOLS * 2) return false;
        for (0..MAX_SYMBOLS) |i| {
            self.freq[i] = std.mem.readInt(u16, data[i * 2 ..][0..2], .little);
        }
        self.buildCumFreq();
        return true;
    }
};

pub const AliasTable = struct {
    prob: [ANS_SCALE]u32,
    alias: [ANS_SCALE]u8,
    sym_start: [MAX_SYMBOLS]u32,

    pub fn build(self: *AliasTable, stats: *const SymbolStats) void {
        for (0..ANS_SCALE) |slot| {
            self.prob[slot] = ANS_SCALE;
            self.alias[slot] = 0;
        }

        for (0..MAX_SYMBOLS) |i| {
            const s: u8 = @intCast(i);
            const f = stats.freq[i];
            if (f == 0) continue;
            const slots = f;
            var j: u32 = 0;
            while (j < slots) : (j += 1) {
                const slot = stats.cum_freq[i] + j;
                if (slot < ANS_SCALE) {
                    self.prob[slot] = ANS_SCALE;
                    self.alias[slot] = s;
                }
            }
        }

        for (0..MAX_SYMBOLS) |i| {
            self.sym_start[i] = stats.cum_freq[i];
        }
    }

    pub fn decode(self: *const AliasTable, state: u64, stats: *const SymbolStats) struct { sym: u8, new_state: u64 } {
        const slot: u32 = @intCast(state % @as(u64, ANS_SCALE));
        const s = self.findSymbol(slot, stats);
        const freq = stats.freq[s];
        const cum = stats.cum_freq[s];
        const new_state = (state / @as(u64, ANS_SCALE)) * @as(u64, freq) + @as(u64, slot) - @as(u64, cum);
        return .{ .sym = s, .new_state = new_state };
    }

    fn findSymbol(self: *const AliasTable, slot: u64, stats: *const SymbolStats) u8 {
        _ = stats;
        return self.alias[@intCast(slot)];
    }
};

pub const RansEncoder = struct {
    state: u64,
    output: std.ArrayList(u8),
    stats: *const SymbolStats,

    pub fn init(allocator: std.mem.Allocator, stats: *const SymbolStats) RansEncoder {
        return .{
            .state = ANS_LOWER_BOUND,
            .output = std.ArrayList(u8).init(allocator),
            .stats = stats,
        };
    }

    pub fn deinit(self: *RansEncoder) void {
        self.output.deinit();
    }

    pub fn encode(self: *RansEncoder, sym: u8) !void {
        const freq = self.stats.freq[sym];
        const cum = self.stats.cum_freq[sym];

        if (freq == 0) return error.SymbolNotInAlphabet;

        const upper = (ANS_UPPER_BOUND / @as(u64, ANS_SCALE)) * @as(u64, freq);
        while (self.state >= upper) {
            const byte: u8 = @intCast(self.state & 0xFF);
            try self.output.append(byte);
            self.state >>= 8;
        }

        self.state = (self.state / @as(u64, freq)) * @as(u64, ANS_SCALE) + @as(u64, cum) + (self.state % @as(u64, freq));
    }

    pub fn flush(self: *RansEncoder) ![]u8 {
        var state = self.state;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            try self.output.append(@intCast(state & 0xFF));
            state >>= 8;
        }
        const result = try self.output.toOwnedSlice();
        std.mem.reverse(u8, result);
        return result;
    }
};

pub const RansDecoder = struct {
    state: u64,
    input: []const u8,
    pos: usize,
    stats: *const SymbolStats,
    table: AliasTable,

    pub fn init(encoded: []const u8, stats: *const SymbolStats) RansDecoder {
        var self = RansDecoder{
            .state = 0,
            .input = encoded,
            .pos = 0,
            .stats = stats,
            .table = undefined,
        };
        self.table.build(stats);

        var state: u64 = 0;
        var i: usize = 0;
        while (i < 8 and i < encoded.len) : (i += 1) {
            state = (state << 8) | encoded[i];
        }
        self.state = state;
        self.pos = @min(8, encoded.len);
        return self;
    }

    pub fn decode(self: *RansDecoder) ?u8 {
        if (self.state < ANS_LOWER_BOUND) return null;

        const slot: u32 = @intCast(self.state % @as(u64, ANS_SCALE));
        const sym = self.table.findSymbol(slot, self.stats);
        const freq = self.stats.freq[sym];
        const cum = self.stats.cum_freq[sym];

        self.state = @as(u64, freq) * (self.state / @as(u64, ANS_SCALE)) + @as(u64, slot) - @as(u64, cum);

        while (self.state < ANS_LOWER_BOUND and self.pos < self.input.len) {
            self.state = (self.state << 8) | self.input[self.pos];
            self.pos += 1;
        }

        return sym;
    }
};

pub fn compress(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) {
        const out = try allocator.alloc(u8, 4);
        std.mem.writeInt(u32, out[0..4], 0, .little);
        return out;
    }

    var stats = SymbolStats.init();
    stats.countFrequencies(data);

    const header_size: usize = 4 + MAX_SYMBOLS * 2;
    var header_buf: [4 + MAX_SYMBOLS * 2]u8 = undefined;
    std.mem.writeInt(u32, header_buf[0..4], @intCast(data.len), .little);
    _ = stats.serialize(header_buf[4..]);

    var encoder = RansEncoder.init(allocator, &stats);
    defer encoder.deinit();

    var i: usize = data.len;
    while (i > 0) {
        i -= 1;
        try encoder.encode(data[i]);
    }

    const encoded = try encoder.flush();
    defer allocator.free(encoded);

    const total = header_size + encoded.len;
    const out = try allocator.alloc(u8, total);
    @memcpy(out[0..header_size], &header_buf);
    @memcpy(out[header_size..], encoded);
    return out;
}

pub fn decompress(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const header_size: usize = 4 + MAX_SYMBOLS * 2;
    if (data.len < 4) return error.InvalidCompressedData;

    const orig_len = std.mem.readInt(u32, data[0..4], .little);
    if (orig_len == 0) return try allocator.alloc(u8, 0);

    if (data.len < header_size) return error.InvalidCompressedData;

    var stats = SymbolStats.init();
    if (!stats.deserialize(data[4..header_size])) return error.InvalidFrequencyTable;

    var valid_symbols: u32 = 0;
    for (stats.freq) |f| {
        if (f > 0) valid_symbols += 1;
    }
    if (valid_symbols == 0) return error.InvalidFrequencyTable;

    const encoded = data[header_size..];
    var decoder = RansDecoder.init(encoded, &stats);

    const out = try allocator.alloc(u8, orig_len);
    errdefer allocator.free(out);

    var j: usize = 0;
    while (j < orig_len) : (j += 1) {
        out[j] = decoder.decode() orelse return error.DecompressionFailed;
    }

    return out;
}

pub const WCBuffer = struct {
    buf: []align(64) u8,
    pos: usize,
    capacity: usize,
    allocator: std.mem.Allocator,
    flush_target: ?[]u8,
    flush_offset: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !WCBuffer {
        const aligned_cap = std.mem.alignForward(usize, capacity, 64);
        const buf = try allocator.alignedAlloc(u8, 64, aligned_cap);
        @memset(buf, 0);
        return Self{
            .buf = buf,
            .pos = 0,
            .capacity = aligned_cap,
            .allocator = allocator,
            .flush_target = null,
            .flush_offset = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buf);
        self.buf = &[_]u8{};
    }

    pub fn write(self: *Self, data: []const u8) usize {
        var written: usize = 0;
        while (written < data.len) {
            const available = self.capacity - self.pos;
            if (available == 0) {
                self.flushToTarget();
                continue;
            }
            const n = @min(data.len - written, available);
            @memcpy(self.buf[self.pos .. self.pos + n], data[written .. written + n]);
            self.pos += n;
            written += n;
            if (self.pos >= self.capacity) {
                self.flushToTarget();
            }
        }
        return written;
    }

    pub fn flushToTarget(self: *Self) void {
        if (self.flush_target) |target| {
            if (self.flush_offset < target.len) {
                const remaining = target.len - self.flush_offset;
                const n = @min(self.pos, remaining);
                if (n > 0) {
                    @memcpy(target[self.flush_offset .. self.flush_offset + n], self.buf[0..n]);
                    self.flush_offset += n;
                }
            }
        }
        @memset(self.buf[0..self.pos], 0);
        self.pos = 0;
    }

    pub fn bytesBuffered(self: *const WCBuffer) usize {
        return self.pos;
    }
};

test "symbol stats" {
    const testing = std.testing;
    const data = "aaabbc";
    var stats = SymbolStats.init();
    stats.countFrequencies(data);
    try testing.expect(stats.freq['a'] > stats.freq['b']);
    try testing.expect(stats.freq['b'] > stats.freq['c']);
    var sum: u32 = 0;
    for (stats.freq) |f| sum += f;
    try testing.expectEqual(ANS_SCALE, sum);
}

test "compress round-trip" {
    const testing = std.testing;
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const original = "hello world, this is a test of the rANS compressor!";
    const compressed = try compress(alloc, original);
    defer alloc.free(compressed);

    const decompressed = try decompress(alloc, compressed);
    defer alloc.free(decompressed);

    try testing.expectEqualStrings(original, decompressed);
}

test "wc buffer basic" {
    const testing = std.testing;
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var wb = try WCBuffer.init(alloc, 256);
    defer wb.deinit();
    const n = wb.write("hello");
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqual(@as(usize, 5), wb.bytesBuffered());
}
