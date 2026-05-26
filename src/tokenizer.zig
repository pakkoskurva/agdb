const std = @import("std");

pub const TokenizerOptions = struct {
    lowercase: bool = true,
    min_token_len: usize = 1,
    max_token_len: usize = 64,
    ngram_min: usize = 1,
    ngram_max: usize = 1,
    drop_stopwords: bool = false,
};

pub const Token = struct {
    text: []const u8,
    position: u32,
    byte_offset: u32,
    byte_length: u32,
};

pub const TokenList = struct {
    items: []Token,
    bytes_owned: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *TokenList) void {
        if (self.bytes_owned.len != 0) self.allocator.free(self.bytes_owned);
        if (self.items.len != 0) self.allocator.free(self.items);
        self.bytes_owned = &[_]u8{};
        self.items = &[_]Token{};
    }
};

const stopwords_en = [_][]const u8{
    "a",   "an",  "the", "and", "or", "but", "if", "then", "else",
    "of",  "in",  "on",  "to",  "is", "are", "as", "by",   "for",
    "with","from","at",  "be",  "it", "this","that","was","were",
    "has", "have","had", "i",   "you","he",  "she","we",  "they",
};

pub fn isStopword(token: []const u8) bool {
    for (stopwords_en) |sw| {
        if (std.mem.eql(u8, sw, token)) return true;
    }
    return false;
}

fn isAlphaNum(cp: u21) bool {
    if (cp >= 'a' and cp <= 'z') return true;
    if (cp >= 'A' and cp <= 'Z') return true;
    if (cp >= '0' and cp <= '9') return true;
    if (cp == '_') return true;
    if (cp >= 0x80) return true;
    return false;
}

fn toLowerCodepoint(cp: u21) u21 {
    if (cp >= 'A' and cp <= 'Z') return cp + 32;
    if (cp >= 0xC0 and cp <= 0xDE and cp != 0xD7) return cp + 32;
    if (cp == 0x0150) return 0x0151;
    if (cp == 0x0170) return 0x0171;
    return cp;
}

fn utf8DecodeNext(bytes: []const u8, pos: *usize) ?u21 {
    if (pos.* >= bytes.len) return null;
    const first = bytes[pos.*];
    if (first < 0x80) {
        pos.* += 1;
        return @as(u21, first);
    }
    const len = std.unicode.utf8ByteSequenceLength(first) catch {
        pos.* += 1;
        return 0xFFFD;
    };
    if (pos.* + len > bytes.len) {
        pos.* = bytes.len;
        return 0xFFFD;
    }
    const cp = std.unicode.utf8Decode(bytes[pos.* .. pos.* + len]) catch {
        pos.* += 1;
        return 0xFFFD;
    };
    pos.* += len;
    return cp;
}

fn writeCodepoint(buf: *std.ArrayList(u8), cp: u21) !void {
    var tmp: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &tmp) catch {
        try buf.appendSlice("?");
        return;
    };
    try buf.appendSlice(tmp[0..n]);
}

pub fn tokenize(allocator: std.mem.Allocator, text: []const u8, opts: TokenizerOptions) !TokenList {
    var tokens = std.ArrayList(Token).init(allocator);
    errdefer tokens.deinit();
    var bytes = std.ArrayList(u8).init(allocator);
    errdefer bytes.deinit();
    var offsets = std.ArrayList(struct { start: u32, len: u32 }).init(allocator);
    defer offsets.deinit();

    var pos: usize = 0;
    var position: u32 = 0;

    while (pos < text.len) {
        var byte_start = pos;
        var cp = utf8DecodeNext(text, &pos) orelse break;
        while (!isAlphaNum(cp)) {
            byte_start = pos;
            cp = utf8DecodeNext(text, &pos) orelse {
                return finalizeTokens(allocator, &tokens, &bytes, &offsets);
            };
        }
        const token_start = byte_start;
        const out_start: u32 = @intCast(bytes.items.len);

        if (opts.lowercase) {
            try writeCodepoint(&bytes, toLowerCodepoint(cp));
        } else {
            try writeCodepoint(&bytes, cp);
        }
        while (pos < text.len) {
            const save = pos;
            const next_cp = utf8DecodeNext(text, &pos) orelse {
                break;
            };
            if (!isAlphaNum(next_cp)) {
                pos = save;
                break;
            }
            if (opts.lowercase) {
                try writeCodepoint(&bytes, toLowerCodepoint(next_cp));
            } else {
                try writeCodepoint(&bytes, next_cp);
            }
        }

        const out_len: u32 = @intCast(bytes.items.len - out_start);
        const utf8_len: u32 = @intCast(pos - token_start);
        if (out_len < opts.min_token_len or out_len > opts.max_token_len) {
            bytes.shrinkRetainingCapacity(out_start);
            continue;
        }
        try offsets.append(.{ .start = out_start, .len = out_len });
        try tokens.append(.{
            .text = undefined,
            .position = position,
            .byte_offset = @intCast(token_start),
            .byte_length = utf8_len,
        });
        position += 1;
    }
    return finalizeTokens(allocator, &tokens, &bytes, &offsets);
}

fn finalizeTokens(
    allocator: std.mem.Allocator,
    tokens: *std.ArrayList(Token),
    bytes: *std.ArrayList(u8),
    offsets: anytype,
) !TokenList {
    const items = try tokens.toOwnedSlice();
    errdefer allocator.free(items);
    const bytes_owned = try bytes.toOwnedSlice();
    errdefer allocator.free(bytes_owned);

    for (items, 0..) |*t, i| {
        const meta = offsets.items[i];
        t.text = bytes_owned[meta.start .. meta.start + meta.len];
    }

    return TokenList{
        .items = items,
        .bytes_owned = bytes_owned,
        .allocator = allocator,
    };
}

pub fn tokenizeAndNgram(allocator: std.mem.Allocator, text: []const u8, opts: TokenizerOptions) !TokenList {
    var base = try tokenize(allocator, text, opts);
    if (opts.ngram_max <= 1) {
        if (opts.drop_stopwords) {
            defer base.deinit();
            return filterStopwords(allocator, &base);
        }
        return base;
    }
    defer base.deinit();

    var out_tokens = std.ArrayList(Token).init(allocator);
    errdefer out_tokens.deinit();
    var out_bytes = std.ArrayList(u8).init(allocator);
    errdefer out_bytes.deinit();
    var offsets = std.ArrayList(struct { start: u32, len: u32 }).init(allocator);
    defer offsets.deinit();

    var position: u32 = 0;
    var n: usize = opts.ngram_min;
    if (n == 0) n = 1;
    while (n <= opts.ngram_max) : (n += 1) {
        if (n == 0) continue;
        if (base.items.len < n) break;
        var i: usize = 0;
        while (i + n <= base.items.len) : (i += 1) {
            if (opts.drop_stopwords) {
                var only_stop = true;
                var k: usize = 0;
                while (k < n) : (k += 1) {
                    if (!isStopword(base.items[i + k].text)) {
                        only_stop = false;
                        break;
                    }
                }
                if (only_stop) continue;
            }
            const start: u32 = @intCast(out_bytes.items.len);
            var k: usize = 0;
            while (k < n) : (k += 1) {
                if (k > 0) try out_bytes.append(' ');
                try out_bytes.appendSlice(base.items[i + k].text);
            }
            const len: u32 = @intCast(out_bytes.items.len - start);
            try offsets.append(.{ .start = start, .len = len });
            try out_tokens.append(.{
                .text = undefined,
                .position = position,
                .byte_offset = base.items[i].byte_offset,
                .byte_length = base.items[i + n - 1].byte_offset + base.items[i + n - 1].byte_length - base.items[i].byte_offset,
            });
            position += 1;
        }
    }
    return finalizeTokens(allocator, &out_tokens, &out_bytes, &offsets);
}

fn filterStopwords(allocator: std.mem.Allocator, src: *TokenList) !TokenList {
    var out_tokens = std.ArrayList(Token).init(allocator);
    errdefer out_tokens.deinit();
    var out_bytes = std.ArrayList(u8).init(allocator);
    errdefer out_bytes.deinit();
    var offsets = std.ArrayList(struct { start: u32, len: u32 }).init(allocator);
    defer offsets.deinit();

    var position: u32 = 0;
    for (src.items) |t| {
        if (isStopword(t.text)) continue;
        const start: u32 = @intCast(out_bytes.items.len);
        try out_bytes.appendSlice(t.text);
        const len: u32 = @intCast(out_bytes.items.len - start);
        try offsets.append(.{ .start = start, .len = len });
        try out_tokens.append(.{
            .text = undefined,
            .position = position,
            .byte_offset = t.byte_offset,
            .byte_length = t.byte_length,
        });
        position += 1;
    }
    return finalizeTokens(allocator, &out_tokens, &out_bytes, &offsets);
}

pub fn hashToken(token: []const u8) u64 {
    return std.hash.Wyhash.hash(0xa9db_2611_5b3e_77c0, token);
}

test "tokenize ascii" {
    const testing = std.testing;
    var tl = try tokenize(testing.allocator, "Hello, World! This is AGDB.", .{});
    defer tl.deinit();
    try testing.expectEqual(@as(usize, 5), tl.items.len);
    try testing.expectEqualStrings("hello", tl.items[0].text);
    try testing.expectEqualStrings("agdb", tl.items[4].text);
}

test "tokenize bigrams" {
    const testing = std.testing;
    var tl = try tokenizeAndNgram(testing.allocator, "memory is fast", .{ .ngram_min = 1, .ngram_max = 2 });
    defer tl.deinit();
    try testing.expect(tl.items.len >= 3);
}

test "stopword filter" {
    const testing = std.testing;
    var tl = try tokenizeAndNgram(testing.allocator, "the cat and the dog", .{ .drop_stopwords = true });
    defer tl.deinit();
    for (tl.items) |t| {
        try testing.expect(!isStopword(t.text));
    }
}
