const std = @import("std");
const tokenizer = @import("tokenizer.zig");

pub const Bm25Params = struct {
    k1: f32 = 1.5,
    b: f32 = 0.75,
    tokenize_opts: tokenizer.TokenizerOptions = .{ .lowercase = true, .min_token_len = 1 },
};

pub const Posting = struct {
    doc_id: u64,
    tf: u32,
};

pub const SearchHit = struct {
    doc_id: u64,
    score: f32,
};

pub const Bm25Index = struct {
    allocator: std.mem.Allocator,
    params: Bm25Params,
    postings: std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(Posting)),
    doc_lengths: std.AutoHashMapUnmanaged(u64, u32),
    doc_id_set: std.AutoHashMapUnmanaged(u64, void),
    total_terms: u64,
    total_docs: u64,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, params: Bm25Params) Self {
        return .{
            .allocator = allocator,
            .params = params,
            .postings = .{},
            .doc_lengths = .{},
            .doc_id_set = .{},
            .total_terms = 0,
            .total_docs = 0,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.postings.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.postings.deinit(self.allocator);
        self.doc_lengths.deinit(self.allocator);
        self.doc_id_set.deinit(self.allocator);
    }

    pub fn addDocument(self: *Self, doc_id: u64, text: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.removeDocumentLocked(doc_id);

        var tokens = try tokenizer.tokenize(self.allocator, text, self.params.tokenize_opts);
        defer tokens.deinit();

        if (tokens.items.len == 0) return;

        var tf_counts = std.AutoHashMap(u64, u32).init(self.allocator);
        defer tf_counts.deinit();

        var doc_len: u32 = 0;
        for (tokens.items) |tok| {
            const h = tokenizer.hashToken(tok.text);
            const gop = try tf_counts.getOrPut(h);
            if (gop.found_existing) {
                gop.value_ptr.* += 1;
            } else {
                gop.value_ptr.* = 1;
            }
            doc_len += 1;
        }

        var tf_it = tf_counts.iterator();
        while (tf_it.next()) |tf_entry| {
            const term_hash = tf_entry.key_ptr.*;
            const tf = tf_entry.value_ptr.*;
            const gop = try self.postings.getOrPut(self.allocator, term_hash);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{};
            }
            try gop.value_ptr.append(self.allocator, Posting{ .doc_id = doc_id, .tf = tf });
        }

        try self.doc_lengths.put(self.allocator, doc_id, doc_len);
        const id_gop = try self.doc_id_set.getOrPut(self.allocator, doc_id);
        if (!id_gop.found_existing) {
            self.total_docs += 1;
        }
        self.total_terms += doc_len;
    }

    fn removeDocumentLocked(self: *Self, doc_id: u64) !void {
        const length_entry = self.doc_lengths.get(doc_id) orelse return;
        var it = self.postings.iterator();
        while (it.next()) |entry| {
            var i: usize = 0;
            while (i < entry.value_ptr.items.len) {
                if (entry.value_ptr.items[i].doc_id == doc_id) {
                    _ = entry.value_ptr.swapRemove(i);
                    continue;
                }
                i += 1;
            }
        }
        _ = self.doc_lengths.remove(doc_id);
        _ = self.doc_id_set.remove(doc_id);
        if (self.total_docs > 0) self.total_docs -= 1;
        if (self.total_terms >= length_entry) {
            self.total_terms -= length_entry;
        } else {
            self.total_terms = 0;
        }
    }

    pub fn removeDocument(self: *Self, doc_id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.removeDocumentLocked(doc_id);
    }

    pub fn search(self: *Self, allocator: std.mem.Allocator, query: []const u8, top_k: usize) ![]SearchHit {
        self.mutex.lock();
        defer self.mutex.unlock();

        var q_tokens = try tokenizer.tokenize(allocator, query, self.params.tokenize_opts);
        defer q_tokens.deinit();
        if (q_tokens.items.len == 0 or self.total_docs == 0) {
            return allocator.alloc(SearchHit, 0);
        }

        const avgdl: f32 = if (self.total_docs == 0) 1.0 else @as(f32, @floatFromInt(self.total_terms)) / @as(f32, @floatFromInt(self.total_docs));
        const N: f32 = @floatFromInt(self.total_docs);

        var scores = std.AutoHashMap(u64, f32).init(allocator);
        defer scores.deinit();

        var seen_terms = std.AutoHashMap(u64, void).init(allocator);
        defer seen_terms.deinit();

        for (q_tokens.items) |tok| {
            const term_hash = tokenizer.hashToken(tok.text);
            const seen_gop = try seen_terms.getOrPut(term_hash);
            if (seen_gop.found_existing) continue;
            const postings = self.postings.get(term_hash) orelse continue;
            const df: f32 = @floatFromInt(postings.items.len);
            if (df == 0) continue;
            const idf_num = N - df + 0.5;
            const idf_den = df + 0.5;
            const idf = @log(@max(idf_num / idf_den, 1e-6) + 1.0);

            for (postings.items) |p| {
                const dl: f32 = @floatFromInt(self.doc_lengths.get(p.doc_id) orelse 1);
                const tf_f: f32 = @floatFromInt(p.tf);
                const denom = tf_f + self.params.k1 * (1.0 - self.params.b + self.params.b * (dl / avgdl));
                const score_contribution = idf * (tf_f * (self.params.k1 + 1.0)) / @max(denom, 1e-6);
                const gop = try scores.getOrPut(p.doc_id);
                if (!gop.found_existing) {
                    gop.value_ptr.* = 0;
                }
                gop.value_ptr.* += score_contribution;
            }
        }

        var all_hits = try allocator.alloc(SearchHit, scores.count());
        var i: usize = 0;
        var s_it = scores.iterator();
        while (s_it.next()) |s| {
            all_hits[i] = SearchHit{ .doc_id = s.key_ptr.*, .score = s.value_ptr.* };
            i += 1;
        }

        std.mem.sort(SearchHit, all_hits, {}, lessThan);

        const limit = @min(top_k, all_hits.len);
        if (limit == all_hits.len) return all_hits;

        const out = try allocator.alloc(SearchHit, limit);
        @memcpy(out, all_hits[0..limit]);
        allocator.free(all_hits);
        return out;
    }

    fn lessThan(_: void, a: SearchHit, b: SearchHit) bool {
        return a.score > b.score;
    }

    pub fn docCount(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.total_docs;
    }

    pub fn termCount(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.postings.count();
    }

    pub fn serialize(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const w = buf.writer();
        try w.writeInt(u32, 0x42_4D_32_35, .little);
        try w.writeInt(u32, 1, .little);
        try w.writeInt(u32, @bitCast(self.params.k1), .little);
        try w.writeInt(u32, @bitCast(self.params.b), .little);
        try w.writeInt(u64, self.total_docs, .little);
        try w.writeInt(u64, self.total_terms, .little);
        try w.writeInt(u64, self.doc_lengths.count(), .little);
        var dl_it = self.doc_lengths.iterator();
        while (dl_it.next()) |e| {
            try w.writeInt(u64, e.key_ptr.*, .little);
            try w.writeInt(u32, e.value_ptr.*, .little);
        }
        try w.writeInt(u64, self.postings.count(), .little);
        var p_it = self.postings.iterator();
        while (p_it.next()) |e| {
            try w.writeInt(u64, e.key_ptr.*, .little);
            try w.writeInt(u32, @intCast(e.value_ptr.items.len), .little);
            for (e.value_ptr.items) |posting| {
                try w.writeInt(u64, posting.doc_id, .little);
                try w.writeInt(u32, posting.tf, .little);
            }
        }
        return buf.toOwnedSlice();
    }

    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !Self {
        var stream = std.io.fixedBufferStream(data);
        const r = stream.reader();
        const magic = try r.readInt(u32, .little);
        if (magic != 0x42_4D_32_35) return error.InvalidIndex;
        const version = try r.readInt(u32, .little);
        if (version != 1) return error.IncompatibleVersion;
        const k1_bits = try r.readInt(u32, .little);
        const b_bits = try r.readInt(u32, .little);
        const k1: f32 = @bitCast(k1_bits);
        const b: f32 = @bitCast(b_bits);
        var self = Self.init(allocator, .{ .k1 = k1, .b = b });
        self.total_docs = try r.readInt(u64, .little);
        self.total_terms = try r.readInt(u64, .little);
        const doc_len_count = try r.readInt(u64, .little);
        var i: u64 = 0;
        while (i < doc_len_count) : (i += 1) {
            const id = try r.readInt(u64, .little);
            const len = try r.readInt(u32, .little);
            try self.doc_lengths.put(self.allocator, id, len);
            try self.doc_id_set.put(self.allocator, id, {});
        }
        const term_count = try r.readInt(u64, .little);
        i = 0;
        while (i < term_count) : (i += 1) {
            const term_hash = try r.readInt(u64, .little);
            const plen = try r.readInt(u32, .little);
            var list: std.ArrayListUnmanaged(Posting) = .{};
            try list.ensureTotalCapacity(self.allocator, plen);
            var j: u32 = 0;
            while (j < plen) : (j += 1) {
                const doc_id = try r.readInt(u64, .little);
                const tf = try r.readInt(u32, .little);
                list.appendAssumeCapacity(.{ .doc_id = doc_id, .tf = tf });
            }
            try self.postings.put(self.allocator, term_hash, list);
        }
        return self;
    }
};

test "bm25 basic" {
    const testing = std.testing;
    var idx = Bm25Index.init(testing.allocator, .{});
    defer idx.deinit();
    try idx.addDocument(1, "the quick brown fox jumps over the lazy dog");
    try idx.addDocument(2, "agdb is a fast unified database in zig");
    try idx.addDocument(3, "zig zig zig fast fast fast");

    const hits = try idx.search(testing.allocator, "zig fast", 10);
    defer testing.allocator.free(hits);
    try testing.expect(hits.len >= 1);
    try testing.expectEqual(@as(u64, 3), hits[0].doc_id);
}

test "bm25 remove" {
    const testing = std.testing;
    var idx = Bm25Index.init(testing.allocator, .{});
    defer idx.deinit();
    try idx.addDocument(1, "hello world");
    try idx.addDocument(2, "hello agdb");
    try idx.removeDocument(1);
    const hits = try idx.search(testing.allocator, "hello", 5);
    defer testing.allocator.free(hits);
    try testing.expect(hits.len == 1);
    try testing.expectEqual(@as(u64, 2), hits[0].doc_id);
}

test "bm25 serialize roundtrip" {
    const testing = std.testing;
    var idx = Bm25Index.init(testing.allocator, .{});
    defer idx.deinit();
    try idx.addDocument(1, "alpha bravo charlie");
    try idx.addDocument(2, "bravo charlie delta");
    const bytes = try idx.serialize(testing.allocator);
    defer testing.allocator.free(bytes);
    var idx2 = try Bm25Index.deserialize(testing.allocator, bytes);
    defer idx2.deinit();
    const hits = try idx2.search(testing.allocator, "bravo", 5);
    defer testing.allocator.free(hits);
    try testing.expect(hits.len == 2);
}
