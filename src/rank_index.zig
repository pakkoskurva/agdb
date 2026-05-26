const std = @import("std");
const Allocator = std.mem.Allocator;

const tokenizer_mod = @import("tokenizer.zig");
const vector_mod = @import("vector.zig");
const ssi_mod = @import("ssi.zig");
const ranker_mod = @import("ranker.zig");
const tensor_mod = @import("tensor.zig");
const types = @import("types.zig");
const io = @import("io.zig");

pub const RankIndexConfig = struct {
    num_ngrams: usize = 3,
    num_hash_functions: usize = 16,
    seed: u64 = 0x4147_4442_5252_414B,
    embedding_dim: u32 = 256,
};

pub const RankIndex = struct {
    allocator: Allocator,
    ssi: ssi_mod.SSI,
    ranker: ranker_mod.Ranker,
    config: RankIndexConfig,
    doc_token_map: std.AutoHashMapUnmanaged(u64, []u32),
    doc_positions: std.AutoHashMapUnmanaged(u64, u64),
    next_position: u64,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: Allocator, config: RankIndexConfig) !Self {
        var ssi = ssi_mod.SSI.init(allocator);
        errdefer ssi.deinit();
        var ranker = try ranker_mod.Ranker.init(allocator, config.num_ngrams, config.num_hash_functions, config.seed);
        errdefer ranker.deinit();
        return .{
            .allocator = allocator,
            .ssi = ssi,
            .ranker = ranker,
            .config = config,
            .doc_token_map = .{},
            .doc_positions = .{},
            .next_position = 1,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.doc_token_map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.doc_token_map.deinit(self.allocator);
        self.doc_positions.deinit(self.allocator);
        self.ssi.deinit();
        self.ranker.deinit();
    }

    pub fn addDocument(self: *Self, doc_id: u64, body: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.doc_token_map.get(doc_id)) |existing| {
            self.allocator.free(existing);
            _ = self.doc_token_map.remove(doc_id);
            _ = self.doc_positions.remove(doc_id);
        }

        const tokens = try tokenizeToU32(self.allocator, body);
        errdefer self.allocator.free(tokens);
        if (tokens.len == 0) {
            self.allocator.free(tokens);
            return;
        }

        const position = self.next_position;
        self.next_position += 1;
        try self.ssi.addSequence(tokens, position, true);
        try self.doc_token_map.put(self.allocator, doc_id, tokens);
        try self.doc_positions.put(self.allocator, doc_id, position);
    }

    pub fn removeDocument(self: *Self, doc_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.doc_token_map.fetchRemove(doc_id)) |kv| {
            self.allocator.free(kv.value);
        }
        _ = self.doc_positions.remove(doc_id);
    }

    pub fn rerank(self: *Self, query: []const u8, candidates: []u64, scores: []f32, allocator: Allocator) !void {
        if (candidates.len != scores.len) return error.LengthMismatch;
        if (candidates.len == 0) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        const query_tokens = try tokenizeToU32(allocator, query);
        defer allocator.free(query_tokens);

        var i: usize = 0;
        while (i < candidates.len) : (i += 1) {
            const doc_tokens = self.doc_token_map.get(candidates[i]) orelse continue;
            const ngram_score = try self.ranker.scoreSequenceWithQuery(doc_tokens, query_tokens, &self.ssi);
            if (!std.math.isNan(ngram_score) and !std.math.isInf(ngram_score)) {
                scores[i] = scores[i] * 0.5 + ngram_score * 0.5;
            }
        }
    }

    pub fn topK(self: *Self, query: []const u8, k: usize, allocator: Allocator) ![]types.RankedSegment {
        self.mutex.lock();
        defer self.mutex.unlock();
        const query_tokens = try tokenizeToU32(allocator, query);
        defer allocator.free(query_tokens);
        return try self.ranker.topKHeap(&self.ssi, query_tokens, k, allocator);
    }

    pub fn jaccardSimilarity(self: *Self, doc_id_a: u64, doc_id_b: u64) f32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const tokens_a = self.doc_token_map.get(doc_id_a) orelse return 0.0;
        const tokens_b = self.doc_token_map.get(doc_id_b) orelse return 0.0;
        const sig_a = self.ranker.minHashSignature(tokens_a) catch return 0.0;
        defer self.allocator.free(sig_a);
        const sig_b = self.ranker.minHashSignature(tokens_b) catch return 0.0;
        defer self.allocator.free(sig_b);
        return ranker_mod.Ranker.jaccardSimilarityFromSignatures(sig_a, sig_b);
    }

    pub fn documentCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.doc_token_map.count();
    }
};

pub fn tokenizeToU32(allocator: Allocator, body: []const u8) ![]u32 {
    var list = std.ArrayListUnmanaged(u32){};
    errdefer list.deinit(allocator);
    var token_list = try tokenizer_mod.tokenize(allocator, body, .{});
    defer token_list.deinit();
    for (token_list.items) |tok| {
        const hash = io.stableHashU32(tok.text, 0x4147_4442_544F_4B45);
        try list.append(allocator, hash);
    }
    return try list.toOwnedSlice(allocator);
}

pub fn embedToTensor(allocator: Allocator, body: []const u8, dim: u32) !tensor_mod.Tensor {
    const vec = try vector_mod.hashEmbed(allocator, body, dim);
    defer allocator.free(vec);
    var t = try tensor_mod.Tensor.init(allocator, &.{dim});
    errdefer t.deinit();
    var i: usize = 0;
    while (i < dim) : (i += 1) t.data[i] = vec[i];
    return t;
}

test "RankIndex add and topK" {
    const a = std.testing.allocator;
    var ri = try RankIndex.init(a, .{});
    defer ri.deinit();
    try ri.addDocument(1, "vector embeddings for similarity search");
    try ri.addDocument(2, "graph indexes for connected data");
    try ri.addDocument(3, "vector and graph hybrid databases");
    const result = try ri.topK("vector search", 2, a);
    defer {
        for (result) |*r| {
            var m = r.*;
            m.deinit(a);
        }
        a.free(result);
    }
    try std.testing.expect(result.len <= 2);
}

test "RankIndex rerank preserves length" {
    const a = std.testing.allocator;
    var ri = try RankIndex.init(a, .{});
    defer ri.deinit();
    try ri.addDocument(10, "alpha beta gamma");
    try ri.addDocument(11, "delta epsilon zeta");
    var ids = [_]u64{ 10, 11 };
    var scores = [_]f32{ 0.5, 0.5 };
    try ri.rerank("alpha", &ids, &scores, a);
    try std.testing.expectEqual(@as(usize, 2), ids.len);
}

test "embedToTensor produces correct shape" {
    const a = std.testing.allocator;
    var t = try embedToTensor(a, "hello world", 64);
    defer t.deinit();
    try std.testing.expectEqual(@as(usize, 64), t.shape.totalSize());
}
