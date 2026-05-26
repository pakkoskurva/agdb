const std = @import("std");
const kv_mod = @import("kv.zig");
const bm25_mod = @import("bm25.zig");
const vector_mod = @import("vector.zig");
const record_mod = @import("record.zig");
const json_mod = @import("json.zig");

pub const DatabaseConfig = struct {
    data_dir: []const u8,
    embedding_dim: u32 = 256,
    distance: vector_mod.Distance = .cosine,
    bm25_k1: f32 = 1.5,
    bm25_b: f32 = 0.75,
    schema_id: u64 = 0x4147_4442_5343_4830,
    auto_embed: bool = true,
};

pub const QueryResult = struct {
    id: u64,
    score: f32,
    source: Source,
    record: record_mod.Record,

    pub const Source = enum { bm25, vector, hybrid };

    pub fn deinit(self: *QueryResult, allocator: std.mem.Allocator) void {
        self.record.deinit(allocator);
    }
};

pub const QueryResults = struct {
    items: []QueryResult,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *QueryResults) void {
        for (self.items) |*r| r.deinit(self.allocator);
        self.allocator.free(self.items);
    }
};

pub const Database = struct {
    allocator: std.mem.Allocator,
    config: DatabaseConfig,
    kv: *kv_mod.KvStore,
    bm25: bm25_mod.Bm25Index,
    vec: vector_mod.VectorIndex,
    next_id: u64,
    mutex: std.Thread.Mutex,
    data_dir_owned: []const u8,

    const Self = @This();

    const NEXT_ID_KEY = "__agdb_next_id";
    const BM25_KEY = "__agdb_bm25_state";
    const VECTOR_KEY = "__agdb_vector_state";

    pub fn open(allocator: std.mem.Allocator, config: DatabaseConfig) !*Self {
        try std.fs.cwd().makePath(config.data_dir);

        const data_dir_owned = try allocator.dupe(u8, config.data_dir);
        errdefer allocator.free(data_dir_owned);

        const kv_path = try std.fmt.allocPrint(allocator, "{s}/store.kv", .{config.data_dir});
        defer allocator.free(kv_path);

        const kv_store = try kv_mod.KvStore.open(allocator, kv_path, config.schema_id);
        errdefer kv_store.close();

        var bm25_index: bm25_mod.Bm25Index = undefined;
        if (try kv_store.get(allocator, BM25_KEY)) |bytes| {
            defer allocator.free(bytes);
            bm25_index = bm25_mod.Bm25Index.deserialize(allocator, bytes) catch bm25_mod.Bm25Index.init(allocator, .{ .k1 = config.bm25_k1, .b = config.bm25_b });
        } else {
            bm25_index = bm25_mod.Bm25Index.init(allocator, .{ .k1 = config.bm25_k1, .b = config.bm25_b });
        }
        errdefer bm25_index.deinit();

        var vec_index: vector_mod.VectorIndex = undefined;
        if (try kv_store.get(allocator, VECTOR_KEY)) |bytes| {
            defer allocator.free(bytes);
            vec_index = vector_mod.VectorIndex.deserialize(allocator, bytes) catch vector_mod.VectorIndex.init(allocator, config.embedding_dim, config.distance);
        } else {
            vec_index = vector_mod.VectorIndex.init(allocator, config.embedding_dim, config.distance);
        }
        errdefer vec_index.deinit();

        var next_id: u64 = 1;
        if (try kv_store.get(allocator, NEXT_ID_KEY)) |bytes| {
            defer allocator.free(bytes);
            if (bytes.len >= 8) {
                next_id = std.mem.readInt(u64, bytes[0..8], .little);
            }
        }

        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .config = config,
            .kv = kv_store,
            .bm25 = bm25_index,
            .vec = vec_index,
            .next_id = next_id,
            .mutex = .{},
            .data_dir_owned = data_dir_owned,
        };
        return self;
    }

    pub fn close(self: *Self) void {
        self.flushState() catch {};
        self.kv.close();
        self.bm25.deinit();
        self.vec.deinit();
        self.allocator.free(self.data_dir_owned);
        const a = self.allocator;
        a.destroy(self);
    }

    fn flushState(self: *Self) !void {
        const bm25_bytes = try self.bm25.serialize(self.allocator);
        defer self.allocator.free(bm25_bytes);
        try self.kv.put(BM25_KEY, bm25_bytes);

        const vec_bytes = try self.vec.serialize(self.allocator);
        defer self.allocator.free(vec_bytes);
        try self.kv.put(VECTOR_KEY, vec_bytes);

        var next_id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &next_id_bytes, self.next_id, .little);
        try self.kv.put(NEXT_ID_KEY, &next_id_bytes);
    }

    pub fn flush(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.flushState();
        try self.kv.flush();
    }

    pub fn nextId(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    pub fn put(self: *Self, record: record_mod.Record) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var assigned_id = record.id;
        if (assigned_id == 0) {
            assigned_id = self.next_id;
            self.next_id += 1;
        } else if (assigned_id >= self.next_id) {
            self.next_id = assigned_id + 1;
        }

        var stored = record;
        stored.id = assigned_id;
        if (stored.embedding == null and self.config.auto_embed and stored.body.len > 0) {
            stored.embedding = try vector_mod.hashEmbed(self.allocator, stored.body, self.config.embedding_dim);
        }

        const key_buf = try idKey(self.allocator, assigned_id);
        defer self.allocator.free(key_buf);

        const encoded = try record_mod.RecordWriter.encode(self.allocator, stored);
        defer self.allocator.free(encoded);

        try self.kv.put(key_buf, encoded);
        var kv_committed = true;
        errdefer if (kv_committed) {
            _ = self.kv.delete(key_buf) catch {};
        };

        try self.bm25.addDocument(assigned_id, stored.body);
        var bm25_committed = true;
        errdefer if (bm25_committed) {
            self.bm25.removeDocument(assigned_id) catch {};
        };

        if (stored.embedding) |emb| {
            if (emb.len == self.config.embedding_dim) {
                try self.vec.upsert(assigned_id, emb);
            }
        }

        _ = &kv_committed;
        _ = &bm25_committed;

        if (record.embedding == null and stored.embedding != null) {
            self.allocator.free(stored.embedding.?);
        }
        return assigned_id;
    }

    pub fn putBytes(self: *Self, kind: record_mod.RecordKind, id: u64, body: []const u8, tags: []const []const u8) !u64 {
        const tag_copy = try self.allocator.alloc([]const u8, tags.len);
        var tags_initialized: usize = 0;
        errdefer {
            var ti: usize = 0;
            while (ti < tags_initialized) : (ti += 1) {
                self.allocator.free(tag_copy[ti]);
            }
            self.allocator.free(tag_copy);
        }
        for (tags, 0..) |t, i| {
            tag_copy[i] = try self.allocator.dupe(u8, t);
            tags_initialized = i + 1;
        }
        const body_copy = try self.allocator.dupe(u8, body);
        errdefer self.allocator.free(body_copy);
        const now = std.time.microTimestamp();
        var rec = record_mod.Record{
            .id = id,
            .kind = kind,
            .created_at_us = now,
            .updated_at_us = now,
            .tags = tag_copy,
            .body = body_copy,
            .embedding = null,
        };
        defer rec.deinit(self.allocator);
        return try self.put(rec);
    }

    pub fn get(self: *Self, id: u64) !?record_mod.Record {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key_buf = try idKey(self.allocator, id);
        defer self.allocator.free(key_buf);

        const bytes = try self.kv.get(self.allocator, key_buf);
        if (bytes == null) return null;
        defer self.allocator.free(bytes.?);
        return try record_mod.RecordReader.decode(self.allocator, bytes.?);
    }

    pub fn delete(self: *Self, id: u64) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const key_buf = try idKey(self.allocator, id);
        defer self.allocator.free(key_buf);
        const existed = try self.kv.delete(key_buf);
        if (!existed) return false;
        try self.bm25.removeDocument(id);
        _ = try self.vec.remove(id);
        return true;
    }

    pub fn searchText(self: *Self, query: []const u8, top_k: usize) !QueryResults {
        self.mutex.lock();
        defer self.mutex.unlock();
        const hits = try self.bm25.search(self.allocator, query, top_k);
        defer self.allocator.free(hits);
        return self.materializeHitsBm25(hits);
    }

    pub fn searchVector(self: *Self, vector: []const f32, top_k: usize) !QueryResults {
        self.mutex.lock();
        defer self.mutex.unlock();
        const hits = try self.vec.search(self.allocator, vector, top_k);
        defer self.allocator.free(hits);
        return self.materializeHitsVector(hits);
    }

    pub fn searchHybrid(self: *Self, query: []const u8, vector: ?[]const f32, top_k: usize, alpha: f32) !QueryResults {
        self.mutex.lock();
        defer self.mutex.unlock();

        const text_hits = try self.bm25.search(self.allocator, query, top_k * 4);
        defer self.allocator.free(text_hits);

        var query_vec_owned: ?[]f32 = null;
        defer if (query_vec_owned) |v| self.allocator.free(v);

        const vector_query: []const f32 = blk: {
            if (vector) |v| break :blk v;
            if (self.config.auto_embed and query.len > 0) {
                query_vec_owned = try vector_mod.hashEmbed(self.allocator, query, self.config.embedding_dim);
                break :blk query_vec_owned.?;
            }
            break :blk &[_]f32{};
        };

        var vec_hits: []vector_mod.SearchHit = &[_]vector_mod.SearchHit{};
        defer if (vec_hits.len > 0) self.allocator.free(vec_hits);
        if (vector_query.len == self.config.embedding_dim) {
            vec_hits = try self.vec.search(self.allocator, vector_query, top_k * 4);
        }

        var combined = std.AutoHashMap(u64, f32).init(self.allocator);
        defer combined.deinit();

        const max_bm = blk: {
            var m: f32 = 0;
            for (text_hits) |h| if (h.score > m) {
                m = h.score;
            };
            break :blk m;
        };
        const max_vec = blk: {
            var m: f32 = 0;
            for (vec_hits) |h| if (h.score > m) {
                m = h.score;
            };
            break :blk m;
        };

        for (text_hits) |h| {
            const normalized = if (max_bm > 0) h.score / max_bm else 0;
            const gop = try combined.getOrPut(h.doc_id);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += alpha * normalized;
        }
        for (vec_hits) |h| {
            const normalized = if (max_vec > 0) h.score / max_vec else 0;
            const gop = try combined.getOrPut(h.doc_id);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += (1.0 - alpha) * normalized;
        }

        const ScoredId = struct {
            id: u64,
            score: f32,
            fn cmp(_: void, a: @This(), b: @This()) bool {
                return a.score > b.score;
            }
        };
        var all = try self.allocator.alloc(ScoredId, combined.count());
        defer self.allocator.free(all);
        var idx: usize = 0;
        var it = combined.iterator();
        while (it.next()) |e| {
            all[idx] = .{ .id = e.key_ptr.*, .score = e.value_ptr.* };
            idx += 1;
        }
        std.mem.sort(ScoredId, all, {}, ScoredId.cmp);
        const limit = @min(top_k, all.len);

        var out = try self.allocator.alloc(QueryResult, limit);
        var emitted: usize = 0;
        errdefer {
            for (out[0..emitted]) |*r| r.deinit(self.allocator);
            self.allocator.free(out);
        }
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            const rec = try self.loadRecord(all[i].id) orelse continue;
            out[emitted] = .{
                .id = all[i].id,
                .score = all[i].score,
                .source = .hybrid,
                .record = rec,
            };
            emitted += 1;
        }
        if (emitted < out.len) {
            out = try self.allocator.realloc(out, emitted);
        }
        return QueryResults{ .items = out, .allocator = self.allocator };
    }

    fn materializeHitsBm25(self: *Self, hits: []bm25_mod.SearchHit) !QueryResults {
        var out = try self.allocator.alloc(QueryResult, hits.len);
        var emitted: usize = 0;
        errdefer {
            for (out[0..emitted]) |*r| r.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (hits) |h| {
            const rec = try self.loadRecord(h.doc_id) orelse continue;
            out[emitted] = .{
                .id = h.doc_id,
                .score = h.score,
                .source = .bm25,
                .record = rec,
            };
            emitted += 1;
        }
        if (emitted < out.len) {
            out = try self.allocator.realloc(out, emitted);
        }
        return QueryResults{ .items = out, .allocator = self.allocator };
    }

    fn materializeHitsVector(self: *Self, hits: []vector_mod.SearchHit) !QueryResults {
        var out = try self.allocator.alloc(QueryResult, hits.len);
        var emitted: usize = 0;
        errdefer {
            for (out[0..emitted]) |*r| r.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (hits) |h| {
            const rec = try self.loadRecord(h.doc_id) orelse continue;
            out[emitted] = .{
                .id = h.doc_id,
                .score = h.score,
                .source = .vector,
                .record = rec,
            };
            emitted += 1;
        }
        if (emitted < out.len) {
            out = try self.allocator.realloc(out, emitted);
        }
        return QueryResults{ .items = out, .allocator = self.allocator };
    }

    fn loadRecord(self: *Self, id: u64) !?record_mod.Record {
        const key_buf = try idKey(self.allocator, id);
        defer self.allocator.free(key_buf);
        const bytes = try self.kv.get(self.allocator, key_buf);
        if (bytes == null) return null;
        defer self.allocator.free(bytes.?);
        return try record_mod.RecordReader.decode(self.allocator, bytes.?);
    }

    pub fn count(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.bm25.docCount();
    }

    pub fn compact(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.flushState();
        try self.kv.compact();
    }

    pub fn putJson(self: *Self, kind: record_mod.RecordKind, value: json_mod.Value) !u64 {
        var rec = try record_mod.fromJson(self.allocator, value, kind, 0);
        defer rec.deinit(self.allocator);
        return try self.put(rec);
    }

    pub fn getJson(self: *Self, allocator: std.mem.Allocator, id: u64) !?json_mod.Value {
        var rec = (try self.get(id)) orelse return null;
        defer rec.deinit(self.allocator);
        return try record_mod.toJson(allocator, rec);
    }
};

fn idKey(allocator: std.mem.Allocator, id: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "rec:{x:0>16}", .{id});
}

test "database basic put search delete" {
    const testing = std.testing;
    const tmp_dir = "agdb-test-db";
    std.fs.cwd().deleteTree(tmp_dir) catch {};
    try std.fs.cwd().makePath(tmp_dir);
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    var db = try Database.open(testing.allocator, .{
        .data_dir = tmp_dir,
        .embedding_dim = 64,
    });
    defer db.close();

    const tags = [_][]const u8{ "memory", "tdai" };
    const id1 = try db.putBytes(.document, 0, "agdb is a unified zig database", &tags);
    const id2 = try db.putBytes(.document, 0, "memory tdai four layer architecture", &tags);
    _ = id2;
    try testing.expect(id1 >= 1);

    var results = try db.searchText("unified zig", 5);
    defer results.deinit();
    try testing.expect(results.items.len >= 1);
    try testing.expectEqual(id1, results.items[0].id);

    var maybe_rec = try db.get(id1);
    try testing.expect(maybe_rec != null);
    defer if (maybe_rec) |*r| r.deinit(testing.allocator);
    try testing.expectEqualStrings("agdb is a unified zig database", maybe_rec.?.body);
}

test "database persistence" {
    const testing = std.testing;
    const tmp_dir = "agdb-test-db-persist";
    std.fs.cwd().deleteTree(tmp_dir) catch {};
    try std.fs.cwd().makePath(tmp_dir);
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    {
        var db = try Database.open(testing.allocator, .{
            .data_dir = tmp_dir,
            .embedding_dim = 32,
        });
        defer db.close();
        const empty_tags = [_][]const u8{};
        _ = try db.putBytes(.document, 0, "persistent record", &empty_tags);
        try db.flush();
    }
    {
        var db = try Database.open(testing.allocator, .{
            .data_dir = tmp_dir,
            .embedding_dim = 32,
        });
        defer db.close();
        var results = try db.searchText("persistent", 1);
        defer results.deinit();
        try testing.expect(results.items.len == 1);
    }
}
