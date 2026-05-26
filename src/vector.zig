const std = @import("std");

pub const Distance = enum {
    cosine,
    inner_product,
    euclidean,
    manhattan,
};

pub const SearchHit = struct {
    doc_id: u64,
    score: f32,
};

pub const VectorEntry = struct {
    doc_id: u64,
    norm: f32,
    vector: []f32,
};

pub const VectorIndex = struct {
    allocator: std.mem.Allocator,
    dim: u32,
    distance: Distance,
    entries: std.ArrayListUnmanaged(VectorEntry),
    id_to_idx: std.AutoHashMapUnmanaged(u64, usize),
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, dim: u32, distance: Distance) Self {
        return .{
            .allocator = allocator,
            .dim = dim,
            .distance = distance,
            .entries = .{},
            .id_to_idx = .{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.vector);
        }
        self.entries.deinit(self.allocator);
        self.id_to_idx.deinit(self.allocator);
    }

    pub fn upsert(self: *Self, doc_id: u64, vector: []const f32) !void {
        if (vector.len != self.dim) return error.VectorDimMismatch;
        self.mutex.lock();
        defer self.mutex.unlock();

        const dup = try self.allocator.dupe(f32, vector);
        errdefer self.allocator.free(dup);
        const norm = computeNorm(dup);

        const gop = try self.id_to_idx.getOrPut(self.allocator, doc_id);
        if (gop.found_existing) {
            const idx = gop.value_ptr.*;
            self.allocator.free(self.entries.items[idx].vector);
            self.entries.items[idx] = .{
                .doc_id = doc_id,
                .norm = norm,
                .vector = dup,
            };
        } else {
            const idx = self.entries.items.len;
            try self.entries.append(self.allocator, .{
                .doc_id = doc_id,
                .norm = norm,
                .vector = dup,
            });
            gop.value_ptr.* = idx;
        }
    }

    pub fn remove(self: *Self, doc_id: u64) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = self.id_to_idx.get(doc_id) orelse return false;
        const last_idx = self.entries.items.len - 1;
        self.allocator.free(self.entries.items[idx].vector);
        if (idx != last_idx) {
            self.entries.items[idx] = self.entries.items[last_idx];
            try self.id_to_idx.put(self.allocator, self.entries.items[idx].doc_id, idx);
        }
        _ = self.entries.pop();
        _ = self.id_to_idx.remove(doc_id);
        return true;
    }

    pub fn search(self: *Self, allocator: std.mem.Allocator, query: []const f32, top_k: usize) ![]SearchHit {
        if (query.len != self.dim) return error.VectorDimMismatch;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.items.len == 0) {
            return allocator.alloc(SearchHit, 0);
        }

        const q_norm = computeNorm(query);

        var heap = try MaxHeap.init(allocator, top_k);
        defer heap.deinit(allocator);

        for (self.entries.items) |entry| {
            const score = switch (self.distance) {
                .cosine => cosineSimilarity(entry.vector, query, entry.norm, q_norm),
                .inner_product => innerProduct(entry.vector, query),
                .euclidean => -euclideanDistance(entry.vector, query),
                .manhattan => -manhattanDistance(entry.vector, query),
            };
            try heap.push(allocator, .{ .doc_id = entry.doc_id, .score = score });
        }

        return heap.toSortedSlice(allocator);
    }

    pub fn vectorCount(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return @intCast(self.entries.items.len);
    }

    pub fn serialize(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const w = buf.writer();
        try w.writeInt(u32, 0x56_45_43_30, .little);
        try w.writeInt(u32, 1, .little);
        try w.writeInt(u32, self.dim, .little);
        try w.writeInt(u32, @intFromEnum(self.distance), .little);
        try w.writeInt(u64, self.entries.items.len, .little);
        for (self.entries.items) |entry| {
            try w.writeInt(u64, entry.doc_id, .little);
            try w.writeInt(u32, @bitCast(entry.norm), .little);
            for (entry.vector) |v| {
                try w.writeInt(u32, @bitCast(v), .little);
            }
        }
        return buf.toOwnedSlice();
    }

    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !Self {
        var stream = std.io.fixedBufferStream(data);
        const r = stream.reader();
        const magic = try r.readInt(u32, .little);
        if (magic != 0x56_45_43_30) return error.InvalidIndex;
        const version = try r.readInt(u32, .little);
        if (version != 1) return error.IncompatibleVersion;
        const dim = try r.readInt(u32, .little);
        const dist_val = try r.readInt(u32, .little);
        const distance: Distance = @enumFromInt(dist_val);
        const count = try r.readInt(u64, .little);
        var self = Self.init(allocator, dim, distance);
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const doc_id = try r.readInt(u64, .little);
            const norm_bits = try r.readInt(u32, .little);
            const norm: f32 = @bitCast(norm_bits);
            const vec = try allocator.alloc(f32, dim);
            errdefer allocator.free(vec);
            var j: u32 = 0;
            while (j < dim) : (j += 1) {
                const bits = try r.readInt(u32, .little);
                vec[j] = @bitCast(bits);
            }
            const idx = self.entries.items.len;
            try self.entries.append(self.allocator, .{
                .doc_id = doc_id,
                .norm = norm,
                .vector = vec,
            });
            try self.id_to_idx.put(self.allocator, doc_id, idx);
        }
        return self;
    }
};

const MaxHeap = struct {
    items: []SearchHit,
    len: usize,
    capacity: usize,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !MaxHeap {
        const c = if (capacity == 0) 1 else capacity;
        return .{
            .items = try allocator.alloc(SearchHit, c),
            .len = 0,
            .capacity = c,
        };
    }

    pub fn deinit(self: *MaxHeap, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
    }

    pub fn push(self: *MaxHeap, allocator: std.mem.Allocator, hit: SearchHit) !void {
        _ = allocator;
        if (self.len < self.capacity) {
            self.items[self.len] = hit;
            self.len += 1;
            self.bubbleUp(self.len - 1);
        } else if (self.items[0].score < hit.score) {
            self.items[0] = hit;
            self.bubbleDown(0);
        }
    }

    fn bubbleUp(self: *MaxHeap, start: usize) void {
        var i = start;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (self.items[parent].score > self.items[i].score) {
                std.mem.swap(SearchHit, &self.items[parent], &self.items[i]);
                i = parent;
            } else break;
        }
    }

    fn bubbleDown(self: *MaxHeap, start: usize) void {
        var i = start;
        while (true) {
            const left = 2 * i + 1;
            const right = 2 * i + 2;
            var smallest = i;
            if (left < self.len and self.items[left].score < self.items[smallest].score) smallest = left;
            if (right < self.len and self.items[right].score < self.items[smallest].score) smallest = right;
            if (smallest == i) break;
            std.mem.swap(SearchHit, &self.items[smallest], &self.items[i]);
            i = smallest;
        }
    }

    pub fn toSortedSlice(self: *MaxHeap, allocator: std.mem.Allocator) ![]SearchHit {
        const out = try allocator.alloc(SearchHit, self.len);
        @memcpy(out, self.items[0..self.len]);
        std.mem.sort(SearchHit, out, {}, descendingScore);
        return out;
    }
};

fn descendingScore(_: void, a: SearchHit, b: SearchHit) bool {
    return a.score > b.score;
}

fn computeNorm(v: []const f32) f32 {
    var sum: f32 = 0;
    for (v) |x| sum += x * x;
    return @sqrt(sum);
}

fn cosineSimilarity(a: []const f32, b: []const f32, a_norm: f32, b_norm: f32) f32 {
    if (a_norm <= 0 or b_norm <= 0) return 0;
    var dot: f32 = 0;
    for (a, 0..) |x, i| dot += x * b[i];
    return dot / (a_norm * b_norm);
}

fn innerProduct(a: []const f32, b: []const f32) f32 {
    var dot: f32 = 0;
    for (a, 0..) |x, i| dot += x * b[i];
    return dot;
}

fn euclideanDistance(a: []const f32, b: []const f32) f32 {
    var sum: f32 = 0;
    for (a, 0..) |x, i| {
        const d = x - b[i];
        sum += d * d;
    }
    return @sqrt(sum);
}

fn manhattanDistance(a: []const f32, b: []const f32) f32 {
    var sum: f32 = 0;
    for (a, 0..) |x, i| {
        sum += @abs(x - b[i]);
    }
    return sum;
}

pub fn hashEmbed(allocator: std.mem.Allocator, text: []const u8, dim: u32) ![]f32 {
    const out = try allocator.alloc(f32, dim);
    @memset(out, 0);
    if (text.len == 0) return out;

    var i: usize = 0;
    var count: u32 = 0;
    while (i < text.len) {
        const start = i;
        while (i < text.len) {
            const c = text[i];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == ',' or c == '.' or c == ';' or c == ':' or c == '?' or c == '!') {
                break;
            }
            i += 1;
        }
        if (i > start) {
            const token = text[start..i];
            const h1 = std.hash.Wyhash.hash(0x1, token);
            const h2 = std.hash.Wyhash.hash(0x2, token);
            const sign: f32 = if (h2 & 1 == 0) 1.0 else -1.0;
            const idx: usize = @intCast(h1 % dim);
            out[idx] += sign;
            count += 1;
        }
        while (i < text.len) {
            const c = text[i];
            if (c != ' ' and c != '\t' and c != '\n' and c != '\r' and c != ',' and c != '.' and c != ';' and c != ':' and c != '?' and c != '!') break;
            i += 1;
        }
    }
    const norm = computeNorm(out);
    if (norm > 0) {
        for (out) |*x| x.* /= norm;
    }
    return out;
}

test "vector cosine search" {
    const testing = std.testing;
    var idx = VectorIndex.init(testing.allocator, 3, .cosine);
    defer idx.deinit();
    try idx.upsert(1, &[_]f32{ 1.0, 0.0, 0.0 });
    try idx.upsert(2, &[_]f32{ 0.0, 1.0, 0.0 });
    try idx.upsert(3, &[_]f32{ 0.7, 0.7, 0.0 });

    const hits = try idx.search(testing.allocator, &[_]f32{ 1.0, 0.1, 0.0 }, 3);
    defer testing.allocator.free(hits);
    try testing.expect(hits.len == 3);
    try testing.expectEqual(@as(u64, 1), hits[0].doc_id);
}

test "vector serialize roundtrip" {
    const testing = std.testing;
    var idx = VectorIndex.init(testing.allocator, 4, .inner_product);
    defer idx.deinit();
    try idx.upsert(10, &[_]f32{ 1, 2, 3, 4 });
    try idx.upsert(20, &[_]f32{ 0, 0, 1, 0 });
    const bytes = try idx.serialize(testing.allocator);
    defer testing.allocator.free(bytes);
    var idx2 = try VectorIndex.deserialize(testing.allocator, bytes);
    defer idx2.deinit();
    try testing.expectEqual(@as(u64, 2), idx2.vectorCount());
    const hits = try idx2.search(testing.allocator, &[_]f32{ 1, 0, 0, 0 }, 2);
    defer testing.allocator.free(hits);
    try testing.expectEqual(@as(u64, 10), hits[0].doc_id);
}

test "hash embed" {
    const testing = std.testing;
    const emb = try hashEmbed(testing.allocator, "agdb is fast", 64);
    defer testing.allocator.free(emb);
    try testing.expectEqual(@as(usize, 64), emb.len);
    var any_nonzero = false;
    for (emb) |x| {
        if (x != 0) {
            any_nonzero = true;
            break;
        }
    }
    try testing.expect(any_nonzero);
}
