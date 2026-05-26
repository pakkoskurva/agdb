const std = @import("std");
const json = @import("json.zig");

pub const RecordKind = enum(u8) {
    document = 0,
    conversation = 1,
    scene = 2,
    persona = 3,
    custom = 255,
};

pub const Record = struct {
    id: u64,
    kind: RecordKind,
    created_at_us: i64,
    updated_at_us: i64,
    tags: []const []const u8,
    body: []const u8,
    embedding: ?[]const f32,

    pub fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        for (self.tags) |t| allocator.free(t);
        allocator.free(self.tags);
        allocator.free(self.body);
        if (self.embedding) |e| allocator.free(e);
    }

    pub fn dupeOwned(self: Record, allocator: std.mem.Allocator) !Record {
        const new_tags = try allocator.alloc([]const u8, self.tags.len);
        errdefer allocator.free(new_tags);
        var owned_tags: usize = 0;
        errdefer {
            var k: usize = 0;
            while (k < owned_tags) : (k += 1) allocator.free(new_tags[k]);
        }
        for (self.tags, 0..) |t, i| {
            new_tags[i] = try allocator.dupe(u8, t);
            owned_tags += 1;
        }
        const new_body = try allocator.dupe(u8, self.body);
        errdefer allocator.free(new_body);
        const new_emb: ?[]f32 = if (self.embedding) |e| try allocator.dupe(f32, e) else null;
        return Record{
            .id = self.id,
            .kind = self.kind,
            .created_at_us = self.created_at_us,
            .updated_at_us = self.updated_at_us,
            .tags = new_tags,
            .body = new_body,
            .embedding = new_emb,
        };
    }
};

const RECORD_MAGIC: u32 = 0x52_45_43_31;

pub const RecordWriter = struct {
    pub fn encode(allocator: std.mem.Allocator, record: Record) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const w = buf.writer();
        try w.writeInt(u32, RECORD_MAGIC, .little);
        try w.writeInt(u8, @intFromEnum(record.kind), .little);
        try w.writeInt(u8, 0, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u64, record.id, .little);
        try w.writeInt(i64, record.created_at_us, .little);
        try w.writeInt(i64, record.updated_at_us, .little);
        try w.writeInt(u32, @intCast(record.tags.len), .little);
        for (record.tags) |t| {
            if (t.len > std.math.maxInt(u16)) return error.TagTooLong;
            try w.writeInt(u16, @intCast(t.len), .little);
            try w.writeAll(t);
        }
        try w.writeInt(u32, @intCast(record.body.len), .little);
        try w.writeAll(record.body);
        if (record.embedding) |e| {
            try w.writeInt(u32, @intCast(e.len), .little);
            for (e) |x| {
                try w.writeInt(u32, @bitCast(x), .little);
            }
        } else {
            try w.writeInt(u32, 0, .little);
        }
        return buf.toOwnedSlice();
    }
};

pub const RecordReader = struct {
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !Record {
        var stream = std.io.fixedBufferStream(data);
        const r = stream.reader();
        const magic = try r.readInt(u32, .little);
        if (magic != RECORD_MAGIC) return error.InvalidRecord;
        const kind_val = try r.readInt(u8, .little);
        _ = try r.readInt(u8, .little);
        _ = try r.readInt(u16, .little);
        const id = try r.readInt(u64, .little);
        const created = try r.readInt(i64, .little);
        const updated = try r.readInt(i64, .little);
        const tag_count = try r.readInt(u32, .little);
        const tags = try allocator.alloc([]const u8, tag_count);
        errdefer {
            for (tags) |t| allocator.free(t);
            allocator.free(tags);
        }
        var i: u32 = 0;
        while (i < tag_count) : (i += 1) {
            const tlen = try r.readInt(u16, .little);
            const t = try allocator.alloc(u8, tlen);
            errdefer allocator.free(t);
            try r.readNoEof(t);
            tags[i] = t;
        }
        const body_len = try r.readInt(u32, .little);
        const body = try allocator.alloc(u8, body_len);
        errdefer allocator.free(body);
        try r.readNoEof(body);
        const emb_len = try r.readInt(u32, .little);
        var embedding: ?[]f32 = null;
        if (emb_len > 0) {
            const emb = try allocator.alloc(f32, emb_len);
            errdefer allocator.free(emb);
            var j: u32 = 0;
            while (j < emb_len) : (j += 1) {
                const bits = try r.readInt(u32, .little);
                emb[j] = @bitCast(bits);
            }
            embedding = emb;
        }
        return Record{
            .id = id,
            .kind = @enumFromInt(kind_val),
            .created_at_us = created,
            .updated_at_us = updated,
            .tags = tags,
            .body = body,
            .embedding = embedding,
        };
    }
};

pub fn fromJson(allocator: std.mem.Allocator, value: json.Value, kind: RecordKind, id: u64) !Record {
    if (value != .object) return error.InvalidRecord;
    const now: i64 = std.time.microTimestamp();

    var tags_list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (tags_list.items) |t| allocator.free(t);
        tags_list.deinit();
    }

    if (value.getField("tags")) |t_val| {
        if (t_val == .array) {
            for (t_val.array) |tag| {
                if (tag.asString()) |s| {
                    try tags_list.append(try allocator.dupe(u8, s));
                }
            }
        }
    }

    var body_str: []const u8 = "";
    if (value.getField("body")) |b| {
        if (b.asString()) |s| body_str = s;
    } else if (value.getField("content")) |b| {
        if (b.asString()) |s| body_str = s;
    } else if (value.getField("text")) |b| {
        if (b.asString()) |s| body_str = s;
    }

    const body = try allocator.dupe(u8, body_str);
    errdefer allocator.free(body);

    var emb: ?[]f32 = null;
    if (value.getField("embedding")) |e| {
        if (e == .array) {
            const arr = try allocator.alloc(f32, e.array.len);
            errdefer allocator.free(arr);
            for (e.array, 0..) |item, i| {
                if (item.asFloat()) |f| arr[i] = @floatCast(f) else arr[i] = 0;
            }
            emb = arr;
        }
    }

    const created = if (value.getField("created_at_us")) |c| (c.asInt() orelse now) else now;
    const updated = if (value.getField("updated_at_us")) |u| (u.asInt() orelse now) else now;

    return Record{
        .id = id,
        .kind = kind,
        .created_at_us = created,
        .updated_at_us = updated,
        .tags = try tags_list.toOwnedSlice(),
        .body = body,
        .embedding = emb,
    };
}

pub fn toJson(allocator: std.mem.Allocator, record: Record) !json.Value {
    var obj: json.Value = .{ .object = .{} };
    errdefer obj.deinit(allocator);
    try json.objectPut(allocator, &obj, "id", json.makeInt(@intCast(record.id)));
    const kind_str = switch (record.kind) {
        .document => "document",
        .conversation => "conversation",
        .scene => "scene",
        .persona => "persona",
        .custom => "custom",
    };
    try json.objectPut(allocator, &obj, "kind", try json.makeString(allocator, kind_str));
    try json.objectPut(allocator, &obj, "created_at_us", json.makeInt(record.created_at_us));
    try json.objectPut(allocator, &obj, "updated_at_us", json.makeInt(record.updated_at_us));
    var tags_arr = try json.makeArray(allocator, record.tags.len);
    for (record.tags, 0..) |t, i| {
        tags_arr.array[i] = try json.makeString(allocator, t);
    }
    try json.objectPut(allocator, &obj, "tags", tags_arr);
    try json.objectPut(allocator, &obj, "body", try json.makeString(allocator, record.body));
    if (record.embedding) |emb| {
        var earr = try json.makeArray(allocator, emb.len);
        for (emb, 0..) |x, i| earr.array[i] = json.makeFloat(@floatCast(x));
        try json.objectPut(allocator, &obj, "embedding", earr);
    } else {
        try json.objectPut(allocator, &obj, "embedding", json.makeNull());
    }
    return obj;
}

test "record encode decode" {
    const testing = std.testing;
    const tags_in = try testing.allocator.alloc([]const u8, 2);
    tags_in[0] = try testing.allocator.dupe(u8, "alpha");
    tags_in[1] = try testing.allocator.dupe(u8, "beta");
    const body_in = try testing.allocator.dupe(u8, "hello world");
    const emb_in = try testing.allocator.dupe(f32, &[_]f32{ 0.1, 0.2, 0.3 });

    var rec = Record{
        .id = 42,
        .kind = .document,
        .created_at_us = 100,
        .updated_at_us = 200,
        .tags = tags_in,
        .body = body_in,
        .embedding = emb_in,
    };
    defer rec.deinit(testing.allocator);

    const bytes = try RecordWriter.encode(testing.allocator, rec);
    defer testing.allocator.free(bytes);

    var rec2 = try RecordReader.decode(testing.allocator, bytes);
    defer rec2.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 42), rec2.id);
    try testing.expectEqualStrings("hello world", rec2.body);
    try testing.expectEqual(@as(usize, 2), rec2.tags.len);
    try testing.expectEqualStrings("alpha", rec2.tags[0]);
    try testing.expect(rec2.embedding != null);
    try testing.expectEqual(@as(usize, 3), rec2.embedding.?.len);
}
