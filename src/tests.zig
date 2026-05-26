const std = @import("std");
const agdb = @import("agdb");

test "end to end put and search" {
    const testing = std.testing;
    const tmp_dir = "agdb-it-e2e";
    std.fs.cwd().deleteTree(tmp_dir) catch {};
    try std.fs.cwd().makePath(tmp_dir);
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    var db = try agdb.Database.open(testing.allocator, .{
        .data_dir = tmp_dir,
        .embedding_dim = 64,
    });
    defer db.close();

    const empty: [0][]const u8 = .{};
    const id_a = try db.putBytes(.document, 0, "agdb stores documents and supports text and vector search", &empty);
    const id_b = try db.putBytes(.document, 0, "vectors live next to text in a unified store", &empty);
    const id_c = try db.putBytes(.document, 0, "unrelated content about cooking and recipes", &empty);
    _ = id_b;
    _ = id_c;
    try db.flush();

    var text_hits = try db.searchText("vector search", 5);
    defer text_hits.deinit();
    try testing.expect(text_hits.items.len >= 1);
    try testing.expectEqual(id_a, text_hits.items[0].id);

    var hybrid_hits = try db.searchHybrid("unified store", null, 5, 0.6);
    defer hybrid_hits.deinit();
    try testing.expect(hybrid_hits.items.len >= 1);

    try db.compact();
    try testing.expect(db.count() == 3);
}

test "kv durability across reopen" {
    const testing = std.testing;
    const tmp_dir = "agdb-it-kv";
    std.fs.cwd().deleteTree(tmp_dir) catch {};
    try std.fs.cwd().makePath(tmp_dir);
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    const path = try std.fmt.allocPrint(testing.allocator, "{s}/kv.dat", .{tmp_dir});
    defer testing.allocator.free(path);

    {
        const store = try agdb.kv.KvStore.open(testing.allocator, path, 0);
        try store.put("a", "1");
        try store.put("b", "two");
        try store.put("c", "thrice");
        _ = try store.delete("b");
        try store.flush();
        store.close();
    }
    {
        const store2 = try agdb.kv.KvStore.open(testing.allocator, path, 0);
        defer store2.close();
        const val_a = try store2.get(testing.allocator, "a");
        defer if (val_a) |v| testing.allocator.free(v);
        const val_c = try store2.get(testing.allocator, "c");
        defer if (val_c) |v| testing.allocator.free(v);
        try testing.expectEqualStrings("1", val_a.?);
        try testing.expectEqualStrings("thrice", val_c.?);
        try testing.expect(!store2.contains("b"));
    }
}

test "bm25 + vector combined" {
    const testing = std.testing;
    var bm = agdb.bm25.Bm25Index.init(testing.allocator, .{});
    defer bm.deinit();
    var vi = agdb.vector.VectorIndex.init(testing.allocator, 8, .cosine);
    defer vi.deinit();

    try bm.addDocument(1, "alpha beta gamma");
    try bm.addDocument(2, "delta epsilon zeta");
    try vi.upsert(1, &[_]f32{ 1, 0, 0, 0, 0, 0, 0, 0 });
    try vi.upsert(2, &[_]f32{ 0, 1, 0, 0, 0, 0, 0, 0 });

    const text_hits = try bm.search(testing.allocator, "alpha", 3);
    defer testing.allocator.free(text_hits);
    const vec_hits = try vi.search(testing.allocator, &[_]f32{ 0, 1, 0, 0, 0, 0, 0, 0 }, 3);
    defer testing.allocator.free(vec_hits);

    try testing.expect(text_hits[0].doc_id == 1);
    try testing.expect(vec_hits[0].doc_id == 2);
}

test "json round trip" {
    const testing = std.testing;
    const src =
        \\{"id":7,"kind":"document","body":"hello","tags":["a","b"]}
    ;
    var v = try agdb.json.parse(testing.allocator, src);
    defer v.deinit(testing.allocator);
    const out = try agdb.json.stringify(testing.allocator, v);
    defer testing.allocator.free(out);
    var v2 = try agdb.json.parse(testing.allocator, out);
    defer v2.deinit(testing.allocator);
    try testing.expectEqualStrings("hello", v2.getField("body").?.asString().?);
}

test "tokenizer normalize" {
    const testing = std.testing;
    var tl = try agdb.tokenizer.tokenize(testing.allocator, "Hello, AGDB! 1234", .{});
    defer tl.deinit();
    try testing.expect(tl.items.len == 3);
    try testing.expectEqualStrings("hello", tl.items[0].text);
    try testing.expectEqualStrings("agdb", tl.items[1].text);
    try testing.expectEqualStrings("1234", tl.items[2].text);
}
