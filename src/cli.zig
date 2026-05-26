const std = @import("std");
const database = @import("database.zig");
const record_mod = @import("record.zig");
const server_mod = @import("server.zig");
const json_mod = @import("json.zig");

pub const CliOptions = struct {
    data_dir: []const u8 = "./agdb-data",
    embedding_dim: u32 = 256,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 7878,
};

pub fn run(allocator: std.mem.Allocator, args: [][]const u8) !u8 {
    if (args.len < 1) {
        try printUsage();
        return 1;
    }

    var opts = CliOptions{};
    var positional = std.ArrayList([]const u8).init(allocator);
    defer positional.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--data") or std.mem.eql(u8, a, "-d")) {
            i += 1;
            if (i >= args.len) {
                try stderrPrint("error: --data requires value\n", .{});
                return 2;
            }
            opts.data_dir = args[i];
        } else if (std.mem.eql(u8, a, "--dim")) {
            i += 1;
            if (i >= args.len) return 2;
            opts.embedding_dim = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, a, "--bind")) {
            i += 1;
            if (i >= args.len) return 2;
            opts.bind_addr = args[i];
        } else if (std.mem.eql(u8, a, "--port")) {
            i += 1;
            if (i >= args.len) return 2;
            opts.bind_port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            try printUsage();
            return 0;
        } else {
            try positional.append(a);
        }
    }

    if (positional.items.len == 0) {
        try printUsage();
        return 1;
    }

    const cmd = positional.items[0];
    const rest = positional.items[1..];

    if (std.mem.eql(u8, cmd, "init")) return try cmdInit(allocator, opts);
    if (std.mem.eql(u8, cmd, "put")) return try cmdPut(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "put-file")) return try cmdPutFile(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "put-json")) return try cmdPutJson(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "get")) return try cmdGet(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "del")) return try cmdDel(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "search")) return try cmdSearch(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "vector-search")) return try cmdVectorSearch(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "stats")) return try cmdStats(allocator, opts);
    if (std.mem.eql(u8, cmd, "compact")) return try cmdCompact(allocator, opts);
    if (std.mem.eql(u8, cmd, "flush")) return try cmdFlush(allocator, opts);
    if (std.mem.eql(u8, cmd, "serve")) return try cmdServe(allocator, opts);
    if (std.mem.eql(u8, cmd, "snapshot")) return try cmdSnapshot(allocator, opts, rest);
    if (std.mem.eql(u8, cmd, "list")) return try cmdList(allocator, opts);
    if (std.mem.eql(u8, cmd, "help")) {
        try printUsage();
        return 0;
    }

    try stderrPrint("unknown command: {s}\n", .{cmd});
    try printUsage();
    return 1;
}

fn openDb(allocator: std.mem.Allocator, opts: CliOptions) !*database.Database {
    return try database.Database.open(allocator, .{
        .data_dir = opts.data_dir,
        .embedding_dim = opts.embedding_dim,
    });
}

fn cmdInit(allocator: std.mem.Allocator, opts: CliOptions) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    try db.flush();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("initialized agdb at {s} (dim={d})\n", .{ opts.data_dir, opts.embedding_dim });
    return 0;
}

fn cmdPut(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    if (rest.len < 1) {
        try stderrPrint("usage: agdb put <body> [--tag t1] [--tag t2] [--kind document|conversation|scene|persona|custom] [--id N]\n", .{});
        return 2;
    }
    var kind: record_mod.RecordKind = .document;
    var explicit_id: u64 = 0;
    var tags = std.ArrayList([]const u8).init(allocator);
    defer tags.deinit();
    var body: ?[]const u8 = null;

    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--tag")) {
            i += 1;
            if (i >= rest.len) return 2;
            try tags.append(rest[i]);
        } else if (std.mem.eql(u8, rest[i], "--kind")) {
            i += 1;
            if (i >= rest.len) return 2;
            kind = parseKindName(rest[i]);
        } else if (std.mem.eql(u8, rest[i], "--id")) {
            i += 1;
            if (i >= rest.len) return 2;
            explicit_id = try std.fmt.parseInt(u64, rest[i], 10);
        } else if (body == null) {
            body = rest[i];
        }
    }
    if (body == null) {
        try stderrPrint("error: missing body\n", .{});
        return 2;
    }

    var db = try openDb(allocator, opts);
    defer db.close();
    const id = try db.putBytes(kind, explicit_id, body.?, tags.items);
    try db.flush();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{d}\n", .{id});
    return 0;
}

fn cmdPutFile(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    if (rest.len < 1) {
        try stderrPrint("usage: agdb put-file <path> [--kind ...] [--tag ...]\n", .{});
        return 2;
    }
    const path = rest[0];
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const max = 64 * 1024 * 1024;
    const content = try file.readToEndAlloc(allocator, max);
    defer allocator.free(content);

    var kind: record_mod.RecordKind = .document;
    var tags = std.ArrayList([]const u8).init(allocator);
    defer tags.deinit();
    var i: usize = 1;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--tag")) {
            i += 1;
            if (i >= rest.len) return 2;
            try tags.append(rest[i]);
        } else if (std.mem.eql(u8, rest[i], "--kind")) {
            i += 1;
            if (i >= rest.len) return 2;
            kind = parseKindName(rest[i]);
        }
    }
    var db = try openDb(allocator, opts);
    defer db.close();
    const id = try db.putBytes(kind, 0, content, tags.items);
    try db.flush();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{d}\n", .{id});
    return 0;
}

fn cmdPutJson(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    var source_path: ?[]const u8 = null;
    var kind: record_mod.RecordKind = .document;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--file")) {
            i += 1;
            if (i >= rest.len) return 2;
            source_path = rest[i];
        } else if (std.mem.eql(u8, rest[i], "--kind")) {
            i += 1;
            if (i >= rest.len) return 2;
            kind = parseKindName(rest[i]);
        }
    }
    var raw: []u8 = undefined;
    var owned_raw = false;
    if (source_path) |p| {
        const file = try std.fs.cwd().openFile(p, .{});
        defer file.close();
        raw = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
        owned_raw = true;
    } else {
        var stdin = std.io.getStdIn().reader();
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = try stdin.read(&chunk);
            if (n == 0) break;
            try buf.appendSlice(chunk[0..n]);
        }
        raw = try buf.toOwnedSlice();
        owned_raw = true;
    }
    defer if (owned_raw) allocator.free(raw);

    var value = try json_mod.parse(allocator, raw);
    defer value.deinit(allocator);

    var db = try openDb(allocator, opts);
    defer db.close();
    const id = try db.putJson(kind, value);
    try db.flush();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{d}\n", .{id});
    return 0;
}

fn cmdGet(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    if (rest.len < 1) {
        try stderrPrint("usage: agdb get <id>\n", .{});
        return 2;
    }
    const id = try std.fmt.parseInt(u64, rest[0], 10);
    var db = try openDb(allocator, opts);
    defer db.close();
    var maybe_json = try db.getJson(allocator, id);
    if (maybe_json == null) {
        try stderrPrint("not found\n", .{});
        return 1;
    }
    defer maybe_json.?.deinit(allocator);
    const out = try json_mod.stringify(allocator, maybe_json.?);
    defer allocator.free(out);
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\n", .{out});
    return 0;
}

fn cmdDel(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    if (rest.len < 1) {
        try stderrPrint("usage: agdb del <id>\n", .{});
        return 2;
    }
    const id = try std.fmt.parseInt(u64, rest[0], 10);
    var db = try openDb(allocator, opts);
    defer db.close();
    const existed = try db.delete(id);
    try db.flush();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\n", .{if (existed) "deleted" else "not found"});
    return if (existed) 0 else 1;
}

fn cmdSearch(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    if (rest.len < 1) {
        try stderrPrint("usage: agdb search <query> [--k N] [--mode text|hybrid] [--alpha 0.5]\n", .{});
        return 2;
    }
    var top_k: usize = 10;
    var mode: enum { text, hybrid } = .text;
    var alpha: f32 = 0.5;
    var query: ?[]const u8 = null;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--k")) {
            i += 1;
            if (i >= rest.len) return 2;
            top_k = try std.fmt.parseInt(usize, rest[i], 10);
        } else if (std.mem.eql(u8, rest[i], "--mode")) {
            i += 1;
            if (i >= rest.len) return 2;
            if (std.mem.eql(u8, rest[i], "hybrid")) {
                mode = .hybrid;
            } else {
                mode = .text;
            }
        } else if (std.mem.eql(u8, rest[i], "--alpha")) {
            i += 1;
            if (i >= rest.len) return 2;
            alpha = try std.fmt.parseFloat(f32, rest[i]);
        } else if (query == null) {
            query = rest[i];
        }
    }
    if (query == null) return 2;

    var db = try openDb(allocator, opts);
    defer db.close();
    var results = switch (mode) {
        .text => try db.searchText(query.?, top_k),
        .hybrid => try db.searchHybrid(query.?, null, top_k, alpha),
    };
    defer results.deinit();

    try printResults(results);
    return 0;
}

fn cmdVectorSearch(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    if (rest.len < 1) {
        try stderrPrint("usage: agdb vector-search '0.1,0.2,...' [--k N]\n", .{});
        return 2;
    }
    var top_k: usize = 10;
    var vec_str: ?[]const u8 = null;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--k")) {
            i += 1;
            if (i >= rest.len) return 2;
            top_k = try std.fmt.parseInt(usize, rest[i], 10);
        } else if (vec_str == null) {
            vec_str = rest[i];
        }
    }
    if (vec_str == null) return 2;
    var list = std.ArrayList(f32).init(allocator);
    defer list.deinit();
    var it = std.mem.tokenizeScalar(u8, vec_str.?, ',');
    while (it.next()) |item| {
        const trimmed = std.mem.trim(u8, item, " \t");
        try list.append(try std.fmt.parseFloat(f32, trimmed));
    }
    var db = try openDb(allocator, opts);
    defer db.close();
    var results = try db.searchVector(list.items, top_k);
    defer results.deinit();
    try printResults(results);
    return 0;
}

fn cmdStats(allocator: std.mem.Allocator, opts: CliOptions) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    const stdout = std.io.getStdOut().writer();
    const disk = db.kv.diskSize();
    const dead = db.kv.deadBytes();
    try stdout.print(
        "records: {d}\ndisk_bytes: {d}\ndead_bytes: {d}\nembedding_dim: {d}\n",
        .{ db.count(), disk, dead, opts.embedding_dim },
    );
    return 0;
}

fn cmdCompact(allocator: std.mem.Allocator, opts: CliOptions) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    try db.compact();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("compacted\n", .{});
    return 0;
}

fn cmdFlush(allocator: std.mem.Allocator, opts: CliOptions) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    try db.flush();
    const stdout = std.io.getStdOut().writer();
    try stdout.print("flushed\n", .{});
    return 0;
}

fn cmdServe(allocator: std.mem.Allocator, opts: CliOptions) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    var srv = server_mod.Server.init(allocator, db, .{
        .address = opts.bind_addr,
        .port = opts.bind_port,
    });
    try srv.run();
    return 0;
}

fn cmdSnapshot(allocator: std.mem.Allocator, opts: CliOptions, rest: [][]const u8) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    try db.flush();
    const ts: u64 = @intCast(std.time.microTimestamp());
    var snapshot_path: []const u8 = undefined;
    var owned = true;
    if (rest.len >= 1) {
        snapshot_path = rest[0];
        owned = false;
    } else {
        snapshot_path = try std.fmt.allocPrint(allocator, "{s}/snapshot-{d}.kv", .{ opts.data_dir, ts });
    }
    defer if (owned) allocator.free(snapshot_path);

    const src = try std.fmt.allocPrint(allocator, "{s}/store.kv", .{opts.data_dir});
    defer allocator.free(src);

    try copyFile(src, snapshot_path);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("snapshot: {s}\n", .{snapshot_path});
    return 0;
}

fn copyFile(src: []const u8, dst: []const u8) !void {
    const src_file = try std.fs.cwd().openFile(src, .{});
    defer src_file.close();
    var dst_file = try std.fs.cwd().createFile(dst, .{ .truncate = true });
    defer dst_file.close();
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try src_file.readAll(&buf);
        if (n == 0) break;
        try dst_file.writeAll(buf[0..n]);
        if (n < buf.len) break;
    }
    try dst_file.sync();
}

fn cmdList(allocator: std.mem.Allocator, opts: CliOptions) !u8 {
    var db = try openDb(allocator, opts);
    defer db.close();
    const stdout = std.io.getStdOut().writer();
    var it = try db.kv.iterator();
    defer it.deinit();
    var emitted: u64 = 0;
    while (true) {
        var kv = (try it.next()) orelse break;
        defer kv.deinit();
        if (std.mem.startsWith(u8, kv.key, "rec:")) {
            const id_hex = kv.key[4..];
            const id = std.fmt.parseInt(u64, id_hex, 16) catch continue;
            try stdout.print("{d}\n", .{id});
            emitted += 1;
        }
    }
    if (emitted == 0) try stdout.print("(empty)\n", .{});
    return 0;
}

fn printResults(results: database.QueryResults) !void {
    const stdout = std.io.getStdOut().writer();
    if (results.items.len == 0) {
        try stdout.print("(no results)\n", .{});
        return;
    }
    for (results.items) |item| {
        const body_preview = preview(item.record.body, 120);
        try stdout.print("{d}\t{d:.4}\t{s}\n", .{ item.id, item.score, body_preview });
    }
}

fn preview(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}

fn parseKindName(s: []const u8) record_mod.RecordKind {
    if (std.mem.eql(u8, s, "conversation")) return .conversation;
    if (std.mem.eql(u8, s, "scene")) return .scene;
    if (std.mem.eql(u8, s, "persona")) return .persona;
    if (std.mem.eql(u8, s, "custom")) return .custom;
    return .document;
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\agdb - unified zig database
        \\
        \\USAGE:
        \\  agdb <command> [options]
        \\
        \\OPTIONS:
        \\  --data,-d <dir>           Data directory (default: ./agdb-data)
        \\  --dim <N>                 Embedding dimension (default: 256)
        \\  --bind <addr>             Server bind address (default: 127.0.0.1)
        \\  --port <port>             Server port (default: 7878)
        \\
        \\COMMANDS:
        \\  init                      Initialize the database
        \\  put <body>                Store a record with the given body
        \\    [--tag t]               Add tag (repeatable)
        \\    [--kind k]              document|conversation|scene|persona|custom
        \\    [--id N]                Use explicit id
        \\  put-file <path>           Read a file and store its contents
        \\  put-json [--file path]    Read JSON from stdin or a file and store
        \\  get <id>                  Retrieve a record by id (json output)
        \\  del <id>                  Delete a record
        \\  search <query>            Text search
        \\    [--k N] [--mode hybrid] [--alpha 0.5]
        \\  vector-search <v1,v2,..>  Vector search
        \\    [--k N]
        \\  list                      List all record ids
        \\  stats                     Show storage statistics
        \\  compact                   Compact the storage file
        \\  flush                     Persist all in-memory indexes to disk
        \\  snapshot [path]           Copy storage file to a snapshot
        \\  serve                     Start REST API server
        \\  help                      Print this help
        \\
    );
}

fn stderrPrint(comptime fmt: []const u8, args: anytype) !void {
    const stderr = std.io.getStdErr().writer();
    try stderr.print(fmt, args);
}
