const std = @import("std");
const database = @import("database.zig");
const record_mod = @import("record.zig");
const json_mod = @import("json.zig");

pub const ServerConfig = struct {
    address: []const u8 = "127.0.0.1",
    port: u16 = 7878,
    backlog: u31 = 64,
    max_body_size: usize = 16 * 1024 * 1024,
    api_token: ?[]const u8 = null,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    config: ServerConfig,
    running: std.atomic.Value(bool),
    listener: ?std.net.Server,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, config: ServerConfig) Server {
        return .{
            .allocator = allocator,
            .db = db,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .listener = null,
        };
    }

    pub fn stop(self: *Server) void {
        self.running.store(false, .release);
        if (self.listener) |*srv| {
            srv.deinit();
            self.listener = null;
        }
    }

    pub fn run(self: *Server) !void {
        const addr = try std.net.Address.parseIp(self.config.address, self.config.port);
        var server = try addr.listen(.{ .reuse_address = true, .force_nonblocking = false });
        self.listener = server;
        defer {
            if (self.listener) |*l| l.deinit();
            self.listener = null;
        }

        self.running.store(true, .release);

        const stdout = std.io.getStdOut().writer();
        try stdout.print("agdb server listening on http://{s}:{d}\n", .{ self.config.address, self.config.port });

        while (self.running.load(.acquire)) {
            const conn = server.accept() catch |err| {
                switch (err) {
                    error.ConnectionAborted, error.SocketNotListening => break,
                    else => continue,
                }
            };
            self.handleConnection(conn) catch |err| {
                std.log.warn("agdb server: connection error: {s}", .{@errorName(err)});
            };
        }
    }

    fn handleConnection(self: *Server, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();

        var read_buf: [16384]u8 = undefined;
        var http_server = std.http.Server.init(conn, &read_buf);
        while (http_server.state == .ready) {
            var request = http_server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => return,
                else => return err,
            };
            try self.handleRequest(&request);
        }
    }

    fn handleRequest(self: *Server, request: *std.http.Server.Request) !void {
        if (self.config.api_token) |token| {
            const auth_opt = headerValue(request, "authorization");
            const expected = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token});
            defer self.allocator.free(expected);
            if (auth_opt == null or !std.mem.eql(u8, auth_opt.?, expected)) {
                try respondJsonError(self.allocator, request, .unauthorized, "missing or invalid api token");
                return;
            }
        }

        const target = request.head.target;
        const method = request.head.method;

        if (method == .GET and std.mem.eql(u8, target, "/health")) {
            try respondJsonStr(request, .ok, "{\"status\":\"ok\"}");
            return;
        }
        if (method == .GET and std.mem.eql(u8, target, "/version")) {
            try respondJsonStr(request, .ok, "{\"name\":\"agdb\",\"version\":\"1.0.0\"}");
            return;
        }
        if (method == .GET and std.mem.eql(u8, target, "/stats")) {
            try self.handleStats(request);
            return;
        }
        if (method == .POST and std.mem.eql(u8, target, "/records")) {
            try self.handlePutRecord(request);
            return;
        }
        if (method == .POST and std.mem.eql(u8, target, "/search")) {
            try self.handleSearch(request);
            return;
        }
        if (method == .POST and std.mem.eql(u8, target, "/compact")) {
            self.db.compact() catch |err| {
                try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
                return;
            };
            try respondJsonStr(request, .ok, "{\"compacted\":true}");
            return;
        }
        if (method == .POST and std.mem.eql(u8, target, "/flush")) {
            self.db.flush() catch |err| {
                try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
                return;
            };
            try respondJsonStr(request, .ok, "{\"flushed\":true}");
            return;
        }
        if (std.mem.startsWith(u8, target, "/records/")) {
            const id_str = target["/records/".len..];
            const id = std.fmt.parseInt(u64, id_str, 10) catch {
                try respondJsonError(self.allocator, request, .bad_request, "invalid id");
                return;
            };
            switch (method) {
                .GET => try self.handleGetRecord(request, id),
                .DELETE => try self.handleDeleteRecord(request, id),
                else => try respondJsonError(self.allocator, request, .method_not_allowed, "method not allowed"),
            }
            return;
        }

        try respondJsonError(self.allocator, request, .not_found, "no such route");
    }

    fn handleStats(self: *Server, request: *std.http.Server.Request) !void {
        const c = self.db.count();
        const buf = try std.fmt.allocPrint(self.allocator, "{{\"records\":{d}}}", .{c});
        defer self.allocator.free(buf);
        try respondJsonStr(request, .ok, buf);
    }

    fn handlePutRecord(self: *Server, request: *std.http.Server.Request) !void {
        const body = try readBody(self.allocator, request, self.config.max_body_size);
        defer self.allocator.free(body);

        var value = json_mod.parse(self.allocator, body) catch {
            try respondJsonError(self.allocator, request, .bad_request, "invalid json");
            return;
        };
        defer value.deinit(self.allocator);

        var kind: record_mod.RecordKind = .document;
        if (value.getField("kind")) |k_val| {
            if (k_val.asString()) |k_str| {
                kind = parseKind(k_str);
            }
        }

        const id = self.db.putJson(kind, value) catch |err| {
            const msg = @errorName(err);
            try respondJsonError(self.allocator, request, .internal_server_error, msg);
            return;
        };
        const out = try std.fmt.allocPrint(self.allocator, "{{\"id\":{d}}}", .{id});
        defer self.allocator.free(out);
        try respondJsonStr(request, .created, out);
    }

    fn handleGetRecord(self: *Server, request: *std.http.Server.Request, id: u64) !void {
        var rec_json = self.db.getJson(self.allocator, id) catch |err| {
            try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
            return;
        };
        if (rec_json == null) {
            try respondJsonError(self.allocator, request, .not_found, "record not found");
            return;
        }
        defer rec_json.?.deinit(self.allocator);
        const body = try json_mod.stringify(self.allocator, rec_json.?);
        defer self.allocator.free(body);
        try respondJsonStr(request, .ok, body);
    }

    fn handleDeleteRecord(self: *Server, request: *std.http.Server.Request, id: u64) !void {
        const existed = self.db.delete(id) catch |err| {
            try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
            return;
        };
        if (!existed) {
            try respondJsonError(self.allocator, request, .not_found, "record not found");
            return;
        }
        try respondJsonStr(request, .ok, "{\"deleted\":true}");
    }

    fn handleSearch(self: *Server, request: *std.http.Server.Request) !void {
        const body = try readBody(self.allocator, request, self.config.max_body_size);
        defer self.allocator.free(body);

        var value = json_mod.parse(self.allocator, body) catch {
            try respondJsonError(self.allocator, request, .bad_request, "invalid json");
            return;
        };
        defer value.deinit(self.allocator);

        const mode_str: []const u8 = blk: {
            if (value.getField("mode")) |m| if (m.asString()) |s| break :blk s;
            break :blk "text";
        };

        const query_str: []const u8 = blk: {
            if (value.getField("query")) |q| if (q.asString()) |s| break :blk s;
            break :blk "";
        };

        const top_k_val: usize = blk: {
            if (value.getField("top_k")) |t| if (t.asInt()) |i| if (i > 0) break :blk @intCast(i);
            break :blk 10;
        };

        const alpha: f32 = blk: {
            if (value.getField("alpha")) |a| if (a.asFloat()) |f| break :blk @floatCast(f);
            break :blk 0.5;
        };

        var maybe_vec: ?[]f32 = null;
        defer if (maybe_vec) |v| self.allocator.free(v);
        if (value.getField("vector")) |v_val| {
            if (v_val == .array) {
                const arr = try self.allocator.alloc(f32, v_val.array.len);
                for (v_val.array, 0..) |it, i| {
                    if (it.asFloat()) |f| arr[i] = @floatCast(f) else arr[i] = 0;
                }
                maybe_vec = arr;
            }
        }

        var results = blk: {
            if (std.mem.eql(u8, mode_str, "vector") and maybe_vec != null) {
                break :blk self.db.searchVector(maybe_vec.?, top_k_val) catch |err| {
                    try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
                    return;
                };
            }
            if (std.mem.eql(u8, mode_str, "hybrid")) {
                break :blk self.db.searchHybrid(query_str, maybe_vec, top_k_val, alpha) catch |err| {
                    try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
                    return;
                };
            }
            break :blk self.db.searchText(query_str, top_k_val) catch |err| {
                try respondJsonError(self.allocator, request, .internal_server_error, @errorName(err));
                return;
            };
        };
        defer results.deinit();

        var out_obj: json_mod.Value = .{ .object = .{} };
        defer out_obj.deinit(self.allocator);
        try json_mod.objectPut(self.allocator, &out_obj, "count", json_mod.makeInt(@intCast(results.items.len)));
        var hits_arr = try json_mod.makeArray(self.allocator, results.items.len);
        var i: usize = 0;
        while (i < results.items.len) : (i += 1) {
            var entry: json_mod.Value = .{ .object = .{} };
            try json_mod.objectPut(self.allocator, &entry, "id", json_mod.makeInt(@intCast(results.items[i].id)));
            try json_mod.objectPut(self.allocator, &entry, "score", json_mod.makeFloat(@floatCast(results.items[i].score)));
            const src_str = switch (results.items[i].source) {
                .bm25 => "bm25",
                .vector => "vector",
                .hybrid => "hybrid",
            };
            try json_mod.objectPut(self.allocator, &entry, "source", try json_mod.makeString(self.allocator, src_str));
            const rec_json = try record_mod.toJson(self.allocator, results.items[i].record);
            try json_mod.objectPut(self.allocator, &entry, "record", rec_json);
            hits_arr.array[i] = entry;
        }
        try json_mod.objectPut(self.allocator, &out_obj, "hits", hits_arr);

        const body_out = try json_mod.stringify(self.allocator, out_obj);
        defer self.allocator.free(body_out);
        try respondJsonStr(request, .ok, body_out);
    }
};

fn parseKind(s: []const u8) record_mod.RecordKind {
    if (std.mem.eql(u8, s, "document")) return .document;
    if (std.mem.eql(u8, s, "conversation")) return .conversation;
    if (std.mem.eql(u8, s, "scene")) return .scene;
    if (std.mem.eql(u8, s, "persona")) return .persona;
    return .custom;
}

fn headerValue(request: *std.http.Server.Request, name: []const u8) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

fn readBody(allocator: std.mem.Allocator, request: *std.http.Server.Request, max: usize) ![]u8 {
    var body_reader = try request.reader();
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try body_reader.read(&buf);
        if (n == 0) break;
        if (result.items.len + n > max) return error.BodyTooLarge;
        try result.appendSlice(buf[0..n]);
    }
    return result.toOwnedSlice();
}

fn respondJsonStr(request: *std.http.Server.Request, status: std.http.Status, body: []const u8) !void {
    try request.respond(body, .{
        .status = status,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "server", .value = "agdb/1.0" },
        },
    });
}

fn respondJsonError(allocator: std.mem.Allocator, request: *std.http.Server.Request, status: std.http.Status, message: []const u8) !void {
    const escaped = try escapeJsonString(allocator, message);
    defer allocator.free(escaped);
    const body = try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}", .{escaped});
    defer allocator.free(body);
    try respondJsonStr(request, status, body);
}

fn escapeJsonString(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice("\\\""),
            '\\' => try buf.appendSlice("\\\\"),
            '\n' => try buf.appendSlice("\\n"),
            '\r' => try buf.appendSlice("\\r"),
            '\t' => try buf.appendSlice("\\t"),
            else => try buf.append(c),
        }
    }
    return buf.toOwnedSlice();
}
