const std = @import("std");

pub const Value = union(enum) {
    null_value,
    bool_value: bool,
    int_value: i64,
    float_value: f64,
    string: []const u8,
    array: []Value,
    object: ObjectEntries,

    pub const ObjectEntries = std.StringArrayHashMapUnmanaged(Value);

    pub fn deinit(self: *Value, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .string => |s| allocator.free(s),
            .array => |items| {
                for (items) |*item| {
                    item.deinit(allocator);
                }
                allocator.free(items);
            },
            .object => |*obj| {
                var it = obj.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.*.deinit(allocator);
                }
                obj.deinit(allocator);
            },
            else => {},
        }
    }

    pub fn clone(self: Value, allocator: std.mem.Allocator) anyerror!Value {
        return switch (self) {
            .null_value => .null_value,
            .bool_value => |b| .{ .bool_value = b },
            .int_value => |i| .{ .int_value = i },
            .float_value => |f| .{ .float_value = f },
            .string => |s| .{ .string = try allocator.dupe(u8, s) },
            .array => |items| blk: {
                const out = try allocator.alloc(Value, items.len);
                errdefer allocator.free(out);
                var i: usize = 0;
                while (i < items.len) : (i += 1) out[i] = .null_value;
                i = 0;
                while (i < items.len) : (i += 1) {
                    out[i] = try items[i].clone(allocator);
                }
                break :blk .{ .array = out };
            },
            .object => |obj| blk: {
                var new_obj: ObjectEntries = .{};
                errdefer new_obj.deinit(allocator);
                var it = obj.iterator();
                while (it.next()) |entry| {
                    const k = try allocator.dupe(u8, entry.key_ptr.*);
                    errdefer allocator.free(k);
                    const v = try entry.value_ptr.*.clone(allocator);
                    try new_obj.put(allocator, k, v);
                }
                break :blk .{ .object = new_obj };
            },
        };
    }

    pub fn getField(self: Value, name: []const u8) ?Value {
        if (self != .object) return null;
        return self.object.get(name);
    }

    pub fn asString(self: Value) ?[]const u8 {
        return switch (self) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .int_value => |i| i,
            .float_value => |f| @intFromFloat(f),
            else => null,
        };
    }

    pub fn asFloat(self: Value) ?f64 {
        return switch (self) {
            .float_value => |f| f,
            .int_value => |i| @floatFromInt(i),
            else => null,
        };
    }

    pub fn asBool(self: Value) ?bool {
        return switch (self) {
            .bool_value => |b| b,
            else => null,
        };
    }
};

pub const ParseError = error{
    UnexpectedToken,
    UnexpectedEnd,
    InvalidNumber,
    InvalidEscape,
    InvalidUtf8,
    DuplicateKey,
    OutOfMemory,
    Overflow,
    InvalidCharacter,
};

const Parser = struct {
    src: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,

    fn peek(self: *Parser) ?u8 {
        if (self.pos >= self.src.len) return null;
        return self.src[self.pos];
    }

    fn advance(self: *Parser) ?u8 {
        if (self.pos >= self.src.len) return null;
        const c = self.src[self.pos];
        self.pos += 1;
        return c;
    }

    fn skipWhitespace(self: *Parser) void {
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                self.pos += 1;
            } else break;
        }
    }

    fn expect(self: *Parser, c: u8) ParseError!void {
        self.skipWhitespace();
        const got = self.peek() orelse return error.UnexpectedEnd;
        if (got != c) return error.UnexpectedToken;
        self.pos += 1;
    }

    fn parseValue(self: *Parser) ParseError!Value {
        self.skipWhitespace();
        const c = self.peek() orelse return error.UnexpectedEnd;
        return switch (c) {
            '{' => self.parseObject(),
            '[' => self.parseArray(),
            '"' => .{ .string = try self.parseString() },
            't', 'f' => self.parseBool(),
            'n' => self.parseNull(),
            '-', '0'...'9' => self.parseNumber(),
            else => error.UnexpectedToken,
        };
    }

    fn parseBool(self: *Parser) ParseError!Value {
        const remaining = self.src[self.pos..];
        if (std.mem.startsWith(u8, remaining, "true")) {
            self.pos += 4;
            return .{ .bool_value = true };
        }
        if (std.mem.startsWith(u8, remaining, "false")) {
            self.pos += 5;
            return .{ .bool_value = false };
        }
        return error.UnexpectedToken;
    }

    fn parseNull(self: *Parser) ParseError!Value {
        const remaining = self.src[self.pos..];
        if (std.mem.startsWith(u8, remaining, "null")) {
            self.pos += 4;
            return .null_value;
        }
        return error.UnexpectedToken;
    }

    fn parseNumber(self: *Parser) ParseError!Value {
        const start = self.pos;
        if (self.peek() == @as(u8, '-')) self.pos += 1;
        var has_dot = false;
        var has_exp = false;
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            switch (c) {
                '0'...'9' => self.pos += 1,
                '.' => {
                    if (has_dot or has_exp) break;
                    has_dot = true;
                    self.pos += 1;
                },
                'e', 'E' => {
                    if (has_exp) break;
                    has_exp = true;
                    self.pos += 1;
                    if (self.pos < self.src.len) {
                        const n = self.src[self.pos];
                        if (n == '+' or n == '-') self.pos += 1;
                    }
                },
                else => break,
            }
        }
        const text = self.src[start..self.pos];
        if (text.len == 0) return error.InvalidNumber;
        if (has_dot or has_exp) {
            const f = std.fmt.parseFloat(f64, text) catch return error.InvalidNumber;
            return .{ .float_value = f };
        }
        const i = std.fmt.parseInt(i64, text, 10) catch {
            const f = std.fmt.parseFloat(f64, text) catch return error.InvalidNumber;
            return .{ .float_value = f };
        };
        return .{ .int_value = i };
    }

    fn parseString(self: *Parser) ParseError![]u8 {
        try self.expect('"');
        var buf = std.ArrayList(u8).init(self.allocator);
        errdefer buf.deinit();
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            self.pos += 1;
            if (c == '"') return buf.toOwnedSlice();
            if (c == '\\') {
                if (self.pos >= self.src.len) return error.UnexpectedEnd;
                const esc = self.src[self.pos];
                self.pos += 1;
                switch (esc) {
                    '"' => try buf.append('"'),
                    '\\' => try buf.append('\\'),
                    '/' => try buf.append('/'),
                    'b' => try buf.append(0x08),
                    'f' => try buf.append(0x0c),
                    'n' => try buf.append('\n'),
                    'r' => try buf.append('\r'),
                    't' => try buf.append('\t'),
                    'u' => {
                        if (self.pos + 4 > self.src.len) return error.UnexpectedEnd;
                        const hex = self.src[self.pos .. self.pos + 4];
                        self.pos += 4;
                        const cp = std.fmt.parseInt(u21, hex, 16) catch return error.InvalidEscape;
                        var tmp: [4]u8 = undefined;
                        const n = std.unicode.utf8Encode(cp, &tmp) catch {
                            try buf.appendSlice("?");
                            continue;
                        };
                        try buf.appendSlice(tmp[0..n]);
                    },
                    else => return error.InvalidEscape,
                }
            } else {
                try buf.append(c);
            }
        }
        return error.UnexpectedEnd;
    }

    fn parseArray(self: *Parser) ParseError!Value {
        try self.expect('[');
        var items = std.ArrayList(Value).init(self.allocator);
        errdefer {
            for (items.items) |*it| it.deinit(self.allocator);
            items.deinit();
        }
        self.skipWhitespace();
        if (self.peek() == @as(u8, ']')) {
            self.pos += 1;
            return .{ .array = try items.toOwnedSlice() };
        }
        while (true) {
            const v = try self.parseValue();
            try items.append(v);
            self.skipWhitespace();
            const c = self.peek() orelse return error.UnexpectedEnd;
            if (c == ',') {
                self.pos += 1;
                continue;
            }
            if (c == ']') {
                self.pos += 1;
                return .{ .array = try items.toOwnedSlice() };
            }
            return error.UnexpectedToken;
        }
    }

    fn parseObject(self: *Parser) ParseError!Value {
        try self.expect('{');
        var obj: Value.ObjectEntries = .{};
        errdefer {
            var it = obj.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.*.deinit(self.allocator);
            }
            obj.deinit(self.allocator);
        }
        self.skipWhitespace();
        if (self.peek() == @as(u8, '}')) {
            self.pos += 1;
            return .{ .object = obj };
        }
        while (true) {
            self.skipWhitespace();
            const key = try self.parseString();
            errdefer self.allocator.free(key);
            self.skipWhitespace();
            try self.expect(':');
            const v = try self.parseValue();
            const gop = try obj.getOrPut(self.allocator, key);
            if (gop.found_existing) {
                self.allocator.free(key);
                gop.value_ptr.*.deinit(self.allocator);
            }
            gop.value_ptr.* = v;
            self.skipWhitespace();
            const c = self.peek() orelse return error.UnexpectedEnd;
            if (c == ',') {
                self.pos += 1;
                continue;
            }
            if (c == '}') {
                self.pos += 1;
                return .{ .object = obj };
            }
            return error.UnexpectedToken;
        }
    }
};

pub fn parse(allocator: std.mem.Allocator, src: []const u8) !Value {
    var parser = Parser{ .src = src, .pos = 0, .allocator = allocator };
    parser.skipWhitespace();
    const v = try parser.parseValue();
    return v;
}

pub fn stringify(allocator: std.mem.Allocator, value: Value) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try writeValue(buf.writer(), value);
    return buf.toOwnedSlice();
}

fn writeValue(writer: anytype, value: Value) anyerror!void {
    switch (value) {
        .null_value => try writer.writeAll("null"),
        .bool_value => |b| try writer.writeAll(if (b) "true" else "false"),
        .int_value => |i| try writer.print("{d}", .{i}),
        .float_value => |f| {
            if (std.math.isNan(f) or std.math.isInf(f)) {
                try writer.writeAll("null");
            } else {
                try writer.print("{d}", .{f});
            }
        },
        .string => |s| try writeString(writer, s),
        .array => |items| {
            try writer.writeByte('[');
            for (items, 0..) |item, i| {
                if (i != 0) try writer.writeByte(',');
                try writeValue(writer, item);
            }
            try writer.writeByte(']');
        },
        .object => |obj| {
            try writer.writeByte('{');
            var it = obj.iterator();
            var first = true;
            while (it.next()) |entry| {
                if (!first) try writer.writeByte(',');
                first = false;
                try writeString(writer, entry.key_ptr.*);
                try writer.writeByte(':');
                try writeValue(writer, entry.value_ptr.*);
            }
            try writer.writeByte('}');
        },
    }
}

fn writeString(writer: anytype, s: []const u8) anyerror!void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0c => try writer.writeAll("\\f"),
            0...0x07, 0x0b, 0x0e...0x1f => try writer.print("\\u{X:0>4}", .{c}),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

pub fn makeObject(allocator: std.mem.Allocator) Value {
    _ = allocator;
    return .{ .object = .{} };
}

pub fn objectPut(allocator: std.mem.Allocator, obj: *Value, key: []const u8, value: Value) !void {
    if (obj.* != .object) return error.NotAnObject;
    const dup_key = try allocator.dupe(u8, key);
    errdefer allocator.free(dup_key);
    const gop = try obj.object.getOrPut(allocator, dup_key);
    if (gop.found_existing) {
        allocator.free(dup_key);
        gop.value_ptr.*.deinit(allocator);
    }
    gop.value_ptr.* = value;
}

pub fn makeString(allocator: std.mem.Allocator, s: []const u8) !Value {
    return .{ .string = try allocator.dupe(u8, s) };
}

pub fn makeInt(i: i64) Value {
    return .{ .int_value = i };
}

pub fn makeFloat(f: f64) Value {
    return .{ .float_value = f };
}

pub fn makeBool(b: bool) Value {
    return .{ .bool_value = b };
}

pub fn makeNull() Value {
    return .null_value;
}

pub fn makeArray(allocator: std.mem.Allocator, len: usize) !Value {
    const items = try allocator.alloc(Value, len);
    for (items) |*it| it.* = .null_value;
    return .{ .array = items };
}

test "json round trip" {
    const testing = std.testing;
    const src =
        \\{"name":"agdb","version":1,"flags":[true,false,null],"meta":{"x":1.5}}
    ;
    var v = try parse(testing.allocator, src);
    defer v.deinit(testing.allocator);
    const name = v.getField("name").?;
    try testing.expectEqualStrings("agdb", name.asString().?);
    try testing.expectEqual(@as(i64, 1), v.getField("version").?.asInt().?);

    const out = try stringify(testing.allocator, v);
    defer testing.allocator.free(out);
    var v2 = try parse(testing.allocator, out);
    defer v2.deinit(testing.allocator);
    try testing.expectEqualStrings("agdb", v2.getField("name").?.asString().?);
}

test "json escapes" {
    const testing = std.testing;
    const src =
        \\"hello\nworld\t\"quote\u00e9"
    ;
    var v = try parse(testing.allocator, src);
    defer v.deinit(testing.allocator);
    const s = v.asString().?;
    try testing.expect(std.mem.indexOf(u8, s, "\n") != null);
    try testing.expect(std.mem.indexOf(u8, s, "\t") != null);
    try testing.expect(std.mem.indexOf(u8, s, "\"quote") != null);
}
