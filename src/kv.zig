const std = @import("std");

pub const KvError = error{
    Corrupted,
    NotFound,
    IoError,
    KeyTooLong,
    ValueTooLong,
    AlreadyOpen,
    NotOpen,
};

const MAGIC: u32 = 0x4147_4442;
const VERSION: u16 = 1;
const HEADER_SIZE: u64 = 64;
const MAX_KEY_LEN: usize = 64 * 1024;
const MAX_VALUE_LEN: usize = 64 * 1024 * 1024;

const Op = enum(u8) {
    put = 1,
    delete = 2,
};

const RecordHeader = extern struct {
    magic: u32,
    op: u8,
    reserved: u8,
    key_len: u16,
    value_len: u32,
    timestamp_us: u64,
    crc32: u32,
    pad: u32,
};

const FileHeader = extern struct {
    magic: u32,
    version: u16,
    reserved: u16,
    created_at: u64,
    schema_id: u64,
    last_offset: u64,
    record_count: u64,
    flags: u64,
    pad: [16]u8,
};

pub const Entry = struct {
    offset: u64,
    value_offset: u64,
    value_len: u32,
    key_len: u16,
};

pub const KvStore = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    file: std.fs.File,
    file_size: u64,
    header: FileHeader,
    index: std.StringHashMapUnmanaged(Entry),
    keys_arena: std.heap.ArenaAllocator,
    mutex: std.Thread.Mutex,
    schema_id: u64,
    record_count: u64,
    dead_bytes: u64,

    const Self = @This();

    pub fn open(allocator: std.mem.Allocator, path: []const u8, schema_id: u64) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const path_dup = try allocator.dupe(u8, path);
        errdefer allocator.free(path_dup);

        const file_existed = blk: {
            std.fs.cwd().access(path, .{}) catch {
                break :blk false;
            };
            break :blk true;
        };

        const file = std.fs.cwd().createFile(path, .{ .read = true, .truncate = false }) catch |err| switch (err) {
            error.PathAlreadyExists => try std.fs.cwd().openFile(path, .{ .mode = .read_write }),
            else => return err,
        };
        errdefer file.close();

        var keys_arena = std.heap.ArenaAllocator.init(allocator);
        errdefer keys_arena.deinit();

        self.* = .{
            .allocator = allocator,
            .path = path_dup,
            .file = file,
            .file_size = 0,
            .header = undefined,
            .index = .{},
            .keys_arena = keys_arena,
            .mutex = .{},
            .schema_id = schema_id,
            .record_count = 0,
            .dead_bytes = 0,
        };

        const stat = try file.stat();
        self.file_size = stat.size;

        if (!file_existed or self.file_size == 0) {
            try self.writeNewHeader();
        } else {
            try self.readAndRepairHeader();
            try self.replayLog();
        }

        return self;
    }

    pub fn close(self: *Self) void {
        self.file.close();
        self.index.deinit(self.allocator);
        self.keys_arena.deinit();
        self.allocator.free(self.path);
        const a = self.allocator;
        a.destroy(self);
    }

    fn writeNewHeader(self: *Self) !void {
        var header = FileHeader{
            .magic = MAGIC,
            .version = VERSION,
            .reserved = 0,
            .created_at = @intCast(std.time.microTimestamp()),
            .schema_id = self.schema_id,
            .last_offset = HEADER_SIZE,
            .record_count = 0,
            .flags = 0,
            .pad = [_]u8{0} ** 16,
        };
        self.header = header;
        const buf: *[@sizeOf(FileHeader)]u8 = @ptrCast(&header);
        try self.file.seekTo(0);
        try self.file.writeAll(buf[0..@sizeOf(FileHeader)]);
        const pad_count = HEADER_SIZE - @sizeOf(FileHeader);
        if (pad_count > 0) {
            const pad_bytes = try self.allocator.alloc(u8, pad_count);
            defer self.allocator.free(pad_bytes);
            @memset(pad_bytes, 0);
            try self.file.writeAll(pad_bytes);
        }
        try self.file.sync();
        self.file_size = HEADER_SIZE;
    }

    fn readAndRepairHeader(self: *Self) !void {
        try self.file.seekTo(0);
        var hdr: FileHeader = undefined;
        const hdr_buf: *[@sizeOf(FileHeader)]u8 = @ptrCast(&hdr);
        const n = try self.file.readAll(hdr_buf);
        if (n < @sizeOf(FileHeader)) return KvError.Corrupted;
        if (hdr.magic != MAGIC) return KvError.Corrupted;
        if (hdr.version != VERSION) return KvError.Corrupted;
        if (self.schema_id != 0 and hdr.schema_id != 0 and hdr.schema_id != self.schema_id) return KvError.Corrupted;
        if (hdr.schema_id == 0 and self.schema_id != 0) {
            hdr.schema_id = self.schema_id;
            try self.flushHeader(&hdr);
        }
        self.header = hdr;
        if (self.header.last_offset > self.file_size) {
            self.header.last_offset = self.file_size;
            try self.flushHeader(&self.header);
        }
    }

    fn flushHeader(self: *Self, hdr: *FileHeader) !void {
        try self.file.seekTo(0);
        const buf: *[@sizeOf(FileHeader)]u8 = @ptrCast(hdr);
        try self.file.writeAll(buf[0..@sizeOf(FileHeader)]);
    }

    fn replayLog(self: *Self) !void {
        var pos: u64 = HEADER_SIZE;
        const max_pos = self.header.last_offset;
        while (pos + @sizeOf(RecordHeader) <= max_pos) {
            try self.file.seekTo(pos);
            var rec: RecordHeader = undefined;
            const rec_buf: *[@sizeOf(RecordHeader)]u8 = @ptrCast(&rec);
            const read_n = try self.file.readAll(rec_buf);
            if (read_n < @sizeOf(RecordHeader)) break;
            if (rec.magic != MAGIC) break;
            const key_len: usize = rec.key_len;
            const value_len: usize = rec.value_len;
            const record_body_size: u64 = @as(u64, key_len) + @as(u64, value_len);
            const total_size: u64 = @sizeOf(RecordHeader) + record_body_size;
            if (pos + total_size > max_pos) break;
            if (key_len > MAX_KEY_LEN) break;
            if (value_len > MAX_VALUE_LEN) break;

            const key_bytes = try self.allocator.alloc(u8, key_len);
            defer self.allocator.free(key_bytes);
            const got_k = try self.file.readAll(key_bytes);
            if (got_k < key_len) break;

            try self.file.seekTo(pos + @sizeOf(RecordHeader) + key_len);
            const value_buf = try self.allocator.alloc(u8, value_len);
            defer self.allocator.free(value_buf);
            const got_v = if (value_len == 0) 0 else try self.file.readAll(value_buf);
            if (got_v < value_len) break;

            const expected_crc = computeCrc(rec.op, key_bytes, value_buf, rec.timestamp_us);
            if (expected_crc != rec.crc32) break;

            const value_offset = pos + @sizeOf(RecordHeader) + key_len;
            switch (@as(Op, @enumFromInt(rec.op))) {
                .put => {
                    const gop = try self.index.getOrPut(self.allocator, key_bytes);
                    if (gop.found_existing) {
                        self.dead_bytes += gop.value_ptr.value_len + @sizeOf(RecordHeader) + gop.value_ptr.key_len;
                    } else {
                        const interned_key = try self.keys_arena.allocator().dupe(u8, key_bytes);
                        gop.key_ptr.* = interned_key;
                        self.record_count += 1;
                    }
                    gop.value_ptr.* = Entry{
                        .offset = pos,
                        .value_offset = value_offset,
                        .value_len = rec.value_len,
                        .key_len = rec.key_len,
                    };
                },
                .delete => {
                    if (self.index.fetchRemove(key_bytes)) |kv| {
                        self.dead_bytes += kv.value.value_len + @sizeOf(RecordHeader) + kv.value.key_len;
                        if (self.record_count > 0) self.record_count -= 1;
                    }
                    self.dead_bytes += @sizeOf(RecordHeader) + key_len;
                },
            }
            pos += total_size;
        }
        if (pos != self.header.last_offset) {
            self.header.last_offset = pos;
            try self.flushHeader(&self.header);
            try self.file.setEndPos(pos);
            self.file_size = pos;
        }
    }

    fn computeCrc(op: u8, key: []const u8, value: []const u8, ts: u64) u32 {
        var crc = std.hash.Crc32.init();
        crc.update(&[_]u8{op});
        var ts_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &ts_bytes, ts, .little);
        crc.update(&ts_bytes);
        crc.update(key);
        crc.update(value);
        return crc.final();
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) !void {
        if (key.len > MAX_KEY_LEN) return KvError.KeyTooLong;
        if (value.len > MAX_VALUE_LEN) return KvError.ValueTooLong;
        self.mutex.lock();
        defer self.mutex.unlock();

        const ts: u64 = @intCast(std.time.microTimestamp());
        var rec = RecordHeader{
            .magic = MAGIC,
            .op = @intFromEnum(Op.put),
            .reserved = 0,
            .key_len = @intCast(key.len),
            .value_len = @intCast(value.len),
            .timestamp_us = ts,
            .crc32 = 0,
            .pad = 0,
        };
        rec.crc32 = computeCrc(rec.op, key, value, ts);

        const offset = self.header.last_offset;
        try self.file.seekTo(offset);
        const hdr_bytes: *[@sizeOf(RecordHeader)]u8 = @ptrCast(&rec);
        try self.file.writeAll(hdr_bytes);
        try self.file.writeAll(key);
        if (value.len > 0) try self.file.writeAll(value);
        try self.file.sync();

        const total: u64 = @sizeOf(RecordHeader) + key.len + value.len;
        const value_offset = offset + @sizeOf(RecordHeader) + key.len;

        const gop = try self.index.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            self.dead_bytes += gop.value_ptr.value_len + @sizeOf(RecordHeader) + gop.value_ptr.key_len;
        } else {
            const interned_key = try self.keys_arena.allocator().dupe(u8, key);
            gop.key_ptr.* = interned_key;
            self.record_count += 1;
        }
        gop.value_ptr.* = Entry{
            .offset = offset,
            .value_offset = value_offset,
            .value_len = rec.value_len,
            .key_len = rec.key_len,
        };

        self.header.last_offset = offset + total;
        self.header.record_count = self.record_count;
        try self.flushHeader(&self.header);
        try self.file.sync();
        self.file_size = self.header.last_offset;
    }

    pub fn get(self: *Self, allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.index.get(key) orelse return null;
        if (entry.value_len == 0) {
            const out = try allocator.alloc(u8, 0);
            return out;
        }
        const buf = try allocator.alloc(u8, entry.value_len);
        errdefer allocator.free(buf);
        try self.file.seekTo(entry.value_offset);
        const n = try self.file.readAll(buf);
        if (n < entry.value_len) return KvError.Corrupted;
        return buf;
    }

    pub fn contains(self: *Self, key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.index.contains(key);
    }

    pub fn delete(self: *Self, key: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const existed = self.index.contains(key);
        if (!existed) return false;

        const ts: u64 = @intCast(std.time.microTimestamp());
        var rec = RecordHeader{
            .magic = MAGIC,
            .op = @intFromEnum(Op.delete),
            .reserved = 0,
            .key_len = @intCast(key.len),
            .value_len = 0,
            .timestamp_us = ts,
            .crc32 = 0,
            .pad = 0,
        };
        rec.crc32 = computeCrc(rec.op, key, &[_]u8{}, ts);

        const offset = self.header.last_offset;
        try self.file.seekTo(offset);
        const hdr_bytes: *[@sizeOf(RecordHeader)]u8 = @ptrCast(&rec);
        try self.file.writeAll(hdr_bytes);
        try self.file.writeAll(key);
        try self.file.sync();

        if (self.index.fetchRemove(key)) |kv| {
            self.dead_bytes += kv.value.value_len + @sizeOf(RecordHeader) + kv.value.key_len;
            if (self.record_count > 0) self.record_count -= 1;
        }
        self.dead_bytes += @sizeOf(RecordHeader) + key.len;

        self.header.last_offset = offset + @sizeOf(RecordHeader) + key.len;
        self.header.record_count = self.record_count;
        try self.flushHeader(&self.header);
        try self.file.sync();
        self.file_size = self.header.last_offset;
        return true;
    }

    pub fn count(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.record_count;
    }

    pub fn diskSize(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.file_size;
    }

    pub fn deadBytes(self: *Self) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.dead_bytes;
    }

    pub fn flush(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.file.sync();
    }

    pub const KeyValue = struct {
        key: []const u8,
        value: []u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *KeyValue) void {
            self.allocator.free(self.key);
            self.allocator.free(self.value);
        }
    };

    pub const Iterator = struct {
        items: []KeyValue,
        index: usize,
        allocator: std.mem.Allocator,

        pub fn next(self: *Iterator) !?KeyValue {
            if (self.index >= self.items.len) return null;
            const item = self.items[self.index];
            self.index += 1;
            return item;
        }

        pub fn deinit(self: *Iterator) void {
            var i: usize = self.index;
            while (i < self.items.len) : (i += 1) {
                self.allocator.free(self.items[i].key);
                self.allocator.free(self.items[i].value);
            }
            self.allocator.free(self.items);
            self.items = &[_]KeyValue{};
            self.index = 0;
        }
    };

    pub fn iterator(self: *Self) !Iterator {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry_count = self.index.count();
        const items = try self.allocator.alloc(KeyValue, entry_count);
        var produced: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < produced) : (i += 1) {
                self.allocator.free(items[i].key);
                self.allocator.free(items[i].value);
            }
            self.allocator.free(items);
        }

        var it = self.index.iterator();
        while (it.next()) |entry| {
            const key_copy = try self.allocator.dupe(u8, entry.key_ptr.*);
            errdefer self.allocator.free(key_copy);
            const value_buf = try self.allocator.alloc(u8, entry.value_ptr.value_len);
            errdefer self.allocator.free(value_buf);
            if (entry.value_ptr.value_len > 0) {
                try self.file.seekTo(entry.value_ptr.value_offset);
                const n = try self.file.readAll(value_buf);
                if (n < entry.value_ptr.value_len) return KvError.Corrupted;
            }
            items[produced] = KeyValue{
                .key = key_copy,
                .value = value_buf,
                .allocator = self.allocator,
            };
            produced += 1;
        }

        return Iterator{
            .items = items,
            .index = 0,
            .allocator = self.allocator,
        };
    }

    pub fn compact(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.compact", .{self.path});
        defer self.allocator.free(tmp_path);
        std.fs.cwd().deleteFile(tmp_path) catch {};

        var tmp = try std.fs.cwd().createFile(tmp_path, .{ .read = true });
        errdefer tmp.close();

        var new_header = FileHeader{
            .magic = MAGIC,
            .version = VERSION,
            .reserved = 0,
            .created_at = self.header.created_at,
            .schema_id = self.schema_id,
            .last_offset = HEADER_SIZE,
            .record_count = 0,
            .flags = 0,
            .pad = [_]u8{0} ** 16,
        };
        const hdr_bytes: *[@sizeOf(FileHeader)]u8 = @ptrCast(&new_header);
        try tmp.writeAll(hdr_bytes);
        const pad_count = HEADER_SIZE - @sizeOf(FileHeader);
        if (pad_count > 0) {
            const pad_bytes = try self.allocator.alloc(u8, pad_count);
            defer self.allocator.free(pad_bytes);
            @memset(pad_bytes, 0);
            try tmp.writeAll(pad_bytes);
        }

        var offset: u64 = HEADER_SIZE;
        var count_after: u64 = 0;

        var new_keys_arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer new_keys_arena.deinit();

        var new_index: std.StringHashMapUnmanaged(Entry) = .{};
        errdefer new_index.deinit(self.allocator);

        var it = self.index.iterator();
        while (it.next()) |kv_entry| {
            const key = kv_entry.key_ptr.*;
            const ventry = kv_entry.value_ptr.*;
            const value_buf = try self.allocator.alloc(u8, ventry.value_len);
            defer self.allocator.free(value_buf);
            if (ventry.value_len > 0) {
                try self.file.seekTo(ventry.value_offset);
                const got = try self.file.readAll(value_buf);
                if (got < ventry.value_len) return KvError.Corrupted;
            }
            const ts: u64 = @intCast(std.time.microTimestamp());
            var rec = RecordHeader{
                .magic = MAGIC,
                .op = @intFromEnum(Op.put),
                .reserved = 0,
                .key_len = @intCast(key.len),
                .value_len = ventry.value_len,
                .timestamp_us = ts,
                .crc32 = 0,
                .pad = 0,
            };
            rec.crc32 = computeCrc(rec.op, key, value_buf, ts);

            const rec_bytes: *[@sizeOf(RecordHeader)]u8 = @ptrCast(&rec);
            try tmp.writeAll(rec_bytes);
            try tmp.writeAll(key);
            if (ventry.value_len > 0) try tmp.writeAll(value_buf);

            const new_value_offset = offset + @sizeOf(RecordHeader) + key.len;
            const interned_key = try new_keys_arena.allocator().dupe(u8, key);
            try new_index.put(self.allocator, interned_key, Entry{
                .offset = offset,
                .value_offset = new_value_offset,
                .value_len = ventry.value_len,
                .key_len = @intCast(key.len),
            });
            offset += @sizeOf(RecordHeader) + key.len + ventry.value_len;
            count_after += 1;
        }

        new_header.last_offset = offset;
        new_header.record_count = count_after;
        try tmp.seekTo(0);
        try tmp.writeAll(hdr_bytes);
        try tmp.sync();
        tmp.close();

        self.file.close();
        try std.fs.cwd().rename(tmp_path, self.path);
        self.file = try std.fs.cwd().openFile(self.path, .{ .mode = .read_write });
        self.file_size = offset;
        self.header = new_header;

        self.index.deinit(self.allocator);
        self.keys_arena.deinit();
        self.index = new_index;
        self.keys_arena = new_keys_arena;
        self.record_count = count_after;
        self.dead_bytes = 0;
    }
};

test "kv put get delete" {
    const testing = std.testing;
    const tmp_dir = "agdb-test-kv";
    std.fs.cwd().deleteTree(tmp_dir) catch {};
    try std.fs.cwd().makePath(tmp_dir);
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    const path = try std.fmt.allocPrint(testing.allocator, "{s}/store.kv", .{tmp_dir});
    defer testing.allocator.free(path);

    var kv = try KvStore.open(testing.allocator, path, 0);
    try kv.put("foo", "bar");
    try kv.put("name", "agdb");
    try testing.expect(kv.contains("foo"));

    const got = try kv.get(testing.allocator, "foo");
    defer if (got) |g| testing.allocator.free(g);
    try testing.expectEqualStrings("bar", got.?);

    _ = try kv.delete("foo");
    try testing.expect(!kv.contains("foo"));
    try testing.expectEqual(@as(u64, 1), kv.count());

    const path_dup = try testing.allocator.dupe(u8, path);
    defer testing.allocator.free(path_dup);
    kv.close();

    var kv2 = try KvStore.open(testing.allocator, path_dup, 0);
    defer kv2.close();
    try testing.expect(!kv2.contains("foo"));
    try testing.expect(kv2.contains("name"));
    try testing.expectEqual(@as(u64, 1), kv2.count());

    try kv2.compact();
    try testing.expect(kv2.contains("name"));
    try testing.expectEqual(@as(u64, 1), kv2.count());
}
