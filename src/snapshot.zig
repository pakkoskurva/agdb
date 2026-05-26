const std = @import("std");
const posix = std.posix;
const header = @import("header.zig");
const pheap = @import("pheap.zig");
const pointer = @import("pointer.zig");

const page_size_bytes: usize = 4096;

pub const SNAPSHOT_MAGIC: u32 = 0x534E5053;
pub const SNAPSHOT_VERSION: u32 = 1;

pub const SnapshotHeader = extern struct {
    magic: u32,
    version: u32,
    snapshot_id: u64,
    timestamp: i64,
    heap_size: u64,
    root_offset: u64,
    root_uuid_low: u64,
    root_uuid_high: u64,
    page_count: u64,
    dirty_page_count: u64,
    merkle_root: [32]u8,
    parent_snapshot: u64,
    checksum: u32,
    reserved: [60]u8,

    pub fn init(id: u64, heap_size: u64, root: pointer.PersistentPtr) SnapshotHeader {
        return SnapshotHeader{
            .magic = SNAPSHOT_MAGIC,
            .version = SNAPSHOT_VERSION,
            .snapshot_id = id,
            .timestamp = std.time.timestamp(),
            .heap_size = heap_size,
            .root_offset = root.offset,
            .root_uuid_low = @truncate(root.pool_uuid),
            .root_uuid_high = @truncate(root.pool_uuid >> 64),
            .page_count = heap_size / page_size_bytes,
            .dirty_page_count = 0,
            .merkle_root = [_]u8{0} ** 32,
            .parent_snapshot = 0,
            .checksum = 0,
            .reserved = [_]u8{0} ** 60,
        };
    }

    pub fn computeChecksum(self: *const SnapshotHeader) u32 {
        const bytes = std.mem.asBytes(self);
        var crc: u32 = 0xFFFFFFFF;
        for (bytes[0..@offsetOf(SnapshotHeader, "checksum")]) |byte| {
            crc ^= @as(u32, byte);
            var j: usize = 0;
            while (j < 8) : (j += 1) {
                crc = if ((crc & 1) != 0) (crc >> 1) ^ 0x82F63B78 else crc >> 1;
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn updateChecksum(self: *SnapshotHeader) void {
        self.checksum = self.computeChecksum();
    }

    pub fn validate(self: *const SnapshotHeader) !void {
        if (self.magic != SNAPSHOT_MAGIC) return error.InvalidSnapshotMagic;
        if (self.version > SNAPSHOT_VERSION) return error.UnsupportedSnapshotVersion;
        if (self.checksum != self.computeChecksum()) return error.ChecksumMismatch;
    }
};

pub const SnapshotMetadata = extern struct {
    page_bitmap_offset: u64,
    page_bitmap_size: u64,
    data_offset: u64,
    data_size: u64,
    merkle_tree_offset: u64,
    merkle_tree_size: u64,
};

pub const MerkleNode = extern struct {
    hash: [32]u8,
    left_offset: u64,
    right_offset: u64,
    flags: u32,
    reserved: u32,
};

pub const DirtyPageTracker = struct {
    bitmap: []u64,
    page_count: u64,
    dirty_count: std.atomic.Value(u64),
    protected: []bool,
    base_addr: [*]const u8,
    page_size: u64,

    const BITS_PER_WORD: u64 = 64;

    pub fn init(allocator_ptr: std.mem.Allocator, heap_size: u64, base_addr: [*]const u8) !DirtyPageTracker {
        const page_count = heap_size / page_size_bytes;
        const bitmap_words = (page_count + BITS_PER_WORD - 1) / BITS_PER_WORD;

        const bitmap = try allocator_ptr.alloc(u64, bitmap_words);
        @memset(bitmap, 0);

        const protected = try allocator_ptr.alloc(bool, page_count);
        @memset(protected, false);

        return DirtyPageTracker{
            .bitmap = bitmap,
            .page_count = page_count,
            .dirty_count = std.atomic.Value(u64).init(0),
            .protected = protected,
            .base_addr = base_addr,
            .page_size = page_size_bytes,
        };
    }

    pub fn deinit(self: *DirtyPageTracker, allocator_ptr: std.mem.Allocator) void {
        allocator_ptr.free(self.bitmap);
        allocator_ptr.free(self.protected);
    }

    pub fn markDirty(self: *DirtyPageTracker, page_idx: u64) void {
        if (page_idx >= self.page_count) return;

        const word_idx = page_idx / BITS_PER_WORD;
        const bit_idx = page_idx % BITS_PER_WORD;
        const mask = @as(u64, 1) << @as(u6, @intCast(bit_idx));

        const old = @atomicRmw(u64, &self.bitmap[word_idx], .Or, mask, .acq_rel);
        if (old & mask == 0) {
            _ = self.dirty_count.fetchAdd(1, .monotonic);
        }
    }

    pub fn isDirty(self: *const DirtyPageTracker, page_idx: u64) bool {
        if (page_idx >= self.page_count) return false;

        const word_idx = page_idx / BITS_PER_WORD;
        const bit_idx = page_idx % BITS_PER_WORD;
        const mask = @as(u64, 1) << @as(u6, @intCast(bit_idx));

        return (self.bitmap[word_idx] & mask) != 0;
    }

    pub fn getDirtyPageCount(self: *const DirtyPageTracker) u64 {
        return self.dirty_count.load(.monotonic);
    }

    pub fn getDirtyPages(self: *const DirtyPageTracker, allocator_ptr: std.mem.Allocator) !std.ArrayList(u64) {
        var pages = std.ArrayList(u64).init(allocator_ptr);

        var page_idx: u64 = 0;
        while (page_idx < self.page_count) : (page_idx += 1) {
            if (self.isDirty(page_idx)) {
                try pages.append(page_idx);
            }
        }

        return pages;
    }

    pub fn clear(self: *DirtyPageTracker) void {
        @memset(self.bitmap, 0);
        self.dirty_count.store(0, .monotonic);
    }

    pub fn protectPages(self: *DirtyPageTracker) !void {
        var page_idx: u64 = 0;
        while (page_idx < self.page_count) : (page_idx += 1) {
            if (!self.protected[page_idx]) {
                const addr = self.base_addr + page_idx * self.page_size;
                const slice = mprotectSlice(addr, self.page_size);
                posix.mprotect(slice, posix.PROT.READ) catch {};
                self.protected[page_idx] = true;
            }
        }
    }

    pub fn unprotectPage(self: *DirtyPageTracker, page_idx: u64) !void {
        if (page_idx >= self.page_count) return;

        const addr = self.base_addr + page_idx * self.page_size;
        const slice = mprotectSlice(addr, self.page_size);
        posix.mprotect(slice, posix.PROT.READ | posix.PROT.WRITE) catch {};
        self.protected[page_idx] = false;
        self.markDirty(page_idx);
    }

    pub fn unprotectAll(self: *DirtyPageTracker) void {
        var page_idx: u64 = 0;
        while (page_idx < self.page_count) : (page_idx += 1) {
            if (self.protected[page_idx]) {
                const addr = self.base_addr + page_idx * self.page_size;
                const slice = mprotectSlice(addr, self.page_size);
                posix.mprotect(slice, posix.PROT.READ | posix.PROT.WRITE) catch {};
                self.protected[page_idx] = false;
            }
        }
    }
};

fn mprotectSlice(addr: [*]const u8, size: u64) []align(std.heap.page_size_min) u8 {
    const mut_ptr: [*]u8 = @ptrFromInt(@intFromPtr(addr));
    const aligned: [*]align(std.heap.page_size_min) u8 = @alignCast(mut_ptr);
    return aligned[0..size];
}

pub const SnapshotManager = struct {
    heap: *pheap.PersistentHeap,
    snapshot_dir: ?[]const u8,
    snapshots: std.ArrayList(SnapshotInfo),
    dirty_tracker: DirtyPageTracker,
    next_snapshot_id: std.atomic.Value(u64),
    allocator: std.mem.Allocator,
    lock: std.Thread.RwLock,
    merkle_tree: []MerkleNode,

    const Self = @This();

    pub const SnapshotInfo = struct {
        id: u64,
        timestamp: i64,
        path: []const u8,
        header: SnapshotHeader,
        valid: bool,
    };

    pub fn init(allocator_ptr: std.mem.Allocator, heap: *pheap.PersistentHeap, snapshot_dir: ?[]const u8) !*SnapshotManager {
        const self = try allocator_ptr.create(SnapshotManager);
        errdefer allocator_ptr.destroy(self);

        const dirty_tracker = try DirtyPageTracker.init(allocator_ptr, heap.getSize(), heap.getBaseAddress());

        const snapshots = std.ArrayList(SnapshotInfo).init(allocator_ptr);

        var dir_copy: ?[]const u8 = null;
        if (snapshot_dir) |dir| {
            std.fs.cwd().makePath(dir) catch {};
            dir_copy = try allocator_ptr.dupe(u8, dir);
        }
        errdefer if (dir_copy) |d| allocator_ptr.free(d);

        self.* = SnapshotManager{
            .heap = heap,
            .snapshot_dir = dir_copy,
            .snapshots = snapshots,
            .dirty_tracker = dirty_tracker,
            .next_snapshot_id = std.atomic.Value(u64).init(1),
            .allocator = allocator_ptr,
            .lock = std.Thread.RwLock{},
            .merkle_tree = &[_]MerkleNode{},
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.snapshots.items) |info| {
            self.allocator.free(info.path);
        }
        self.snapshots.deinit();
        self.dirty_tracker.deinit(self.allocator);
        self.allocator.free(self.merkle_tree);
        if (self.snapshot_dir) |dir| {
            self.allocator.free(dir);
        }
        self.allocator.destroy(self);
    }

    pub fn createSnapshot(self: *Self) !u64 {
        self.lock.lock();
        defer self.lock.unlock();

        const snapshot_id = self.next_snapshot_id.fetchAdd(1, .monotonic);

        const root = self.heap.getRoot();
        const root_ptr = root orelse pointer.PersistentPtr.NULL;

        var snap_header = SnapshotHeader.init(snapshot_id, self.heap.getSize(), root_ptr);
        snap_header.dirty_page_count = self.dirty_tracker.getDirtyPageCount();

        const dirty_pages = try self.dirty_tracker.getDirtyPages(self.allocator);
        defer dirty_pages.deinit();

        snap_header.page_count = self.heap.getSize() / page_size_bytes;

        const snapshot_filename = try std.fmt.allocPrint(self.allocator, "snapshot_{d}.snap", .{snapshot_id});
        defer self.allocator.free(snapshot_filename);

        var snapshot_path: []const u8 = undefined;
        if (self.snapshot_dir) |dir| {
            snapshot_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dir, snapshot_filename });
        } else {
            snapshot_path = try self.allocator.dupe(u8, snapshot_filename);
        }
        errdefer self.allocator.free(snapshot_path);

        var snapshot_file = try std.fs.cwd().createFile(snapshot_path, .{ .read = true, .truncate = true });
        defer snapshot_file.close();

        snap_header.updateChecksum();
        try snapshot_file.writeAll(std.mem.asBytes(&snap_header));

        var metadata = SnapshotMetadata{
            .page_bitmap_offset = @sizeOf(SnapshotHeader),
            .page_bitmap_size = (snap_header.page_count + 63) / 64 * 8,
            .data_offset = 0,
            .data_size = 0,
            .merkle_tree_offset = 0,
            .merkle_tree_size = 0,
        };

        const bitmap_size_words = (snap_header.page_count + 63) / 64;
        var bitmap = try self.allocator.alloc(u64, bitmap_size_words);
        defer self.allocator.free(bitmap);
        @memset(bitmap, 0);

        for (dirty_pages.items) |page_idx| {
            const word_idx = page_idx / 64;
            const bit_idx = page_idx % 64;
            bitmap[word_idx] |= @as(u64, 1) << @as(u6, @intCast(bit_idx));
        }

        try snapshot_file.writeAll(std.mem.sliceAsBytes(bitmap));

        metadata.data_offset = metadata.page_bitmap_offset + metadata.page_bitmap_size;

        const base_addr = self.heap.getBaseAddress();
        var total_written: u64 = 0;

        for (dirty_pages.items) |page_idx| {
            const page_offset = page_idx * page_size_bytes;
            const page_data = base_addr[page_offset .. page_offset + page_size_bytes];
            try snapshot_file.writeAll(page_data);
            total_written += page_size_bytes;
        }

        metadata.data_size = total_written;

        try self.buildMerkleTree();

        const info = SnapshotInfo{
            .id = snapshot_id,
            .timestamp = snap_header.timestamp,
            .path = snapshot_path,
            .header = snap_header,
            .valid = true,
        };

        try self.snapshots.append(info);

        self.dirty_tracker.clear();

        return snapshot_id;
    }

    pub fn restoreSnapshot(self: *Self, snapshot_id: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const info = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;

        if (!info.valid) {
            return error.SnapshotInvalid;
        }

        var snapshot_file = try std.fs.cwd().openFile(info.path, .{});
        defer snapshot_file.close();

        try info.header.validate();

        var header_buf: [@sizeOf(SnapshotHeader)]u8 = undefined;
        _ = try snapshot_file.readAll(&header_buf);
        const loaded_header: *const SnapshotHeader = @ptrCast(@alignCast(&header_buf));

        try loaded_header.validate();

        const bitmap_size_words = (loaded_header.page_count + 63) / 64;
        const bitmap = try self.allocator.alloc(u64, bitmap_size_words);
        defer self.allocator.free(bitmap);

        _ = try snapshot_file.readAll(std.mem.sliceAsBytes(bitmap));

        const data_offset = @sizeOf(SnapshotHeader) + bitmap.len * @sizeOf(u64);
        try snapshot_file.seekTo(data_offset);

        const base_addr = self.heap.getBaseAddress();

        var page_idx: u64 = 0;
        while (page_idx < loaded_header.page_count) : (page_idx += 1) {
            const word_idx = page_idx / 64;
            const bit_idx = page_idx % 64;

            if ((bitmap[word_idx] & (@as(u64, 1) << @as(u6, @intCast(bit_idx)))) != 0) {
                const page_offset = page_idx * page_size_bytes;
                var page_buf: [page_size_bytes]u8 = undefined;
                _ = try snapshot_file.readAll(&page_buf);
                @memcpy(base_addr[page_offset .. page_offset + page_size_bytes], &page_buf);
            }
        }

        try self.heap.flush();
    }

    pub fn deleteSnapshot(self: *Self, snapshot_id: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();

        var idx: usize = 0;
        while (idx < self.snapshots.items.len) : (idx += 1) {
            if (self.snapshots.items[idx].id == snapshot_id) {
                const info = self.snapshots.orderedRemove(idx);
                std.fs.cwd().deleteFile(info.path) catch {};
                self.allocator.free(info.path);
                return;
            }
        }

        return error.SnapshotNotFound;
    }

    pub fn listSnapshots(self: *Self) []const SnapshotInfo {
        return self.snapshots.items;
    }

    pub fn getSnapshotCount(self: *Self) u64 {
        return @as(u64, @intCast(self.snapshots.items.len));
    }

    pub fn getLatestSnapshot(self: *Self) ?SnapshotInfo {
        if (self.snapshots.items.len == 0) return null;
        return self.snapshots.items[self.snapshots.items.len - 1];
    }

    fn findSnapshot(self: *Self, snapshot_id: u64) ?SnapshotInfo {
        for (self.snapshots.items) |info| {
            if (info.id == snapshot_id) {
                return info;
            }
        }
        return null;
    }

    pub fn verifySnapshot(self: *Self, snapshot_id: u64) !bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const info = self.findSnapshot(snapshot_id) orelse return error.SnapshotNotFound;

        var snapshot_file = std.fs.cwd().openFile(info.path, .{}) catch return false;
        defer snapshot_file.close();

        var header_buf: [@sizeOf(SnapshotHeader)]u8 = undefined;
        _ = snapshot_file.readAll(&header_buf) catch return false;
        const header_ptr: *const SnapshotHeader = @ptrCast(@alignCast(&header_buf));

        header_ptr.validate() catch return false;

        return true;
    }

    fn buildMerkleTree(self: *Self) !void {
        const page_count = self.heap.getSize() / page_size_bytes;
        const node_count = page_count * 2 - 1;

        if (self.merkle_tree.len < node_count) {
            self.allocator.free(self.merkle_tree);
            self.merkle_tree = try self.allocator.alloc(MerkleNode, node_count);
        }

        const base_addr = self.heap.getBaseAddress();

        var i: u64 = 0;
        while (i < page_count) : (i += 1) {
            const page_offset = i * page_size_bytes;
            const page_data = base_addr[page_offset .. page_offset + page_size_bytes];
            self.merkle_tree[i].hash = sha256Hash(page_data);
            self.merkle_tree[i].left_offset = 0;
            self.merkle_tree[i].right_offset = 0;
            self.merkle_tree[i].flags = 0;
            self.merkle_tree[i].reserved = 0;
        }

        var level_size = page_count;
        var level_start: u64 = 0;

        while (level_size > 1) {
            const next_level_start = level_start + level_size;
            const next_level_size = level_size / 2;

            i = 0;
            while ( i < next_level_size) : (i += 1) {
                const left_idx = level_start + i * 2;
                const right_idx = left_idx + 1;
                const node_idx = next_level_start + i;

                var combined: [64]u8 = undefined;
                @memcpy(combined[0..32], &self.merkle_tree[left_idx].hash);
                @memcpy(combined[32..64], &self.merkle_tree[right_idx].hash);

                self.merkle_tree[node_idx].hash = sha256Hash(&combined);
                self.merkle_tree[node_idx].left_offset = left_idx;
                self.merkle_tree[node_idx].right_offset = right_idx;
            }

            level_start = next_level_start;
            level_size = next_level_size;
        }
    }

    pub fn getMerkleRoot(self: *Self) [32]u8 {
        if (self.merkle_tree.len == 0) {
            return [_]u8{0} ** 32;
        }
        return self.merkle_tree[self.merkle_tree.len - 1].hash;
    }

    pub fn markPageDirty(self: *Self, offset: u64) void {
        const page_idx = offset / page_size_bytes;
        self.dirty_tracker.markDirty(page_idx);
    }
};

fn sha256Hash(data: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

test "snapshot manager creation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const test_heap_path = "/tmp/test_snapshot.dat";
    const test_snap_dir = "/tmp/test_snaps";
    std.fs.cwd().deleteFile(test_heap_path) catch {};

    var heap = try pheap.PersistentHeap.init(alloc, test_heap_path, 1024 * 1024, null);
    defer heap.deinit() catch {};

    var snap_mgr = try SnapshotManager.init(alloc, heap, test_snap_dir);
    defer snap_mgr.deinit();

    const snap_id = try snap_mgr.createSnapshot();
    try testing.expectEqual(@as(u64, 1), snap_id);
    try testing.expectEqual(@as(u64, 1), snap_mgr.getSnapshotCount());
}
