const std = @import("std");
const builtin = @import("builtin");

pub const CACHE_LINE_SIZE: usize = 64;
pub const L1_SIZE: usize = 32 * 1024;
pub const L2_SIZE: usize = 256 * 1024;
pub const L3_SIZE: usize = 8 * 1024 * 1024;
pub const PAGE_SIZE: usize = 4096;
pub const HBM_BANDWIDTH_GBPS: u32 = 900;
pub const DRAM_BANDWIDTH_GBPS: u32 = 50;
pub const NVM_LATENCY_NS: u32 = 300;
pub const DRAM_LATENCY_NS: u32 = 80;

pub fn CacheLinePadded(comptime T: type) type {
    const data_size = @sizeOf(T);
    const padding_size = if (data_size % CACHE_LINE_SIZE == 0)
        0
    else
        CACHE_LINE_SIZE - (data_size % CACHE_LINE_SIZE);
    return struct {
        data: T align(CACHE_LINE_SIZE),
        _pad: [padding_size]u8,

        pub fn init(value: T) @This() {
            return .{ .data = value, ._pad = [_]u8{0} ** padding_size };
        }

        pub fn get(self: *@This()) *T {
            return &self.data;
        }

        pub fn getConst(self: *const @This()) *const T {
            return &self.data;
        }
    };
}

pub fn cacheLineCount(comptime T: type) usize {
    const s = @sizeOf(T);
    return (s + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE;
}

pub fn optimalSlabSize(comptime T: type, objects_per_slab: usize) usize {
    const obj_size = @sizeOf(T);
    const obj_align = @alignOf(T);
    const aligned_size = std.mem.alignForward(usize, obj_size, obj_align);
    const raw = aligned_size * objects_per_slab;
    return std.mem.alignForward(usize, raw, PAGE_SIZE);
}

pub fn fieldPackingAnalysis(comptime T: type) type {
    return struct {
        pub const total_size = @sizeOf(T);
        pub const alignment = @alignOf(T);
        pub const cache_lines = cacheLineCount(T);
        pub const wasted_bytes = blk: {
            var used: usize = 0;
            for (@typeInfo(T).@"struct".fields) |f| {
                used += @sizeOf(f.type);
            }
            break :blk total_size - used;
        };
        pub const packing_efficiency_pct = blk: {
            var used: usize = 0;
            for (@typeInfo(T).@"struct".fields) |f| {
                used += @sizeOf(f.type);
            }
            if (total_size == 0) break :blk @as(usize, 100);
            break :blk (used * 100) / total_size;
        };
        pub const fits_in_cache_line = total_size <= CACHE_LINE_SIZE;
        pub const fits_in_two_cache_lines = total_size <= 2 * CACHE_LINE_SIZE;
        pub const optimal_batch_size: usize = blk: {
            if (total_size == 0) break :blk 64;
            const l1_fit = L1_SIZE / total_size;
            break :blk if (l1_fit > 64) 64 else if (l1_fit > 0) l1_fit else 1;
        };
    };
}

pub fn PackedSlab(comptime T: type, comptime slab_objects: usize) type {
    const analysis = fieldPackingAnalysis(T);
    const slab_sz = optimalSlabSize(T, slab_objects);
    const actual_cap = slab_sz / @sizeOf(T);

    return struct {
        data: [actual_cap]T align(CACHE_LINE_SIZE),
        bitmap: [((actual_cap + 63) / 64)]u64,
        count: usize,

        pub const capacity = actual_cap;
        pub const size_of_slab = slab_sz;
        pub const Analysis = analysis;

        const Self = @This();

        pub fn init() Self {
            var self: Self = undefined;
            @memset(&self.bitmap, 0);
            self.count = 0;
            return self;
        }

        pub fn alloc(self: *Self) ?*T {
            if (self.count >= capacity) return null;
            var slot: usize = 0;
            while (slot < capacity) : (slot += 1) {
                const word = slot / 64;
                const bit: u6 = @intCast(slot % 64);
                if ((self.bitmap[word] >> bit) & 1 == 0) {
                    self.bitmap[word] |= @as(u64, 1) << bit;
                    self.count += 1;
                    return &self.data[slot];
                }
            }
            return null;
        }

        pub fn free(self: *Self, ptr: *T) bool {
            const base = @intFromPtr(&self.data[0]);
            const addr = @intFromPtr(ptr);
            if (addr < base) return false;
            const idx = (addr - base) / @sizeOf(T);
            if (idx >= capacity) return false;
            const word = idx / 64;
            const bit: u6 = @intCast(idx % 64);
            if ((self.bitmap[word] >> bit) & 1 == 0) return false;
            self.bitmap[word] &= ~(@as(u64, 1) << bit);
            self.count -= 1;
            return true;
        }

        pub fn available(self: *const Self) usize {
            return capacity - self.count;
        }
    };
}

pub fn WorkStealDeque(comptime T: type) type {
    return struct {
        buf: []T,
        top: std.atomic.Value(i64),
        bottom: std.atomic.Value(i64),
        allocator: std.mem.Allocator,
        capacity: usize,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, cap: usize) !Self {
            const actual_cap = std.math.ceilPowerOfTwo(usize, @max(cap, 1)) catch return error.OutOfMemory;
            const buf = try allocator.alloc(T, actual_cap);
            return Self{
                .buf = buf,
                .top = std.atomic.Value(i64).init(0),
                .bottom = std.atomic.Value(i64).init(0),
                .allocator = allocator,
                .capacity = actual_cap,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buf);
        }

        pub fn push(self: *Self, item: T) bool {
            const b = self.bottom.load(.acquire);
            const t = self.top.load(.acquire);
            const sz = b - t;
            if (sz >= @as(i64, @intCast(self.capacity))) return false;
            const mask = @as(i64, @intCast(self.capacity - 1));
            self.buf[@intCast(b & mask)] = item;
            asm volatile ("" ::: "memory");
            self.bottom.store(b + 1, .release);
            return true;
        }

        pub fn pop(self: *Self) ?T {
            const b = self.bottom.load(.acquire) - 1;
            self.bottom.store(b, .seq_cst);
            const t = self.top.load(.acquire);
            if (t <= b) {
                const mask = @as(i64, @intCast(self.capacity - 1));
                const item = self.buf[@intCast(b & mask)];
                if (t == b) {
                    if (@cmpxchgStrong(i64, &self.top.raw, t, t + 1, .seq_cst, .seq_cst) != null) {
                        self.bottom.store(b + 1, .seq_cst);
                        return null;
                    }
                    self.bottom.store(b + 1, .seq_cst);
                }
                return item;
            } else {
                self.bottom.store(b + 1, .seq_cst);
                return null;
            }
        }

        pub fn steal(self: *Self) ?T {
            const t = self.top.load(.acquire);
            asm volatile ("" ::: "memory");
            const b = self.bottom.load(.acquire);
            if (t >= b) return null;
            const mask = @as(i64, @intCast(self.capacity - 1));
            const item = self.buf[@intCast(t & mask)];
            if (@cmpxchgStrong(i64, &self.top.raw, t, t + 1, .acq_rel, .acquire) != null) {
                return null;
            }
            return item;
        }

        pub fn size(self: *const Self) usize {
            const b = self.bottom.load(.acquire);
            const t = self.top.load(.acquire);
            if (b <= t) return 0;
            return @intCast(b - t);
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.size() == 0;
        }
    };
}

pub fn computeOptimalThreadCount(work_items: usize, item_cost_ns: u64, sync_overhead_ns: u64) u32 {
    if (item_cost_ns == 0) return 1;
    if (sync_overhead_ns >= item_cost_ns * work_items) return 1;
    const cpu_count: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const ideal = (work_items * item_cost_ns) / (item_cost_ns + sync_overhead_ns);
    const bounded: u32 = @min(@as(u32, @intCast(ideal)), cpu_count);
    return @max(1, bounded);
}

pub const MicroarchProfile = struct {
    l1_cache_size: usize,
    l2_cache_size: usize,
    l3_cache_size: usize,
    cache_line_size: usize,
    cpu_count: u32,
    has_hyperthreading: bool,
    numa_nodes: u32,

    pub fn detect() MicroarchProfile {
        const cpu_count: u32 = @intCast(std.Thread.getCpuCount() catch 1);
        return .{
            .l1_cache_size = L1_SIZE,
            .l2_cache_size = L2_SIZE,
            .l3_cache_size = L3_SIZE,
            .cache_line_size = CACHE_LINE_SIZE,
            .cpu_count = cpu_count,
            .has_hyperthreading = cpu_count > 1,
            .numa_nodes = 1,
        };
    }

    pub fn optimalBatchSize(self: *const MicroarchProfile, comptime T: type) usize {
        const obj_size = @sizeOf(T);
        if (obj_size == 0) return 64;
        const l1_fit = self.l1_cache_size / obj_size;
        return if (l1_fit > 64) 64 else if (l1_fit > 0) l1_fit else 1;
    }

    pub fn optimalSlabObjects(self: *const MicroarchProfile, comptime T: type) usize {
        const obj_size = @sizeOf(T);
        if (obj_size == 0) return 64;
        const l2_fit = self.l2_cache_size / obj_size;
        return std.mem.alignForward(usize, @max(l2_fit, 16), 8);
    }
};

pub fn MPSCQueue(comptime T: type) type {
    return struct {
        const Node = struct {
            value: T,
            next: ?*Node,
        };

        head: ?*Node align(64),
        tail: ?*Node align(64),
        lock: std.Thread.Mutex,
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return Self{
                .head = null,
                .tail = null,
                .lock = .{},
                .allocator = allocator,
            };
        }

        pub fn initPtr(self: *Self, allocator: std.mem.Allocator) void {
            self.allocator = allocator;
            self.head = null;
            self.tail = null;
            self.lock = .{};
        }

        pub fn deinit(self: *Self) void {
            while (self.dequeue()) |_| {}
        }

        pub fn enqueue(self: *Self, value: T) !void {
            const node = try self.allocator.create(Node);
            node.* = .{
                .value = value,
                .next = null,
            };
            self.lock.lock();
            defer self.lock.unlock();
            if (self.tail) |t| {
                t.next = node;
                self.tail = node;
            } else {
                self.head = node;
                self.tail = node;
            }
        }

        pub fn dequeue(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();
            const node = self.head orelse return null;
            self.head = node.next;
            if (self.head == null) self.tail = null;
            const value = node.value;
            self.allocator.destroy(node);
            return value;
        }

        pub fn isEmpty(self: *Self) bool {
            self.lock.lock();
            defer self.lock.unlock();
            return self.head == null;
        }
    };
}

test "cache line padded" {
    const CLP = CacheLinePadded(u64);
    try std.testing.expect(@sizeOf(CLP) % CACHE_LINE_SIZE == 0);
    var v = CLP.init(42);
    try std.testing.expectEqual(@as(u64, 42), v.get().*);
}

test "packed slab" {
    const Slab = PackedSlab(u64, 8);
    try std.testing.expect(Slab.size_of_slab % PAGE_SIZE == 0 or Slab.capacity >= 8);
    var slab = Slab.init();
    const p = slab.alloc() orelse unreachable;
    p.* = 99;
    try std.testing.expect(slab.count == 1);
    try std.testing.expect(slab.free(p));
    try std.testing.expect(slab.count == 0);
}

test "work steal deque" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var deque = try WorkStealDeque(u64).init(alloc, 16);
    defer deque.deinit();

    try testing.expect(deque.push(1));
    try testing.expect(deque.push(2));
    try testing.expect(deque.push(3));
    try testing.expectEqual(@as(usize, 3), deque.size());

    const a = deque.pop() orelse unreachable;
    try testing.expectEqual(@as(u64, 3), a);

    const b = deque.steal() orelse unreachable;
    try testing.expectEqual(@as(u64, 1), b);
}

test "mpsc queue" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var q: MPSCQueue(u64) = undefined;
    q.initPtr(alloc);
    defer q.deinit();

    try q.enqueue(10);
    try q.enqueue(20);
    try q.enqueue(30);

    const a = q.dequeue();
    const b = q.dequeue();
    _ = a;
    _ = b;
}

test "field packing analysis" {
    const T = struct { a: u8, b: u64, c: u8 };
    const analysis = fieldPackingAnalysis(T);
    try std.testing.expect(analysis.total_size >= 10);
    try std.testing.expect(analysis.packing_efficiency_pct <= 100);
}
