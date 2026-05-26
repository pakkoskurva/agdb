const std = @import("std");
const time = std.time;
const pheap = @import("pheap.zig");
const allocator_mod = @import("allocator.zig");
const wal_mod = @import("wal.zig");
const transaction_mod = @import("transaction.zig");

pub const BenchmarkResult = struct {
    name: []const u8,
    iterations: u64,
    total_time_ns: u64,
    avg_time_ns: u64,
    min_time_ns: u64,
    max_time_ns: u64,
    ops_per_sec: f64,
    throughput_mb_sec: f64,
};

pub const BenchmarkConfig = struct {
    iterations: u64,
    warmup_iterations: u64,
    object_size: u64,
    batch_size: u64,
    read_ratio: f64,
    heap_size: u64,
};

pub const BenchmarkSuite = struct {
    results: std.ArrayList(BenchmarkResult),
    config: BenchmarkConfig,
    allocator: std.mem.Allocator,
    heap: ?*pheap.PersistentHeap,
    alloc: ?*allocator_mod.PersistentAllocator,
    wal: ?*wal_mod.WAL,

    const Self = @This();

    pub fn init(allocator_ptr: std.mem.Allocator, config: BenchmarkConfig) BenchmarkSuite {
        return BenchmarkSuite{
            .results = std.ArrayList(BenchmarkResult).init(allocator_ptr),
            .config = config,
            .allocator = allocator_ptr,
            .heap = null,
            .alloc = null,
            .wal = null,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.results.items) |result| {
            self.allocator.free(result.name);
        }
        self.results.deinit();

        if (self.alloc) |a| {
            a.deinit();
        }
        if (self.wal) |w| {
            w.deinit();
        }
        if (self.heap) |h| {
            h.deinit() catch {};
        }
    }

    pub fn setup(self: *Self) !void {
        const heap_path = "/tmp/bench_heap.dat";
        const wal_path = "/tmp/bench_wal.wal";

        std.fs.cwd().deleteFile(heap_path) catch {};
        std.fs.cwd().deleteFile(wal_path) catch {};

        self.heap = try pheap.PersistentHeap.init(self.allocator, heap_path, self.config.heap_size, null);
        errdefer self.heap.?.deinit() catch {};

        self.wal = try wal_mod.WAL.init(self.allocator, wal_path, null);
        errdefer self.wal.?.deinit();

        self.alloc = try allocator_mod.PersistentAllocator.init(self.allocator, self.heap.?, self.wal.?);
    }

    pub fn teardown(self: *Self) void {
        if (self.alloc) |a| {
            a.deinit();
            self.alloc = null;
        }
        if (self.wal) |w| {
            w.deinit();
            self.wal = null;
        }
        if (self.heap) |h| {
            h.deinit();
            self.heap = null;
        }
    }

    pub fn runAllocationBenchmark(self: *Self) !BenchmarkResult {
        const alloc = self.alloc orelse return error.NotInitialized;

        var times = try self.allocator.alloc(u64, self.config.iterations);
        defer self.allocator.free(times);

        var i: u64 = 0;
        while (i < self.config.warmup_iterations) : (i += 1) {
            const ptr = try alloc.alloc(self.config.object_size, 64);
            try alloc.free(ptr);
        }

        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            const start = time.nanoTimestamp();
            const ptr = try alloc.alloc(self.config.object_size, 64);
            try alloc.free(ptr);
            const end = time.nanoTimestamp();
            times[i] = @as(u64, @intCast(end - start));
        }

        return self.computeResult("allocation", times, self.config.object_size);
    }

    pub fn runWriteBenchmark(self: *Self) !BenchmarkResult {
        const alloc = self.alloc orelse return error.NotInitialized;
        const heap = self.heap orelse return error.NotInitialized;

        const ptr = try alloc.alloc(self.config.object_size, 64);
        defer alloc.free(ptr) catch {};

        const data = try self.allocator.alloc(u8, self.config.object_size);
        defer self.allocator.free(data);
        @memset(data, 0xAB);

        var times = try self.allocator.alloc(u64, self.config.iterations);
        defer self.allocator.free(times);

        var i: u64 = 0;
        while (i < self.config.warmup_iterations) : (i += 1) {
            try heap.write(ptr.offset, data);
        }

        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            const start = time.nanoTimestamp();
            try heap.write(ptr.offset, data);
            const end = time.nanoTimestamp();
            times[i] = @as(u64, @intCast(end - start));
        }

        return self.computeResult("write", times, self.config.object_size);
    }

    pub fn runReadBenchmark(self: *Self) !BenchmarkResult {
        const alloc = self.alloc orelse return error.NotInitialized;
        const heap = self.heap orelse return error.NotInitialized;

        const ptr = try alloc.alloc(self.config.object_size, 64);
        defer alloc.free(ptr) catch {};

        const buffer = try self.allocator.alloc(u8, self.config.object_size);
        defer self.allocator.free(buffer);

        var times = try self.allocator.alloc(u64, self.config.iterations);
        defer self.allocator.free(times);

        var i: u64 = 0;
        while (i < self.config.warmup_iterations) : (i += 1) {
            try heap.read(ptr.offset, buffer);
        }

        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            const start = time.nanoTimestamp();
            try heap.read(ptr.offset, buffer);
            const end = time.nanoTimestamp();
            times[i] = @as(u64, @intCast(end - start));
        }

        return self.computeResult("read", times, self.config.object_size);
    }

    pub fn runTransactionBenchmark(self: *Self) !BenchmarkResult {
        const wal_inst = self.wal orelse return error.NotInitialized;

        var times = try self.allocator.alloc(u64, self.config.iterations);
        defer self.allocator.free(times);

        var i: u64 = 0;
        while (i < self.config.warmup_iterations) : (i += 1) {
            var tx = try wal_inst.beginTransaction();
            try wal_inst.commitTransaction(&tx);
        }

        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            const start = time.nanoTimestamp();
            var tx = try wal_inst.beginTransaction();
            try wal_inst.appendRecord(&tx, .write, i * 64, 64);
            try wal_inst.commitTransaction(&tx);
            const end = time.nanoTimestamp();
            times[i] = @as(u64, @intCast(end - start));
        }

        return self.computeResult("transaction", times, 64);
    }

    pub fn runMixedWorkloadBenchmark(self: *Self) !BenchmarkResult {
        const alloc = self.alloc orelse return error.NotInitialized;
        const heap = self.heap orelse return error.NotInitialized;

        var ptrs = try self.allocator.alloc(@import("pointer.zig").PersistentPtr, self.config.batch_size);
        defer self.allocator.free(ptrs);

        var i: usize = 0;
        while (i < self.config.batch_size) : (i += 1) {
            ptrs[i] = try alloc.alloc(self.config.object_size, 64);
        }

        const buffer = try self.allocator.alloc(u8, self.config.object_size);
        defer self.allocator.free(buffer);

        var times = try self.allocator.alloc(u64, self.config.iterations);
        defer self.allocator.free(times);

        const read_count: u64 = @intFromFloat(@as(f64, @floatFromInt(self.config.batch_size)) * self.config.read_ratio);
        const write_count = self.config.batch_size - read_count;

        var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(time.timestamp())));
        const rand = prng.random();

        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            const start = time.nanoTimestamp();

            var j: u64 = 0;
            while (j < read_count) : (j += 1) {
                const idx = rand.intRangeLessThan(u64, 0, self.config.batch_size);
                try heap.read(ptrs[idx].offset, buffer);
            }

            j = 0;
            while (j < write_count) : (j += 1) {
                const idx = rand.intRangeLessThan(u64, 0, self.config.batch_size);
                try heap.write(ptrs[idx].offset, buffer);
            }

            const end = time.nanoTimestamp();
            times[i] = @as(u64, @intCast(end - start));
        }

        for (ptrs) |ptr| {
            alloc.free(ptr) catch {};
        }

        return self.computeResult("mixed_workload", times, self.config.object_size * self.config.batch_size);
    }

    fn computeResult(self: *Self, name: []const u8, times: []u64, bytes_per_op: u64) BenchmarkResult {
        var total: u64 = 0;
        var min_time: u64 = std.math.maxInt(u64);
        var max_time: u64 = 0;

        for (times) |t| {
            total += t;
            min_time = @min(min_time, t);
            max_time = @max(max_time, t);
        }

        const avg_time = total / times.len;
        const ops_per_sec = if (avg_time > 0) @as(f64, 1e9) / @as(f64, @floatFromInt(avg_time)) else 0;
        const throughput = if (avg_time > 0) @as(f64, @floatFromInt(bytes_per_op)) * ops_per_sec / (1024 * 1024) else 0;

        const result = BenchmarkResult{
            .name = self.allocator.dupe(u8, name) catch name,
            .iterations = times.len,
            .total_time_ns = total,
            .avg_time_ns = avg_time,
            .min_time_ns = min_time,
            .max_time_ns = max_time,
            .ops_per_sec = ops_per_sec,
            .throughput_mb_sec = throughput,
        };

        self.results.append(result) catch {};
        return result;
    }

    pub fn runAll(self: *Self) !void {
        try self.setup();

        _ = try self.runAllocationBenchmark();
        _ = try self.runReadBenchmark();
        _ = try self.runWriteBenchmark();
        _ = try self.runTransactionBenchmark();
        _ = try self.runMixedWorkloadBenchmark();
    }

    pub fn printResults(self: *const Self) void {
        const stdout = std.io.getStdOut().writer();

        stdout.print("\n=== Benchmark Results ===\n\n", .{}) catch {};
        stdout.print("{s:20} {s:>12} {s:>12} {s:>12} {s:>15} {s:>15}\n", .{
            "Benchmark",
            "Avg (ns)",
            "Min (ns)",
            "Max (ns)",
            "Ops/sec",
            "MB/s",
        }) catch {};
        stdout.print("{s:->20} {s:->12} {s:->12} {s:->12} {s:->15} {s:->15}\n", .{ "", "", "", "", "", "" }) catch {};

        for (self.results.items) |result| {
            stdout.print("{s:20} {d:>12.0} {d:>12.0} {d:>12.0} {d:>15.2} {d:>15.2}\n", .{
                result.name,
                result.avg_time_ns,
                result.min_time_ns,
                result.max_time_ns,
                result.ops_per_sec,
                result.throughput_mb_sec,
            }) catch {};
        }
    }

    pub fn getWriteAmplification(self: *Self) !f64 {
        const alloc = self.alloc orelse return error.NotInitialized;
        const wal_inst = self.wal orelse return error.NotInitialized;

        const heap_written = alloc.metadata.total_allocated;
        const wal_written = wal_inst.getSize();

        if (heap_written == 0) return 0;

        return @as(f64, @floatFromInt(wal_written)) / @as(f64, @floatFromInt(heap_written));
    }
};

pub fn benchmarkFunction(
    allocator_ptr: std.mem.Allocator,
    comptime func: anytype,
    args: anytype,
    iterations: u64,
    warmup: u64,
) !BenchmarkResult {
    var times = try allocator_ptr.alloc(u64, iterations);
    defer allocator_ptr.free(times);

    var i: u64 = 0;
    while (i < warmup) : (i += 1) {
        _ = @call(.auto, func, args);
    }

    i = 0;
    while (i < iterations) : (i += 1) {
        const start = time.nanoTimestamp();
        _ = @call(.auto, func, args);
        const end = time.nanoTimestamp();
        times[i] = @as(u64, @intCast(end - start));
    }

    var total: u64 = 0;
    var min_time: u64 = std.math.maxInt(u64);
    var max_time: u64 = 0;

    for (times) |t| {
        total += t;
        min_time = @min(min_time, t);
        max_time = @max(max_time, t);
    }

    const avg_time = total / iterations;
    const ops_per_sec = if (avg_time > 0) @as(f64, 1e9) / @as(f64, @floatFromInt(avg_time)) else 0;

    return BenchmarkResult{
        .name = "custom",
        .iterations = iterations,
        .total_time_ns = total,
        .avg_time_ns = avg_time,
        .min_time_ns = min_time,
        .max_time_ns = max_time,
        .ops_per_sec = ops_per_sec,
        .throughput_mb_sec = 0,
    };
}

pub const LatencyHistogram = struct {
    buckets: []u64,
    bucket_boundaries: []u64,
    count: u64,
    sum: u64,
    min_val: u64,
    max_val: u64,

    pub fn init(allocator_ptr: std.mem.Allocator, num_buckets: usize) !LatencyHistogram {
        const buckets = try allocator_ptr.alloc(u64, num_buckets);
        @memset(buckets, 0);

        const boundaries = try allocator_ptr.alloc(u64, num_buckets + 1);
        var i: usize = 0;
        var boundary: u64 = 1;
        while (i <= num_buckets) : (i += 1) {
            boundaries[i] = boundary;
            boundary = boundary * 2;
        }

        return LatencyHistogram{
            .buckets = buckets,
            .bucket_boundaries = boundaries,
            .count = 0,
            .sum = 0,
            .min_val = std.math.maxInt(u64),
            .max_val = 0,
        };
    }

    pub fn deinit(self: *LatencyHistogram, allocator_ptr: std.mem.Allocator) void {
        allocator_ptr.free(self.buckets);
        allocator_ptr.free(self.bucket_boundaries);
    }

    pub fn record(self: *LatencyHistogram, value: u64) void {
        self.count += 1;
        self.sum += value;
        self.min_val = @min(self.min_val, value);
        self.max_val = @max(self.max_val, value);

        var bucket_idx: usize = 0;
        while (bucket_idx < self.buckets.len - 1) : (bucket_idx += 1) {
            if (value < self.bucket_boundaries[bucket_idx + 1]) {
                break;
            }
        }

        self.buckets[bucket_idx] += 1;
    }

    pub fn percentile(self: *const LatencyHistogram, p: f64) u64 {
        if (self.count == 0) return 0;

        const target: u64 = @intFromFloat(@as(f64, @floatFromInt(self.count)) * p / 100.0);

        var cumulative: u64 = 0;
        var bucket_idx: usize = 0;

        while (bucket_idx < self.buckets.len) : (bucket_idx += 1) {
            cumulative += self.buckets[bucket_idx];
            if (cumulative >= target) {
                return self.bucket_boundaries[bucket_idx];
            }
        }

        return self.bucket_boundaries[self.bucket_boundaries.len - 1];
    }

    pub fn avg(self: *const LatencyHistogram) u64 {
        if (self.count == 0) return 0;
        return self.sum / self.count;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const config = BenchmarkConfig{
        .iterations = 10000,
        .warmup_iterations = 1000,
        .object_size = 256,
        .batch_size = 100,
        .read_ratio = 0.8,
        .heap_size = 1024 * 1024 * 100,
    };

    var suite = BenchmarkSuite.init(alloc, config);
    defer suite.deinit();

    try suite.runAll();
    suite.printResults();
}
