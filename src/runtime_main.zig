const std = @import("std");
const agdb = @import("agdb");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args_iter = try std.process.argsWithAllocator(alloc);
    defer args_iter.deinit();
    _ = args_iter.next();

    var heap_path: []const u8 = "agdb.heap";
    var wal_path: []const u8 = "agdb.wal";
    var snap_dir: []const u8 = "agdb-snapshots";
    var heap_size: u64 = 1024 * 1024 * 256;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--heap")) {
            heap_path = args_iter.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--wal")) {
            wal_path = args_iter.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--snapshots")) {
            snap_dir = args_iter.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--size")) {
            const v = args_iter.next() orelse return error.MissingValue;
            heap_size = try std.fmt.parseInt(u64, v, 10);
        }
    }

    const config = agdb.RuntimeConfig{
        .heap_path = heap_path,
        .heap_size = heap_size,
        .wal_path = wal_path,
        .snapshot_dir = snap_dir,
        .enable_encryption = false,
        .master_key = null,
        .gc_threshold = 1024,
        .snapshot_interval_ms = 60_000,
    };

    var rt = try agdb.Runtime.init(alloc, config);
    defer rt.deinit();

    const stdout = std.io.getStdOut().writer();
    const stats = rt.getStats();
    try stdout.print(
        "agdb runtime ready\n  heap: {s} ({d}/{d} bytes)\n  wal: {s} ({d} bytes)\n  snapshots: {s} ({d})\n",
        .{ heap_path, stats.heap_used, stats.heap_total, wal_path, stats.wal_size, snap_dir, stats.snapshot_count },
    );
}
