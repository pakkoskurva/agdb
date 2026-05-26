const std = @import("std");
const agdb = @import("agdb");

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const raw_args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, raw_args);

    if (raw_args.len <= 1) {
        var empty = [_][]const u8{};
        return try agdb.cli.run(alloc, empty[0..]);
    }
    const slice = try alloc.alloc([]const u8, raw_args.len - 1);
    defer alloc.free(slice);
    for (raw_args[1..], 0..) |a, i| slice[i] = a;
    return try agdb.cli.run(alloc, slice);
}
