const std = @import("std");
const pheap = @import("pheap.zig");
const header = @import("header.zig");
const allocator_mod = @import("allocator.zig");
const wal_mod = @import("wal.zig");
const recovery = @import("recovery.zig");
const pointer = @import("pointer.zig");

pub const InspectCommand = enum(u8) {
    header,
    stats,
    objects,
    wal,
    all,
};

pub const InspectResult = struct {
    command: InspectCommand,
    success: bool,
    message: []const u8,
    data: ?[]const u8,
};

pub const HeapInspector = struct {
    heap_path: []const u8,
    heap: *pheap.PersistentHeap,
    allocator: std.mem.Allocator,

    pub fn init(allocator_ptr: std.mem.Allocator, heap_path: []const u8) !HeapInspector {
        const heap = try pheap.PersistentHeap.init(allocator_ptr, heap_path, 0, null);

        return HeapInspector{
            .heap_path = heap_path,
            .heap = heap,
            .allocator = allocator_ptr,
        };
    }

    pub fn deinit(self: *HeapInspector) void {
        self.heap.deinit() catch {};
    }

    pub fn inspectHeader(self: *HeapInspector) !InspectResult {
        const hdr = self.heap.header;

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        try writer.print("=== Heap Header ===\n", .{});
        try writer.print("Magic: {s}\n", .{hdr.magic});
        try writer.print("Version: {}\n", .{hdr.version});
        try writer.print("Pool UUID: {x}\n", .{hdr.getPoolUUID()});
        try writer.print("Endianness: {}\n", .{hdr.endianness});
        try writer.print("Heap Size: {} bytes ({:.2} MB)\n", .{ hdr.heap_size, @as(f64, @floatFromInt(hdr.heap_size)) / (1024 * 1024) });
        try writer.print("Used Size: {} bytes\n", .{hdr.used_size});
        try writer.print("Root Offset: {}\n", .{hdr.root_offset});
        try writer.print("Transaction ID: {}\n", .{hdr.transaction_id});
        try writer.print("Dirty Flag: {}\n", .{hdr.isDirty()});
        try writer.print("Checksum: 0x{x:0>8}\n", .{hdr.checksum});

        const computed = hdr.computeChecksum();
        try writer.print("Computed Checksum: 0x{x:0>8}\n", .{computed});
        try writer.print("Checksum Valid: {}\n", .{computed == hdr.checksum});

        const message = try self.allocator.dupe(u8, buffer.items);

        return InspectResult{
            .command = .header,
            .success = true,
            .message = message,
            .data = null,
        };
    }

    pub fn inspectStats(self: *HeapInspector) !InspectResult {
        const base_addr = self.heap.getBaseAddress();
        const metadata: *const allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        const in_use_bytes: u64 = if (metadata.total_allocated >= metadata.total_freed)
            metadata.total_allocated - metadata.total_freed
        else
            0;

        try writer.print("=== Allocation Statistics ===\n", .{});
        try writer.print("Total Allocated: {} bytes\n", .{metadata.total_allocated});
        try writer.print("Total Freed: {} bytes\n", .{metadata.total_freed});
        try writer.print("In-Use: {} bytes\n", .{in_use_bytes});
        try writer.print("Allocation Count: {}\n", .{metadata.allocation_count});
        try writer.print("Free Count: {}\n", .{metadata.free_count});

        const heap_size = self.heap.getSize();
        const utilization = if (heap_size > 0)
            @as(f64, @floatFromInt(in_use_bytes)) / @as(f64, @floatFromInt(heap_size)) * 100.0
        else
            0.0;

        try writer.print("Heap Utilization: {d:.2}%\n", .{utilization});
        try writer.print("Size Classes: {}\n", .{metadata.num_size_classes});

        const message = try self.allocator.dupe(u8, buffer.items);

        return InspectResult{
            .command = .stats,
            .success = true,
            .message = message,
            .data = null,
        };
    }

    pub fn inspectObjects(self: *HeapInspector, start_offset: u64, count: u64) !InspectResult {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        try writer.print("=== Objects ===\n", .{});

        const base_addr = self.heap.getBaseAddress();
        const heap_size = self.heap.getSize();

        var found: u64 = 0;
        var offset = start_offset;

        const objects_start = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata);
        if (offset < objects_start) {
            offset = objects_start;
        }

        while (found < count and offset + @sizeOf(header.ObjectHeader) <= heap_size) {
            const obj: *const header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));

            if (obj.magic == header.ObjectHeader.OBJECT_MAGIC) {
                try writer.print("Object at offset {}:\n", .{offset});
                try writer.print("  Size: {} bytes\n", .{obj.size});
                try writer.print("  Ref Count: {}\n", .{obj.ref_count});
                try writer.print("  Schema ID: {}\n", .{obj.schema_id});
                try writer.print("  Freed: {}\n", .{obj.isFreed()});
                try writer.print("  Pinned: {}\n", .{obj.isPinned()});

                found += 1;

                const advance_result = @addWithOverflow(@as(u64, @sizeOf(header.ObjectHeader)), obj.size);
                const advance = advance_result[0];
                if (advance_result[1] != 0 or advance == 0 or offset + advance > heap_size) {
                    break;
                }
                offset += advance;
            } else if (obj.magic == allocator_mod.FreeListNode.NODE_MAGIC) {
                const free_node: *const allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + offset));
                try writer.print("Free block at offset {}:\n", .{offset});
                try writer.print("  Size: {} bytes\n", .{free_node.size});

                const free_size = free_node.size;
                if (free_size == 0 or offset + free_size > heap_size) {
                    break;
                }
                offset += free_size;
            } else {
                const next_offset = offset + 64;
                if (next_offset <= offset or next_offset > heap_size) {
                    break;
                }
                offset = next_offset;
            }
        }

        try writer.print("\nFound {} objects\n", .{found});

        const message = try self.allocator.dupe(u8, buffer.items);

        return InspectResult{
            .command = .objects,
            .success = true,
            .message = message,
            .data = null,
        };
    }

    pub fn inspectWAL(self: *HeapInspector, wal_path: []const u8) !InspectResult {
        var wal = try wal_mod.WAL.init(self.allocator, wal_path, null);
        defer wal.deinit();

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        try writer.print("=== WAL Status ===\n", .{});
        try writer.print("Magic: 0x{x:0>8}\n", .{wal.header.magic});
        try writer.print("Version: {}\n", .{wal.header.version});
        try writer.print("File Size: {} bytes\n", .{wal.header.file_size});
        try writer.print("Transaction Counter: {}\n", .{wal.header.transaction_counter});
        try writer.print("Head Offset: {}\n", .{wal.header.head_offset});
        try writer.print("Tail Offset: {}\n", .{wal.header.tail_offset});
        try writer.print("Last Checkpoint: {}\n", .{wal.header.last_checkpoint});

        const transactions = try wal.getTransactions();
        defer {
            for (transactions.items) |*tx| {
                tx.deinit();
            }
            transactions.deinit();
        }

        try writer.print("\nTransactions: {}\n", .{transactions.items.len});

        for (transactions.items, 0..) |tx, i| {
            try writer.print("\nTransaction {}:\n", .{i});
            try writer.print("  ID: {}\n", .{tx.id});
            try writer.print("  State: {}\n", .{tx.state});
            try writer.print("  Records: {}\n", .{tx.records.items.len});
        }

        const message = try self.allocator.dupe(u8, buffer.items);

        return InspectResult{
            .command = .wal,
            .success = true,
            .message = message,
            .data = null,
        };
    }

    pub fn validateHeap(self: *HeapInspector) !InspectResult {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        try writer.print("=== Heap Validation ===\n", .{});

        var errors: u64 = 0;
        var header_ok = true;
        var metadata_ok = true;

        self.heap.header.validate() catch |err| {
            try writer.print("Header validation error: {}\n", .{err});
            errors += 1;
            header_ok = false;
        };

        if (header_ok) {
            try writer.print("Header: OK\n", .{});
        }

        const base_addr = self.heap.getBaseAddress();
        const metadata: *const allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        metadata.validate() catch |err| {
            try writer.print("Allocator metadata validation error: {}\n", .{err});
            errors += 1;
            metadata_ok = false;
        };

        if (metadata_ok) {
            try writer.print("Allocator Meta: OK\n", .{});
        }

        var offset = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata);
        const heap_size = self.heap.getSize();

        var valid_objects: u64 = 0;
        var invalid_objects: u64 = 0;

        while (offset + @sizeOf(header.ObjectHeader) <= heap_size) {
            const obj: *const header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));

            if (obj.magic == header.ObjectHeader.OBJECT_MAGIC) {
                const computed_checksum = obj.computeChecksum();
                if (obj.checksum != computed_checksum) {
                    invalid_objects += 1;
                } else {
                    valid_objects += 1;
                }

                const advance_result = @addWithOverflow(@as(u64, @sizeOf(header.ObjectHeader)), obj.size);
                const advance = advance_result[0];
                if (advance_result[1] != 0 or advance == 0 or offset + advance > heap_size) {
                    break;
                }
                offset += advance;
            } else if (obj.magic == allocator_mod.FreeListNode.NODE_MAGIC) {
                const free_node: *const allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + offset));
                const free_size = free_node.size;
                if (free_size == 0 or offset + free_size > heap_size) {
                    break;
                }
                offset += free_size;
            } else {
                const next_offset = offset + 64;
                if (next_offset <= offset or next_offset > heap_size) {
                    break;
                }
                offset = next_offset;
            }
        }

        try writer.print("Valid Objects: {}\n", .{valid_objects});
        try writer.print("Invalid Objects: {}\n", .{invalid_objects});
        try writer.print("Total Errors: {}\n", .{errors + invalid_objects});

        const message = try self.allocator.dupe(u8, buffer.items);

        return InspectResult{
            .command = .all,
            .success = errors == 0 and invalid_objects == 0,
            .message = message,
            .data = null,
        };
    }
};

pub fn printUsage() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("pheap-tool - Persistent Heap Inspector\n\n", .{}) catch {};
    stdout.print("Usage: pheap-tool <command> <heap_path> [options]\n\n", .{}) catch {};
    stdout.print("Commands:\n", .{}) catch {};
    stdout.print("  header    Inspect heap header\n", .{}) catch {};
    stdout.print("  stats     Show allocation statistics\n", .{}) catch {};
    stdout.print("  objects   List objects in heap\n", .{}) catch {};
    stdout.print("  wal       Inspect WAL file\n", .{}) catch {};
    stdout.print("  validate  Validate heap integrity\n", .{}) catch {};
    stdout.print("  all       Full validation (same as 'validate')\n", .{}) catch {};
    stdout.print("\nOptions:\n", .{}) catch {};
    stdout.print("  --wal <path>       Path to WAL file\n", .{}) catch {};
    stdout.print("  --offset <n>       Starting offset for object listing\n", .{}) catch {};
    stdout.print("  --count <n>        Number of objects to list\n", .{}) catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 3) {
        printUsage();
        return;
    }

    const command_str = args[1];
    const heap_path = args[2];

    const command = if (std.mem.eql(u8, command_str, "header"))
        InspectCommand.header
    else if (std.mem.eql(u8, command_str, "stats"))
        InspectCommand.stats
    else if (std.mem.eql(u8, command_str, "objects"))
        InspectCommand.objects
    else if (std.mem.eql(u8, command_str, "wal"))
        InspectCommand.wal
    else if (std.mem.eql(u8, command_str, "validate"))
        InspectCommand.all
    else if (std.mem.eql(u8, command_str, "all"))
        InspectCommand.all
    else {
        printUsage();
        return;
    };

    var inspector = HeapInspector.init(alloc, heap_path) catch |err| {
        std.debug.print("Failed to open heap: {}\n", .{err});
        return;
    };
    defer inspector.deinit();

    const result = switch (command) {
        .header => try inspector.inspectHeader(),
        .stats => try inspector.inspectStats(),
        .objects => blk: {
            var start_offset: u64 = 0;
            var count: u64 = 100;

            var i: usize = 3;
            while (i < args.len) : (i += 1) {
                if (std.mem.eql(u8, args[i], "--offset") and i + 1 < args.len) {
                    start_offset = try std.fmt.parseInt(u64, args[i + 1], 10);
                    i += 1;
                } else if (std.mem.eql(u8, args[i], "--count") and i + 1 < args.len) {
                    count = try std.fmt.parseInt(u64, args[i + 1], 10);
                    i += 1;
                }
            }

            break :blk try inspector.inspectObjects(start_offset, count);
        },
        .wal => blk: {
            var wal_path: ?[]const u8 = null;
            var i: usize = 3;
            while (i < args.len) : (i += 1) {
                if (std.mem.eql(u8, args[i], "--wal") and i + 1 < args.len) {
                    wal_path = args[i + 1];
                    i += 1;
                }
            }

            if (wal_path) |wp| {
                break :blk try inspector.inspectWAL(wp);
            } else {
                std.debug.print("WAL path required for wal command\n", .{});
                return;
            }
        },
        .all => try inspector.validateHeap(),
    };

    std.debug.print("{s}\n", .{result.message});

    if (result.data) |data| {
        alloc.free(data);
    }
    alloc.free(result.message);
}
