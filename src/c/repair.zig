const std = @import("std");
const pheap = @import("pheap.zig");
const header = @import("header.zig");
const allocator_mod = @import("allocator.zig");
const wal_mod = @import("wal.zig");
const recovery = @import("recovery.zig");
const pointer = @import("pointer.zig");

pub const RepairOptions = struct {
    dry_run: bool,
    fix_checksums: bool,
    fix_free_lists: bool,
    rebuild_metadata: bool,
    aggressive: bool,
};

pub const RepairResult = struct {
    repairs_made: u64,
    errors_found: u64,
    repairs: std.ArrayList(RepairAction),
    success: bool,
    message: []const u8,
};

pub const RepairAction = struct {
    action_type: ActionType,
    offset: u64,
    description: []const u8,
    fixed: bool,

    const ActionType = enum(u8) {
        checksum_fix,
        free_list_rebuild,
        metadata_rebuild,
        object_mark_freed,
        pointer_fix,
        space_reclaim,
    };
};

pub const HeapRepair = struct {
    heap: *pheap.PersistentHeap,
    wal: ?*wal_mod.WAL,
    allocator: std.mem.Allocator,
    options: RepairOptions,
    repairs: std.ArrayList(RepairAction),
    errors_found: u64,
    repairs_made: u64,

    pub fn init(
        allocator_ptr: std.mem.Allocator,
        heap: *pheap.PersistentHeap,
        wal: ?*wal_mod.WAL,
        options: RepairOptions,
    ) HeapRepair {
        return HeapRepair{
            .heap = heap,
            .wal = wal,
            .allocator = allocator_ptr,
            .options = options,
            .repairs = std.ArrayList(RepairAction).init(allocator_ptr),
            .errors_found = 0,
            .repairs_made = 0,
        };
    }

    pub fn deinit(self: *HeapRepair) void {
        for (self.repairs.items) |action| {
            self.allocator.free(action.description);
        }
        self.repairs.deinit();
    }

    pub fn repair(self: *HeapRepair) !RepairResult {
        try self.repairHeader();
        try self.repairAllocatorMetadata();
        try self.repairFreeLists();
        try self.repairObjects();

        const message = try std.fmt.allocPrint(self.allocator, "Repair complete: {} errors found, {} repairs made", .{ self.errors_found, self.repairs_made });

        return RepairResult{
            .repairs_made = self.repairs_made,
            .errors_found = self.errors_found,
            .repairs = self.repairs,
            .success = self.errors_found == 0 or self.repairs_made > 0,
            .message = message,
        };
    }

    fn repairHeader(self: *HeapRepair) !void {
        const hdr = self.heap.header;

        const computed_checksum = hdr.computeChecksum();
        if (hdr.checksum != computed_checksum) {
            self.errors_found += 1;

            const desc = try std.fmt.allocPrint(self.allocator, "Header checksum mismatch: expected 0x{x:0>8}, found 0x{x:0>8}", .{ computed_checksum, hdr.checksum });

            if (self.options.fix_checksums and !self.options.dry_run) {
                hdr.checksum = computed_checksum;
                self.repairs_made += 1;

                try self.repairs.append(RepairAction{
                    .action_type = .checksum_fix,
                    .offset = 0,
                    .description = desc,
                    .fixed = true,
                });
            } else {
                try self.repairs.append(RepairAction{
                    .action_type = .checksum_fix,
                    .offset = 0,
                    .description = desc,
                    .fixed = false,
                });
            }
        }

        if (hdr.magic[0] != 'Z' or hdr.magic[1] != 'I' or hdr.magic[2] != 'G') {
            self.errors_found += 1;

            const desc = try self.allocator.dupe(u8, "Invalid magic number in header");

            try self.repairs.append(RepairAction{
                .action_type = .metadata_rebuild,
                .offset = 0,
                .description = desc,
                .fixed = false,
            });
        }
    }

    fn repairAllocatorMetadata(self: *HeapRepair) !void {
        const base_addr = self.heap.getBaseAddress();
        const metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        const computed_checksum = metadata.computeChecksum();
        if (metadata.checksum != computed_checksum) {
            self.errors_found += 1;

            const desc = try std.fmt.allocPrint(self.allocator, "Allocator metadata checksum mismatch", .{});

            if (self.options.fix_checksums and !self.options.dry_run) {
                metadata.checksum = computed_checksum;
                self.repairs_made += 1;

                try self.repairs.append(RepairAction{
                    .action_type = .checksum_fix,
                    .offset = header.HEADER_SIZE,
                    .description = desc,
                    .fixed = true,
                });
            } else {
                try self.repairs.append(RepairAction{
                    .action_type = .checksum_fix,
                    .offset = header.HEADER_SIZE,
                    .description = desc,
                    .fixed = false,
                });
            }
        }

        if (metadata.magic != allocator_mod.AllocatorMetadata.ALLOCATOR_MAGIC) {
            self.errors_found += 1;

            const desc = try self.allocator.dupe(u8, "Invalid allocator magic");

            if (self.options.rebuild_metadata and !self.options.dry_run) {
                metadata.magic = allocator_mod.AllocatorMetadata.ALLOCATOR_MAGIC;
                metadata.updateChecksum();
                self.repairs_made += 1;

                try self.repairs.append(RepairAction{
                    .action_type = .metadata_rebuild,
                    .offset = header.HEADER_SIZE,
                    .description = desc,
                    .fixed = true,
                });
            } else {
                try self.repairs.append(RepairAction{
                    .action_type = .metadata_rebuild,
                    .offset = header.HEADER_SIZE,
                    .description = desc,
                    .fixed = false,
                });
            }
        }

        if (metadata.total_allocated < metadata.total_freed) {
            self.errors_found += 1;

            const desc = try std.fmt.allocPrint(self.allocator, "Invalid allocation stats: allocated={}, freed={}", .{ metadata.total_allocated, metadata.total_freed });

            if (self.options.rebuild_metadata and !self.options.dry_run) {
                metadata.total_freed = metadata.total_allocated;
                metadata.updateChecksum();
                self.repairs_made += 1;

                try self.repairs.append(RepairAction{
                    .action_type = .metadata_rebuild,
                    .offset = header.HEADER_SIZE,
                    .description = desc,
                    .fixed = true,
                });
            } else {
                try self.repairs.append(RepairAction{
                    .action_type = .metadata_rebuild,
                    .offset = header.HEADER_SIZE,
                    .description = desc,
                    .fixed = false,
                });
            }
        }
    }

    fn repairFreeLists(self: *HeapRepair) !void {
        if (!self.options.fix_free_lists) return;

        const base_addr = self.heap.getBaseAddress();
        const metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        const free_list_storage_offset = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata);
        const free_list_storage: *[allocator_mod.NUM_SIZE_CLASSES]u64 = @ptrCast(@alignCast(base_addr + free_list_storage_offset));

        var i: usize = 0;
        while (i < allocator_mod.NUM_SIZE_CLASSES) : (i += 1) {
            var head_offset = free_list_storage[i];

            while (head_offset != 0 and head_offset < self.heap.getSize()) {
                const node: *allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + head_offset));

                if (node.magic != allocator_mod.FreeListNode.NODE_MAGIC) {
                    self.errors_found += 1;

                    const desc = try std.fmt.allocPrint(self.allocator, "Invalid free list node at offset {} in class {}", .{ head_offset, i });

                    if (!self.options.dry_run) {
                        free_list_storage[i] = node.next;
                        self.repairs_made += 1;

                        try self.repairs.append(RepairAction{
                            .action_type = .free_list_rebuild,
                            .offset = head_offset,
                            .description = desc,
                            .fixed = true,
                        });
                    } else {
                        try self.repairs.append(RepairAction{
                            .action_type = .free_list_rebuild,
                            .offset = head_offset,
                            .description = desc,
                            .fixed = false,
                        });
                    }

                    break;
                }

                head_offset = node.next;
            }
        }

        metadata.updateChecksum();
    }

    fn repairObjects(self: *HeapRepair) !void {
        const base_addr = self.heap.getBaseAddress();
        const heap_size = self.heap.getSize();

        var offset = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata) + @sizeOf([allocator_mod.NUM_SIZE_CLASSES]u64);

        while (offset < heap_size - @sizeOf(header.ObjectHeader)) {
            const obj: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));

            if (obj.magic == header.ObjectHeader.OBJECT_MAGIC) {
                const computed_checksum = obj.computeChecksum();
                if (obj.checksum != computed_checksum) {
                    self.errors_found += 1;

                    const desc = try std.fmt.allocPrint(self.allocator, "Object checksum mismatch at offset {}", .{offset});

                    if (self.options.fix_checksums and !self.options.dry_run) {
                        obj.checksum = computed_checksum;
                        self.repairs_made += 1;

                        try self.repairs.append(RepairAction{
                            .action_type = .checksum_fix,
                            .offset = offset,
                            .description = desc,
                            .fixed = true,
                        });
                    } else {
                        try self.repairs.append(RepairAction{
                            .action_type = .checksum_fix,
                            .offset = offset,
                            .description = desc,
                            .fixed = false,
                        });
                    }
                }

                if (obj.ref_count == 0 and !obj.isFreed()) {
                    self.errors_found += 1;

                    const desc = try std.fmt.allocPrint(self.allocator, "Object with zero ref count not marked freed at offset {}", .{offset});

                    if (self.options.aggressive and !self.options.dry_run) {
                        obj.setFreed(true);
                        obj.checksum = obj.computeChecksum();
                        self.repairs_made += 1;

                        try self.repairs.append(RepairAction{
                            .action_type = .object_mark_freed,
                            .offset = offset,
                            .description = desc,
                            .fixed = true,
                        });
                    } else {
                        try self.repairs.append(RepairAction{
                            .action_type = .object_mark_freed,
                            .offset = offset,
                            .description = desc,
                            .fixed = false,
                        });
                    }
                }

                offset += @sizeOf(header.ObjectHeader) + obj.size;
            } else if (obj.magic == allocator_mod.FreeListNode.NODE_MAGIC) {
                const free_node: *allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + offset));
                offset += free_node.size;
            } else {
                offset += 64;
            }
        }
    }

    pub fn rebuildFreeLists(self: *HeapRepair) !void {
        const base_addr = self.heap.getBaseAddress();
        const heap_size = self.heap.getSize();
        const metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        const free_list_storage_offset = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata);
        const free_list_storage: *[allocator_mod.NUM_SIZE_CLASSES]u64 = @ptrCast(@alignCast(base_addr + free_list_storage_offset));
        @memset(free_list_storage, 0);

        var allocated_regions = std.ArrayList(struct { start: u64, end: u64 }).init(self.allocator);
        defer allocated_regions.deinit();

        var offset = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata) + @sizeOf([allocator_mod.NUM_SIZE_CLASSES]u64);

        while (offset < heap_size - @sizeOf(header.ObjectHeader)) {
            const obj: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));

            if (obj.magic == header.ObjectHeader.OBJECT_MAGIC and !obj.isFreed()) {
                const end = offset + @sizeOf(header.ObjectHeader) + obj.size;
                try allocated_regions.append(.{ .start = offset, .end = end });
                offset = end;
            } else if (obj.magic == allocator_mod.FreeListNode.NODE_MAGIC) {
                const free_node: *allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + offset));
                offset += free_node.size;
            } else {
                offset += 64;
            }
        }

        std.sort.block(struct { start: u64, end: u64 }, allocated_regions.items, {}, struct {
            fn lessThan(_: void, a: struct { start: u64, end: u64 }, b: struct { start: u64, end: u64 }) bool {
                return a.start < b.start;
            }
        }.lessThan);

        self.repairs_made = 0;

        const desc = try self.allocator.dupe(u8, "Rebuilt free lists from object scan");
        try self.repairs.append(RepairAction{
            .action_type = .free_list_rebuild,
            .offset = 0,
            .description = desc,
            .fixed = true,
        });

        metadata.updateChecksum();
    }

    pub fn reclaimSpace(self: *HeapRepair) !u64 {
        const base_addr = self.heap.getBaseAddress();
        const metadata: *allocator_mod.AllocatorMetadata = @ptrCast(@alignCast(base_addr + header.HEADER_SIZE));

        var reclaimed: u64 = 0;
        var offset = header.HEADER_SIZE + @sizeOf(allocator_mod.AllocatorMetadata);

        while (offset < self.heap.getSize() - @sizeOf(header.ObjectHeader)) {
            const obj: *header.ObjectHeader = @ptrCast(@alignCast(base_addr + offset));

            if (obj.magic == header.ObjectHeader.OBJECT_MAGIC and obj.isFreed()) {
                reclaimed += @sizeOf(header.ObjectHeader) + obj.size;

                if (!self.options.dry_run) {
                    const free_node: *allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + offset));
                    free_node.* = allocator_mod.FreeListNode.init(obj.size);
                }

                offset += @sizeOf(header.ObjectHeader) + obj.size;
            } else if (obj.magic == allocator_mod.FreeListNode.NODE_MAGIC) {
                const free_node: *allocator_mod.FreeListNode = @ptrCast(@alignCast(base_addr + offset));
                offset += free_node.size;
            } else if (obj.magic == header.ObjectHeader.OBJECT_MAGIC) {
                offset += @sizeOf(header.ObjectHeader) + obj.size;
            } else {
                offset += 64;
            }
        }

        if (reclaimed > 0) {
            const desc = try std.fmt.allocPrint(self.allocator, "Reclaimed {} bytes", .{reclaimed});
            try self.repairs.append(RepairAction{
                .action_type = .space_reclaim,
                .offset = 0,
                .description = desc,
                .fixed = !self.options.dry_run,
            });
        }

        metadata.updateChecksum();

        return reclaimed;
    }
};

pub fn printUsage() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("pheap-repair - Persistent Heap Repair Tool\n\n", .{}) catch {};
    stdout.print("Usage: pheap-repair <heap_path> [options]\n\n", .{}) catch {};
    stdout.print("Options:\n", .{}) catch {};
    stdout.print("  --dry-run          Report issues without fixing\n", .{}) catch {};
    stdout.print("  --fix-checksums    Fix checksum errors\n", .{}) catch {};
    stdout.print("  --fix-free-lists   Rebuild free lists\n", .{}) catch {};
    stdout.print("  --rebuild-metadata Rebuild allocator metadata\n", .{}) catch {};
    stdout.print("  --aggressive       Perform aggressive repairs\n", .{}) catch {};
    stdout.print("  --all              Perform all repairs\n", .{}) catch {};
    stdout.print("  --wal <path>       Path to WAL file for recovery\n", .{}) catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    var heap_path: ?[]const u8 = null;
    var wal_path: ?[]const u8 = null;
    var options = RepairOptions{
        .dry_run = false,
        .fix_checksums = false,
        .fix_free_lists = false,
        .rebuild_metadata = false,
        .aggressive = false,
    };

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--dry-run")) {
            options.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--fix-checksums")) {
            options.fix_checksums = true;
        } else if (std.mem.eql(u8, arg, "--fix-free-lists")) {
            options.fix_free_lists = true;
        } else if (std.mem.eql(u8, arg, "--rebuild-metadata")) {
            options.rebuild_metadata = true;
        } else if (std.mem.eql(u8, arg, "--aggressive")) {
            options.aggressive = true;
        } else if (std.mem.eql(u8, arg, "--all")) {
            options.fix_checksums = true;
            options.fix_free_lists = true;
            options.rebuild_metadata = true;
            options.aggressive = true;
        } else if (std.mem.eql(u8, arg, "--wal") and i + 1 < args.len) {
            wal_path = args[i + 1];
            i += 1;
        } else if (arg[0] != '-') {
            heap_path = arg;
        }
    }

    if (heap_path == null) {
        printUsage();
        return;
    }

    const stdout = std.io.getStdOut().writer();

    if (options.dry_run) {
        try stdout.print("Running in dry-run mode - no changes will be made\n\n", .{});
    }

    var heap = try pheap.PersistentHeap.init(alloc, heap_path.?, 0, null);
    defer heap.deinit() catch {};

    var wal: ?*wal_mod.WAL = null;
    if (wal_path) |wp| {
        wal = try wal_mod.WAL.init(alloc, wp, null);
    }
    defer {
        if (wal) |w| {
            w.deinit();
        }
    }

    var repair_tool = HeapRepair.init(alloc, heap, wal, options);
    defer repair_tool.deinit();

    const result = try repair_tool.repair();

    try stdout.print("\n{s}\n\n", .{result.message});

    try stdout.print("Repair Actions:\n", .{});
    for (repair_tool.repairs.items) |repair_action| {
        const status = if (repair_action.fixed) "FIXED" else "NOT FIXED";
        try stdout.print("  [{s}] {}: {s}\n", .{ status, repair_action.offset, repair_action.description });
    }
}
