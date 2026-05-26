const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const is_linux = builtin.os.tag == .linux;

pub const MPOL_DEFAULT: u32 = 0;
pub const MPOL_PREFERRED: u32 = 1;
pub const MPOL_BIND: u32 = 2;
pub const MPOL_INTERLEAVE: u32 = 3;
pub const MPOL_LOCAL: u32 = 4;
pub const MPOL_F_NODE: u32 = 1 << 0;
pub const MPOL_F_ADDR: u32 = 1 << 1;
pub const MPOL_F_MEMS_ALLOWED: u32 = 1 << 2;
pub const MPOL_MF_STRICT: u32 = 1 << 0;
pub const MPOL_MF_MOVE: u32 = 1 << 1;
pub const MPOL_MF_MOVE_ALL: u32 = 1 << 2;

pub const MAX_NUMA_NODES: usize = 64;
pub const INVALID_NODE: u32 = 0xFFFFFFFF;

pub const CpuSet = struct {
    bits: [16]u64,

    pub fn init() CpuSet {
        return .{ .bits = [_]u64{0} ** 16 };
    }

    pub fn set(self: *CpuSet, cpu: u32) void {
        const word = cpu / 64;
        const bit: u6 = @intCast(cpu % 64);
        if (word < self.bits.len) {
            self.bits[word] |= @as(u64, 1) << bit;
        }
    }

    pub fn clear(self: *CpuSet, cpu: u32) void {
        const word = cpu / 64;
        const bit: u6 = @intCast(cpu % 64);
        if (word < self.bits.len) {
            self.bits[word] &= ~(@as(u64, 1) << bit);
        }
    }

    pub fn isSet(self: *const CpuSet, cpu: u32) bool {
        const word = cpu / 64;
        const bit: u6 = @intCast(cpu % 64);
        if (word >= self.bits.len) return false;
        return (self.bits[word] >> bit) & 1 != 0;
    }

    pub fn count(self: *const CpuSet) u32 {
        var n: u32 = 0;
        for (self.bits) |w| n += @popCount(w);
        return n;
    }
};

pub const NumaNode = struct {
    node_id: u32,
    cpu_set: CpuSet,
    total_mem_bytes: u64,
    free_mem_bytes: u64,
    distance: [MAX_NUMA_NODES]u8,

    pub fn init(id: u32) NumaNode {
        return .{
            .node_id = id,
            .cpu_set = CpuSet.init(),
            .total_mem_bytes = 0,
            .free_mem_bytes = 0,
            .distance = [_]u8{10} ** MAX_NUMA_NODES,
        };
    }
};

pub const NumaTopology = struct {
    nodes: [MAX_NUMA_NODES]NumaNode,
    node_count: u32,
    hbm_nodes: [MAX_NUMA_NODES]u32,
    hbm_count: u32,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn detect(allocator: std.mem.Allocator) NumaTopology {
        var self = NumaTopology{
            .nodes = undefined,
            .node_count = 0,
            .hbm_nodes = [_]u32{INVALID_NODE} ** MAX_NUMA_NODES,
            .hbm_count = 0,
            .allocator = allocator,
        };
        for (0..MAX_NUMA_NODES) |i| {
            self.nodes[i] = NumaNode.init(@intCast(i));
        }
        self.detectLinux();
        return self;
    }

    fn detectLinux(self: *Self) void {
        if (!comptime is_linux) return;

        var n: u32 = 0;
        while (n < MAX_NUMA_NODES) : (n += 1) {
            var path_buf: [128]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "/sys/devices/system/node/node{d}", .{n}) catch break;
            std.fs.cwd().access(path, .{}) catch break;
            self.nodes[n].node_id = n;
            self.loadNodeMeminfo(n);
            self.loadNodeCpus(n);
            self.node_count += 1;
        }

        if (self.node_count == 0) {
            self.nodes[0].node_id = 0;
            self.node_count = 1;
            self.nodes[0].cpu_set.set(0);
        }

        self.detectHBM();
    }

    fn loadNodeMeminfo(self: *Self, node: u32) void {
        var path_buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/sys/devices/system/node/node{d}/meminfo", .{node}) catch return;
        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();
        var buf: [4096]u8 = undefined;
        const n = file.read(&buf) catch return;
        const content = buf[0..n];

        if (std.mem.indexOf(u8, content, "MemTotal:")) |idx| {
            const line = content[idx..];
            const end = std.mem.indexOf(u8, line, "\n") orelse line.len;
            const part = std.mem.trim(u8, line[9..end], " \t");
            const kb_end = std.mem.indexOf(u8, part, " ") orelse part.len;
            const kb = std.fmt.parseInt(u64, part[0..kb_end], 10) catch 0;
            self.nodes[node].total_mem_bytes = kb * 1024;
        }

        if (std.mem.indexOf(u8, content, "MemFree:")) |idx| {
            const line = content[idx..];
            const end = std.mem.indexOf(u8, line, "\n") orelse line.len;
            const part = std.mem.trim(u8, line[8..end], " \t");
            const kb_end = std.mem.indexOf(u8, part, " ") orelse part.len;
            const kb = std.fmt.parseInt(u64, part[0..kb_end], 10) catch 0;
            self.nodes[node].free_mem_bytes = kb * 1024;
        }
    }

    fn loadNodeCpus(self: *Self, node: u32) void {
        var path_buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/sys/devices/system/node/node{d}/cpulist", .{node}) catch return;
        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();
        var buf: [1024]u8 = undefined;
        const n = file.read(&buf) catch return;
        const content = std.mem.trim(u8, buf[0..n], " \t\n");

        var iter = std.mem.splitScalar(u8, content, ',');
        while (iter.next()) |token| {
            const t = std.mem.trim(u8, token, " \t");
            if (std.mem.indexOf(u8, t, "-")) |dash_pos| {
                const start = std.fmt.parseInt(u32, t[0..dash_pos], 10) catch continue;
                const end_cpu = std.fmt.parseInt(u32, t[dash_pos + 1 ..], 10) catch continue;
                var cpu = start;
                while (cpu <= end_cpu) : (cpu += 1) {
                    self.nodes[node].cpu_set.set(cpu);
                }
            } else {
                const cpu = std.fmt.parseInt(u32, t, 10) catch continue;
                self.nodes[node].cpu_set.set(cpu);
            }
        }
    }

    fn detectHBM(self: *Self) void {
        var n: u32 = 0;
        while (n < self.node_count) : (n += 1) {
            if (self.nodes[n].total_mem_bytes > 0 and
                self.nodes[n].cpu_set.count() == 0 and
                self.nodes[n].total_mem_bytes <= 128 * 1024 * 1024 * 1024)
            {
                self.hbm_nodes[self.hbm_count] = n;
                self.hbm_count += 1;
            }
        }
    }

    pub fn localNode(self: *const Self) u32 {
        if (!comptime is_linux) return 0;
        if (self.node_count == 0) return 0;
        return getCurrentNumaNode();
    }

    pub fn nearestHBMNode(self: *const Self) ?u32 {
        if (self.hbm_count == 0) return null;
        const local = self.localNode();
        var best_dist: u8 = 0xFF;
        var best: u32 = INVALID_NODE;
        for (self.hbm_nodes[0..self.hbm_count]) |hbm| {
            const dist = self.nodes[local].distance[hbm];
            if (dist < best_dist) {
                best_dist = dist;
                best = hbm;
            }
        }
        if (best == INVALID_NODE) return null;
        return best;
    }

    pub fn nodeCount(self: *const Self) u32 {
        return self.node_count;
    }

    pub fn hbmNodeCount(self: *const Self) u32 {
        return self.hbm_count;
    }
};

pub fn getCurrentNumaNode() u32 {
    if (!comptime is_linux) return 0;
    var cpu: u32 = 0;
    var node: u32 = 0;
    const ret = std.os.linux.syscall3(
        .getcpu,
        @intFromPtr(&cpu),
        @intFromPtr(&node),
        0,
    );
    if (@as(isize, @bitCast(ret)) < 0) return 0;
    return node;
}

pub fn mbind(
    addr: [*]u8,
    len: usize,
    mode: u32,
    nodemask: ?*const u64,
    maxnode: u64,
    flags: u32,
) bool {
    if (!comptime is_linux) return false;
    const nm_ptr: usize = if (nodemask) |nm| @intFromPtr(nm) else 0;
    const ret = std.os.linux.syscall6(
        .mbind,
        @intFromPtr(addr),
        len,
        @as(usize, mode),
        nm_ptr,
        @as(usize, @intCast(maxnode)),
        @as(usize, flags),
    );
    return @as(isize, @bitCast(ret)) == 0;
}

pub fn bindMemoryToNode(ptr: []u8, node: u32) bool {
    if (!comptime is_linux) return true;
    if (node >= MAX_NUMA_NODES) return false;
    const shift: u6 = @intCast(node);
    var nodemask: u64 = @as(u64, 1) << shift;
    return mbind(ptr.ptr, ptr.len, MPOL_BIND, &nodemask, MAX_NUMA_NODES + 1, MPOL_MF_MOVE);
}

pub fn migrateMemoryToNode(ptr: []u8, dst_node: u32) bool {
    if (!comptime is_linux) return true;
    return bindMemoryToNode(ptr, dst_node);
}

pub fn setThreadAffinity(cpu: u32) bool {
    if (!comptime is_linux) return true;
    var cpuset: CpuSet = CpuSet.init();
    cpuset.set(cpu);
    const ret = std.os.linux.syscall3(
        .sched_setaffinity,
        0,
        @sizeOf(CpuSet),
        @intFromPtr(&cpuset),
    );
    return @as(isize, @bitCast(ret)) == 0;
}

pub fn setThreadAffinityNode(topo: *const NumaTopology, node: u32) bool {
    if (node >= topo.node_count) return false;
    const node_cpus = &topo.nodes[node].cpu_set;
    if (!comptime is_linux) return true;
    const ret = std.os.linux.syscall3(
        .sched_setaffinity,
        0,
        @sizeOf(CpuSet),
        @intFromPtr(node_cpus),
    );
    return @as(isize, @bitCast(ret)) == 0;
}

pub fn allocaOnNode(allocator: std.mem.Allocator, size: usize, node: u32) ![]u8 {
    const buf = try allocator.alloc(u8, size);
    @memset(buf, 0);
    if (node != INVALID_NODE) {
        _ = bindMemoryToNode(buf, node);
    }
    return buf;
}

pub const NumaAwareAllocator = struct {
    backing: std.mem.Allocator,
    preferred_node: u32,
    topo: *const NumaTopology,

    const Self = @This();

    pub fn init(backing: std.mem.Allocator, topo: *const NumaTopology, node: u32) Self {
        return .{
            .backing = backing,
            .preferred_node = node,
            .topo = topo,
        };
    }

    pub fn alloc(self: *Self, size: usize) ![]u8 {
        return allocaOnNode(self.backing, size, self.preferred_node);
    }

    pub fn free(self: *Self, buf: []u8) void {
        self.backing.free(buf);
    }

    pub fn migrate(self: *Self, buf: []u8, new_node: u32) bool {
        if (new_node == self.preferred_node) return true;
        const ok = migrateMemoryToNode(buf, new_node);
        if (ok) self.preferred_node = new_node;
        return ok;
    }
};

comptime {
    _ = posix;
}

test "cpuset operations" {
    const testing = std.testing;
    var cs = CpuSet.init();
    cs.set(0);
    cs.set(63);
    cs.set(127);
    try testing.expect(cs.isSet(0));
    try testing.expect(cs.isSet(63));
    try testing.expect(cs.isSet(127));
    try testing.expect(!cs.isSet(1));
    try testing.expectEqual(@as(u32, 3), cs.count());
    cs.clear(63);
    try testing.expect(!cs.isSet(63));
    try testing.expectEqual(@as(u32, 2), cs.count());
}

test "numa topology detect" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const topo = NumaTopology.detect(gpa.allocator());
    try testing.expect(topo.node_count >= 1);
}

test "numa current node" {
    const n = getCurrentNumaNode();
    _ = n;
}
