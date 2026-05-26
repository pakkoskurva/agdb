const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const is_x86_64 = builtin.cpu.arch == .x86_64;
pub const is_linux = builtin.os.tag == .linux;

pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

pub const AllocClass = enum(u8) {
    tiny = 0,
    small = 1,
    medium = 2,
    large = 3,
    huge = 4,
};

pub const AllocStats = struct {
    counts: [5]u64 = [_]u64{0} ** 5,
    bytes: [5]u64 = [_]u64{0} ** 5,
    total_allocs: u64 = 0,

    pub fn record(self: *AllocStats, size: usize) AllocClass {
        self.total_allocs += 1;
        const cls = classify(size);
        const idx = @intFromEnum(cls);
        self.counts[idx] += 1;
        self.bytes[idx] += size;
        return cls;
    }

    pub fn dominantClass(self: *const AllocStats) AllocClass {
        var best: usize = 0;
        var best_count: u64 = 0;
        for (self.counts, 0..) |c, i| {
            if (c > best_count) {
                best_count = c;
                best = i;
            }
        }
        return @enumFromInt(best);
    }

    pub fn hotPathClass(self: *const AllocStats) AllocClass {
        return self.dominantClass();
    }
};

pub fn classify(size: usize) AllocClass {
    if (size <= 16) return .tiny;
    if (size <= 256) return .small;
    if (size <= 4096) return .medium;
    if (size <= 2 * 1024 * 1024) return .large;
    return .huge;
}

pub const JITAllocPolicy = struct {
    thresholds: [4]usize,
    classes: [5]AllocClass,
    hot_path: AllocClass,

    pub fn default() JITAllocPolicy {
        return .{
            .thresholds = [_]usize{ 16, 256, 4096, 2 * 1024 * 1024 },
            .classes = [_]AllocClass{ .tiny, .small, .medium, .large, .huge },
            .hot_path = .small,
        };
    }

    pub fn fromStats(stats: *const AllocStats) JITAllocPolicy {
        var policy = JITAllocPolicy.default();
        policy.hot_path = stats.hotPathClass();
        return policy;
    }

    pub fn classifySize(self: *const JITAllocPolicy, size: usize) AllocClass {
        if (size <= self.thresholds[0]) return self.classes[0];
        if (size <= self.thresholds[1]) return self.classes[1];
        if (size <= self.thresholds[2]) return self.classes[2];
        if (size <= self.thresholds[3]) return self.classes[3];
        return self.classes[4];
    }
};

pub const JITCode = struct {
    mem: []align(std.heap.page_size_min) u8,
    size: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn alloc(allocator: std.mem.Allocator, max_size: usize) !Self {
        const aligned = std.mem.alignForward(usize, max_size, std.heap.page_size_min);
        if (!comptime is_linux) {
            const mem = try allocator.alignedAlloc(u8, std.heap.page_size_min, aligned);
            @memset(mem, 0xCC);
            return Self{ .mem = mem, .size = 0, .allocator = allocator };
        }
        const mem = try posix.mmap(
            null,
            aligned,
            posix.PROT.READ | posix.PROT.WRITE | posix.PROT.EXEC,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        @memset(mem, 0xCC);
        return Self{ .mem = mem, .size = 0, .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        if (!comptime is_linux) {
            self.allocator.free(self.mem);
            return;
        }
        posix.munmap(self.mem);
        self.mem = &.{};
    }

    pub fn emit(self: *Self, bytes: []const u8) !usize {
        const pos = self.size;
        if (pos + bytes.len > self.mem.len) return error.CodeBufferFull;
        @memcpy(self.mem[pos .. pos + bytes.len], bytes);
        self.size += bytes.len;
        return pos;
    }

    pub fn makeExecutable(self: *Self) !void {
        if (!comptime is_linux) return;
        try posix.mprotect(self.mem, posix.PROT.READ | posix.PROT.EXEC);
    }

    pub fn makeWritable(self: *Self) !void {
        if (!comptime is_linux) return;
        try posix.mprotect(self.mem, posix.PROT.READ | posix.PROT.WRITE | posix.PROT.EXEC);
    }

    pub fn getPtr(self: *const Self) [*]const u8 {
        return self.mem.ptr;
    }
};

pub const x86_64_Emitter = struct {
    code: *JITCode,

    const Self = @This();

    pub fn init(code: *JITCode) Self {
        return .{ .code = code };
    }

    pub fn emitNop(self: *Self) !void {
        _ = try self.code.emit(&[_]u8{0x90});
    }

    pub fn emitRet(self: *Self) !void {
        _ = try self.code.emit(&[_]u8{0xC3});
    }

    pub fn emitMovRaxImm64(self: *Self, imm: u64) !void {
        var bytes: [10]u8 = undefined;
        bytes[0] = 0x48;
        bytes[1] = 0xB8;
        std.mem.writeInt(u64, bytes[2..10], imm, .little);
        _ = try self.code.emit(&bytes);
    }

    pub fn emitMovEaxImm32(self: *Self, imm: u32) !void {
        var bytes: [5]u8 = undefined;
        bytes[0] = 0xB8;
        std.mem.writeInt(u32, bytes[1..5], imm, .little);
        _ = try self.code.emit(&bytes);
    }

    pub fn emitPushRbp(self: *Self) !void {
        _ = try self.code.emit(&[_]u8{0x55});
    }

    pub fn emitPopRbp(self: *Self) !void {
        _ = try self.code.emit(&[_]u8{0x5D});
    }

    pub fn emitMovRbpRsp(self: *Self) !void {
        _ = try self.code.emit(&[_]u8{ 0x48, 0x89, 0xE5 });
    }

    pub fn emitMovRspRbp(self: *Self) !void {
        _ = try self.code.emit(&[_]u8{ 0x48, 0x89, 0xEC });
    }

    pub fn emitCmpRdiImm32(self: *Self, imm: u32) !void {
        var bytes: [7]u8 = undefined;
        bytes[0] = 0x48;
        bytes[1] = 0x81;
        bytes[2] = 0xFF;
        std.mem.writeInt(u32, bytes[3..7], imm, .little);
        _ = try self.code.emit(&bytes);
    }

    pub fn emitJa(self: *Self, rel8: i8) !void {
        _ = try self.code.emit(&[_]u8{ 0x77, @bitCast(rel8) });
    }

    pub fn emitJb(self: *Self, rel8: i8) !void {
        _ = try self.code.emit(&[_]u8{ 0x72, @bitCast(rel8) });
    }

    pub fn emitJle(self: *Self, rel8: i8) !void {
        _ = try self.code.emit(&[_]u8{ 0x7E, @bitCast(rel8) });
    }

    pub fn emitJmp(self: *Self, rel8: i8) !void {
        _ = try self.code.emit(&[_]u8{ 0xEB, @bitCast(rel8) });
    }
};

const ClassifyFn = *const fn (usize) callconv(.C) u8;

pub fn jitCompileClassifier(code: *JITCode, policy: *const JITAllocPolicy) !ClassifyFn {
    if (!comptime is_x86_64) {
        return &softwareClassify;
    }

    var emit = x86_64_Emitter.init(code);
    try code.makeWritable();
    code.size = 0;

    try emit.emitPushRbp();
    try emit.emitMovRbpRsp();

    inline for (0..4) |i| {
        const threshold: u32 = @intCast(@min(policy.thresholds[i], 0xFFFFFFFF));
        const class: u8 = @intFromEnum(policy.classes[i]);
        try emit.emitCmpRdiImm32(threshold);
        try emit.emitJa(5);
        try emit.emitMovEaxImm32(class);
        try emit.emitMovRspRbp();
        try emit.emitPopRbp();
        try emit.emitRet();
    }

    try emit.emitMovEaxImm32(@intFromEnum(AllocClass.huge));
    try emit.emitMovRspRbp();
    try emit.emitPopRbp();
    try emit.emitRet();

    try code.makeExecutable();

    const fn_ptr: ClassifyFn = @ptrCast(@alignCast(code.mem.ptr));
    return fn_ptr;
}

fn softwareClassify(size: usize) callconv(.C) u8 {
    return @intFromEnum(classify(size));
}

pub const AdaptiveAllocator = struct {
    backing: std.mem.Allocator,
    stats: AllocStats,
    policy: JITAllocPolicy,
    jit_code: ?JITCode,
    classify_fn: ?ClassifyFn,
    sample_interval: u64,
    sample_count: u64,
    recompile_threshold: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, recompile_threshold: u64) Self {
        return .{
            .backing = allocator,
            .stats = .{},
            .policy = JITAllocPolicy.default(),
            .jit_code = null,
            .classify_fn = null,
            .sample_interval = 1000,
            .sample_count = 0,
            .recompile_threshold = recompile_threshold,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.jit_code) |*c| c.deinit();
    }

    pub fn classifyAlloc(self: *Self, size: usize) AllocClass {
        _ = self.stats.record(size);
        self.sample_count += 1;
        if (self.sample_count % self.sample_interval == 0) {
            self.maybeRecompile() catch {};
        }
        if (self.classify_fn) |f| {
            return @enumFromInt(f(size));
        }
        return self.policy.classifySize(size);
    }

    pub fn alloc(self: *Self, size: usize) ![]u8 {
        _ = self.classifyAlloc(size);
        return self.backing.alloc(u8, size);
    }

    pub fn free(self: *Self, buf: []u8) void {
        self.backing.free(buf);
    }

    fn maybeRecompile(self: *Self) !void {
        if (self.stats.total_allocs < self.recompile_threshold) return;
        const new_policy = JITAllocPolicy.fromStats(&self.stats);
        if (std.meta.eql(new_policy.hot_path, self.policy.hot_path)) return;
        self.policy = new_policy;
        if (self.jit_code == null) {
            self.jit_code = try JITCode.alloc(self.backing, 4096);
        }
        if (self.jit_code) |*code| {
            self.classify_fn = jitCompileClassifier(code, &self.policy) catch null;
        }
    }
};

test "alloc classify" {
    const testing = std.testing;
    try testing.expectEqual(AllocClass.tiny, classify(8));
    try testing.expectEqual(AllocClass.small, classify(128));
    try testing.expectEqual(AllocClass.medium, classify(1024));
    try testing.expectEqual(AllocClass.large, classify(65536));
    try testing.expectEqual(AllocClass.huge, classify(4 * 1024 * 1024));
}

test "jit policy" {
    const policy = JITAllocPolicy.default();
    try std.testing.expectEqual(AllocClass.tiny, policy.classifySize(8));
    try std.testing.expectEqual(AllocClass.small, policy.classifySize(64));
    try std.testing.expectEqual(AllocClass.medium, policy.classifySize(2048));
    try std.testing.expectEqual(AllocClass.large, policy.classifySize(65536));
    try std.testing.expectEqual(AllocClass.huge, policy.classifySize(4 * 1024 * 1024));
}

test "alloc stats" {
    const testing = std.testing;
    var stats = AllocStats{};
    for (0..100) |_| _ = stats.record(128);
    for (0..10) |_| _ = stats.record(16);
    const dom = stats.dominantClass();
    try testing.expectEqual(AllocClass.small, dom);
}

test "adaptive allocator" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var aa = AdaptiveAllocator.init(gpa.allocator(), 500);
    defer aa.deinit();
    const buf = try aa.alloc(256);
    defer aa.free(buf);
    try testing.expectEqual(@as(usize, 256), buf.len);
}
