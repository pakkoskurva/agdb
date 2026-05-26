const std = @import("std");
const builtin = @import("builtin");

pub const is_x86_64 = builtin.cpu.arch == .x86_64;
pub const has_rtm = is_x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .rtm);

pub const HTM_STARTED: u32 = 0xFFFFFFFF;
pub const HTM_ABORT_EXPLICIT: u32 = 0x01;
pub const HTM_ABORT_RETRY: u32 = 0x02;
pub const HTM_ABORT_CONFLICT: u32 = 0x04;
pub const HTM_ABORT_CAPACITY: u32 = 0x08;
pub const HTM_ABORT_DEBUG: u32 = 0x10;
pub const HTM_ABORT_NESTED: u32 = 0x20;

pub const HTMStatus = enum(u32) {
    started = HTM_STARTED,
    abort_explicit = HTM_ABORT_EXPLICIT,
    abort_retry = HTM_ABORT_RETRY,
    abort_conflict = HTM_ABORT_CONFLICT,
    abort_capacity = HTM_ABORT_CAPACITY,
    abort_debug = HTM_ABORT_DEBUG,
    abort_nested = HTM_ABORT_NESTED,
    not_supported = 0,
    _,
};

pub const HTMResult = union(enum) {
    success: void,
    aborted: u32,
    not_supported: void,
};

pub fn xbegin() u32 {
    if (!comptime is_x86_64) return 0;
    return asm volatile (
        \\.byte 0xC7, 0xF8
        \\.long 0x00000000
        : [ret] "={eax}" (-> u32),
        :
        : "memory", "eax", "ebx", "ecx", "edx", "esi", "edi"
    );
}

pub fn xend() void {
    if (!comptime is_x86_64) return;
    asm volatile (
        \\.byte 0x0F, 0x01, 0xD5
        :
        :
        : "memory"
    );
}

pub fn xabort(imm: u8) noreturn {
    if (!comptime is_x86_64) {
        @panic("xabort on non-x86_64");
    }
    switch (imm) {
        0 => asm volatile (
            \\.byte 0xC6, 0xF8, 0x00
            :
            :
            : "memory"
        ),
        1 => asm volatile (
            \\.byte 0xC6, 0xF8, 0x01
            :
            :
            : "memory"
        ),
        2 => asm volatile (
            \\.byte 0xC6, 0xF8, 0x02
            :
            :
            : "memory"
        ),
        else => asm volatile (
            \\.byte 0xC6, 0xF8, 0xFF
            :
            :
            : "memory"
        ),
    }
    unreachable;
}

pub fn xtest() bool {
    if (!comptime is_x86_64) return false;
    const result = asm volatile (
        \\.byte 0x0F, 0x01, 0xD6
        \\ setnz %[ret]
        : [ret] "=r" (-> u8),
        :
        : "memory"
    );
    return result != 0;
}

pub const HTMConfig = struct {
    max_retries: u32 = 8,
    retry_conflict: bool = true,
    retry_capacity: bool = false,
    fallback_mutex: ?*std.Thread.Mutex = null,
};

pub fn htmBegin() HTMResult {
    if (!comptime is_x86_64) return .not_supported;
    const status = xbegin();
    if (status == HTM_STARTED) return .success;
    return .{ .aborted = status };
}

pub fn htmCommit() void {
    xend();
}

pub fn htmAbort() void {
    if (comptime is_x86_64) {
        asm volatile (
            \\.byte 0xC6, 0xF8, 0xFF
            :
            :
            : "memory"
        );
    }
}

pub fn shouldRetry(abort_code: u32, config: HTMConfig) bool {
    if (abort_code & HTM_ABORT_RETRY != 0) return true;
    if (config.retry_conflict and (abort_code & HTM_ABORT_CONFLICT != 0)) return true;
    return false;
}

pub fn HTMTransaction(comptime lock_type: type) type {
    return struct {
        lock: *lock_type,
        config: HTMConfig,
        in_htm: bool,
        retries: u32,

        const Self = @This();

        pub fn init(lock: *lock_type, config: HTMConfig) Self {
            return .{
                .lock = lock,
                .config = config,
                .in_htm = false,
                .retries = 0,
            };
        }

        pub fn begin(self: *Self) void {
            var attempts: u32 = 0;
            while (attempts <= self.config.max_retries) : (attempts += 1) {
                const result = htmBegin();
                switch (result) {
                    .success => {
                        if (isMutexLocked(self.lock)) {
                            htmAbort();
                        } else {
                            self.in_htm = true;
                            self.retries = attempts;
                            return;
                        }
                    },
                    .aborted => |code| {
                        if (!shouldRetry(code, self.config)) break;
                        std.atomic.spinLoopHint();
                    },
                    .not_supported => break,
                }
            }
            if (self.config.fallback_mutex) |m| {
                m.lock();
            }
            self.in_htm = false;
            self.retries = attempts;
        }

        pub fn commit(self: *Self) void {
            if (self.in_htm) {
                htmCommit();
                self.in_htm = false;
            } else {
                if (self.config.fallback_mutex) |m| {
                    m.unlock();
                }
            }
        }

        pub fn abort(self: *Self) void {
            if (self.in_htm) {
                htmAbort();
                self.in_htm = false;
            } else {
                if (self.config.fallback_mutex) |m| {
                    m.unlock();
                }
            }
        }

        fn isMutexLocked(lock: *lock_type) bool {
            _ = lock;
            return false;
        }
    };
}

pub const HTMStats = struct {
    htm_commits: u64 = 0,
    htm_aborts: u64 = 0,
    fallback_commits: u64 = 0,
    conflict_aborts: u64 = 0,
    capacity_aborts: u64 = 0,

    pub fn recordCommit(self: *HTMStats, was_htm: bool) void {
        if (was_htm) {
            _ = @atomicRmw(u64, &self.htm_commits, .Add, 1, .seq_cst);
        } else {
            _ = @atomicRmw(u64, &self.fallback_commits, .Add, 1, .seq_cst);
        }
    }

    pub fn recordAbort(self: *HTMStats, code: u32) void {
        _ = @atomicRmw(u64, &self.htm_aborts, .Add, 1, .seq_cst);
        if (code & HTM_ABORT_CONFLICT != 0) {
            _ = @atomicRmw(u64, &self.conflict_aborts, .Add, 1, .seq_cst);
        }
        if (code & HTM_ABORT_CAPACITY != 0) {
            _ = @atomicRmw(u64, &self.capacity_aborts, .Add, 1, .seq_cst);
        }
    }

    pub fn htmSuccessRate(self: *const HTMStats) f64 {
        const total = self.htm_commits + self.fallback_commits;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.htm_commits)) / @as(f64, @floatFromInt(total));
    }
};

pub fn runWithHTM(
    lock: *std.Thread.Mutex,
    config: HTMConfig,
    stats: ?*HTMStats,
    comptime body: fn () void,
) void {
    var attempts: u32 = 0;
    while (attempts <= config.max_retries) : (attempts += 1) {
        const result = htmBegin();
        switch (result) {
            .success => {
                body();
                htmCommit();
                if (stats) |s| s.recordCommit(true);
                return;
            },
            .aborted => |code| {
                if (stats) |s| s.recordAbort(code);
                if (!shouldRetry(code, config)) break;
                std.atomic.spinLoopHint();
            },
            .not_supported => break,
        }
    }
    lock.lock();
    defer lock.unlock();
    body();
    if (stats) |s| s.recordCommit(false);
}

test "htm xtest not in transaction" {
    const testing = std.testing;
    if (!is_x86_64) return;
    const in_tx = xtest();
    try testing.expect(!in_tx);
}

test "htm status codes" {
    const testing = std.testing;
    try testing.expect(HTM_STARTED == 0xFFFFFFFF);
    try testing.expect(HTM_ABORT_CONFLICT == 0x04);
}

test "htm stats" {
    const testing = std.testing;
    var stats = HTMStats{};
    stats.recordCommit(true);
    stats.recordCommit(false);
    stats.recordAbort(HTM_ABORT_CONFLICT);
    try testing.expectEqual(@as(u64, 1), stats.htm_commits);
    try testing.expectEqual(@as(u64, 1), stats.fallback_commits);
    try testing.expectEqual(@as(u64, 1), stats.htm_aborts);
    try testing.expectEqual(@as(u64, 1), stats.conflict_aborts);
}
