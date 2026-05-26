const std = @import("std");
const builtin = @import("builtin");
const atomic = std.atomic;

pub const is_x86_64 = builtin.cpu.arch == .x86_64;

pub fn rdtsc() u64 {
    if (!comptime is_x86_64) {
        const ts = std.time.nanoTimestamp();
        return if (ts < 0) 0 else @as(u64, @intCast(ts));
    }
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        :
        : "memory"
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

pub fn rdtscp() struct { tsc: u64, cpu_id: u32 } {
    if (!comptime is_x86_64) {
        const ts = std.time.nanoTimestamp();
        return .{ .tsc = if (ts < 0) 0 else @as(u64, @intCast(ts)), .cpu_id = 0 };
    }
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    var aux: u32 = undefined;
    asm volatile ("rdtscp"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
          [aux] "={ecx}" (aux),
        :
        : "memory"
    );
    return .{
        .tsc = (@as(u64, hi) << 32) | @as(u64, lo),
        .cpu_id = aux & 0xFFF,
    };
}

pub fn lfence() void {
    if (comptime is_x86_64) {
        asm volatile ("lfence" ::: "memory");
    }
}

pub fn mfence() void {
    if (comptime is_x86_64) {
        asm volatile ("mfence" ::: "memory");
    }
}

pub fn rdtscSerialized() u64 {
    lfence();
    const t = rdtsc();
    lfence();
    return t;
}

pub fn rdrand64() ?u64 {
    if (!comptime is_x86_64) return null;
    var value: u64 = undefined;
    var ok: u8 = undefined;
    asm volatile (
        \\ rdrand %[val]
        \\ setc %[ok]
        : [val] "=r" (value),
          [ok] "=qm" (ok),
        :
        : "cc"
    );
    if (ok == 0) return null;
    return value;
}

pub fn rdrandRetry(max_retries: u32) ?u64 {
    var i: u32 = 0;
    while (i < max_retries) : (i += 1) {
        if (rdrand64()) |v| return v;
        std.atomic.spinLoopHint();
    }
    return null;
}

pub fn rdseed64() ?u64 {
    if (!comptime is_x86_64) return null;
    var value: u64 = undefined;
    var ok: u8 = undefined;
    asm volatile (
        \\ rdseed %[val]
        \\ setc %[ok]
        : [val] "=r" (value),
          [ok] "=qm" (ok),
        :
        : "cc"
    );
    if (ok == 0) return null;
    return value;
}

pub const TscSequencer = struct {
    counter: atomic.Value(u64) align(64),
    tsc_base: u64,
    _pad: [48]u8,

    pub fn init() TscSequencer {
        return .{
            .counter = atomic.Value(u64).init(rdtsc()),
            .tsc_base = rdtsc(),
            ._pad = [_]u8{0} ** 48,
        };
    }

    pub fn next(self: *TscSequencer) u64 {
        const tsc = rdtsc();
        const counter = self.counter.fetchAdd(1, .acq_rel);
        return (tsc << 20) | (counter & 0xFFFFF);
    }

    pub fn nextMonotonic(self: *TscSequencer) u64 {
        return self.counter.fetchAdd(1, .acq_rel);
    }

    pub fn peek(self: *const TscSequencer) u64 {
        return self.counter.load(.acquire);
    }

    pub fn tscDelta(self: *const TscSequencer) u64 {
        return rdtsc() -% self.tsc_base;
    }
};

pub const HardwareRng = struct {
    fallback_prng: std.Random.DefaultPrng,
    use_rdrand: bool,

    pub fn init() HardwareRng {
        const seed = blk: {
            if (rdrand64()) |v| break :blk v;
            const ts = std.time.nanoTimestamp();
            const ts_u64: u64 = if (ts < 0) 0 else @as(u64, @intCast(ts));
            break :blk ts_u64 ^ rdtsc();
        };
        return .{
            .fallback_prng = std.Random.DefaultPrng.init(seed),
            .use_rdrand = blk: {
                const v = rdrand64();
                break :blk v != null;
            },
        };
    }

    pub fn next64(self: *HardwareRng) u64 {
        if (self.use_rdrand) {
            if (rdrand64()) |v| return v;
        }
        return self.fallback_prng.random().int(u64);
    }

    pub fn nextBytes(self: *HardwareRng, out: []u8) void {
        var i: usize = 0;
        while (i + 8 <= out.len) : (i += 8) {
            const v = self.next64();
            std.mem.writeInt(u64, out[i..][0..8], v, .little);
        }
        if (i < out.len) {
            const v = self.next64();
            const bytes = std.mem.asBytes(&v);
            @memcpy(out[i..], bytes[0 .. out.len - i]);
        }
    }

    pub fn nextInRange(self: *HardwareRng, min: u64, max: u64) u64 {
        if (min >= max) return min;
        const range = max - min;
        const v = self.next64();
        return min + (v % range);
    }
};

pub const CpuTimer = struct {
    start: u64,

    pub fn begin() CpuTimer {
        lfence();
        return .{ .start = rdtsc() };
    }

    pub fn elapsedCycles(self: *const CpuTimer) u64 {
        lfence();
        return rdtsc() -% self.start;
    }

    pub fn elapsedNsApprox(self: *const CpuTimer, cycles_per_ns: f64) u64 {
        const cycles = self.elapsedCycles();
        return @as(u64, @intFromFloat(@as(f64, @floatFromInt(cycles)) / cycles_per_ns));
    }
};

pub fn estimateTscFreqHz(sample_ms: u64) u64 {
    const ns_start = std.time.nanoTimestamp();
    const tsc_start = rdtscp().tsc;
    const target_ns: i128 = @as(i128, @intCast(sample_ms)) * 1_000_000;
    while (true) {
        const now = std.time.nanoTimestamp();
        if (now < ns_start) break;
        const elapsed = now - ns_start;
        if (elapsed >= target_ns) break;
    }
    const ns_end = std.time.nanoTimestamp();
    const tsc_end = rdtscp().tsc;

    const elapsed_i128 = ns_end - ns_start;
    if (elapsed_i128 <= 0) return 3_000_000_000;
    const elapsed_ns: u64 = @intCast(elapsed_i128);

    const tsc_delta = tsc_end -% tsc_start;
    return (tsc_delta * 1_000_000_000) / elapsed_ns;
}

test "tsc reads" {
    const testing = std.testing;
    const t1 = rdtsc();
    const t2 = rdtsc();
    try testing.expect(t2 >= t1);
}

test "tsc sequencer monotonic" {
    const testing = std.testing;
    var seq = TscSequencer.init();
    const a = seq.nextMonotonic();
    const b = seq.nextMonotonic();
    const c = seq.nextMonotonic();
    try testing.expect(b > a);
    try testing.expect(c > b);
}

test "hardware rng" {
    const testing = std.testing;
    var rng = HardwareRng.init();
    const a = rng.next64();
    const b = rng.next64();
    _ = a;
    _ = b;
    var buf: [32]u8 = undefined;
    rng.nextBytes(&buf);
    var all_zero = true;
    for (buf) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "cpu timer" {
    const testing = std.testing;
    const timer = CpuTimer.begin();
    std.time.sleep(1_000);
    const elapsed = timer.elapsedCycles();
    try testing.expect(elapsed > 0);
}
