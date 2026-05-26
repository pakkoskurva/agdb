const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const posix = std.posix;

pub const is_linux = builtin.os.tag == .linux;

pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_FSYNC: u8 = 3;
pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_POLL_ADD: u8 = 6;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 9;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_FALLOCATE: u8 = 16;
pub const IORING_OP_CLOSE: u8 = 19;

pub const IORING_SETUP_SQPOLL: u32 = 0x00000002;
pub const IORING_SETUP_SQ_AFF: u32 = 0x00000004;
pub const IORING_SETUP_IOPOLL: u32 = 0x00000001;
pub const IORING_SETUP_CQSIZE: u32 = 0x00000008;

pub const IORING_FEAT_NODROP: u32 = 0x00000001;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 0x00000002;
pub const IORING_FEAT_RW_CUR_POS: u32 = 0x00000004;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 0x00000008;
pub const IORING_FEAT_FAST_POLL: u32 = 0x00000010;

pub const IORING_FSYNC_DATASYNC: u32 = 0x00000001;

pub const IORING_ENTER_GETEVENTS: u32 = 1;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 2;

pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;

pub const io_uring_sqe = extern struct {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    _pad2: [2]u64,
};

pub const io_uring_cqe = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

pub const io_sqring_offsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    resv2: u64,
};

pub const io_cqring_offsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    resv2: u64,
};

pub const io_uring_params = extern struct {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [3]u32,
    sq_off: io_sqring_offsets,
    cq_off: io_cqring_offsets,
};

pub const IOUringError = error{
    SetupFailed,
    NotSupported,
    SubmitFailed,
    WaitFailed,
    OutOfSQEs,
    MappingFailed,
};

const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;

pub const IOUring = struct {
    ring_fd: i32,
    sq_ring: []align(std.heap.page_size_min) u8,
    cq_ring: []align(std.heap.page_size_min) u8,
    sqes: []align(std.heap.page_size_min) io_uring_sqe,
    params: io_uring_params,
    sq_head: *u32,
    sq_tail: *u32,
    sq_mask: *u32,
    sq_entries: *u32,
    sq_flags: *u32,
    sq_array: [*]u32,
    cq_head: *u32,
    cq_tail: *u32,
    cq_mask: *u32,
    cq_entries: *u32,
    cqes_ptr: [*]io_uring_cqe,
    pending: u32,

    const Self = @This();

    pub fn init(entries: u32, flags: u32) IOUringError!Self {
        if (!comptime is_linux) return error.NotSupported;

        var params = std.mem.zeroes(io_uring_params);
        params.flags = flags;
        params.sq_entries = entries;

        const ring_fd = linux_io_uring_setup(entries, &params) catch {
            return error.SetupFailed;
        };

        const sq_ring_size = params.sq_off.array + params.sq_entries * @sizeOf(u32);
        const cq_ring_size = params.cq_off.cqes + params.cq_entries * @sizeOf(io_uring_cqe);

        const sq_ring = mapRing(ring_fd, IORING_OFF_SQ_RING, sq_ring_size) catch return error.MappingFailed;
        errdefer posix.munmap(sq_ring);

        const cq_ring = if (params.features & IORING_FEAT_SINGLE_MMAP != 0)
            sq_ring
        else
            mapRing(ring_fd, IORING_OFF_CQ_RING, cq_ring_size) catch return error.MappingFailed;
        errdefer if (params.features & IORING_FEAT_SINGLE_MMAP == 0) posix.munmap(cq_ring);

        const sqes_size = params.sq_entries * @sizeOf(io_uring_sqe);
        const sqes_raw = mapRing(ring_fd, IORING_OFF_SQES, sqes_size) catch return error.MappingFailed;
        errdefer posix.munmap(sqes_raw);

        const sqes: []align(std.heap.page_size_min) io_uring_sqe = blk: {
            const count = sqes_size / @sizeOf(io_uring_sqe);
            const ptr: [*]align(std.heap.page_size_min) io_uring_sqe = @ptrCast(@alignCast(sqes_raw.ptr));
            break :blk ptr[0..count];
        };

        const sq_head: *u32 = @ptrCast(@alignCast(sq_ring.ptr + params.sq_off.head));
        const sq_tail: *u32 = @ptrCast(@alignCast(sq_ring.ptr + params.sq_off.tail));
        const sq_mask: *u32 = @ptrCast(@alignCast(sq_ring.ptr + params.sq_off.ring_mask));
        const sq_entries: *u32 = @ptrCast(@alignCast(sq_ring.ptr + params.sq_off.ring_entries));
        const sq_flags: *u32 = @ptrCast(@alignCast(sq_ring.ptr + params.sq_off.flags));
        const sq_array: [*]u32 = @ptrCast(@alignCast(sq_ring.ptr + params.sq_off.array));

        const cq_head: *u32 = @ptrCast(@alignCast(cq_ring.ptr + params.cq_off.head));
        const cq_tail: *u32 = @ptrCast(@alignCast(cq_ring.ptr + params.cq_off.tail));
        const cq_mask: *u32 = @ptrCast(@alignCast(cq_ring.ptr + params.cq_off.ring_mask));
        const cq_entries: *u32 = @ptrCast(@alignCast(cq_ring.ptr + params.cq_off.ring_entries));
        const cqes_ptr: [*]io_uring_cqe = @ptrCast(@alignCast(cq_ring.ptr + params.cq_off.cqes));

        return Self{
            .ring_fd = ring_fd,
            .sq_ring = sq_ring,
            .cq_ring = cq_ring,
            .sqes = sqes,
            .params = params,
            .sq_head = sq_head,
            .sq_tail = sq_tail,
            .sq_mask = sq_mask,
            .sq_entries = sq_entries,
            .sq_flags = sq_flags,
            .sq_array = sq_array,
            .cq_head = cq_head,
            .cq_tail = cq_tail,
            .cq_mask = cq_mask,
            .cq_entries = cq_entries,
            .cqes_ptr = cqes_ptr,
            .pending = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (!comptime is_linux) return;
        const sqes_raw: []align(std.heap.page_size_min) u8 = @as([*]align(std.heap.page_size_min) u8, @ptrCast(self.sqes.ptr))[0 .. self.params.sq_entries * @sizeOf(io_uring_sqe)];
        posix.munmap(sqes_raw);
        if (self.params.features & IORING_FEAT_SINGLE_MMAP == 0 and self.cq_ring.ptr != self.sq_ring.ptr) {
            posix.munmap(self.cq_ring);
        }
        posix.munmap(self.sq_ring);
        posix.close(self.ring_fd);
    }

    pub fn getSQE(self: *Self) IOUringError!*io_uring_sqe {
        const tail = @atomicLoad(u32, self.sq_tail, .acquire);
        const head = @atomicLoad(u32, self.sq_head, .acquire);
        const mask = self.sq_mask.*;
        if (tail -% head >= self.sq_entries.*) return error.OutOfSQEs;
        const idx = tail & mask;
        self.sq_array[idx] = idx;
        @atomicStore(u32, self.sq_tail, tail +% 1, .release);
        const sqe = &self.sqes[idx];
        sqe.* = std.mem.zeroes(io_uring_sqe);
        self.pending += 1;
        return sqe;
    }

    pub fn prepWrite(self: *Self, fd: i32, buf: []const u8, offset: u64, user_data: u64) IOUringError!void {
        const sqe = try self.getSQE();
        sqe.opcode = IORING_OP_WRITE;
        sqe.fd = fd;
        sqe.addr = @intFromPtr(buf.ptr);
        sqe.len = @intCast(buf.len);
        sqe.off = offset;
        sqe.user_data = user_data;
        sqe.flags = 0;
        sqe.op_flags = 0;
    }

    pub fn prepRead(self: *Self, fd: i32, buf: []u8, offset: u64, user_data: u64) IOUringError!void {
        const sqe = try self.getSQE();
        sqe.opcode = IORING_OP_READ;
        sqe.fd = fd;
        sqe.addr = @intFromPtr(buf.ptr);
        sqe.len = @intCast(buf.len);
        sqe.off = offset;
        sqe.user_data = user_data;
        sqe.flags = 0;
        sqe.op_flags = 0;
    }

    pub fn prepFsync(self: *Self, fd: i32, datasync: bool, user_data: u64) IOUringError!void {
        const sqe = try self.getSQE();
        sqe.opcode = IORING_OP_FSYNC;
        sqe.fd = fd;
        sqe.user_data = user_data;
        sqe.op_flags = if (datasync) IORING_FSYNC_DATASYNC else 0;
        sqe.addr = 0;
        sqe.len = 0;
        sqe.off = 0;
    }

    pub fn submit(self: *Self) IOUringError!u32 {
        if (self.pending == 0) return 0;
        if (!comptime is_linux) return error.NotSupported;
        const submitted = linux_io_uring_enter(self.ring_fd, self.pending, 0, 0) catch return error.SubmitFailed;
        self.pending = 0;
        return @intCast(submitted);
    }

    pub fn submitAndWait(self: *Self, min_complete: u32) IOUringError!u32 {
        if (!comptime is_linux) return error.NotSupported;
        const to_submit = self.pending;
        const completed = linux_io_uring_enter(self.ring_fd, to_submit, min_complete, IORING_ENTER_GETEVENTS) catch return error.WaitFailed;
        self.pending = 0;
        return @intCast(completed);
    }

    pub fn peekCQE(self: *Self) ?io_uring_cqe {
        const head = @atomicLoad(u32, self.cq_head, .acquire);
        const tail = @atomicLoad(u32, self.cq_tail, .acquire);
        if (head == tail) return null;
        const mask = self.cq_mask.*;
        const cqe = self.cqes_ptr[head & mask];
        @atomicStore(u32, self.cq_head, head +% 1, .release);
        return cqe;
    }

    pub fn drainCQEs(self: *Self, completions: []io_uring_cqe) u32 {
        var count: u32 = 0;
        while (count < completions.len) {
            const cqe = self.peekCQE() orelse break;
            completions[count] = cqe;
            count += 1;
        }
        return count;
    }

    pub fn waitCQE(self: *Self) IOUringError!io_uring_cqe {
        while (true) {
            if (self.peekCQE()) |cqe| return cqe;
            _ = linux_io_uring_enter(self.ring_fd, 0, 1, IORING_ENTER_GETEVENTS) catch return error.WaitFailed;
        }
    }
};

const IORING_FEAT_SINGLE_MMAP: u32 = 0x00000001;

fn mapRing(fd: i32, offset: u64, size: usize) ![]align(std.heap.page_size_min) u8 {
    if (!comptime is_linux) return error.NotSupported;
    const aligned_size = std.mem.alignForward(usize, size, std.heap.page_size_min);
    const ptr = try posix.mmap(
        null,
        aligned_size,
        posix.PROT.READ | posix.PROT.WRITE,
        .{ .TYPE = .SHARED },
        fd,
        @intCast(offset),
    );
    return ptr;
}

fn linux_io_uring_setup(entries: u32, params: *io_uring_params) !i32 {
    if (!comptime is_linux) return error.NotSupported;
    const ret = std.os.linux.syscall2(.io_uring_setup, entries, @intFromPtr(params));
    const signed = @as(isize, @bitCast(ret));
    if (signed < 0) return error.SetupFailed;
    return @intCast(ret);
}

fn linux_io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32) !usize {
    if (!comptime is_linux) return error.NotSupported;
    const ret = std.os.linux.syscall6(
        .io_uring_enter,
        @as(usize, @bitCast(@as(isize, fd))),
        to_submit,
        min_complete,
        flags,
        0,
        0,
    );
    const signed = @as(isize, @bitCast(ret));
    if (signed < 0) return error.SubmitFailed;
    return ret;
}

pub const WALIOUringWriter = struct {
    ring: IOUring,
    fd: i32,
    write_offset: u64,
    inflight: u32,
    allocator: std.mem.Allocator,

    const Self = @This();
    const MAX_BATCH: u32 = 64;

    pub fn init(allocator: std.mem.Allocator, fd: i32, ring_entries: u32) !Self {
        if (!comptime is_linux) return error.NotSupported;
        const ring = try IOUring.init(ring_entries, 0);
        return Self{
            .ring = ring,
            .fd = fd,
            .write_offset = 0,
            .inflight = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self.flush() catch {};
        if (comptime is_linux) self.ring.deinit();
    }

    pub fn enqueueWrite(self: *Self, data: []const u8, user_data: u64) !u64 {
        const offset = self.write_offset;
        try self.ring.prepWrite(self.fd, data, offset, user_data);
        self.write_offset += data.len;
        self.inflight += 1;
        if (self.inflight >= MAX_BATCH) {
            _ = try self.ring.submit();
        }
        return offset;
    }

    pub fn enqueueFsync(self: *Self, datasync: bool) !void {
        try self.ring.prepFsync(self.fd, datasync, 0xFFFFFFFF_FFFFFFFF);
        self.inflight += 1;
    }

    pub fn flush(self: *Self) !u32 {
        if (self.inflight == 0) return 0;
        const n = try self.ring.submitAndWait(self.inflight);
        self.inflight = 0;
        return n;
    }

    pub fn drainCompletions(self: *Self, max: u32) !u32 {
        var buf: [64]io_uring_cqe = undefined;
        const count = self.ring.drainCQEs(buf[0..@min(max, 64)]);
        var errors: u32 = 0;
        for (buf[0..count]) |cqe| {
            if (cqe.res < 0) errors += 1;
        }
        return count - errors;
    }
};

test "iouring not supported on non-linux gracefully" {
    if (comptime !is_linux) {
        const result = IOUring.init(64, 0);
        try std.testing.expectError(error.NotSupported, result);
    }
}
