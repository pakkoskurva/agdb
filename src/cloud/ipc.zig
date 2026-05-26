const std = @import("std");

pub const IPC_MAGIC: u32 = 0x47444241;
pub const HEADER_SIZE: usize = 20;

pub const IpcHeader = struct {
    magic: u32,
    request_id: u64,
    msg_type: u8,
    status: u8,
    payload_len: u32,
};

pub const IpcMessage = struct {
    header: IpcHeader,
    payload: []u8,

    pub fn deinit(self: *IpcMessage, allocator: std.mem.Allocator) void {
        if (self.payload.len > 0) {
            allocator.free(self.payload);
        }
    }
};

fn serializeHeader(hdr: IpcHeader) [HEADER_SIZE]u8 {
    var out: [HEADER_SIZE]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], hdr.magic, .little);
    std.mem.writeInt(u64, out[4..12], hdr.request_id, .little);
    out[12] = hdr.msg_type;
    out[13] = hdr.status;
    out[14] = 0;
    out[15] = 0;
    std.mem.writeInt(u32, out[16..20], hdr.payload_len, .little);
    return out;
}

fn deserializeHeader(buf: [HEADER_SIZE]u8) IpcHeader {
    return IpcHeader{
        .magic = std.mem.readInt(u32, buf[0..4], .little),
        .request_id = std.mem.readInt(u64, buf[4..12], .little),
        .msg_type = buf[12],
        .status = buf[13],
        .payload_len = std.mem.readInt(u32, buf[16..20], .little),
    };
}

fn writeAll(fd: i32, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const rc = std.os.linux.write(fd, data[written..].ptr, data.len - written);
        const err = std.posix.errno(rc);
        if (err != .SUCCESS) {
            if (err == .INTR) continue;
            if (err == .AGAIN) continue;
            return error.WriteFailed;
        }
        if (rc == 0) return error.WriteFailed;
        written += @intCast(rc);
    }
}

fn readAll(fd: i32, buf: []u8) !void {
    var read_n: usize = 0;
    while (read_n < buf.len) {
        const rc = std.os.linux.read(fd, buf[read_n..].ptr, buf.len - read_n);
        const err = std.posix.errno(rc);
        if (err != .SUCCESS) {
            if (err == .INTR) continue;
            if (err == .AGAIN) continue;
            return error.ReadFailed;
        }
        if (rc == 0) return error.ConnectionClosed;
        read_n += @intCast(rc);
    }
}

pub fn sendMessage(fd: i32, msg_type: u8, status: u8, request_id: u64, payload: []const u8) !void {
    if (payload.len > std.math.maxInt(u32)) return error.PayloadTooLarge;
    const header = IpcHeader{
        .magic = IPC_MAGIC,
        .request_id = request_id,
        .msg_type = msg_type,
        .status = status,
        .payload_len = @intCast(payload.len),
    };
    const hdr_bytes = serializeHeader(header);
    try writeAll(fd, &hdr_bytes);
    if (payload.len > 0) try writeAll(fd, payload);
}

pub fn recvMessage(allocator: std.mem.Allocator, fd: i32) !IpcMessage {
    var hdr_bytes: [HEADER_SIZE]u8 = undefined;
    try readAll(fd, &hdr_bytes);
    const header = deserializeHeader(hdr_bytes);
    if (header.magic != IPC_MAGIC) return error.InvalidMagic;

    const payload = try allocator.alloc(u8, header.payload_len);
    errdefer allocator.free(payload);

    if (header.payload_len > 0) {
        try readAll(fd, payload);
    }
    return IpcMessage{
        .header = header,
        .payload = payload,
    };
}
