const std = @import("std");

pub const GPUError = error{
    ContextInitFailed,
    KernelNotFound,
    InvalidArgument,
    MemoryAllocationFailed,
    ExecutionFailed,
    SynchronizationFailed,
    InvalidContext,
    UnsupportedType,
    OutOfGPUMemory,
    DriverError,
};

pub const GPUValueType = enum(u8) {
    int32,
    int64,
    float32,
    float64,
    bool_,
    array_int32,
    array_int64,
    array_float32,
    array_float64,
};

pub const GPUValue = union(GPUValueType) {
    int32: i32,
    int64: i64,
    float32: f32,
    float64: f64,
    bool_: bool,
    array_int32: GPUArray(i32),
    array_int64: GPUArray(i64),
    array_float32: GPUArray(f32),
    array_float64: GPUArray(f64),

    pub fn getType(self: GPUValue) GPUValueType {
        return std.meta.activeTag(self);
    }

    pub fn deinit(self: *GPUValue) void {
        switch (self.*) {
            .array_int32 => |*arr| arr.deinit(),
            .array_int64 => |*arr| arr.deinit(),
            .array_float32 => |*arr| arr.deinit(),
            .array_float64 => |*arr| arr.deinit(),
            else => {},
        }
    }

    pub fn borrow(self: GPUValue) GPUValue {
        return switch (self) {
            .int32 => |v| GPUValue{ .int32 = v },
            .int64 => |v| GPUValue{ .int64 = v },
            .float32 => |v| GPUValue{ .float32 = v },
            .float64 => |v| GPUValue{ .float64 = v },
            .bool_ => |v| GPUValue{ .bool_ = v },
            .array_int32 => |arr| GPUValue{ .array_int32 = arr.borrow() },
            .array_int64 => |arr| GPUValue{ .array_int64 = arr.borrow() },
            .array_float32 => |arr| GPUValue{ .array_float32 = arr.borrow() },
            .array_float64 => |arr| GPUValue{ .array_float64 = arr.borrow() },
        };
    }
};

pub fn GPUArray(comptime T: type) type {
    return struct {
        data: []T,
        device_data: []T,
        device_ptr: ?*anyopaque,
        owned_host: bool,
        owned_device: bool,
        allocator: ?std.mem.Allocator,

        const Self = @This();

        fn emptySlice() []T {
            return @constCast(&[_]T{});
        }

        pub fn init(host_data: []T) Self {
            return Self{
                .data = host_data,
                .device_data = host_data[0..0],
                .device_ptr = null,
                .owned_host = false,
                .owned_device = false,
                .allocator = null,
            };
        }

        pub fn initOwned(allocator: std.mem.Allocator, count: usize) !Self {
            const host_data = allocator.alloc(T, count) catch return GPUError.MemoryAllocationFailed;
            errdefer allocator.free(host_data);

            const device_data = allocator.alloc(T, count) catch return GPUError.OutOfGPUMemory;
            errdefer allocator.free(device_data);

            return Self{
                .data = host_data,
                .device_data = device_data,
                .device_ptr = if (device_data.len == 0) null else @as(?*anyopaque, @ptrCast(device_data.ptr)),
                .owned_host = true,
                .owned_device = true,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.allocator) |allocator| {
                if (self.owned_device and self.device_data.len > 0) {
                    const same_allocation = self.data.len > 0 and @intFromPtr(self.data.ptr) == @intFromPtr(self.device_data.ptr);
                    if (!same_allocation) {
                        allocator.free(self.device_data);
                    }
                }

                if (self.owned_host and self.data.len > 0) {
                    allocator.free(self.data);
                }
            }

            self.data = emptySlice();
            self.device_data = emptySlice();
            self.device_ptr = null;
            self.owned_host = false;
            self.owned_device = false;
            self.allocator = null;
        }

        pub fn len(self: Self) usize {
            return self.data.len;
        }

        pub fn borrow(self: Self) Self {
            return Self{
                .data = self.data,
                .device_data = self.device_data,
                .device_ptr = self.device_ptr,
                .owned_host = false,
                .owned_device = false,
                .allocator = null,
            };
        }
    };
}

pub const GPUKernelFn = *const fn (ctx: *GPUContext, inputs: []const GPUValue, allocator: std.mem.Allocator) anyerror!GPUValue;

pub const GPUKernelInfo = struct {
    name: []const u8,
    input_types: []const GPUValueType,
    output_type: GPUValueType,
    kernel_fn: GPUKernelFn,
};

pub const GPUContext = struct {
    handle: ?*anyopaque,
    config: ?*anyopaque,
    kernel_library: ?std.DynLib,
    kernels: std.StringHashMap(GPUKernelInfo),
    allocator: std.mem.Allocator,
    initialized: bool,
    supports_unified_memory: bool,
    device_name: [256]u8,

    const Self = @This();
    const KernelRegisterFn = *const fn (*GPUContext) callconv(.C) c_int;

    pub fn init(allocator: std.mem.Allocator, kernel_lib_path: []const u8) !*GPUContext {
        const self = allocator.create(GPUContext) catch return GPUError.MemoryAllocationFailed;
        errdefer allocator.destroy(self);

        var kernel_lib: ?std.DynLib = null;
        errdefer {
            if (kernel_lib) |*lib| {
                lib.close();
            }
        }

        if (kernel_lib_path.len > 0) {
            kernel_lib = std.DynLib.open(kernel_lib_path) catch return GPUError.ContextInitFailed;
        }

        self.* = GPUContext{
            .handle = null,
            .config = null,
            .kernel_library = kernel_lib,
            .kernels = std.StringHashMap(GPUKernelInfo).init(allocator),
            .allocator = allocator,
            .initialized = false,
            .supports_unified_memory = false,
            .device_name = [_]u8{0} ** 256,
        };

        errdefer self.kernels.deinit();

        try self.createContext();

        if (self.kernel_library) |*lib| {
            try self.loadKernelSymbols(lib);
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.destroyContext();

        if (self.kernel_library) |*lib| {
            lib.close();
            self.kernel_library = null;
        }

        var iter = self.kernels.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.input_types);
        }

        self.kernels.deinit();
        self.allocator.destroy(self);
    }

    fn loadKernelSymbols(self: *Self, lib: *std.DynLib) !void {
        const register = lib.lookup(KernelRegisterFn, "gpu_register_kernels") orelse return GPUError.KernelNotFound;
        if (register(self) != 0) {
            return GPUError.DriverError;
        }
    }

    pub fn createContext(self: *Self) !void {
        if (self.initialized) {
            return;
        }

        self.handle = self;
        self.config = null;
        self.supports_unified_memory = false;

        const name = "host-managed-gpu-context";
        @memset(&self.device_name, 0);
        @memcpy(self.device_name[0..name.len], name[0..name.len]);

        self.initialized = true;
    }

    pub fn destroyContext(self: *Self) void {
        self.handle = null;
        self.config = null;
        self.initialized = false;
    }

    pub fn allocateArray(self: *Self, comptime T: type, count: usize) !GPUArray(T) {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        try ensureSupportedElementType(T);
        return GPUArray(T).initOwned(self.allocator, count);
    }

    pub fn freeArray(self: *Self, comptime T: type, arr: *GPUArray(T)) void {
        _ = self;
        arr.deinit();
    }

    pub fn copyToDevice(self: *Self, comptime T: type, arr: *GPUArray(T)) !void {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        try ensureSupportedElementType(T);

        if (arr.allocator == null) {
            arr.allocator = self.allocator;
        }

        const allocator = arr.allocator.?;

        if (arr.device_data.len != arr.data.len) {
            if (arr.owned_device and arr.device_data.len > 0) {
                allocator.free(arr.device_data);
            }

            arr.device_data = allocator.alloc(T, arr.data.len) catch return GPUError.OutOfGPUMemory;
            arr.owned_device = true;
        }

        if (arr.data.len > 0) {
            @memcpy(arr.device_data, arr.data);
            arr.device_ptr = @as(?*anyopaque, @ptrCast(arr.device_data.ptr));
        } else {
            arr.device_ptr = null;
        }
    }

    pub fn copyFromDevice(self: *Self, comptime T: type, arr: *GPUArray(T)) !void {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        try ensureSupportedElementType(T);

        if (arr.data.len != arr.device_data.len) {
            return GPUError.InvalidArgument;
        }

        if (arr.data.len > 0 and arr.device_ptr == null) {
            return GPUError.InvalidArgument;
        }

        if (arr.data.len > 0) {
            @memcpy(arr.data, arr.device_data);
        }
    }

    pub fn runKernel(
        self: *Self,
        kernel_name: []const u8,
        inputs: []const GPUValue,
        output_type: GPUValueType,
    ) !GPUValue {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        const info = self.kernels.get(kernel_name) orelse return GPUError.KernelNotFound;

        if (info.input_types.len != inputs.len) {
            return GPUError.InvalidArgument;
        }

        for (inputs, 0..) |input, index| {
            if (input.getType() != info.input_types[index]) {
                return GPUError.InvalidArgument;
            }
        }

        if (info.output_type != output_type) {
            return GPUError.InvalidArgument;
        }

        var result = info.kernel_fn(self, inputs, self.allocator) catch return GPUError.ExecutionFailed;

        if (result.getType() != output_type) {
            result.deinit();
            return GPUError.ExecutionFailed;
        }

        return result;
    }

    pub fn synchronize(self: *Self) !void {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }
    }

    pub fn registerKernel(
        self: *Self,
        name: []const u8,
        input_types: []const GPUValueType,
        output_type: GPUValueType,
        kernel_fn: GPUKernelFn,
    ) !void {
        if (name.len == 0) {
            return GPUError.InvalidArgument;
        }

        const name_copy = self.allocator.dupe(u8, name) catch return GPUError.MemoryAllocationFailed;
        errdefer self.allocator.free(name_copy);

        const input_types_copy = self.allocator.dupe(GPUValueType, input_types) catch return GPUError.MemoryAllocationFailed;
        errdefer self.allocator.free(input_types_copy);

        const info = GPUKernelInfo{
            .name = name_copy,
            .input_types = input_types_copy,
            .output_type = output_type,
            .kernel_fn = kernel_fn,
        };

        if (try self.kernels.fetchPut(name_copy, info)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value.input_types);
        }
    }

    pub fn getKernel(self: *Self, name: []const u8) ?GPUKernelInfo {
        return self.kernels.get(name);
    }

    pub fn hasKernel(self: *Self, name: []const u8) bool {
        return self.kernels.contains(name);
    }

    pub fn getDeviceName(self: *Self) []const u8 {
        const sentinel = std.mem.indexOfScalar(u8, &self.device_name, 0) orelse self.device_name.len;
        return self.device_name[0..sentinel];
    }

    pub fn isInitialized(self: *Self) bool {
        return self.initialized;
    }

    pub fn supportsUnifiedMemory(self: *Self) bool {
        return self.supports_unified_memory;
    }
};

pub const ComputeContext = struct {
    gpu_ctx: *GPUContext,
    transaction_id: u64,
    input_values: std.ArrayList(GPUValue),
    output_values: std.ArrayList(GPUValue),
    state: ComputeState,
    allocator: std.mem.Allocator,

    pub const ComputeState = enum(u8) {
        idle,
        preparing,
        prepared,
        executing,
        executed,
        synchronizing,
        committed,
        failed,
    };

    pub fn init(allocator: std.mem.Allocator, gpu_ctx: *GPUContext, tx_id: u64) !ComputeContext {
        if (!gpu_ctx.isInitialized()) {
            return GPUError.InvalidContext;
        }

        return ComputeContext{
            .gpu_ctx = gpu_ctx,
            .transaction_id = tx_id,
            .input_values = std.ArrayList(GPUValue).init(allocator),
            .output_values = std.ArrayList(GPUValue).init(allocator),
            .state = .idle,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ComputeContext) void {
        for (self.input_values.items) |*value| {
            value.deinit();
        }

        for (self.output_values.items) |*value| {
            value.deinit();
        }

        self.input_values.deinit();
        self.output_values.deinit();
        self.state = .failed;
    }

    pub fn prepareInput(self: *ComputeContext, comptime T: type, data: []const T) !GPUArray(T) {
        if (self.state != .idle and self.state != .prepared) {
            self.state = .failed;
            return GPUError.InvalidArgument;
        }

        self.state = .preparing;

        var arr = self.gpu_ctx.allocateArray(T, data.len) catch |err| {
            self.state = .failed;
            return err;
        };

        if (data.len > 0) {
            @memcpy(arr.data, data);
        }

        self.gpu_ctx.copyToDevice(T, &arr) catch |err| {
            arr.deinit();
            self.state = .failed;
            return err;
        };

        const value = valueFromArray(T, arr) catch |err| {
            arr.deinit();
            self.state = .failed;
            return err;
        };

        self.input_values.append(value) catch |err| {
            arr.deinit();
            self.state = .failed;
            return err;
        };

        self.state = .prepared;
        return arr.borrow();
    }

    pub fn execute(self: *ComputeContext, kernel_name: []const u8, output_type: GPUValueType) !GPUValue {
        if (self.state != .prepared and self.state != .idle) {
            self.state = .failed;
            return GPUError.InvalidArgument;
        }

        self.state = .executing;

        var result = self.gpu_ctx.runKernel(kernel_name, self.input_values.items, output_type) catch |err| {
            self.state = .failed;
            return err;
        };

        const view = result.borrow();

        self.output_values.append(result) catch |err| {
            result.deinit();
            self.state = .failed;
            return err;
        };

        self.state = .executed;
        return view;
    }

    pub fn commit(self: *ComputeContext) !void {
        if (self.state != .executed and self.state != .prepared and self.state != .idle) {
            self.state = .failed;
            return GPUError.InvalidArgument;
        }

        self.state = .synchronizing;

        self.gpu_ctx.synchronize() catch |err| {
            self.state = .failed;
            return err;
        };

        self.state = .committed;
    }

    pub fn abort(self: *ComputeContext) void {
        if (self.state == .committed) {
            return;
        }

        for (self.input_values.items) |*value| {
            value.deinit();
        }

        for (self.output_values.items) |*value| {
            value.deinit();
        }

        self.input_values.clearRetainingCapacity();
        self.output_values.clearRetainingCapacity();
        self.state = .failed;
    }

    pub fn getState(self: *const ComputeContext) ComputeState {
        return self.state;
    }
};

pub const FutharkInterface = struct {
    allocator: std.mem.Allocator,
    context: ?*anyopaque,
    config: ?*anyopaque,
    unified_memory: bool,
    initialized: bool,

    const ArrayHeader = struct {
        allocator: std.mem.Allocator,
        bytes: []u8,
        element_size: usize,
        rank: u8,
        dim0: usize,
        dim1: usize,
    };

    pub fn init(allocator: std.mem.Allocator) FutharkInterface {
        return FutharkInterface{
            .allocator = allocator,
            .context = null,
            .config = null,
            .unified_memory = false,
            .initialized = false,
        };
    }

    pub fn deinit(self: *FutharkInterface) void {
        self.destroyContext();
    }

    pub fn createContext(self: *FutharkInterface) !void {
        if (self.initialized) {
            return;
        }

        self.context = self;
        self.config = self;
        self.initialized = true;
    }

    pub fn destroyContext(self: *FutharkInterface) void {
        self.context = null;
        self.config = null;
        self.initialized = false;
    }

    pub fn newArray1D(self: *FutharkInterface, comptime T: type, data: []const T) !?*anyopaque {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        try ensureSupportedElementType(T);

        const header = self.allocator.create(ArrayHeader) catch return GPUError.MemoryAllocationFailed;
        errdefer self.allocator.destroy(header);

        const source_bytes = std.mem.sliceAsBytes(data);
        const bytes = self.allocator.alloc(u8, source_bytes.len) catch return GPUError.MemoryAllocationFailed;
        errdefer self.allocator.free(bytes);

        if (source_bytes.len > 0) {
            @memcpy(bytes, source_bytes);
        }

        header.* = ArrayHeader{
            .allocator = self.allocator,
            .bytes = bytes,
            .element_size = @sizeOf(T),
            .rank = 1,
            .dim0 = data.len,
            .dim1 = 1,
        };

        return @as(?*anyopaque, @ptrCast(header));
    }

    pub fn newArray2D(self: *FutharkInterface, comptime T: type, data: []const T, dim0: usize, dim1: usize) !?*anyopaque {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        try ensureSupportedElementType(T);

        if (dim1 != 0 and dim0 > std.math.maxInt(usize) / dim1) {
            return GPUError.InvalidArgument;
        }

        if (data.len != dim0 * dim1) {
            return GPUError.InvalidArgument;
        }

        const header = self.allocator.create(ArrayHeader) catch return GPUError.MemoryAllocationFailed;
        errdefer self.allocator.destroy(header);

        const source_bytes = std.mem.sliceAsBytes(data);
        const bytes = self.allocator.alloc(u8, source_bytes.len) catch return GPUError.MemoryAllocationFailed;
        errdefer self.allocator.free(bytes);

        if (source_bytes.len > 0) {
            @memcpy(bytes, source_bytes);
        }

        header.* = ArrayHeader{
            .allocator = self.allocator,
            .bytes = bytes,
            .element_size = @sizeOf(T),
            .rank = 2,
            .dim0 = dim0,
            .dim1 = dim1,
        };

        return @as(?*anyopaque, @ptrCast(header));
    }

    pub fn values1D(self: *FutharkInterface, comptime T: type, arr: *anyopaque, out: []T) !void {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }

        try ensureSupportedElementType(T);

        const header: *ArrayHeader = @ptrCast(@alignCast(arr));

        if (header.rank != 1) {
            return GPUError.InvalidArgument;
        }

        if (header.element_size != @sizeOf(T)) {
            return GPUError.InvalidArgument;
        }

        if (out.len != header.dim0) {
            return GPUError.InvalidArgument;
        }

        const destination_bytes = std.mem.sliceAsBytes(out);

        if (destination_bytes.len != header.bytes.len) {
            return GPUError.InvalidArgument;
        }

        if (destination_bytes.len > 0) {
            @memcpy(destination_bytes, header.bytes);
        }
    }

    pub fn freeArray(self: *FutharkInterface, arr: *anyopaque) void {
        _ = self;

        const header: *ArrayHeader = @ptrCast(@alignCast(arr));
        header.allocator.free(header.bytes);
        header.allocator.destroy(header);
    }

    pub fn sync(self: *FutharkInterface) !void {
        if (!self.initialized) {
            return GPUError.InvalidContext;
        }
    }

    pub fn setUnifiedMemory(self: *FutharkInterface, enabled: bool) void {
        self.unified_memory = enabled;
    }
};

fn ensureSupportedElementType(comptime T: type) !void {
    if (T != i32 and T != i64 and T != f32 and T != f64) {
        return GPUError.UnsupportedType;
    }
}

fn arrayValueTypeFromElementType(comptime T: type) !GPUValueType {
    if (T == i32) {
        return .array_int32;
    }

    if (T == i64) {
        return .array_int64;
    }

    if (T == f32) {
        return .array_float32;
    }

    if (T == f64) {
        return .array_float64;
    }

    return GPUError.UnsupportedType;
}

fn valueFromArray(comptime T: type, arr: GPUArray(T)) !GPUValue {
    _ = try arrayValueTypeFromElementType(T);

    if (T == i32) {
        return GPUValue{ .array_int32 = @as(GPUArray(i32), arr) };
    }

    if (T == i64) {
        return GPUValue{ .array_int64 = @as(GPUArray(i64), arr) };
    }

    if (T == f32) {
        return GPUValue{ .array_float32 = @as(GPUArray(f32), arr) };
    }

    if (T == f64) {
        return GPUValue{ .array_float64 = @as(GPUArray(f64), arr) };
    }

    return GPUError.UnsupportedType;
}

fn testSumI32Kernel(ctx: *GPUContext, inputs: []const GPUValue, allocator: std.mem.Allocator) anyerror!GPUValue {
    _ = ctx;
    _ = allocator;

    if (inputs.len != 1) {
        return GPUError.InvalidArgument;
    }

    const arr = switch (inputs[0]) {
        .array_int32 => |value| value,
        else => return GPUError.InvalidArgument,
    };

    var total: i64 = 0;

    for (arr.device_data) |value| {
        total += value;
    }

    return GPUValue{ .int64 = total };
}

fn testIdentityI32Kernel(ctx: *GPUContext, inputs: []const GPUValue, allocator: std.mem.Allocator) anyerror!GPUValue {
    _ = allocator;

    if (inputs.len != 1) {
        return GPUError.InvalidArgument;
    }

    const input = switch (inputs[0]) {
        .array_int32 => |value| value,
        else => return GPUError.InvalidArgument,
    };

    var output = try ctx.allocateArray(i32, input.device_data.len);
    errdefer output.deinit();

    if (input.device_data.len > 0) {
        @memcpy(output.device_data, input.device_data);
        @memcpy(output.data, input.device_data);
        output.device_ptr = @as(?*anyopaque, @ptrCast(output.device_data.ptr));
    }

    return GPUValue{ .array_int32 = output };
}

test "gpu context initialization without dynamic library" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var gpu_ctx = try GPUContext.init(alloc, "");
    defer gpu_ctx.deinit();

    try testing.expect(gpu_ctx.isInitialized());
    try testing.expectEqualStrings("host-managed-gpu-context", gpu_ctx.getDeviceName());
}

test "gpu context initialization fails for missing dynamic library" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    try testing.expectError(GPUError.ContextInitFailed, GPUContext.init(alloc, "/nonexistent.so"));
}

test "gpu value types" {
    const testing = std.testing;

    var val: GPUValue = GPUValue{ .int32 = 42 };
    try testing.expectEqual(GPUValueType.int32, val.getType());

    val = GPUValue{ .float64 = 3.14159 };
    try testing.expectEqual(GPUValueType.float64, val.getType());
}

test "gpu array operations" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var gpu_ctx = try GPUContext.init(alloc, "");
    defer gpu_ctx.deinit();

    var arr = try gpu_ctx.allocateArray(i32, 10);
    defer gpu_ctx.freeArray(i32, &arr);

    try testing.expectEqual(@as(usize, 10), arr.len());

    for (arr.data, 0..) |*item, index| {
        item.* = @intCast(index);
    }

    try gpu_ctx.copyToDevice(i32, &arr);

    for (arr.data) |*item| {
        item.* = 0;
    }

    try gpu_ctx.copyFromDevice(i32, &arr);

    for (arr.data, 0..) |item, index| {
        try testing.expectEqual(@as(i32, @intCast(index)), item);
    }
}

test "kernel registration and execution" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var gpu_ctx = try GPUContext.init(alloc, "");
    defer gpu_ctx.deinit();

    const input_types = [_]GPUValueType{.array_int32};
    try gpu_ctx.registerKernel("sum_i32", &input_types, .int64, testSumI32Kernel);

    var arr = try gpu_ctx.allocateArray(i32, 4);
    defer arr.deinit();

    arr.data[0] = 1;
    arr.data[1] = 2;
    arr.data[2] = 3;
    arr.data[3] = 4;

    try gpu_ctx.copyToDevice(i32, &arr);

    var input_value = GPUValue{ .array_int32 = arr.borrow() };
    const inputs = [_]GPUValue{input_value};

    var result = try gpu_ctx.runKernel("sum_i32", &inputs, .int64);
    defer result.deinit();

    try testing.expectEqual(GPUValueType.int64, result.getType());

    switch (result) {
        .int64 => |value| try testing.expectEqual(@as(i64, 10), value),
        else => return error.TestUnexpectedResult,
    }

    input_value.deinit();
}

test "kernel registration replacement" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var gpu_ctx = try GPUContext.init(alloc, "");
    defer gpu_ctx.deinit();

    const input_types = [_]GPUValueType{.array_int32};
    try gpu_ctx.registerKernel("identity_i32", &input_types, .array_int32, testIdentityI32Kernel);
    try gpu_ctx.registerKernel("identity_i32", &input_types, .array_int32, testIdentityI32Kernel);

    try testing.expect(gpu_ctx.hasKernel("identity_i32"));
    try testing.expect(gpu_ctx.getKernel("identity_i32") != null);
}

test "compute context lifecycle" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var gpu_ctx = try GPUContext.init(alloc, "");
    defer gpu_ctx.deinit();

    const input_types = [_]GPUValueType{.array_int32};
    try gpu_ctx.registerKernel("sum_i32", &input_types, .int64, testSumI32Kernel);

    var compute_ctx = try ComputeContext.init(alloc, gpu_ctx, 123);
    defer compute_ctx.deinit();

    const data = [_]i32{ 5, 6, 7 };
    const prepared = try compute_ctx.prepareInput(i32, &data);
    try testing.expectEqual(@as(usize, 3), prepared.len());
    try testing.expectEqual(ComputeContext.ComputeState.prepared, compute_ctx.getState());

    var result = try compute_ctx.execute("sum_i32", .int64);
    defer result.deinit();

    switch (result) {
        .int64 => |value| try testing.expectEqual(@as(i64, 18), value),
        else => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(ComputeContext.ComputeState.executed, compute_ctx.getState());

    try compute_ctx.commit();
    try testing.expectEqual(ComputeContext.ComputeState.committed, compute_ctx.getState());
}

test "futhark interface arrays" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var interface = FutharkInterface.init(alloc);
    defer interface.deinit();

    try interface.createContext();
    interface.setUnifiedMemory(true);

    const input = [_]i32{ 1, 2, 3, 4 };
    const opaque_array = (try interface.newArray1D(i32, &input)) orelse return error.TestUnexpectedResult;
    defer interface.freeArray(opaque_array);

    var output = [_]i32{ 0, 0, 0, 0 };
    try interface.values1D(i32, opaque_array, &output);

    try testing.expectEqualSlices(i32, &input, &output);
    try interface.sync();
}

test "futhark interface rejects invalid 2d dimensions" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var interface = FutharkInterface.init(alloc);
    defer interface.deinit();

    try interface.createContext();

    const input = [_]i32{ 1, 2, 3 };

    try testing.expectError(GPUError.InvalidArgument, interface.newArray2D(i32, &input, 2, 2));
}
