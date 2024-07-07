const std = @import("std");
const testing = std.testing;
const Crc32 = std.hash.crc.Crc32;
const Allocator = std.mem.Allocator;

pub const ChunkType = struct {
    const ChunkTypeError = error{InvalidChunkType};

    bytes: [4]u8,

    pub fn init(bytes: [4]u8) ChunkTypeError!ChunkType {
        var chunk_type: ChunkType = undefined;

        for (bytes, 0..) |byte, i| {
            if (!std.ascii.isAlphabetic(byte))
                return error.InvalidChunkType;

            chunk_type.bytes[i] = byte;
        }

        return chunk_type;
    }

    pub fn is_valid(self: ChunkType) bool {
        if (!self.is_reserved_bit_valid())
            return false;

        for (self.bytes) |byte|
            if (!std.ascii.isAlphabetic(byte))
                return false;

        return true;
    }

    pub fn is_critical(self: ChunkType) bool {
        return self.bytes[0] >> 5 & 1 == 0;
    }

    pub fn is_public(self: ChunkType) bool {
        return self.bytes[1] >> 5 & 1 == 0;
    }

    pub fn is_reserved_bit_valid(self: ChunkType) bool {
        return self.bytes[2] >> 5 & 1 == 0;
    }

    pub fn is_safe_to_copy(self: ChunkType) bool {
        return self.bytes[3] >> 5 & 1 == 1;
    }

    pub fn format(
        self: ChunkType,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try writer.print("\"{s}\" ({s}, {s}, {s})", .{
            self.bytes,
            if (self.is_critical()) "critical" else "ancillary",
            if (self.is_public()) "public" else "private",
            if (self.is_safe_to_copy()) "safe to copy" else "unsafe to copy",
        });
    }
};

pub const Chunk = struct {
    const ChunkError = error{
        TruncatedChunk,
        InvalidChunkLength,
        InvalidCrc,
    } || ChunkType.ChunkTypeError;
    const ChunkStreamError = ChunkError || Allocator.Error || std.io.AnyReader.Error || error{NoData};

    length: u32,
    chunk_type: ChunkType,
    data: [*]const u8,

    /// initialise chunk without copying any data.
    pub fn init(chunk_type: ChunkType, data: []const u8) ChunkError!Chunk {
        if (data.len > 2 << 30)
            return ChunkError.TruncatedChunk;

        return .{
            .length = @truncate(data.len),
            .chunk_type = chunk_type,
            .data = data.ptr,
        };
    }

    /// read chunk from buffer without copying the chunk data.
    pub fn read(data: []u8) ChunkError!Chunk {
        var chunk: Chunk = undefined;

        chunk.length = std.mem.readInt(u32, data[0..4], .big);

        if (data.len < 4 * 3 + chunk.length)
            return ChunkError.TruncatedChunk;

        if (chunk.length > 2 << 30)
            return ChunkError.TruncatedChunk;

        chunk.chunk_type = try ChunkType.init(data[4..][0..4].*);
        chunk.data = data.ptr + 4 * 2; // redundant, but okay

        const crc32: u32 = std.mem.readInt(u32, data[4 * 2 + chunk.length ..][0..4], .big);
        if (crc32 != chunk.crc())
            return ChunkError.InvalidCrc;

        return chunk;
    }

    fn readStreamInner(reader: anytype, allocator: Allocator) ChunkStreamError!Chunk {
        var chunk: Chunk = undefined;

        chunk.length = reader.readInt(u32, .big) catch |err| return switch (@as(anyerror, @errorCast(err))) {
            error.EndOfStream => ChunkStreamError.NoData, // what if it's not?
            else => err,
        };

        if (chunk.length > 2 << 30)
            return ChunkError.TruncatedChunk;

        chunk.chunk_type = try ChunkType.init(try reader.readBytesNoEof(4));
        const data: []u8 = try allocator.alloc(u8, chunk.length);
        chunk.data = data.ptr;
        errdefer allocator.free(data);
        try reader.readNoEof(data);

        const crc32: u32 = try reader.readInt(u32, .big);
        if (crc32 != chunk.crc())
            return ChunkError.InvalidCrc;

        return chunk;
    }

    /// read chunk from stream, reading the chunk data to a buffer using `allocator`.
    /// the `data` field of the returned chunk should be deallocated after use.
    pub fn readStream(reader: anytype, allocator: Allocator) ChunkStreamError!Chunk {
        return readStreamInner(reader, allocator) catch |err| switch (err) {
            error.EndOfStream => ChunkStreamError.TruncatedChunk,
            else => err,
        };
    }

    /// calculate 32-bit CRC on chunk type and data fields.
    pub fn crc(chunk: Chunk) u32 {
        var crc32: Crc32 = Crc32.init();
        crc32.update(chunk.chunk_type.bytes[0..]);
        crc32.update(chunk.data[0..chunk.length]);
        return crc32.final();
    }

    pub fn format(
        self: Chunk,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("Chunk ({s}, {x})", .{
            self.chunk_type.bytes[0..],
            self.crc(),
        });

        // try writer.writeAll(" 0x");
        // try std.fmt.fmtSliceHexLower(self.data[0..self.length]).format(fmt, options, writer);
        try writer.writeAll(" \"");
        try std.fmt.fmtSliceEscapeLower(self.data[0..self.length]).format(fmt, options, writer);
        try writer.writeByte('"');
    }
};

pub fn ChunkIterator(comptime T: type) type {
    return struct {
        const Self = @This();

        reader: T,
        allocator: Allocator,

        pub fn next(self: Self) !?Chunk {
            return Chunk.readStream(self.reader, self.allocator) catch |err| switch (err) {
                Chunk.ChunkStreamError.NoData => null,
                else => err,
            };
        }
    };
}

pub const Png = struct {
    pub const STANDARD_HEADER: []const u8 = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a";
    const Chunks = std.ArrayList(Chunk);
    const PngError = error{ InvalidHeader, InvalidStartChunk, InvalidEndChunk, MissingChunks };
    const Self = @This();

    chunks: Chunks,

    pub fn init(allocator: Allocator) !Png {
        return .{ .chunks, try Chunks.initCapacity(allocator, 2) };
    }

    pub fn deinit(self: Self) void {
        self.chunks.deinit();
    }

    pub fn read(allocator: Allocator, reader: anytype) !Png {
        var self: Png = try Png.init(allocator);
        errdefer self.deinit();

        var header: [STANDARD_HEADER.len]u8 = undefined;
        try reader.readNoEof(header[0..]);
        if (!std.mem.eql(u8, STANDARD_HEADER, header[0..]))
            return PngError.InvalidHeader;

        const Iter = ChunkIterator(@TypeOf(reader));
        var iter: Iter = .{
            .reader = reader,
            .allocator = allocator,
        };

        if (try iter.next()) |chunk| {
            if (!std.mem.eql(u8, chunk.chunk_type.bytes, "IHDR")) return PngError.InvalidStartChunk;
            try self.chunks.append(chunk);
        } else return PngError.MissingChunks;

        while (try iter.next()) |chunk| try self.chunks.append(chunk);

        const len: usize = self.chunks.items.len;
        if (len < 2) return PngError.MissingChunks;
        if (!std.mem.eql(u8, self.chunks.items[len - 1].chunk_type.bytes, "IEND")) return PngError.InvalidEndChunk;

        return self;
    }
};

test "chunk_type_type_from_bytes" {
    const expected = [4]u8{ 82, 117, 83, 116 };
    const actual = try ChunkType.init([4]u8{ 82, 117, 83, 116 });

    try testing.expectEqualSlices(u8, &expected, &actual.bytes);
}

test "chunk_type_type_from_str" {
    const expected = try ChunkType.init([4]u8{ 82, 117, 83, 116 });
    const actual = try ChunkType.init("RuSt".*);
    try testing.expectEqualSlices(u8, &expected.bytes, &actual.bytes);
}

test "chunk_type_type_is_critical" {
    const chunk_type = try ChunkType.init("RuSt".*);
    try testing.expect(chunk_type.is_critical());
}

test "chunk_type_type_is_not_critical" {
    const chunk_type = try ChunkType.init("ruSt".*);
    try testing.expect(!chunk_type.is_critical());
}

test "chunk_type_type_is_public" {
    const chunk_type = try ChunkType.init("RUSt".*);
    try testing.expect(chunk_type.is_public());
}

test "chunk_type_type_is_not_public" {
    const chunk_type = try ChunkType.init("RuSt".*);
    try testing.expect(!chunk_type.is_public());
}

test "chunk_type_type_is_reserved_bit_valid" {
    const chunk_type = try ChunkType.init("RuSt".*);
    try testing.expect(chunk_type.is_reserved_bit_valid());
}

test "chunk_type_type_is_reserved_bit_invalid" {
    const chunk_type = try ChunkType.init("Rust".*);
    try testing.expect(!chunk_type.is_reserved_bit_valid());
}

test "chunk_type_type_is_safe_to_copy" {
    const chunk_type = try ChunkType.init("RuSt".*);
    try testing.expect(chunk_type.is_safe_to_copy());
}

test "chunk_type_type_is_unsafe_to_copy" {
    const chunk_type = try ChunkType.init("RuST".*);
    try testing.expect(!chunk_type.is_safe_to_copy());
}

test "valid_chunk_type_is_valid" {
    const chunk_type = try ChunkType.init("RuSt".*);
    try testing.expect(chunk_type.is_valid());
}

test "invalid_chunk_type_is_valid" {
    {
        const chunk_type: ?ChunkType = ChunkType.init("Rust".*) catch null;
        try testing.expect(chunk_type != null and !chunk_type.?.is_valid());
    }

    {
        const chunk_type: ?ChunkType = ChunkType.init("Ru1t".*) catch null;
        try testing.expect(chunk_type == null);
    }
}

test "chunk_type_type_string" {
    const chunk_type = try ChunkType.init("RuSt".*);
    try testing.expectEqualSlices(u8, &chunk_type.bytes, "RuSt");
}

fn chunk_buffer(
    chunk_type: []const u8,
    data: []const u8,
    data_length: u32,
    crc32: u32,
    alloc: Allocator,
) ![]u8 {
    const buffer: []u8 = try alloc.alloc(u8, 4 * 3 + data_length);
    std.mem.writeInt(u32, buffer[4 * 0 ..][0..4], data_length, .big);
    std.mem.copyForwards(u8, buffer[4 * 1 ..], chunk_type);
    std.mem.copyForwards(u8, buffer[4 * 2 ..], data);
    std.mem.writeInt(u32, buffer[4 * 2 + data_length ..][0..4], crc32, .big);
    return buffer;
}

test "new_chunk" {
    const chunk_type: ChunkType = try ChunkType.init("RuSt".*);
    const data: []const u8 = "This is where your secret message will be!";
    const chunk: Chunk = try Chunk.init(chunk_type, data);
    try testing.expectEqual(42, chunk.length);
    try testing.expectEqual(2882656334, chunk.crc());
}

test "chunk_crc" {
    const alloc = std.testing.allocator;
    const chunk_type: []const u8 = "RuSt";
    const message: []const u8 = "This is where your secret message will be!";
    const data_length: u32 = @truncate(message.len);
    const crc32: u32 = 2882656334;

    const buffer: []u8 = try chunk_buffer(
        chunk_type,
        message,
        data_length,
        crc32,
        alloc,
    );
    defer alloc.free(buffer);

    var fbs = std.io.fixedBufferStream(buffer);
    const reader = fbs.reader();

    var chunks: [2]Chunk = undefined;
    chunks[0] = try Chunk.read(buffer);
    chunks[1] = try Chunk.readStream(reader, alloc);
    defer alloc.free(chunks[1].data[0..chunks[1].length]);

    for (chunks) |chunk| {
        try testing.expectEqual(42, chunk.length);
        try testing.expectEqualSlices(u8, "RuSt", chunk.chunk_type.bytes[0..]);
        try testing.expectEqual(2882656334, chunk.crc());
        try testing.expectEqualSlices(u8, "This is where your secret message will be!", chunk.data[0..chunk.length]);

        std.debug.print("{}\n", .{chunk});
    }
}

test "invalid_chunk" {
    const alloc = std.testing.allocator;
    const chunk_type: []const u8 = "RuSt";
    const message: []const u8 = "This is where your secret message will be!";
    const data_length: u32 = @truncate(message.len);
    const crc32: u32 = 2882656333; // this changed

    const buffer: []u8 = try chunk_buffer(
        chunk_type,
        message,
        data_length,
        crc32,
        alloc,
    );
    defer alloc.free(buffer);

    try testing.expectError(Chunk.ChunkError.InvalidCrc, Chunk.read(buffer));
}
