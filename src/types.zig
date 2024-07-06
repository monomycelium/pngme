const std = @import("std");
const testing = std.testing;

const ChunkType = struct {
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

        try writer.print("'{s}' ([4]u8{s}, {s}, {s})", .{
            self.bytes,
            if (self.is_critical()) "critical" else "ancillary",
            if (self.is_public()) "public" else "private",
            if (self.is_safe_to_copy()) "safe to copy" else "unsafe to copy",
        });
    }
};

const Chunk = struct {
    const ChunkError = error{
        TruncatedChunk,
        InvalidChunkLength,
        InvalidCksum,
    } || ChunkType.ChunkTypeError;

    length: u32,
    chunk_type: ChunkType,
    data: [*]const u8,

    pub fn init(chunk_type: ChunkType, data: []u8) ChunkError!Chunk {
        if (data.len > 2 << 30)
            return ChunkError.TruncatedChunk;

        return .{
            .length = data.len,
            .chunk_type = chunk_type,
            .data = data.ptr,
        };
    }

    pub fn read(data: []u8) ChunkError!Chunk {
        var chunk: Chunk = undefined;

        chunk.length = std.mem.readInt(u32, data[0..4], .big);

        if (data.len < 4 * 3 + chunk.length)
            return ChunkError.TruncatedChunk;

        if (chunk.length > 2 << 30)
            return ChunkError.TruncatedChunk;

        chunk.chunk_type = try ChunkType.init(data[4..][0..4].*);
        chunk.data = data[4 * 2 ..][0..chunk.length].ptr; // redundant, but okay

        const crc32: u32 = std.mem.readInt(u32, data[4 * 2 + chunk.length ..][0..4], .big);
        std.debug.print("{x}:{x}\n", .{ crc32, chunk.crc() });
        if (crc32 != chunk.crc())
            return ChunkError.InvalidCksum;

        return chunk;
    }

    pub fn readStream(reader: anytype, allocator: std.mem.Allocator) !Chunk {
        var chunk: Chunk = undefined;

        chunk.length = try reader.readInt(u32, .big);

        if (chunk.length > 2 << 30)
            return ChunkError.TruncatedChunk;

        chunk.chunk_type = try ChunkType.init(try reader.readBytesNoEof(4));
        const data: []u8 = try allocator.alloc(u8, chunk.length);
        chunk.data = data.ptr;
        errdefer allocator.free(data);
        try reader.readNoEof(data);

        const crc32: u32 = try reader.readInt(u32, .big);
        std.debug.print("{x}:{x}\n", .{ crc32, chunk.crc() });
        if (crc32 != chunk.crc())
            return ChunkError.InvalidCksum;

        return chunk;
    }

    pub fn crc(chunk: Chunk) u32 { // TODO: fix hash to include chunk type. But how?
        return std.hash.crc.Crc32Cksum.hash(chunk.data[0..chunk.length]);
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

fn testing_chunk() !Chunk {
    const alloc = std.testing.allocator;

    const chunk_type: []const u8 = "RuSt";
    const message: []const u8 = "This is where your secret message will be!";
    const data_length: u32 = @truncate(message.len);
    const crc32: u32 = 2882656334;

    const buffer: []u8 = try alloc.alloc(u8, 4 * 3 + data_length);
    std.mem.writeInt(u32, buffer[4 * 0 ..][0..4], data_length, .big);
    std.mem.copyForwards(u8, buffer[4 * 1 ..], chunk_type);
    std.mem.copyForwards(u8, buffer[4 * 2 ..], message);
    std.mem.writeInt(u32, buffer[4 * 2 + data_length ..][0..4], crc32, .big);
    defer alloc.free(buffer);

    var fbs = std.io.fixedBufferStream(buffer);
    const reader = fbs.reader();

    const chunk_two: Chunk = try Chunk.readStream(reader, alloc);
    const chunk_one: Chunk = try Chunk.read(buffer);
    defer alloc.free(chunk_two.data[0..chunk_two.length]);

    try testing.expectEqualDeep(chunk_one, chunk_two);
    return chunk_one;
}

test "chunk" {
    _ = try testing_chunk();
}
