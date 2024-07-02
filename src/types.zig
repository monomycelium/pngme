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

        try writer.print("[4]u8{s} ([4]u8{s}, {s}, {s}, {s})", .{
            self.bytes,
            if (self.is_critical()) "critical" else "ancillary",
            if (self.is_public()) "public" else "private",
            if (self.is_safe_to_copy()) "safe to copy" else "unsafe to copy",
        });
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
