const std = @import("std");
const testing = std.testing;

const Chunk = struct {
    const ChunkError = error{InvalidChunk};

    bytes: [4]u8,

    pub fn init(bytes: [4]u8) Chunk.ChunkError!Chunk {
        var chunk: Chunk = undefined;

        for (bytes, 0..) |byte, i| {
            if (!std.ascii.isAlphabetic(byte))
                return error.InvalidChunk;

            chunk.bytes[i] = byte;
        }

        return chunk;
    }

    pub fn is_valid(self: Chunk) bool {
        if (!self.is_reserved_bit_valid())
            return false;

        for (self.bytes) |byte|
            if (!std.ascii.isAlphabetic(byte))
                return false;

        return true;
    }

    pub fn is_critical(self: Chunk) bool {
        return self.bytes[0] >> 5 & 1 == 0;
    }

    pub fn is_public(self: Chunk) bool {
        return self.bytes[1] >> 5 & 1 == 0;
    }

    pub fn is_reserved_bit_valid(self: Chunk) bool {
        return self.bytes[2] >> 5 & 1 == 0;
    }

    pub fn is_safe_to_copy(self: Chunk) bool {
        return self.bytes[3] >> 5 & 1 == 1;
    }

    pub fn format(
        self: Chunk,
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

test "chunk_type_from_bytes" {
    const expected = [4]u8{ 82, 117, 83, 116 };
    const actual = try Chunk.init([4]u8{ 82, 117, 83, 116 });

    try testing.expectEqualSlices(u8, &expected, &actual.bytes);
}

test "chunk_type_from_str" {
    const expected = try Chunk.init([4]u8{ 82, 117, 83, 116 });
    const actual = try Chunk.init("RuSt".*);
    try testing.expectEqualSlices(u8, &expected.bytes, &actual.bytes);
}

test "chunk_type_is_critical" {
    const chunk = try Chunk.init("RuSt".*);
    try testing.expect(chunk.is_critical());
}

test "chunk_type_is_not_critical" {
    const chunk = try Chunk.init("ruSt".*);
    try testing.expect(!chunk.is_critical());
}

test "chunk_type_is_public" {
    const chunk = try Chunk.init("RUSt".*);
    try testing.expect(chunk.is_public());
}

test "chunk_type_is_not_public" {
    const chunk = try Chunk.init("RuSt".*);
    try testing.expect(!chunk.is_public());
}

test "chunk_type_is_reserved_bit_valid" {
    const chunk = try Chunk.init("RuSt".*);
    try testing.expect(chunk.is_reserved_bit_valid());
}

test "chunk_type_is_reserved_bit_invalid" {
    const chunk = try Chunk.init("Rust".*);
    try testing.expect(!chunk.is_reserved_bit_valid());
}

test "chunk_type_is_safe_to_copy" {
    const chunk = try Chunk.init("RuSt".*);
    try testing.expect(chunk.is_safe_to_copy());
}

test "chunk_type_is_unsafe_to_copy" {
    const chunk = try Chunk.init("RuST".*);
    try testing.expect(!chunk.is_safe_to_copy());
}

test "valid_chunk_is_valid" {
    const chunk = try Chunk.init("RuSt".*);
    try testing.expect(chunk.is_valid());
}

test "invalid_chunk_is_valid" {
    {
        const chunk: ?Chunk = Chunk.init("Rust".*) catch null;
        try testing.expect(chunk != null and !chunk.?.is_valid());
    }

    {
        const chunk: ?Chunk = Chunk.init("Ru1t".*) catch null;
        try testing.expect(chunk == null);
    }
}

test "chunk_type_string" {
    const chunk = try Chunk.init("RuSt".*);
    try testing.expectEqualSlices(u8, &chunk.bytes, "RuSt");
}
