const pngme = @import("pngme");
const std = @import("std");
const testing = std.testing;
const ChunkType = pngme.ChunkType;
const Chunk = pngme.Chunk;
const Png = pngme.Png;
const Allocator = std.mem.Allocator;

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

        const buf: []u8 = try alloc.alloc(u8, buffer.len);
        defer alloc.free(buf);
        const new: []u8 = try chunk.write(buf);
        try testing.expectEqualSlices(u8, buffer, new);

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

fn chunk_from_strings(chunk_type: [4]u8, data: []const u8) Chunk {
    return .{
        .chunk_type = .{ .bytes = chunk_type },
        .data = data.ptr,
        .length = @truncate(data.len),
    };
}

const chunk_array = [_]Chunk{
    chunk_from_strings("IHDR".*, "I am the first chunk"),
    chunk_from_strings("FrSt".*, "I am the first chunk"),
    chunk_from_strings("miDl".*, "I am another chunk"),
    chunk_from_strings("LASt".*, "I am the second-last chunk"),
    chunk_from_strings("LASt".*, "I am the last chunk"),
    chunk_from_strings("IEND".*, "I am the first chunk"),
};

fn testing_chunks() ![]Chunk {
    const List = std.ArrayList(Chunk);
    var list = try List.initCapacity(testing.allocator, chunk_array.len);
    list.appendSliceAssumeCapacity(chunk_array[0..]);
    return try list.toOwnedSlice();
}

test "from_chunks" {
    const chunks = try testing_chunks();
    // defer testing.allocator.free(chunks); // will be deinitialised when calling png.deinit();

    var png = Png.initFromChunks(testing.allocator, chunks);
    defer png.deinit();
    try testing.expectEqual(png.chunks.items.len, chunk_array.len);

    var size: usize = Png.STANDARD_HEADER.len;
    for (png.chunks.items) |chunk| size += chunk.length + 4 * 3;

    var buffers: [2][]u8 = undefined;
    for (&buffers) |*b| b.* = try testing.allocator.alloc(u8, size);
    defer for (&buffers) |b| testing.allocator.free(b);
    var fbs = std.io.fixedBufferStream(buffers[1]);
    const writer = fbs.writer();

    const out = try png.write(buffers[0]);
    try png.writeStream(writer);

    try testing.expectEqualSlices(u8, out, buffers[1]);

    var map = try png.chunksByType();
    defer Png.deinitMap(&map);

    const list = map.get("LASt".*).?;
    for (list.items, 0..) |c, i|
        try testing.expectEqual(c.crc(), chunks[3 + i].crc());

    fbs.seekTo(0) catch unreachable;
    const reader = fbs.reader();
    const new_png = try Png.readStream(testing.allocator, reader);
    defer new_png.deinitAllocatedChunks();

    for (new_png.chunks.items, 0..) |chunk, i|
        try testing.expectEqual(chunk.crc(), png.chunks.items[i].crc());

    const chunk = chunk_from_strings("HELL".*, "lorem ipsum");
    try png.appendChunk(chunk);

    try testing.expectEqual(chunks.len + 1, png.chunks.items.len);
    try testing.expectEqualSlices(u8, "IEND", png.chunks.getLast().chunk_type.bytes[0..]);
    try testing.expectEqual(chunk.crc(), png.chunks.items[png.chunks.items.len - 2].crc());
}

test "invalid_header" {
    var size: usize = Png.STANDARD_HEADER.len;
    for (chunk_array) |chunk| size += chunk.length + 4 * 3;

    const buffer: []u8 = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(buffer);
    var fbs = std.io.fixedBufferStream(buffer);

    const writer = fbs.writer();
    try writer.writeAll(&[_]u8{ 13, 80, 78, 71, 13, 10, 26, 10 });
    for (chunk_array) |chunk| try chunk.writeStream(writer);

    fbs.seekTo(0) catch unreachable;
    const reader = fbs.reader();

    try testing.expectError(Png.PngError.InvalidHeader, Png.readStream(testing.allocator, reader));
}

test "png_from_file" {
    const data = @embedFile("test.png");
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    const png = try Png.readStream(testing.allocator, reader);
    defer png.deinitAllocatedChunks();

    for (png.chunks.items) |chunk|
        std.debug.print("{}\n", .{chunk});

    const buffer: []u8 = try testing.allocator.alloc(u8, data.len);
    defer testing.allocator.free(buffer);
    var fbs_two = std.io.fixedBufferStream(buffer);
    const writer = fbs_two.writer();

    try png.writeStream(writer);
    try testing.expectEqualSlices(u8, data, buffer);
}
