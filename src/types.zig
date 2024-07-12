const std = @import("std");
const Crc32 = std.hash.crc.Crc32;
const Allocator = std.mem.Allocator;

pub const ChunkType = struct {
    pub const ChunkTypeError = error{InvalidChunkType};

    pub const ChunkTypeContext = struct {
        const Self = @This();

        pub fn hash(self: Self, chunk_type: [4]u8) u32 {
            _ = self;
            return std.mem.readInt(u32, chunk_type[0..], .big);
        }

        pub fn eql(self: Self, a: [4]u8, b: [4]u8, b_index: usize) bool {
            _ = b_index;
            return self.hash(a) == self.hash(b);
        }
    };

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
    pub const ChunkError = error{
        TruncatedChunk,
        InvalidChunkLength,
        InvalidCrc,
    } || ChunkType.ChunkTypeError;
    pub const ChunkReadStreamError = ChunkError || Allocator.Error || std.io.AnyReader.Error || error{NoData};
    pub const ChunkWriteStreamError = std.io.AnyWriter.Error;
    pub const ChunkWriteError = error{Overflow};
    const Self = @This();

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

    /// deallocates chunk (where the data field must be allocated by `allocator`).
    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.data[0..self.length]);
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

    fn readStreamInner(reader: anytype, allocator: Allocator) ChunkReadStreamError!Chunk {
        var chunk: Chunk = undefined;

        chunk.length = reader.readInt(u32, .big) catch |err| return switch (@as(anyerror, @errorCast(err))) {
            error.EndOfStream => ChunkReadStreamError.NoData, // what if it's not?
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
    pub fn readStream(reader: anytype, allocator: Allocator) ChunkReadStreamError!Chunk {
        return readStreamInner(reader, allocator) catch |err| switch (err) {
            error.EndOfStream => ChunkReadStreamError.TruncatedChunk,
            else => err,
        };
    }

    /// write chunk to buffer.
    pub fn write(self: Chunk, buffer: []u8) ChunkWriteError![]u8 {
        if (buffer.len < self.length + 4 * 3)
            return ChunkWriteError.Overflow;

        std.mem.writeInt(u32, buffer[4 * 0 ..][0..4], self.length, .big);
        std.mem.copyForwards(u8, buffer[4 * 1 ..], self.chunk_type.bytes[0..]);
        std.mem.copyForwards(u8, buffer[4 * 2 ..], self.data[0..self.length]);
        std.mem.writeInt(u32, buffer[4 * 2 + self.length ..][0..4], self.crc(), .big);

        return buffer[0 .. self.length + 4 * 3];
    }

    /// write chunk to stream.
    pub fn writeStream(self: Chunk, writer: anytype) ChunkWriteStreamError!void {
        try writer.writeInt(u32, self.length, .big);
        try writer.writeAll(self.chunk_type.bytes[0..]);
        try writer.writeAll(self.data[0..self.length]);
        try writer.writeInt(u32, self.crc(), .big);
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
                Chunk.ChunkReadStreamError.NoData => null,
                else => err,
            };
        }
    };
}

pub const Png = struct { // TODO: add write functions!
    pub const STANDARD_HEADER: []const u8 = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a";
    const Self = @This();
    const Chunks = std.ArrayList(Chunk);
    pub const PngError = error{ InvalidHeader, InvalidStartChunk, InvalidEndChunk, MissingChunks };
    pub const PngModError = error{EmptyList} || Allocator.Error;
    pub const ChunkList = std.ArrayList(*Chunk);
    pub const Map = std.array_hash_map.ArrayHashMap([4]u8, ChunkList, ChunkType.ChunkTypeContext, true);

    chunks: Chunks,

    pub fn init(allocator: Allocator) Allocator.Error!Self {
        return .{ .chunks = try Chunks.initCapacity(allocator, 2) };
    }

    /// Initialise from existing slice of `chunks` allocated using `allocator`.
    pub fn initFromChunks(allocator: Allocator, chunks: []Chunk) Self {
        return .{ .chunks = .{
            .items = chunks,
            .capacity = chunks.len,
            .allocator = allocator,
        } };
    }

    /// Append a chunk before the IEND chunk. The `data` field of the chunk should be allocated using the same allocator as the one used for other chunks in the `chunks` field if using `deinitAllocatedChunks`.
    pub fn appendChunk(self: *Self, chunk: Chunk) PngModError!void {
        const new: *Chunk = try self.chunks.addOne();
        const last: *Chunk = @ptrCast(@as([*]Chunk, @ptrCast(new)) - 1);
        new.* = last.*;
        last.* = chunk;
    }

    /// Generate a hash map, where chunk type is the key and pointer to chunk is the value.
    pub fn chunksByType(self: Self) !Map {
        var map = Map.init(self.chunks.allocator);
        errdefer map.deinit();

        for (self.chunks.items) |*chunk| {
            const result = try map.getOrPut(chunk.chunk_type.bytes);

            if (!result.found_existing)
                result.value_ptr.* = try ChunkList.initCapacity(self.chunks.allocator, 1);

            try result.value_ptr.append(chunk);
        }

        return map;
    }

    pub fn deinitMap(map: *Map) void {
        var iter = map.iterator();
        while (iter.next()) |entry|
            entry.value_ptr.deinit();
        map.deinit();
    }

    pub fn deinit(self: Self) void {
        self.chunks.deinit();
    }

    // TODO: find better name
    /// deallocate every chunk and the arraylist (using the allocator from the list).
    pub fn deinitAllocatedChunks(self: Self) void {
        for (self.chunks.items) |chunk|
            chunk.deinit(self.chunks.allocator);

        self.deinit();
    }

    /// read PNG data from stream.
    pub fn readStream(allocator: Allocator, reader: anytype) !Png {
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
            if (!std.mem.eql(u8, chunk.chunk_type.bytes[0..], "IHDR")) return PngError.InvalidStartChunk;
            try self.chunks.append(chunk);
        } else return PngError.MissingChunks;

        while (try iter.next()) |chunk| try self.chunks.append(chunk);

        const len: usize = self.chunks.items.len;
        if (len < 2) return PngError.MissingChunks;
        if (!std.mem.eql(u8, self.chunks.items[len - 1].chunk_type.bytes[0..], "IEND")) return PngError.InvalidEndChunk;

        return self;
    }

    /// write PNG data to stream.
    pub fn writeStream(self: Self, writer: anytype) !void {
        try writer.writeAll(Self.STANDARD_HEADER);
        for (self.chunks.items) |chunk|
            try chunk.writeStream(writer);
    }

    /// write PNG data to buffer.
    pub fn write(self: Self, buffer: []u8) ![]u8 {
        std.mem.copyForwards(u8, buffer, Self.STANDARD_HEADER);
        var i: usize = Self.STANDARD_HEADER.len;

        for (self.chunks.items) |chunk| {
            const out = try chunk.write(buffer[i..]);
            i += out.len;
        }

        return buffer[0..i];
    }

    pub fn format(
        self: Png,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        for (self.chunks.items) |chunk|
            try writer.print("{}\n", .{chunk});
    }
};
