const std = @import("std");
const yazap = @import("yazap");

const App = yazap.App;
const Arg = yazap.Arg;
const pos = Arg.positional;

const pnglib = @import("pngme");

const Subcommand = enum(u8) {
    encode = 'e',
    decode = 'd',
    remove = 'r',
    chunks = 'c',

    /// Get count of minimum required arguments.
    fn count(subcmd: Subcommand) usize {
        return switch (subcmd) {
            .encode => 3,
            .decode => 2,
            .remove => 2,
            .chunks => 1,
        };
    }
};

const Command = struct {
    name: []const u8,
    desc: []const u8,
    args: []const Arg,
};

fn getPositional(map: *const yazap.arg_matches.ArgHashMap, key: []const u8) error{MissingArguments}![]const u8 {
    const x = map.get(key) orelse return error.MissingArguments;
    return x.single;
}

// TODO: can `matches` field of `arg_matches.MatchedSubCommand` be assumed not to be null?
// TODO: in `ArgHashMap`, can the tagged union be assumed to be `.single`?
const Parsed = struct { // `undefined` for unused fields
    const Self = @This();
    const TEMP_EXT = ".temp";

    alloc: std.mem.Allocator,
    input: std.fs.File,
    chunk_type: pnglib.ChunkType,
    data: ?std.fs.File,
    output: ?std.fs.File,
    /// Name of temporary file (only if editing in-place).
    /// The original file will be replaced with the temporary file.
    /// The name must be the name of the original file with `TEMP_EXT` appended.
    temp_name: ?[]const u8,
    subcmd: Subcommand,

    fn init(cmd: *const yazap.arg_matches.MatchedSubCommand, alloc: std.mem.Allocator) !Self {
        var self: Self = .{
            .input = undefined,
            .chunk_type = undefined,
            .data = null,
            .output = null,
            .temp_name = null,
            .alloc = alloc,
            .subcmd = @enumFromInt(cmd.name[0]),
        };
        const args: *const yazap.arg_matches.ArgHashMap = &cmd.matches.?.args;
        if (args.count() < self.subcmd.count()) return error.MissingArguments;

        const cwd = std.fs.cwd();

        const input_b = try getPositional(args, "INPUT");
        self.input = try cwd.openFile(input_b, .{ .mode = .read_only });
        errdefer self.input.close();

        if (self.subcmd == .chunks) return self;

        const ct_b = try getPositional(args, "TYPE");
        if (ct_b.len != 4) return error.InvalidChunkType;
        self.chunk_type = try pnglib.ChunkType.init(ct_b[0..4].*);
        if (!self.chunk_type.is_valid()) return error.InvalidChunkType;

        if (self.subcmd == .decode) return self;

        if (args.get("OUTPUT")) |output| {
            self.output = try cwd.createFile(output.single, .{ .read = false });
        } else {
            self.temp_name = try std.fmt.allocPrint(alloc, "{s}{s}", .{ input_b, TEMP_EXT });
            self.output = try cwd.createFile(self.temp_name.?, .{ .read = false, .exclusive = true });
        }
        errdefer self.output.?.close();
        errdefer if (self.temp_name) |t| alloc.free(t);

        if (self.subcmd == .remove) return self;

        const data_b = try getPositional(args, "DATA");
        self.data = try cwd.openFile(data_b, .{ .mode = .read_only });
        errdefer self.data.?.close();

        return self;
    }

    fn deinit(self: Self) void {
        self.input.close();
        if (self.data) |d| d.close();
        if (self.output) |o| o.close();
    }

    fn deinitWrite(self: *const Self) !void {
        self.deinit();

        if (self.temp_name) |name| {
            const cwd = std.fs.cwd();
            const old = name[0 .. name.len - TEMP_EXT.len];

            try cwd.deleteFile(old);
            try cwd.rename(name, old);

            self.alloc.free(name);
        }
    }
};

const arguments = [_]Arg{
    pos("INPUT", "path to input file", null),
    pos("TYPE", "chunk type", null),
    pos("DATA", "path to file with data to encode", null),
    pos("OUTPUT", "path to output file (optional)", null),
};

const commands = [_]Command{
    .{ .name = "encode", .desc = "Encode data into PNG file.", .args = arguments[0..] },
    .{ .name = "decode", .desc = "Decode data from PNG file.", .args = arguments[0..2] },
    .{ .name = "remove", .desc = "Remove data from PNG file.", .args = &[_]Arg{ arguments[0], arguments[1], arguments[3] } },
    .{ .name = "chunks", .desc = "Print all chunks in PNG file.", .args = arguments[0..1] },
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = arena.allocator();
    defer arena.deinit();

    var app = yazap.App.init(alloc, "pngme", "Hide messages in PNG files.");
    defer app.deinit();
    var pngme = app.rootCommand();

    for (commands) |cmd| {
        var command = app.createCommand(cmd.name, cmd.desc);
        try command.addArgs(cmd.args);
        try pngme.addSubcommand(command);
    }

    const matches = try app.parseProcess();
    const cmd = matches.subcommand orelse {
        try app.displayHelp();
        return yazap.YazapError.CommandSubcommandNotProvided;
    };

    const parsed = try Parsed.init(cmd, alloc);
    errdefer parsed.deinit();

    var input_bfr = std.io.bufferedReader(parsed.input.reader());
    var data_bfr = if (parsed.data) |d| std.io.bufferedReader(d.reader()) else undefined;
    const stdout = std.io.getStdOut().writer();
    var output_bfw = if (parsed.output) |o| std.io.bufferedWriter(o.writer()) else undefined;

    switch (parsed.subcmd) {
        .encode => try pnglib.Png.encode(
            alloc,
            input_bfr.reader(),
            output_bfw.writer(),
            parsed.chunk_type,
            data_bfr.reader(),
        ),
        .decode => { // when making debug build, every byte of chunk data is printed as \xaa. TODO: investigate
            const chunks = try pnglib.Png.decode(
                alloc,
                input_bfr.reader(),
                parsed.chunk_type,
            );

            if (chunks) |cs| {
                defer alloc.free(cs);
                for (cs) |c| try stdout.print("{}\n", .{c});
            } else try stdout.print("no chunks of type {s} found\n", .{parsed.chunk_type.bytes[0..]});
        },
        .remove => {
            const n = try pnglib.Png.remove(
                alloc,
                input_bfr.reader(),
                output_bfw.writer(),
                parsed.chunk_type,
            );

            try stdout.print("removed {d} items\n", .{n});
        },
        .chunks => {
            const png = try pnglib.Png.readStream(alloc, input_bfr.reader());
            try png.format("{}", .{}, stdout);
        },
    }

    try output_bfw.flush();
    try parsed.deinitWrite();
}
