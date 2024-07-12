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

    input: std.fs.File,
    chunk_type: pnglib.ChunkType,
    data: std.fs.File,
    output: ?std.fs.File,
    subcmd: Subcommand,

    fn init(cmd: *const yazap.arg_matches.MatchedSubCommand) !Self {
        var self: Self = undefined;
        self.subcmd = @enumFromInt(cmd.name[0]);
        const args: *const yazap.arg_matches.ArgHashMap = &cmd.matches.?.args;

        if (args.count() < self.subcmd.count()) return error.MissingArguments;

        const cwd = std.fs.cwd();

        if (self.subcmd == .encode) {
            if (args.get("OUTPUT")) |output| {
                self.output = try cwd.createFile(output.single, .{ .read = false });
            } else self.output = null;
            errdefer if (self.output) |o| o.close();

            const data_b = try getPositional(args, "DATA");
            self.data = try cwd.openFile(data_b, .{ .mode = .read_only });
            errdefer self.data.close();
        }

        const input_b = try getPositional(args, "INPUT");
        self.input = try cwd.openFile(input_b, .{ .mode = if (self.subcmd == .encode and self.output == null) .read_write else .read_only });
        errdefer self.input.close();

        switch (self.subcmd) {
            .encode, .decode, .remove => {
                const ct_b = try getPositional(args, "TYPE");
                if (ct_b.len != 4) return error.InvalidChunkType;
                self.chunk_type = try pnglib.ChunkType.init(ct_b[0..4].*);
                if (!self.chunk_type.is_valid()) return error.InvalidChunkType;
            },
            .chunks => {},
        }

        return self;
    }

    fn deinit(self: *const Self) void {
        self.input.close();
        if (self.subcmd == .encode) {
            self.data.close();
            if (self.output) |o| o.close();
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
    .{ .name = "remove", .desc = "Remove data from PNG file.", .args = arguments[0..2] },
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

    const parsed = try Parsed.init(cmd);
    defer parsed.deinit();
}
