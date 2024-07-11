const std = @import("std");
const yazap = @import("yazap");

const App = yazap.App;
const Arg = yazap.Arg;
const pos = Arg.positional;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = arena.allocator();
    defer arena.deinit();

    var app = App.init(alloc, "pngme", "Hide messages in PNG files.");
    defer app.deinit();
    var pngme = app.rootCommand();

    var cmd_enc = app.createCommand("encode", "Encode data into PNG file.");
    var arg_enc = [_]Arg{
        pos("INPUT", "path to input file", null),
        pos("TYPE", "chunk type", null),
        pos("DATA", "data to encode", null),
        pos("OUTPUT", "path to output file (optional)", null),
    };
    try cmd_enc.addArgs(arg_enc[0..]);

    var cmd_dec = app.createCommand("decode", "Decode data from PNG file.");
    try cmd_dec.addArgs(arg_enc[0..2]);

    var cmd_rem = app.createCommand("remove", "Remove data from PNG file.");
    try cmd_rem.addArgs(arg_enc[0..2]);

    var cmd_pri = app.createCommand("print", "Print all chunks in PNG file.");
    try cmd_pri.addArg(arg_enc[0]);

    var subcommands = [_]yazap.Command{
        cmd_enc,
        cmd_dec,
        cmd_rem,
        cmd_pri,
    };
    try pngme.addSubcommands(subcommands[0..]);

    const matches = try app.parseProcess();
    if (matches.subcommand == null) {
        try app.displayHelp();
        return yazap.YazapError.CommandSubcommandNotProvided;
    }

    const cmd = matches.subcommand.?;
    switch (cmd.name[0]) { // TODO: do stuff
        'e' => std.debug.print("encode!", .{}),
        'd' => std.debug.print("decode!", .{}),
        'r' => std.debug.print("remove!", .{}),
        'p' => std.debug.print("print!", .{}),
        else => unreachable,
    }
}
