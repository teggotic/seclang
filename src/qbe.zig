const std = @import("std");
const c = @import("qbe_c");
usingnamespace c;
const c_amd64 = @import("qbe_amd64");
const c_arm64 = @import("qbe_arm64");
const c_rv64 = @import("qbe_rv64");

// pub extern var instrOnly: c_char = 0;

// pub extern var outf: ?*std.c.FILE;
// pub extern var T: ?*c.Target;

fn data(d: [*c]c.Dat) callconv(.C) void {
    _ = d;
}

pub extern "c" fn fdopen(fd: c_int, mode: [*:0]const u8) ?*std.c.FILE;

pub const CompiledInstructions = struct {
    code: [*:0]u8,
    mmap: []align(std.mem.page_size) const u8,

    pub fn deinit(self: *const @This()) void {
        std.posix.munmap(self.mmap);
    }
};

pub fn compile(fdin: std.posix.fd_t, entrypoint: []const u8) !CompiledInstructions {
    try std.posix.lseek_SET(fdin, 0);

    const fdout = try std.posix.memfd_create("qbe_out", 0);

    const fin = fdopen(fdin, "r");
    defer _ = std.c.fclose(fin.?);

    const fout = fdopen(fdout, "w");

    {
        const writer = (std.fs.File {.handle = fdout}).writer();
        try std.fmt.format(writer, "jmp {s}\n", .{entrypoint});
    }

    defer _ = std.c.fclose(fout.?);
    c.setup_impl(@alignCast(@ptrCast(fout.?)), @alignCast(@ptrCast(fin.?)));

    const out_size = try std.posix.lseek_CUR_get(fdout);
    // std.debug.print("out_size: {d}\n", .{out_size});

    const out_mem = try std.posix.mmap(null, out_size + 1, std.posix.PROT.READ | std.posix.PROT.WRITE, std.posix.MAP{ .TYPE = .SHARED }, fdout, 0);
    out_mem[out_size] = 0;

    return .{
        .code = @ptrCast(out_mem.ptr),
        .mmap = out_mem,
    };
}
