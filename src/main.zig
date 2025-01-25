const std = @import("std");
const keystone = @import("keystone");
const posix = std.posix;
const pretty = @import("pretty");
const qbe = @import("qbe.zig");
const sexp = @import("sexp.zig");
const llexp = @import("llexp.zig");

const Indexes = sexp.Interner.Indexes;

var x: u32 = 100;

fn extern_func(str: [*:0]const u8) callconv(.C) u32 {
    const l = std.mem.len(str);
    const s = str[0..l];
    std.debug.print("extern_func: str = {s}\n", .{s});
    return 0xaaaa;
}

pub const CtxItem = union(enum) {
    Function: struct {
        name: Indexes.String,
        fptr: []align(std.mem.page_size) const u8,
        pub fn deinit(self: *const @This()) void {
            posix.munmap(self.func_mem);
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const f = try std.fs.cwd().openFile("t.sec", .{});
    // const f = try std.fs.openFileAbsolute("/tmp/test.lisp", .{});
    defer f.close();
    const source = try f.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(source);

    var strings_interner = sexp.Interner.Strings.init(allocator);
    defer strings_interner.deinit();

    sexp.Interner.Strings.g = &strings_interner;

    var lltypesInterner = llexp.LLType.TypeInterner.init(allocator);
    defer lltypesInterner.deinit();

    llexp.LLType.TypeInterner.g = lltypesInterner;

    var ctx = sexp.Sexp.ParsingContext.init(allocator);
    defer ctx.deinit();

    var sexpIter = ctx.createTopsIter(source);
    defer sexpIter.deinit(allocator);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    //const arena = arena_state.allocator();
    var llastParser = llexp.LLParser.init(&ctx, allocator);
    defer llastParser.deinit();

    var llTypesContext = llexp.LLType.TypesContext.init(&ctx, allocator);
    defer llTypesContext.deinit();

    var llTypeChecker = llexp.LLType.TypesContext.TypeChecker.init(&llTypesContext);
    defer llTypeChecker.deinit();

    var llJitContext = llexp.LLType.TypesContext.JitContext.init(&llTypesContext);
    defer llJitContext.deinit();

    var c: usize = 0;

    // var compileArena = std.heap.ArenaAllocator.init(allocator);
    while (try sexpIter.next()) |root| {
        // defer _ = compileArena.reset(.retain_capacity);
        // defer {
        //     const res = arena_state.reset(.retain_capacity);
        //     std.debug.assert(res);
        // }
        // defer ctx.freeNode(root) catch unreachable;
        // ctx.print(root);
        // std.debug.print("\n", .{});
        var ast = try llastParser.parse(root);
        // ast.print(0, &ctx);
        const typeCheckedAst = try llTypeChecker.typeCheck(&ast);
        // pretty.print(std.heap.page_allocator, typeCheckedAst, .{}) catch unreachable;

        const compiledFunction = llJitContext.compile(typeCheckedAst, arena_state.allocator()) catch unreachable;
        llJitContext.functions.put(compiledFunction.name, .{ .compiled = compiledFunction }) catch unreachable;
        // const func: *const (fn (u32, u32) callconv(.C) u32) = @ptrCast(compiledFunction.code);
        // const xxx = func(20, 47);
        // std.debug.print("func(...) = {}\n", .{xxx});
        // _ = xxx;
        c += 1;

        // defer ast.free(allocator);
        // try ctx.freeNode(root);
        // print(&ctx, root);
        // std.debug.print("\n", .{});
    }

    if (llJitContext.functions.get(strings_interner.pushString("main"))) |mainF| {
        const func: *const (fn () callconv(.C) void) = @ptrCast(mainF.compiled.code);
        func();
    }

    std.debug.print("c = {}\n", .{c});

    std.debug.print("strings_interner.strings_raw.len = {}\n", .{strings_interner.strings_raw.items.len});
    std.debug.print("lltypesInterner.types.len = {}\n", .{lltypesInterner.types.len});
    std.debug.print("ctx.impl.lists.len = {}\n", .{ctx.impl.lists.items.len});
    std.debug.print("ctx.impl.nodes.len = {}\n", .{ctx.impl.nodes.len});
    std.debug.print("ctx.impl.nodes.len - free_nodes = {}\n", .{ctx.impl.nodes.len - ctx.impl.free_nodes.items.len});

    // const f = try std.fs.cwd().openFile("t.qbe", .{});
    // const qbecode = try f.readToEndAlloc(std.heap.page_allocator, std.math.maxInt(usize));
    // defer f.close();

    // {
    //     var code = try qbe.compile(qbecode);
    //     std.debug.print("code.code:\n{s}\n", .{code.mmap});

    //     const func_mem = try jitCode(ks, code.code);
    //     {
    //         const binf = std.fs.createFileAbsolute("/tmp/t.bin", .{}) catch unreachable;
    //         defer binf.close();
    //         binf.writeAll(func_mem) catch unreachable;
    //     }
    //     {
    //         for (0..func_mem.len) |idx| {
    //             std.debug.print("{x:0>2} ", .{func_mem[idx]});
    //         }
    //         std.debug.print("\n", .{});
    //     }

    //     code.deinit();
    //     const func: *const (fn (c_int, c_int) callconv(.C) c_int) = @ptrCast(func_mem.ptr);
    //     const xxx = func(1, 2);
    //     defer posix.munmap(func_mem);
    //     std.debug.print("func(...) = {x}\n", .{xxx});
    // }

    // {
    //     const err = keystone.ks_close(ks);
    //     if (err != keystone.KS_ERR_OK) {
    //         std.debug.panic("failed to close keystone engine: {*}", .{keystone.ks_strerror(err)});
    //     }
    // }

}
