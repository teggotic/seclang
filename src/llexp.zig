const std = @import("std");
const keystone = @import("keystone");
const qbe = @import("qbe.zig");
const sexp = @import("sexp.zig");
const Allocator = std.mem.Allocator;
const SexpIndex = sexp.Sexp.ParsingContext.Index;
const pretty = @import("pretty");

fn dump_and_fail(value: anytype) noreturn {
    pretty.print(std.heap.page_allocator, value, .{}) catch unreachable;
    unreachable;
}

pub fn nextAlignment(offset: usize, alignment: usize) usize {
    const rem = offset % alignment;
    if (rem == 0) {
        return offset;
    }
    return (offset - rem) + alignment;
}

test "nextAlignment" {
    try std.testing.expectEqual(0, nextAlignment(0, 1));
    try std.testing.expectEqual(0, nextAlignment(0, 2));
    try std.testing.expectEqual(0, nextAlignment(0, 4));
    try std.testing.expectEqual(0, nextAlignment(0, 8));

    try std.testing.expectEqual(1, nextAlignment(1, 1));
    try std.testing.expectEqual(2, nextAlignment(1, 2));
    try std.testing.expectEqual(4, nextAlignment(1, 4));
    try std.testing.expectEqual(8, nextAlignment(1, 8));

    try std.testing.expectEqual(2, nextAlignment(2, 1));
    try std.testing.expectEqual(2, nextAlignment(2, 2));
    try std.testing.expectEqual(4, nextAlignment(2, 4));
    try std.testing.expectEqual(8, nextAlignment(2, 8));

    try std.testing.expectEqual(3, nextAlignment(3, 1));
    try std.testing.expectEqual(4, nextAlignment(3, 2));
    try std.testing.expectEqual(4, nextAlignment(3, 4));
    try std.testing.expectEqual(8, nextAlignment(3, 8));

    try std.testing.expectEqual(4, nextAlignment(4, 1));
    try std.testing.expectEqual(4, nextAlignment(4, 2));
    try std.testing.expectEqual(4, nextAlignment(4, 4));
    try std.testing.expectEqual(8, nextAlignment(4, 8));

    try std.testing.expectEqual(5, nextAlignment(5, 1));
    try std.testing.expectEqual(6, nextAlignment(5, 2));
    try std.testing.expectEqual(8, nextAlignment(5, 4));
    try std.testing.expectEqual(8, nextAlignment(5, 8));
}

pub const LLType = union(enum) {
    fn AstT(comptime T: type) type {
        return struct {
            ast: T,
            typ: LLType,

            pub const Ast = T;

            pub fn copyAs(self: *const @This(), comptime ResT: type) ResT {
                return .{
                    .ast = self.ast,
                    .typ = self.typ,
                };
            }
        };
    }

    pub const TypedAst = AstT(LLAst(AstT, LLType));

    pub const StructType = struct {
        name: []const u8,
        fields: []Field,

        pub fn size(self: *const StructType) usize {
            var sz: usize = 0;
            for (self.fields) |field| {
                sz = nextAlignment(sz, field.typ.alignment());
                sz += field.typ.size();
            }
            return sz;
        }

        pub fn indexOf(self: *const StructType, fieldName: []const u8) ?usize {
            for (self.fields, 0..) |field, idx| {
                if (std.mem.eql(u8, field.name, fieldName)) {
                    return idx;
                }
            }
            return null;
        }

        pub fn offsetOf(self: *const StructType, index: usize) usize {
            var offset: usize = 0;
            for (self.fields, 0..) |field, i| {
                offset = nextAlignment(offset, field.typ.alignment());
                if (i == index) {
                    return offset;
                }
                offset += field.typ.size();
            }
            unreachable;
        }

        pub fn alignment(self: *const StructType) usize {
            var mx: usize = 0;
            for (self.fields) |field| {
                mx = @max(mx, field.typ.alignment());
            }
            return mx;
        }
        pub const Field = struct {
            typ: LLType,
            name: []const u8,
        };
    };

    number_literal: struct {
        negative: bool,
        float: bool,
    },
    integer: struct {
        signed: bool,
        bits: u16,
    },
    floating: u32,
    pointer: *LLType,
    struct_: StructType,
    function: FunctionType,
    macro: FunctionType,
    void: void,

    pub inline fn isVoid(self: *const LLType) bool {
        return self.* == .void;
    }

    pub const FunctionType = struct {
        name: []const u8,
        return_type: *LLType,
        params: []Param,

        pub const Param = struct {
            name: []const u8,
            typ: *LLType,
        };
    };

    pub fn size(self: *const LLType) usize {
        switch (self) {
            .integer => |int| return @intCast(int.bits / 8),
            .floating => |bits| return @intCast(bits / 8),
            .pointer => return 8,
            .struct_ => |struct_| return struct_.size(),
            .void => return 0,
        }
    }

    fn alignment(self: *const LLType) usize {
        switch (self) {
            .integer => |int| return @intCast(int.bits / 8),
            .floating => |bits| return @intCast(bits / 8),
            .pointer => return 8,
            .struct_ => |struct_| return struct_.alignment(),
            .void => return 0,
        }
    }

    pub fn acceptsType(self: *const LLType, other: *const LLType) bool {
        switch (self.*) {
            .integer => |int| {
                switch (other.*) {
                    .integer => |other_int| return int.signed == other_int.signed and int.bits == other_int.bits,
                    .number_literal => |other_int| {
                        if (other_int.float) { return false; }
                        if (other_int.negative) {
                            return int.signed;
                        }
                        // TODO: check for overflow
                        return true;
                    },
                    else => {
                        return false;
                    },
                }
            },
            .number_literal => |num| {
                switch (other.*) {
                    .number_literal => |other_num| {
                        if (num.float != other_num.float) {
                            return false;
                        }
                        if (num.negative != other_num.negative) {
                            return false;
                        }
                        return true;
                    },
                    .integer => {
                        return other.acceptsType(self);
                    },
                    else => {
                        unreachable;
                    },
                }
            },
            else => {
                unreachable;
            }
        }
    }

    pub const TypesContext = struct {
        allocator: Allocator,
        sexpCtx: *sexp.Sexp.ParsingContext,
        types: std.StringHashMap(LLType),

        pub fn init(sexpCtx: *sexp.Sexp.ParsingContext, allocator: Allocator) @This() {
            var types = std.StringHashMap(LLType).init(allocator);

            types.put("i8", .{ .integer = .{ .signed = true, .bits = 8 } }) catch unreachable;
            types.put("u8", .{ .integer = .{ .signed = false, .bits = 8 } }) catch unreachable;

            types.put("i16", .{ .integer = .{ .signed = true, .bits = 16 } }) catch unreachable;
            types.put("u16", .{ .integer = .{ .signed = false, .bits = 16 } }) catch unreachable;

            types.put("i32", .{ .integer = .{ .signed = true, .bits = 32 } }) catch unreachable;
            types.put("u32", .{ .integer = .{ .signed = false, .bits = 32 } }) catch unreachable;

            types.put("i64", .{ .integer = .{ .signed = true, .bits = 64 } }) catch unreachable;
            types.put("u64", .{ .integer = .{ .signed = false, .bits = 64 } }) catch unreachable;

            types.put("f32", .{ .floating = 32 }) catch unreachable;
            types.put("f64", .{ .floating = 64 }) catch unreachable;

            types.put("void", .{ .void = void{} }) catch unreachable;
            types.put("sexp", .{ .pointer = types.getPtr("void") orelse unreachable }) catch unreachable;

            return @This(){
                .sexpCtx = sexpCtx,
                .types = types,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *@This()) void {
            self.types.deinit();
        }

        pub fn voidType(self: *@This()) LLType {
            _ = self;
            return .{ .void = void{} };
        }

        pub fn resolveRef(self: *@This(), ref: []const u8) !LLType {
            const idx = self.types.get(ref) orelse {
                return error.UnknownType;
            };
            return idx;
        }

        pub fn pushType(self: *@This(), name: []const u8, ty: LLType) !void {
            self.types.put(name, ty) catch unreachable;
        }

        pub const JitContext = struct {
            var globalThis: ?*@This() = null;

            pub const CompiledFunction = struct {
                name: []const u8,
                code: []const align(std.mem.page_size)u8,
                fn_type: LLType.FunctionType,

                pub fn deinit(self: *const @This()) void {
                    std.posix.munmap(self.code);
                }
            };
            pub const BuiltinFunction = struct {
                name: []const u8,
                ptr: *void,
            };
            pub const Func = union(enum) {
                builtin: BuiltinFunction,
                compiled: CompiledFunction,
            };

            ctx: *TypesContext,
            functions: std.StringHashMap(Func),
            ks: *keystone.ks_engine,

            pub fn init(ctx: *TypesContext) *@This() {
                std.debug.assert(globalThis == null);

                var ks_nullable: ?*keystone.ks_engine = undefined;
                {
                    const err = keystone.ks_open(keystone.KS_ARCH_X86, keystone.KS_MODE_64, &ks_nullable);
                    if (err != keystone.KS_ERR_OK) {
                        std.debug.panic("failed to open keystone engine: {*}\n", .{keystone.ks_strerror(err)});
                    }
                }

                const fdin = std.posix.memfd_create("qbe_in", 0) catch unreachable;
                std.posix.lseek_SET(fdin, 0) catch unreachable;

                const ks = ks_nullable.?;

                {
                    const err = keystone.ks_option(ks, keystone.KS_OPT_SYNTAX, keystone.KS_OPT_SYNTAX_ATT);
                    if (err != keystone.KS_ERR_OK) {
                        std.debug.panic("failed to set ATT syntax: {*}\n", .{keystone.ks_strerror(err)});
                    }
                }
                {
                    const err = keystone.ks_option(ks, keystone.KS_OPT_SYM_RESOLVER, @intFromPtr(&symResolver));
                    if (err != keystone.KS_ERR_OK) {
                        std.debug.panic("failed to set symbol resolver: {*}\n", .{keystone.ks_strerror(err)});
                    }
                }

                const ptr = ctx.allocator.create(@This()) catch unreachable;

                ptr.* = .{
                    .ctx = ctx,
                    .functions = std.StringHashMap(Func).init(ctx.allocator),
                    .ks = ks,
                };
                globalThis = ptr;

                std.debug.assert(globalThis != null);

                return ptr;
            }

            pub fn deinit(self: *@This()) void {
                std.debug.assert(globalThis != null);
                std.debug.assert(self == globalThis);
                globalThis = null;
                self.functions.deinit();
                // self.ctx.allocator.destroy(globalThis.?);
            }

            fn resolveSymbol(self: *@This(), symbol: []const u8, value: [*c]u64) bool {
                std.debug.print("resolveSymbol: got symbol = {s}\n", .{symbol});
                if (self.functions.get(symbol)) |f| {
                    switch (f) {
                        .builtin => |builtin| {
                            value.* = @intFromPtr(builtin.ptr);
                            return true;
                        },
                        .compiled => |compiled| {
                            value.* = @intFromPtr(compiled.code.ptr);
                            return true;
                        },
                    }
                    return true;
                }
                return false;
            }

            fn symResolver(symbol: [*c]u8, value: [*c]u64) callconv(.C) bool {
                const s = symbol[0..std.mem.len(symbol)];
                std.debug.assert(globalThis != null);
                return globalThis.?.resolveSymbol(s, value);
            }

            pub fn compile(self: *@This(), func: TypedAst, allocator: Allocator) !CompiledFunction {
                var compiler = Compiler.init(self, allocator);
                defer compiler.deinit();

                return compiler.compile(func);
            }

            pub const Compiler = struct {
                const Scope = std.StringHashMapUnmanaged(ValueRef);
                jitCtx: *JitContext,
                qbeState: struct {
                    fdin: std.posix.fd_t,
                    writer: std.fs.File.Writer,
                },
                scopes: std.ArrayListUnmanaged(Scope) = .{},
                globals_to_process: std.StringHashMapUnmanaged(struct { name: ValueRef, typ: LLType, ref: ValueRef }) = .{},
                vari: usize = 0,
                allocator: Allocator,

                pub fn init(jitCtx: *JitContext, allocator: Allocator) Compiler {
                    const fd = std.posix.memfd_create("qbe_in", 0) catch unreachable;
                    return .{
                        .jitCtx = jitCtx,
                        .qbeState = .{
                            .fdin = fd,
                            .writer = (std.fs.File {.handle = fd}).writer(),
                        },
                        .allocator = allocator,
                    };
                }

                pub fn deinit(self: *@This()) void {
                    std.debug.assert(self.scopes.items.len == 0);
                    self.scopes.deinit(self.allocator);
                    self.globals_to_process.deinit(self.allocator);
                }

                pub fn newScope(self: *@This()) void {
                    self.scopes.append(self.allocator, .{}) catch unreachable;
                }

                pub fn closeScope(self: *@This()) void {
                    std.debug.assert(self.scopes.items.len > 0);
                    var scope = self.scopes.pop();
                    scope.deinit(self.allocator);
                }

                pub fn pushIntoScope(self: *@This(), name: []const u8, typ: ValueRef) void {
                    std.debug.assert(self.scopes.items.len > 0);
                    var scope = &self.scopes.items[self.scopes.items.len - 1];
                    std.debug.assert(!scope.contains(name));
                    scope.put(self.allocator, name, typ) catch unreachable;
                }

                pub fn lookup(self: *@This(), name: []const u8) ?ValueRef {
                    std.debug.assert(self.scopes.items.len > 0);
                    for (0..self.scopes.items.len) |i| {
                        const idx = self.scopes.items.len - 1 - i;
                        const scope = self.scopes.items[idx];
                        if (scope.contains(name)) {
                            return scope.get(name);
                        }
                    }
                    if (self.jitCtx.functions.get(name)) |_| {
                        self.globals_to_process.put(self.allocator, name, .{
                            .name = .{ .external_global = name },
                            .typ = self.jitCtx.ctx.types.get(name) orelse unreachable,
                            .ref = .{ .global = name },
                        }) catch unreachable;
                        return .{
                            .external_global = name
                        };
                    }
                    return null;
                }

                fn format(self: *@This(), comptime fmt: []const u8, args: anytype) void {
                    std.fmt.format(self.qbeState.writer, fmt, args) catch unreachable;
                }

                fn t2s(self: *@This(), typ: LLType) ![]const u8 {
                    _ = self;
                    switch (typ) {
                        .integer => |int| {
                            switch (int.bits) {
                                32 => {
                                    return "w";
                                },
                                64 => {
                                    return "l";
                                },
                                else => {
                                    dump_and_fail(.{typ});
                                }
                            }
                        },
                        .pointer => {
                            return "l";
                        },
                        .number_literal => {
                            return error.NumberLiteralIsNotSupported;
                        },
                        .void => {
                            return "l";
                        },
                        .function => {
                            return "l";
                        },
                        else => {
                            dump_and_fail(.{typ});
                        },
                    }
                }

                fn emitQBE(self: *@This(), defun: TypedAst.Ast.Defun, fn_type: LLType.FunctionType) !void {
                    self.newScope();
                    self.format("function {s} ${s}(", .{try self.t2s(fn_type.return_type.*), defun.name});
                    for (fn_type.params, 0..) |param, i| {
                        if (i > 0) {
                            self.format(", ", .{});
                        }
                        self.format("{s} %arg_{s}", .{try self.t2s(param.typ.*), param.name});
                        self.pushIntoScope(param.name, .{ .arg = param.name });
                    }
                    self.format(") {{\n", .{});
                    self.format("@start\n", .{});
                    var ret: ?ValueRef = null;
                    for (defun.body) |statement| {
                        ret = try self.emitExpr(statement);
                    }
                    if (!fn_type.return_type.isVoid()) {
                        self.format("    ret {any}\n", .{ ret.? });
                    } else {
                        self.format("    ret 0\n", .{});
                    }
                    self.format("}}\n", .{});
                    self.closeScope();
                    std.debug.assert(self.scopes.items.len == 0);
                }

                const ValueRef = union(enum) {
                    none,
                    local: usize,
                    arg: []const u8,
                    global: []const u8,
                    external_global: []const u8,
                    integer: isize,

                    pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
                        _ = options;
                        _ = fmt;
                        // std.debug.print("{s}\n", .{fmt});
                        switch (self) {
                            .none => { unreachable; },
                            .local => |local| {
                                try std.fmt.format(writer, "%v_{}", .{local});
                            },
                            .arg => |arg| {
                                try std.fmt.format(writer, "%arg_{s}", .{arg});
                            },
                            .global => |global| {
                                try std.fmt.format(writer, "${s}", .{global});
                            },
                            .external_global => |global| {
                                try std.fmt.format(writer, "$ref_{s}", .{global});
                            },
                            .integer => |int| {
                                try std.fmt.format(writer, "{}", .{int});
                            },
                        }
                    }
                };

                fn emitExpr(self: *@This(), expr: TypedAst) !ValueRef {
                    switch (expr.ast) {
                        .symbol => |symbol| {
                            return self.lookup(symbol.name) orelse unreachable;
                        },
                        .int_value => |int_value| {
                            return .{ .integer = @intCast(int_value) };
                        },
                        .call => |call| {
                            const Builtin = enum {
                                @"+",
                            };
                            const builtin = std.meta.stringToEnum(Builtin, call.name) orelse {
                                const fnType = self.jitCtx.ctx.types.get(call.name) orelse {
                                    dump_and_fail(.{.call = call});
                                };
                                std.debug.assert(fnType == .function);
                                const nameRef = self.lookup(call.name) orelse {
                                    dump_and_fail(.{.call = call});
                                };
                                const fnRef = self.qbeAssignTemporary(fnType) catch unreachable;
                                self.format("loadl {any}\n", .{nameRef});
                                var args = std.ArrayList(ValueRef).init(self.allocator);
                                defer args.deinit();
                                for (call.args) |arg| {
                                    try args.append(try self.emitExpr(arg));
                                }
                                const resRef = self.qbeAssignTemporary(expr.typ) catch unreachable;
                                self.format("call {any}(", .{fnRef});
                                for (args.items, fnType.function.params, 0..) |arg, param, i| {
                                    if (i == 0) {
                                        self.format("{s} {any}", .{ try self.t2s(param.typ.*), arg });
                                    } else {
                                        self.format(", {s} {any}", .{ try self.t2s(param.typ.*), arg });
                                    }
                                }
                                self.format(")\n", .{});
                                return resRef;
                            };
                            switch (builtin) {
                                .@"+" => {
                                    const arg1Ref = try self.emitExpr(call.args[0]);
                                    const arg2Ref = try self.emitExpr(call.args[1]);
                                    var resRef = self.qbeAssignTemporary(expr.typ) catch unreachable;
                                    self.format("add {any}, {any}\n", .{ arg1Ref, arg2Ref });
                                    for (call.args[2..]) |arg| {
                                        const curRef = resRef;
                                        const argRef = try self.emitExpr(arg);
                                        resRef = self.qbeAssignTemporary(expr.typ) catch unreachable;
                                        self.format("add {any}, {any}\n", .{ argRef, curRef });
                                    }
                                    return resRef;
                                },
                            }
                        },
                        else => {
                            unreachable;
                        }
                    }
                }

                fn qbeAssign(self: *@This(), place: ValueRef, typ: LLType) !void {
                    self.format("{any} ={s} ", .{ place, try self.t2s(typ) });
                }

                fn getTemporary(self: *@This()) ValueRef {
                    defer self.vari += 1;
                    return .{ .local = self.vari };
                }

                fn qbeAssignTemporary(self: *@This(), typ: LLType) !ValueRef {
                    const place = self.getTemporary();
                    try self.qbeAssign(place, typ);
                    return place;
                }

                extern "c" fn fdopen(fd: c_int, mode: [*:0]const u8) ?*std.c.FILE;
                pub fn compile(self: *@This(), func: TypedAst) !CompiledFunction {
                    const defun = func.ast.defun;
                    const funcType = func.typ.function;

                    {
                        try std.posix.lseek_SET(self.qbeState.fdin, 0);
                        try std.posix.ftruncate(self.qbeState.fdin, 0);
                    }

                    try self.emitQBE(defun, funcType);
                    var glbIt = self.globals_to_process.iterator();
                    while (glbIt.next()) |glbEntry| {
                        const glb = glbEntry.value_ptr.*;
                        std.debug.assert(glb.name == .external_global);
                        std.debug.assert(glb.ref == .global);
                        self.format("data {any} = {{ {s} {any} }}\n", .{glb.name, try self.t2s(glb.typ), glb.ref});
                    }

                    {
                        const out_size = try std.posix.lseek_CUR_get(self.qbeState.fdin);
                        const out_mem = try std.posix.mmap(null, out_size, std.posix.PROT.READ | std.posix.PROT.WRITE, std.posix.MAP{ .TYPE = .SHARED }, self.qbeState.fdin, 0);
                        defer std.posix.munmap(out_mem);
                        std.debug.print("{s}\n", .{out_mem});
                        // dump_and_fail(out_mem);
                    }

                    // unreachable;

                    const instructions = try self.qbeCompile(defun.name);
                    std.debug.print("{s}\n", .{instructions.mmap});
                    defer instructions.deinit();
                    const fn_mem = try self.jitCode(instructions.code);
                    return .{
                        .name = defun.name,
                        .code = fn_mem,
                        .fn_type = funcType,
                    };
                }

                fn qbeCompile(self: *@This(), entrypoint: []const u8) !qbe.CompiledInstructions {
                    return qbe.compile(self.qbeState.fdin, entrypoint);
                }

                fn jitCode(self: *@This(), code: [*c]const u8) ![]const align(std.mem.page_size)u8 {
                    var encode: [*c]u8 = undefined;
                    var count: usize = 0;
                    var sz: usize = 0;

                    if (keystone.ks_asm(self.jitCtx.ks, code, 0, &encode, &sz, &count) != keystone.KS_ERR_OK) {
                        std.debug.panic("ERROR: ks_asm() failed & count = {}, error = {*}\n", .{count, keystone.ks_strerror(keystone.ks_errno(self.jitCtx.ks))});
                    } else {
                        // std.debug.print("Compiled: {} bytes, statements: {}\n", .{sz, count});
                    }

                    const globals_size = 0;

                    const func_mem = try std.posix.mmap(null, sz + globals_size, std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
                    @memset(func_mem[0..globals_size], 0);
                    @memcpy(func_mem[globals_size..], encode[0..sz]);
                    // try posix.mprotect(func_mem, posix.PROT.EXEC);
                    keystone.ks_free(encode);
                    return func_mem;
                }

            };
        };

        pub const TypeChecker = struct {
            const Scope = std.StringHashMap(LLType);
            scopes: std.ArrayList(Scope),
            ctx: *TypesContext,
            current_fn: ?LLType.FunctionType = null,

            pub fn init(ctx: *TypesContext) TypeChecker {
                return .{
                    .ctx = ctx,
                    .scopes = std.ArrayList(Scope).init(ctx.allocator),
                };
            }

            pub fn deinit(self: *@This()) void {
                self.scopes.deinit();
            }

            pub fn newScope(self: *@This()) void {
                self.scopes.append(Scope.init(self.ctx.allocator)) catch unreachable;
            }
            pub fn closeScope(self: *@This()) void {
                std.debug.assert(self.scopes.items.len > 0);
                var scope = self.scopes.pop();
                scope.deinit();
            }

            pub fn pushIntoScope(self: *@This(), name: []const u8, typ: LLType) void {
                std.debug.assert(self.scopes.items.len > 0);
                var scope = &self.scopes.items[self.scopes.items.len - 1];
                std.debug.assert(!scope.contains(name));
                scope.put(name, typ) catch unreachable;
            }

            pub fn lookup(self: *@This(), name: []const u8) ?LLType {
                std.debug.assert(self.scopes.items.len > 0);
                for (0..self.scopes.items.len) |i| {
                    const idx = self.scopes.items.len - 1 - i;
                    const scope = self.scopes.items[idx];
                    if (scope.contains(name)) {
                        return scope.get(name);
                    }
                }
                return self.ctx.types.get(name);
            }

            fn typeCheckDefun(self: *@This(), defun: LLParser.UnresolvedLLAst.Defun) anyerror!TypedAst {
                self.newScope();
                errdefer self.closeScope();

                const name = defun.name;

                const return_type = self.ctx.allocator.create(LLType) catch unreachable;
                return_type.* = try self.ctx.parseTypeReference(defun.ret_type);

                // TODO: DO NOT USE TypedAst here. Create a new union type to fix this shit.
                var params = std.ArrayList(LLType.FunctionType.Param).init(self.ctx.allocator);
                errdefer params.deinit();
                var args = std.ArrayList(TypedAst.Ast.Defun.Arg).init(self.ctx.allocator);
                errdefer args.deinit();

                for (defun.args) |arg| {
                    const arg_type = self.ctx.allocator.create(LLType) catch unreachable;
                    arg_type.* = try self.ctx.parseTypeReference(arg.typ);
                    self.pushIntoScope(arg.name, arg_type.*);
                    std.debug.assert(self.lookup(arg.name) != null);
                    params.append(.{
                        .name = arg.name,
                        .typ = arg_type,
                    }) catch unreachable;
                    args.append(.{
                        .name = arg.name,
                        .typ = arg_type.*,
                    }) catch unreachable;
                }

                const fn_type: LLType.FunctionType = .{
                    .name = name,
                    .return_type = return_type,
                    .params = try params.toOwnedSlice(),
                };

                const current_fn = self.current_fn;
                defer self.current_fn = current_fn;

                self.current_fn = fn_type;

                var body = std.ArrayList(TypedAst).init(self.ctx.allocator);
                errdefer body.deinit();

                var ret = self.ctx.types.get("void") orelse unreachable;
                for (defun.body) |statement| {
                    const stmt = try self.typeCheckImpl(&statement);
                    body.append(stmt) catch unreachable;
                    ret = stmt.typ;
                }

                if (!return_type.isVoid()) {
                    try self.ctx.assertAcceptableType(fn_type.return_type, &ret);
                }

                self.closeScope();

                self.pushIntoScope(name, .{
                    .function = fn_type,
                });

                try self.ctx.pushType(name, .{
                    .function = fn_type,
                });

                return .{
                    .ast = .{
                        .defun = .{
                            .name = name,
                            .ret_type = return_type.*,
                            .args = try args.toOwnedSlice(),
                            .body = try body.toOwnedSlice(),
                        },
                    },
                    .typ = .{.function = fn_type},
                };
            }

            pub fn typeCheck(self: *@This(), root: *const LLParser.UnresolvedLLAst) !TypedAst {
                std.debug.assert(self.scopes.items.len == 0);
                self.newScope();
                defer {
                    self.closeScope();
                    std.debug.assert(self.scopes.items.len == 0);
                }
                return self.typeCheckImpl(root);
            }

            fn typeCheckImpl(self: *@This(), root: *const LLParser.UnresolvedLLAst) !TypedAst {
                switch (root.*) {
                    .defun => |defun| {
                        return try self.typeCheckDefun(defun);
                    },
                    .returnStmt => |returnExpr| {
                        std.debug.assert(self.current_fn != null);
                        const returnType = self.current_fn.?.return_type;
                        switch (returnType.*) {
                            .void => {
                                std.debug.assert(returnExpr == null);
                                return .{
                                    .ast = .{ .returnStmt = null },
                                    .typ = self.ctx.voidType(),
                                };
                            },
                            else => {
                                const returnTypeChecked = self.ctx.allocator.create(TypedAst) catch unreachable;
                                returnTypeChecked.* = try self.typeCheckImpl(returnExpr.?);
                                try self.ctx.assertAcceptableType(&returnTypeChecked.typ, returnType);
                                return .{
                                    .ast = .{ .returnStmt = returnTypeChecked },
                                    .typ = returnType.*,
                                };
                            },
                        }
                    },
                    .call => |call| {
                        const Case = enum {
                            @"+",
                        };

                        var args = std.ArrayList(TypedAst).init(self.ctx.allocator);
                        errdefer args.deinit();

                        for (call.args) |arg| {
                            const argTyped = try self.typeCheckImpl(&arg);
                            args.append(argTyped) catch unreachable;
                        }

                        const cs: Case = std.meta.stringToEnum(Case, call.name) orelse {
                            const fnType = self.lookup(call.name) orelse {
                                std.debug.print("Unknown symbol {s}\n", .{call.name});
                                return error.UnknownSymbol;
                            };
                            switch (fnType) {
                                .function => |function| {
                                    std.debug.assert(function.params.len == args.items.len);

                                    for (function.params, args.items) |param, arg| {
                                        try self.ctx.assertAcceptableType(&arg.typ, param.typ);
                                    }

                                    return .{
                                        .ast = .{
                                            .call = .{
                                                .name = call.name,
                                                .args = try args.toOwnedSlice(),
                                            },
                                        },
                                        .typ = function.return_type.*,
                                    };
                                },
                                else => {
                                    return error.NotAFunction;
                                },
                            }
                        };

                        switch (cs) {
                            .@"+" => {
                                const fst = args.items[0];
                                const typs = &[_]LLType {
                                    self.ctx.types.get("i32") orelse unreachable,
                                    self.ctx.types.get("u32") orelse unreachable,
                                };
                                const typ = blk: inline for (typs) |*typ| {
                                    if (fst.typ.acceptsType(typ)) {
                                        break :blk typ;
                                    }
                                } else {
                                    return error.InvalidType;
                                };

                                for (args.items[1..]) |arg| {
                                    try self.ctx.assertAcceptableType(&arg.typ, typ);
                                }

                                return .{
                                    .ast = .{
                                        .call = .{
                                            .name = call.name,
                                            .args = try args.toOwnedSlice(),
                                        }
                                    },
                                    .typ = typ.*,
                                };
                            },
                        }
                    },
                    .symbol => |symbol| {
                        const typ = self.lookup(symbol.name) orelse {
                            std.debug.print("symbol = {s}\n", .{symbol.name});
                            const scope = self.scopes.items[self.scopes.items.len - 1];
                            var iter = scope.iterator();
                            while (iter.next()) |item| {
                                std.debug.print("{s}\n", .{item.key_ptr.*});
                            }
                            return error.UnknownSymbol;
                        };
                        return .{
                            .ast = .{ .symbol = .{ .name = symbol.name } },
                            .typ = typ,
                        };
                    },
                    .int_value => |int_value| {
                        return .{
                            .ast = .{ .int_value = int_value },
                            .typ = .{ .number_literal = .{ .negative = int_value < 0, .float = false } },
                        };
                    },
                    .block_scope => |statements| {
                        dump_and_fail(root);
                        var ret = self.ctx.types.get("void") orelse unreachable;
                        var checkedStatements = try std.ArrayList(TypedAst).initCapacity(self.ctx.allocator, statements.len);
                        self.newScope();
                        for (statements) |stmt| {
                            const x = try self.typeCheckImpl(&stmt);
                            checkedStatements.appendAssumeCapacity(x);
                            ret = x.typ;
                        }
                        self.closeScope();
                        return .{
                            .ast = .{ .block_scope = try checkedStatements.toOwnedSlice() },
                            .typ = ret,
                        };
                    },
                    else => {
                        dump_and_fail(root);
                        unreachable;
                    },
                }
            }
        };

        pub fn assertAcceptableType(self: *@This(), expr: *const LLType, expected: *const LLType) !void {
            _ = self;
            // if (expr.is(expected)) {
            //     return;
            // }
            if (expected.acceptsType(expr)) {
                return;
            }
            return error.TypeMismatch; // TODO: better error message
        }

        pub fn parseTypeReference(self: *@This(), root: SexpIndex.Node) !LLType {
            const tags = self.sexpCtx.nodesItems(.tag);
            const data = self.sexpCtx.nodesItems(.data);
            switch (tags.get(root)) {
                .string,
                .int_value,
                .float_value,
                .bool_value,
                .list => {
                    return error.NotATypeReference;
                },
                .symbol => {
                    const name = self.sexpCtx.getString(data.get(root).symbol);
                    return try self.resolveRef(name);
                },
            }
        }
    };
};

pub fn LLAst(comptime ExprT: fn(type) type, comptime TypT: type) type {
    return union(enum) {
        pub const Self = @This();
        pub const Defun = struct {
            name: []const u8,
            ret_type: TypT,
            args: []Arg,
            body: []ExprT(Self),

            pub const Arg = struct {
                name: []const u8,
                typ: TypT,
            };
        };

        defun: Defun,
        symbol: struct {
            name: []const u8,
        },
        string: struct {
            name: []const u8,
        },
        call: struct {
            name: []const u8,
            args: []ExprT(Self),
        },
        int_value: isize,
        float_value: f64,
        bool_value: bool,
        sexp: SexpIndex.Node,
        block_scope: []ExprT(Self),
        defvar: struct {
            name: []const u8,
            typ: TypT,
            value: ?*ExprT(Self),
        },
        returnStmt: ?*ExprT(Self),

        pub fn free(self: *const @This(), allocator: Allocator) void {
            switch (self.*) {
                .defun => |defun| {
                    allocator.free(defun.args);
                    for (defun.body) |body| {
                        body.free(allocator);
                    }
                    allocator.free(defun.body);
                },
                .symbol => {},
                .string => {},
                .int_value => {},
                .float_value => {},
                .bool_value => {},
                .call => |call| {
                    for (call.args) |arg| {
                        arg.free(allocator);
                    }
                    allocator.free(call.args);
                },
                .block_scope => |body| {
                    for (body) |item| {
                        item.free(allocator);
                    }
                    allocator.free(body);
                },
                .defvar => |def| {
                    if (def.value) |value| {
                        value.free(allocator);
                        allocator.destroy(value);
                    }
                },
                .sexp => {},
                .returnStmt => {
                    if (self.returnStmt) |returnStmt| {
                        returnStmt.free(allocator);
                        allocator.destroy(returnStmt);
                    }
                },
            }
        }

        pub fn print(self: @This(), indent: usize, ctx: *sexp.Sexp.ParsingContext) void {
            const indent_raw = " " ** 30;
            std.debug.assert(indent < indent_raw.len);
            const indent_str = indent_raw[0..indent];
            switch (self) {
                .defun => |defun| {
                    std.debug.print("{s}defun {s}:\n{s}  args:\n", .{ indent_str, defun.name, indent_str });
                    for (defun.args) |arg| {
                        std.debug.print("{s}    {s}:\n", .{ indent_str, arg.name });
                        ctx.print(arg.typ, indent + 6);
                        std.debug.print("\n", .{});
                    }
                    std.debug.print("{s}  return type:\n", .{ indent_str });
                    ctx.print(defun.ret_type, indent + 4);
                    std.debug.print("\nbody:\n", .{});
                    for (defun.body) |body| {
                        body.print(indent + 4, ctx);
                    }
                },
                .symbol => |symbol| {
                    std.debug.print("{s}symbol {s}\n", .{ indent_str, symbol.name });
                },
                .string => |string| {
                    std.debug.print("{s}string {s}\n", .{ indent_str, string.name });
                },
                .int_value => |int_value| {
                    std.debug.print("{s}int_value {}\n", .{ indent_str, int_value });
                },
                .float_value => |float_value| {
                    std.debug.print("{s}float_value {}\n", .{ indent_str, float_value });
                },
                .bool_value => |bool_value| {
                    std.debug.print("{s}bool_value {}\n", .{ indent_str, bool_value });
                },
                .call => |call| {
                    std.debug.print("{s}call {s}\n", .{ indent_str, call.name });
                    for (call.args) |arg| {
                        arg.print(indent + 2, ctx);
                    }
                },
                .block_scope => |body| {
                    std.debug.print("begin:\n", .{});
                    for (body) |item| {
                        item.print(indent + 2, ctx);
                    }
                },
                .defvar => |defvar| {
                    if (defvar.value) |value| {
                        _ = value;
                        std.debug.print("{s}defvar {s} =\n", .{ indent_str, defvar.name });
                        // if (ExprT(X) == SexpIndex.Node) {
                        //     value.print(indent + 2, ctx);
                        // }
                    } else {
                        std.debug.print("{s}defvar {s} uninitialized\n", .{ indent_str, defvar.name });
                    }
                },
                .returnStmt => |returnStmt| {
                    if (returnStmt) |value| {
                        std.debug.print("{s}returnStmt:\n", .{ indent_str });
                        value.print(indent + 2, ctx);
                    } else {
                        std.debug.print("{s}return\n", .{ indent_str });
                    }
                },
                .sexp => |sexp_idx| {
                    ctx.print(sexp_idx, indent);
                },
            }
        }

    };
}

pub const LLParser = struct {
    fn Id(comptime T: type) type {
        return T;
    }
    pub const UnresolvedLLAst = LLAst(Id, SexpIndex.Node);

    allocator: Allocator,
    sexpCtx: *sexp.Sexp.ParsingContext,

    pub fn init(sexpCtx: *sexp.Sexp.ParsingContext, allocator: Allocator) LLParser {
        return LLParser{
            .sexpCtx = sexpCtx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LLParser) void {
        _ = self;
    }

    pub fn parse(self: *LLParser, root: SexpIndex.Node) !UnresolvedLLAst {
        const tags = self.sexpCtx.nodesItems(.tag);
        const data = self.sexpCtx.nodesItems(.data);
        switch (tags.get(root)) {
            .symbol => {
                return .{ .symbol = .{ .name = self.sexpCtx.getString(data.get(root).symbol) } };
            },
            .string => {
                return .{ .string = .{ .name = self.sexpCtx.getString(data.get(root).string) } };
            },
            .int_value => return .{ .int_value = data.get(root).int_value },
            .float_value => return .{ .float_value = data.get(root).float_value },
            .bool_value => return .{ .bool_value = data.get(root).bool_value },
            .list => {
                const items = self.sexpCtx.getList(data.get(root).list);
                std.debug.assert(items.len > 0);
                const fst = blk: {
                    switch (tags.get(items[0])) {
                        .symbol => {
                            break :blk self.sexpCtx.getString(data.get(items[0]).symbol);
                        },
                        else => {
                            return error.InvalidCall;
                        },
                    }
                };
                const Case = enum {
                    defun,
                    begin,
                    defvar,
                    @"return",
                };

                const cs: Case = std.meta.stringToEnum(Case, fst) orelse {
                    var args = std.ArrayList(UnresolvedLLAst).initCapacity(self.allocator, items.len - 1) catch unreachable;
                    for (items[1..]) |item| {
                        args.appendAssumeCapacity(try self.parse(item));
                    }
                    return .{ .call = .{ .name = fst, .args = try args.toOwnedSlice() } };
                };

                switch (cs) {
                    .defun => {
                        const defunArgs = items[1..];
                        std.debug.assert(defunArgs.len >= 3);
                        const retType = defunArgs[0];
                        const name = blk: {
                            const nameIdx = defunArgs[1];
                            std.debug.assert(tags.get(nameIdx) == .symbol);
                            break :blk self.sexpCtx.getString(data.get(nameIdx).symbol);
                        };
                        const args = blk: {
                            const argsIdx = defunArgs[2];

                            std.debug.assert(tags.get(argsIdx) == .list);
                            const argsItems = self.sexpCtx.getList(data.get(argsIdx).list);

                            var argsList = std.ArrayList(UnresolvedLLAst.Defun.Arg).initCapacity(self.allocator, argsItems.len) catch unreachable;
                            for (argsItems) |item| {
                                std.debug.assert(tags.get(item) == .list);
                                const argPair = self.sexpCtx.getList(data.get(item).list);
                                std.debug.assert(argPair.len == 2);
                                const argNameIdx = argPair[0];
                                std.debug.assert(tags.get(argNameIdx) == .symbol);
                                const argName = self.sexpCtx.getString(data.get(argNameIdx).symbol);
                                argsList.appendAssumeCapacity(.{ .typ = argPair[1], .name = argName });
                            }
                            break :blk try argsList.toOwnedSlice();
                        };
                        const body = blk: {
                            const bodyItems = defunArgs[3..];
                            var bodyList = std.ArrayList(UnresolvedLLAst).initCapacity(self.allocator, bodyItems.len) catch unreachable;
                            for (bodyItems) |item| {
                                bodyList.appendAssumeCapacity(try self.parse(item));
                            }
                            break :blk try bodyList.toOwnedSlice();
                        };
                        return .{ .defun = .{ .name = name, .ret_type = retType, .args = args, .body = body } };
                    },
                    .begin => {
                        std.debug.assert(items.len > 1);
                        const body = blk: {
                            const bodyItems = items[1..];
                            var bodyList = std.ArrayList(UnresolvedLLAst).initCapacity(self.allocator, bodyItems.len) catch unreachable;
                            for (bodyItems) |item| {
                                bodyList.appendAssumeCapacity(try self.parse(item));
                            }
                            break :blk try bodyList.toOwnedSlice();
                        };
                        return .{ .block_scope = body };
                    },
                    .defvar => {
                        std.debug.assert(items.len >= 3);
                        const name = blk: {
                            const nameIdx = items[1];
                            std.debug.assert(tags.get(nameIdx) == .symbol);
                            break :blk self.sexpCtx.getString(data.get(nameIdx).symbol);
                        };
                        const typIdx = items[2];
                        const value = if (items.len > 2) blk: {
                            const valueIdx = items[2];
                            const ptr = self.allocator.create(UnresolvedLLAst) catch unreachable;
                            ptr.* = try self.parse(valueIdx);
                            break :blk ptr;
                        } else null;
                        return .{ .defvar = .{ .name = name, .typ = typIdx, .value = value } };
                    },
                    .@"return" => {
                        std.debug.assert(items.len == 1 or items.len == 2);
                        const value = blk: {
                            if (items.len == 1) {
                                break :blk null;
                            }
                            const ptr = self.allocator.create(UnresolvedLLAst) catch unreachable;
                            ptr.* = try self.parse(items[1]);
                            break :blk ptr;
                        };
                        return .{ .returnStmt = value };
                    },
                }
            },
        }
    }
};
