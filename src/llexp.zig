const std = @import("std");
const keystone = @import("keystone");
const qbe = @import("qbe.zig");
const sexp = @import("sexp.zig");
const Allocator = std.mem.Allocator;
const SexpIndex = sexp.Sexp.ParsingContext.Index;
const pretty = @import("pretty");

const Interner = sexp.Interner;
const Indexes = Interner.Indexes;

fn dump_and_fail(value: anytype) noreturn {
    pretty.print(std.heap.page_allocator, value, .{}) catch unreachable;
    unreachable;
}

pub const LLType = struct {
    pub const Tag = enum(u8) {
        number_literal,
        pointer,
        struct_,
        function,
    };
    pub const Data = union {
        number_literal: struct {
            negative: bool,
            float: bool,
        },
        pointer: TypeInterner.Index,
        struct_: StructType,
        function: Function,
    };

    tag: Tag,
    data: Data,

    fn AstT(comptime T: type) type {
        return struct {
            ast: T,
            typ: TypeInterner.Index,

            pub const Ast = T;

            pub fn copyAs(self: *const @This(), comptime ResT: type) ResT {
                return .{
                    .ast = self.ast,
                    .typ = self.typ,
                };
            }
        };
    }

    pub const TypeInterner = struct {
        pub var g: *@This() = undefined;

        allocator: Allocator,
        types: std.MultiArrayList(LLType),

        pub fn init(allocator: Allocator) *@This() {
            const ptr = allocator.create(@This()) catch unreachable;
            ptr.* = .{
                .types = .{},
                .allocator = allocator,
            };
            ptr.types.ensureUnusedCapacity(allocator, Index.offset) catch unreachable;
            for (0..Index.offset) |_| {
                _ = ptr.types.addOneAssumeCapacity();
            }
            std.debug.assert(ptr.types.len == Index.offset);
            return ptr;
        }

        pub fn deinit(self: *@This()) void {
            self.types.deinit(self.allocator);
            self.allocator.destroy(self);
        }

        pub fn intern(self: *@This(), typ: LLType) Index {
            const idx: Index = @enumFromInt(self.types.len);
            self.types.append(self.allocator, typ) catch unreachable;
            return idx;
        }

        pub const Index = enum(u32) {
            any,

            void,
            bool,

            u8,
            u16,
            u32,
            u64,

            i8,
            i16,
            i32,
            i64,

            f32,
            f64,

            number_literal,
            negative_number_literal,
            float_number_literal,
            negative_float_number_literal,

            _,

            const offset = blk: {
                var max = 0;

                for (@typeInfo(Index).@"enum".fields) |field| {
                    max = @max(max, field.value);
                }

                break :blk max + 1;
            };

            const Impl = struct {
                const DataField = std.meta.FieldEnum(LLType.Data);
                fn FieldType(comptime field: DataField) type {
                    return std.meta.fieldInfo(LLType.Data, field).type;
                }

                pub fn intInfo(comptime self: Index) struct {signed: bool, bits: u8} {
                    return switch (self) {
                        .i8 => .{ .signed = true, .bits = 8 },
                        .u8 => .{ .signed = false, .bits = 8 },
                        .i16 => .{ .signed = true, .bits = 16 },
                        .u16 => .{ .signed = false, .bits = 16 },
                        .i32 => .{ .signed = true, .bits = 32 },
                        .u32 => .{ .signed = false, .bits = 32 },
                        .i64 => .{ .signed = true, .bits = 64 },
                        .u64 => .{ .signed = false, .bits = 64 },
                        else => @compileError("unsupported integer type"),
                    };
                }

                pub fn floatInfo(comptime self: Index) struct {bits: u8} {
                    return switch (self) {
                        .f32 => .{ .bits = 32 },
                        .f64 => .{ .bits = 64 },
                        else => @compileError("unsupported float type"),
                    };
                }

                pub fn numberLiteralInfo(comptime self: Index) struct {negative: bool, float: bool} {
                    return switch (self) {
                        .number_literal => .{ .negative = false, .float = false },
                        .negative_number_literal => .{ .negative = true, .float = false },
                        .float_number_literal => .{ .negative = false, .float = true },
                        .negative_float_number_literal => .{ .negative = true, .float = true },
                        else => @compileError("unsupported number literal type"),
                    };
                }
            };

            pub fn forceData(self: Index, comptime f: Impl.DataField) Impl.FieldType(f) {
                return @field(self.in(TypeInterner.g.types.items(.data)), std.meta.fieldInfo(LLType.Data, f).name);
            }

            fn SliceItem(comptime T: type) type {
                const t = @typeInfo(T);
                std.debug.assert(t == .pointer);
                const p = t.pointer;
                std.debug.assert(p.size == .slice);
                return p.child;
            }

            pub inline fn in(self: Index, items: anytype) SliceItem(@TypeOf(items)) {
                return items[@intFromEnum(self)];
            }

            pub inline fn isVoid(self: Index) bool {
                return self == Index.void;
            }

            pub fn sizeBytes(self: Index) usize {
                return switch (self) {
                    .void => 0,
                    .bool => 1,

                    .u8  => 1,
                    .u16 => 2,
                    .u32 => 4,
                    .u64 => 8,

                    .i8  => 1,
                    .i16 => 2,
                    .i32 => 4,
                    .i64 => 8,

                    .f32 => 4,
                    .f64 => 8,

                    else => switch (self.in(TypeInterner.g.types.items(.tag))) {
                        .number_literal => unreachable,
                        .pointer => return 8,
                        .struct_ => return self.in(TypeInterner.g.types.items(.data)).struct_.sizeBytes(),
                        .function => return 8,
                    }
                };

            }

            fn alignment(self: Index) usize {
                return switch (self) {
                    inline .u8, .i8, .u16, .i16, .u32, .i32, .u64, .i64 => |int| @intCast(Impl.intInfo(int).bits / 8),
                    inline .f32, .f64 => |float| @intCast(Impl.floatInfo(float).bits / 8),
                    .pointer => return 8,
                    .struct_ => |struct_| return struct_.alignment(),
                    .void => return 0,
                };
            }

            pub fn acceptsType(expected: Index, actual: Index) bool {
                if (expected == actual) {
                    return true;
                }
                switch (expected) {
                    inline .u8, .i8, .u16, .i16, .u32, .i32, .u64, .i64 => |expected_| {
                        const int = Impl.intInfo(expected_);
                        switch (actual) {
                            inline .u8, .i8, .u16, .i16, .u32, .i32, .u64, .i64 => |other_| {
                                const other_int = Impl.intInfo(other_);
                                return int.signed == other_int.signed and int.bits == other_int.bits;
                            },
                            inline .number_literal, .negative_number_literal, .float_number_literal, .negative_float_number_literal => |other_| {
                                const other_int = Impl.numberLiteralInfo(other_);
                                if (other_int.float) return false;
                                if (other_int.negative) return int.signed;

                                // TODO: check for overflow
                                return true;
                            },
                            else => {
                                return false;
                            },
                        }
                    },
                    .number_literal => {
                        switch (actual) {
                            .number_literal => {
                                const num = expected.forceData(.number_literal);
                                const other_num = actual.forceData(.number_literal);
                                if (num.float != other_num.float) {
                                    return false;
                                }
                                if (num.negative != other_num.negative) {
                                    return false;
                                }
                                return true;
                            },
                            .u8, .i8, .u16, .i16, .u32, .i32, .u64, .i64 => {
                                return actual.acceptsType(expected);
                            },
                            else => {
                                unreachable;
                            },
                        }
                    },
                    else => {
                        std.debug.print("Unknown type: {any}\n", .{expected});
                        unreachable;
                    }
                }
            }
        };
    };

    pub const TypedAst = AstT(LLAst(AstT, TypeInterner.Index));

    pub const StructType = struct {
        name: Indexes.String,
        fields: []Field,

        pub fn sizeBytes(self: *const StructType) usize {
            var sz: usize = 0;
            for (self.fields) |field| {
                sz = sexp.nextAlignment(sz, field.typ.alignment());
                sz += field.typ.sizeBytes();
            }
            return sz;
        }

        pub fn indexOf(self: *const StructType, fieldName: Indexes.String) ?usize {
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
                offset = sexp.nextAlignment(offset, field.typ.alignment());
                if (i == index) {
                    return offset;
                }
                offset += field.typ.sizeBytes();
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
            typ: TypeInterner.Index,
            name: Indexes.String,
        };
    };

    pub const Function = struct {
        name: Indexes.String,
        return_type: TypeInterner.Index,
        params: []Param,

        pub const Param = struct {
            name: Indexes.String,
            typ: TypeInterner.Index,
        };
    };

    pub const TypesContext = struct {
        allocator: Allocator,
        sexpCtx: *sexp.Sexp.ParsingContext,
        types: std.AutoHashMap(Indexes.String, TypeInterner.Index),

        pub fn init(sexpCtx: *sexp.Sexp.ParsingContext, allocator: Allocator) @This() {
            var types = std.AutoHashMap(Indexes.String, TypeInterner.Index).init(allocator);

            types.put(Interner.Strings.g.pushString("void"), TypeInterner.Index.void) catch unreachable;
            types.put(Interner.Strings.g.pushString("bool"), TypeInterner.Index.bool) catch unreachable;

            types.put(Interner.Strings.g.pushString("i8"), TypeInterner.Index.i8) catch unreachable;
            types.put(Interner.Strings.g.pushString("i16"), TypeInterner.Index.i16) catch unreachable;
            types.put(Interner.Strings.g.pushString("i32"), TypeInterner.Index.i32) catch unreachable;
            types.put(Interner.Strings.g.pushString("i64"), TypeInterner.Index.i64) catch unreachable;

            types.put(Interner.Strings.g.pushString("u8"), TypeInterner.Index.u8) catch unreachable;
            types.put(Interner.Strings.g.pushString("u16"), TypeInterner.Index.u16) catch unreachable;
            types.put(Interner.Strings.g.pushString("u32"), TypeInterner.Index.u32) catch unreachable;
            types.put(Interner.Strings.g.pushString("u64"), TypeInterner.Index.u64) catch unreachable;

            types.put(Interner.Strings.g.pushString("f32"), TypeInterner.Index.f32) catch unreachable;
            types.put(Interner.Strings.g.pushString("f64"), TypeInterner.Index.f64) catch unreachable;

            return .{
                .sexpCtx = sexpCtx,
                .types = types,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *@This()) void {
            self.types.deinit();
        }

        pub fn resolveRef(self: *@This(), ref: Indexes.String) !TypeInterner.Index {
            const idx = self.types.get(ref) orelse {
                return error.UnknownType;
            };
            return idx;
        }

        pub fn pushType(self: *@This(), name: Indexes.String, ty: TypeInterner.Index) !void {
            self.types.put(name, ty) catch unreachable;
        }

        pub const JitContext = struct {
            var globalThis: ?*@This() = null;

            pub const CompiledFunction = struct {
                name: Indexes.String,
                code: []const align(std.mem.page_size)u8,
                fn_type: LLType.Function,

                pub fn deinit(self: *const @This()) void {
                    std.posix.munmap(self.code);
                }
            };
            pub const BuiltinFunction = struct {
                name: Indexes.String,
                ptr: *void,
            };
            pub const Func = union(enum) {
                builtin: BuiltinFunction,
                compiled: CompiledFunction,
            };

            ctx: *TypesContext,
            functions: std.AutoHashMap(Indexes.String, Func),
            ks: *keystone.ks_engine,

            const Builtins = struct {
                fn print_int(i: u32) callconv(.C) void {
                    std.debug.print("print_int: {d}\n", .{i});
                }
            };

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
                    .functions = std.AutoHashMap(Indexes.String, Func).init(ctx.allocator),
                    .ks = ks,
                };
                globalThis = ptr;

                {
                    const n = Interner.Strings.g.pushString("print_int");
                    ptr.functions.put(n, .{
                        .builtin = .{
                            .name = n,
                            .ptr = @constCast(@ptrCast(&Builtins.print_int)),
                        }
                    }) catch unreachable;
                    const params = ctx.allocator.dupe(Function.Param, &[_]Function.Param{
                        .{
                            .name = n,
                            .typ = TypeInterner.Index.u32,
                        }
                    }) catch unreachable;
                    const x: TypeInterner.Index = TypeInterner.g.intern(.{
                        .tag = .function,
                        .data = .{
                            .function = .{
                                .name = n,
                                .return_type = TypeInterner.Index.void,
                                .params = @constCast(params),
                            },
                        },
                    });
                    // std.debug.print("putting {s}: {any}\n", .{ "print_int", x });
                    ctx.types.put(n, x) catch unreachable;
                }
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

            fn resolveSymbol(self: *@This(), symbol: Indexes.String, value: [*c]u64) bool {
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
                const n = Interner.Strings.g.pushString(s);
                return globalThis.?.resolveSymbol(n, value);
            }

            pub fn compile(self: *@This(), func: TypedAst, allocator: Allocator) !CompiledFunction {
                var compiler = Compiler.init(self, allocator);
                defer compiler.deinit();

                return compiler.compile(func);
            }

            pub const Compiler = struct {
                const Scope = std.AutoHashMapUnmanaged(Indexes.String, ValueRef);
                jitCtx: *JitContext,
                qbeState: struct {
                    fdin: std.posix.fd_t,
                    writer: std.fs.File.Writer,
                },
                scopes: std.ArrayListUnmanaged(Scope) = .{},
                globals_to_process: std.AutoHashMapUnmanaged(Indexes.String, struct { name: ValueRef, typ: TypeInterner.Index, ref: ValueRef }) = .{},
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

                pub fn pushIntoScope(self: *@This(), name: Indexes.String, typ: ValueRef) void {
                    std.debug.assert(self.scopes.items.len > 0);
                    var scope = &self.scopes.items[self.scopes.items.len - 1];
                    std.debug.assert(!scope.contains(name));
                    scope.put(self.allocator, name, typ) catch unreachable;
                }

                pub fn lookup(self: *@This(), name: Indexes.String) ?ValueRef {
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

                fn t2s(self: *@This(), typ: TypeInterner.Index) []const u8 {
                    _ = self;
                    return switch (typ) {
                        .i32, .u32 => "w",
                        .i64, .u64 => "l",
                        .f32, .f64, .bool, .i8, .u8, .i16, .u16 => {
                            unreachable;
                        },
                        // TODO: This should not be here :)
                        .void => "l",
                        .number_literal, .negative_number_literal, .float_number_literal, .negative_float_number_literal => {
                            dump_and_fail(.{error.NumberLiteralIsNotSupported});
                        },
                        else => switch (typ.in(TypeInterner.g.types.items(.tag))) {
                            .pointer => "l",
                            .function => "l",
                            else => {
                                dump_and_fail(.{typ});
                            }
                        },
                    };
                }

                fn emitQBE(self: *@This(), defun: TypedAst.Ast.Defun, fn_type: LLType.Function) !void {
                    self.newScope();
                    self.format("function {s} ${s}(", .{self.t2s(fn_type.return_type), defun.name.asString()});
                    for (fn_type.params, 0..) |param, i| {
                        if (i > 0) {
                            self.format(", ", .{});
                        }
                        self.format("{s} %arg_{s}", .{self.t2s(param.typ), param.name.asString()});
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
                    arg: Indexes.String,
                    global: Indexes.String,
                    external_global: Indexes.String,
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
                                try std.fmt.format(writer, "%arg_{s}", .{arg.asString()});
                            },
                            .global => |global| {
                                try std.fmt.format(writer, "${s}", .{global.asString()});
                            },
                            .external_global => |global| {
                                try std.fmt.format(writer, "$ref_{s}", .{global.asString()});
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
                            const callName = call.name.asString();
                            const builtin = std.meta.stringToEnum(Builtin, callName) orelse {
                                const fnType = self.jitCtx.ctx.types.get(call.name) orelse {
                                    dump_and_fail(.{.call = call});
                                };
                                std.debug.assert(fnType.in(TypeInterner.g.types.items(.tag)) == .function);
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
                                for (args.items, fnType.forceData(.function).params, 0..) |arg, param, i| {
                                    if (i == 0) {
                                        self.format("{s} {any}", .{ self.t2s(param.typ), arg });
                                    } else {
                                        self.format(", {s} {any}", .{ self.t2s(param.typ), arg });
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

                fn qbeAssign(self: *@This(), place: ValueRef, typ: TypeInterner.Index) !void {
                    self.format("{any} ={s} ", .{ place, self.t2s(typ) });
                }

                fn getTemporary(self: *@This()) ValueRef {
                    defer self.vari += 1;
                    return .{ .local = self.vari };
                }

                fn qbeAssignTemporary(self: *@This(), typ: TypeInterner.Index) !ValueRef {
                    const place = self.getTemporary();
                    try self.qbeAssign(place, typ);
                    return place;
                }

                extern "c" fn fdopen(fd: c_int, mode: [*:0]const u8) ?*std.c.FILE;
                pub fn compile(self: *@This(), func: TypedAst) !CompiledFunction {
                    const defun = func.ast.defun;
                    const funcType = func.typ.forceData(.function);

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
                        self.format("data {any} = {{ {s} {any} }}\n", .{glb.name, self.t2s(glb.typ), glb.ref});
                    }

                    {
                        const out_size = try std.posix.lseek_CUR_get(self.qbeState.fdin);
                        const out_mem = try std.posix.mmap(null, out_size, std.posix.PROT.READ | std.posix.PROT.WRITE, std.posix.MAP{ .TYPE = .SHARED }, self.qbeState.fdin, 0);
                        defer std.posix.munmap(out_mem);
                        // std.debug.print("{s}\n", .{out_mem});
                        // dump_and_fail(out_mem);
                    }

                    // unreachable;

                    const instructions = try self.qbeCompile(defun.name);
                    // std.debug.print("{s}\n", .{instructions.mmap});
                    defer instructions.deinit();
                    const fn_mem = try self.jitCode(instructions.code);
                    return .{
                        .name = defun.name,
                        .code = fn_mem,
                        .fn_type = funcType,
                    };
                }

                fn qbeCompile(self: *@This(), entrypoint: Indexes.String) !qbe.CompiledInstructions {
                    return qbe.compile(self.qbeState.fdin, entrypoint.asString());
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
            const Scope = std.AutoHashMap(Indexes.String, TypeInterner.Index);
            scopes: std.ArrayList(Scope),
            ctx: *TypesContext,
            current_fn: ?LLType.Function = null,

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

            pub fn pushIntoScope(self: *@This(), name: Indexes.String, typ: TypeInterner.Index) void {
                std.debug.assert(self.scopes.items.len > 0);
                var scope = &self.scopes.items[self.scopes.items.len - 1];
                std.debug.assert(!scope.contains(name));
                scope.put(name, typ) catch unreachable;
            }

            pub fn lookup(self: *@This(), name: Indexes.String) ?TypeInterner.Index {
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

                const return_type = try self.ctx.parseTypeReference(defun.ret_type);

                // TODO: DO NOT USE TypedAst here. Create a new union type to fix this shit.
                var params = std.ArrayList(LLType.Function.Param).init(self.ctx.allocator);
                errdefer params.deinit();
                var args = std.ArrayList(TypedAst.Ast.Defun.Arg).init(self.ctx.allocator);
                errdefer args.deinit();

                for (defun.args) |arg| {
                    const arg_type = try self.ctx.parseTypeReference(arg.typ);
                    self.pushIntoScope(arg.name, arg_type);
                    params.append(.{
                        .name = arg.name,
                        .typ = arg_type,
                    }) catch unreachable;
                    args.append(.{
                        .name = arg.name,
                        .typ = arg_type,
                    }) catch unreachable;
                }

                const ft: LLType.Function = .{
                    .name = name,
                    .return_type = return_type,
                    .params = try params.toOwnedSlice(),
                };

                const current_fn = self.current_fn;
                defer self.current_fn = current_fn;

                self.current_fn = ft;

                var body = std.ArrayList(TypedAst).init(self.ctx.allocator);
                errdefer body.deinit();

                var ret: TypeInterner.Index = .void;
                for (defun.body, 0..) |statement, i| {
                    const last = i == defun.body.len - 1;
                    const stmt = try self.typeCheckImpl(&statement, if (return_type != .void and last) return_type else .any);
                    body.append(stmt) catch unreachable;
                    ret = stmt.typ;
                }

                if (!return_type.isVoid()) {
                    try self.ctx.assertAcceptableType(ft.return_type, ret);
                }

                self.closeScope();

                const fn_type = TypeInterner.g.intern(
                    .{
                        .tag = .function,
                        .data = .{
                            .function = ft,
                        },
                    },
                );
                self.pushIntoScope(name, fn_type);
                try self.ctx.pushType(name, fn_type);

                return .{
                    .ast = .{
                        .defun = .{
                            .name = name,
                            .ret_type = return_type,
                            .args = try args.toOwnedSlice(),
                            .body = try body.toOwnedSlice(),
                        },
                    },
                    .typ = fn_type,
                };
            }

            pub fn typeCheck(self: *@This(), root: *const LLParser.UnresolvedLLAst) !TypedAst {
                std.debug.assert(self.scopes.items.len == 0);
                self.newScope();
                defer {
                    self.closeScope();
                    std.debug.assert(self.scopes.items.len == 0);
                }
                return self.typeCheckImpl(root, .any);
            }

            fn typeCheckImpl(self: *@This(), root: *const LLParser.UnresolvedLLAst, expectedType: TypeInterner.Index) !TypedAst {
                std.debug.assert(expectedType != .void);
                switch (root.*) {
                    .defun => |defun| {
                        std.debug.assert(expectedType == .any);
                        return try self.typeCheckDefun(defun);
                    },
                    .returnStmt => |returnExpr| {
                        std.debug.assert(self.current_fn != null);
                        const returnType = self.current_fn.?.return_type;
                        switch (returnType) {
                            .void => {
                                std.debug.assert(returnExpr == null);
                                return .{
                                    .ast = .{ .returnStmt = null },
                                    .typ = TypeInterner.Index.void,
                                };
                            },
                            else => {
                                const returnTypeChecked = self.ctx.allocator.create(TypedAst) catch unreachable;
                                returnTypeChecked.* = try self.typeCheckImpl(returnExpr.?, returnType);
                                try self.ctx.assertAcceptableType(returnTypeChecked.typ, returnType);
                                return .{
                                    .ast = .{ .returnStmt = returnTypeChecked },
                                    .typ = returnType,
                                };
                            },
                        }
                    },
                    .call => |call| {
                        const Case = enum {
                            @"+",
                        };

                        const callName = call.name.asString();
                        const cs: Case = std.meta.stringToEnum(Case, callName) orelse {
                            const fnType = self.lookup(call.name) orelse {
                                std.debug.print("Unknown symbol [{s}]\n", .{callName});
                                return error.UnknownSymbol;
                            };
                            switch (fnType.in(TypeInterner.g.types.items(.tag))) {
                                .function => {
                                    var args = std.ArrayList(TypedAst).init(self.ctx.allocator);
                                    errdefer args.deinit();

                                    const function = fnType.in(TypeInterner.g.types.items(.data)).function;

                                    for (function.params, call.args) |param, arg| {
                                        const argTyped = try self.typeCheckImpl(&arg, param.typ);
                                        try self.ctx.assertAcceptableType(argTyped.typ, param.typ);
                                        args.append(argTyped) catch unreachable;
                                    }

                                    std.debug.assert(function.params.len == args.items.len);

                                    return .{
                                        .ast = .{
                                            .call = .{
                                                .name = call.name,
                                                .args = try args.toOwnedSlice(),
                                            },
                                        },
                                        .typ = function.return_type,
                                    };
                                },
                                else => {
                                    return error.NotAFunction;
                                },
                            }
                        };

                        switch (cs) {
                            .@"+" => {
                                var args = std.ArrayList(TypedAst).init(self.ctx.allocator);
                                errdefer args.deinit();
                                for (call.args) |arg| {
                                    const argTyped = try self.typeCheckImpl(&arg, .any);
                                    args.append(argTyped) catch unreachable;
                                }

                                const fst = args.items[0];
                                const typs = &[_]TypeInterner.Index { .i32, .u32 };
                                const typ = blk: inline for (typs) |typ| {
                                    if (fst.typ.acceptsType(typ)) {
                                        break :blk typ;
                                    }
                                } else {
                                    return error.InvalidType;
                                };

                                for (args.items[1..]) |*arg| {
                                    try self.ctx.assertAcceptableType(arg.typ, typ);
                                    switch (arg.typ) {
                                        .number_literal, .negative_number_literal, .float_number_literal, .negative_float_number_literal => {
                                            arg.typ = typ;
                                        },
                                        else => {},
                                    }
                                }

                                return .{
                                    .ast = .{
                                        .call = .{
                                            .name = call.name,
                                            .args = try args.toOwnedSlice(),
                                        }
                                    },
                                    .typ = typ,
                                };
                            },
                        }
                    },
                    .symbol => |symbol| {
                        const typ = self.lookup(symbol.name) orelse {
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
                            .typ = blk: {
                                if (int_value < 0) {
                                    break :blk TypeInterner.Index.negative_number_literal;
                                } else {
                                    break :blk TypeInterner.Index.number_literal;
                                }
                            },
                        };
                    },
                    .block_scope => |statements| {
                        dump_and_fail(root);
                        var ret = self.ctx.types.get("void") orelse unreachable;
                        var checkedStatements = try std.ArrayList(TypedAst).initCapacity(self.ctx.allocator, statements.len);
                        self.newScope();
                        for (statements, 0..) |stmt, i| {
                            const x = try self.typeCheckImpl(&stmt, if (expectedType != .void and i == statements.len - 1) expectedType else .any);
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

        pub fn assertAcceptableType(self: *@This(), expr: TypeInterner.Index, expected: TypeInterner.Index) !void {
            _ = self;
            // if (expr.is(expected)) {
            //     return;
            // }
            if (expected.acceptsType(expr)) {
                return;
            }
            return error.TypeMismatch; // TODO: better error message
        }

        pub fn parseTypeReference(self: *@This(), root: SexpIndex.Node) !TypeInterner.Index {
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
                    const name = data.get(root).symbol;
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
            name: Indexes.String,
            ret_type: TypT,
            args: []Arg,
            body: []ExprT(Self),

            pub const Arg = struct {
                name: Indexes.String,
                typ: TypT,
            };
        };

        defun: Defun,
        symbol: struct {
            name: Indexes.String,
        },
        string: struct {
            name: Indexes.String,
        },
        call: struct {
            name: Indexes.String,
            args: []ExprT(Self),
        },
        int_value: isize,
        float_value: f64,
        bool_value: bool,
        sexp: SexpIndex.Node,
        block_scope: []ExprT(Self),
        defvar: struct {
            name: Indexes.String,
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
                    std.debug.print("{s}defun {s}:\n{s}  args:\n", .{ indent_str, defun.name.asString(), indent_str });
                    for (defun.args) |arg| {
                        std.debug.print("{s}    {s}:\n", .{ indent_str, arg.name.asString() });
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
                    std.debug.print("{s}symbol {s}\n", .{ indent_str, symbol.name.asString() });
                },
                .string => |string| {
                    std.debug.print("{s}string {s}\n", .{ indent_str, string.name.asString() });
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
                    std.debug.print("{s}call {s}\n", .{ indent_str, call.name.asString() });
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
                        std.debug.print("{s}defvar {s} =\n", .{ indent_str, defvar.name.asString() });
                        // if (ExprT(X) == SexpIndex.Node) {
                        //     value.print(indent + 2, ctx);
                        // }
                    } else {
                        std.debug.print("{s}defvar {s} uninitialized\n", .{ indent_str, defvar.name.asString() });
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
                return .{ .symbol = .{ .name = data.get(root).symbol } };
            },
            .string => {
                return .{ .string = .{ .name = data.get(root).string } };
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
                            break :blk data.get(items[0]).symbol;
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

                const cs: Case = std.meta.stringToEnum(Case, fst.asString()) orelse {
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
                            break :blk data.get(nameIdx).symbol;
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
                                const argName = data.get(argNameIdx).symbol;
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
                            break :blk data.get(nameIdx).symbol;
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
