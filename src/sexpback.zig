const std = @import("std");
const pretty = @import("pretty");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

fn dump_and_fail(value: anytype) noreturn {
    pretty.print(std.heap.page_allocator, value, .{}) catch unreachable;
    unreachable;
}

pub const Sexp = union(enum) {
    integer: u64,
    string: []const u8,
    atom: []const u8,
    list: []const *Sexp,

    pub fn print(self: *Sexp) void {
        switch (self.*) {
            .integer => |i| std.debug.print("Integer: {d}\n", .{i}),
            .string => |s| std.debug.print("String: {s}\n", .{s}),
            .atom => |a| std.debug.print("Atom: {s}\n", .{a}),
            .list => |l| {
                std.debug.print("List:|\n", .{});
                for (l) |item| {
                    item.print();
                }
                std.debug.print("|\n", .{});
            },
        }
    }

    pub const ParseError = error{
        ExpectedOpeningParenthesis,
    };

    pub const ParserContext = struct {
        allocator: Allocator,
        sexprs: std.ArrayListUnmanaged(*Sexp),

        pub fn init(allocator: Allocator) @This() {
            return @This() {
                .allocator = allocator,
                .sexprs = .{},
            };
        }

        pub fn deinit(self: *@This()) void {
            for (self.sexprs.items) |sexpr| {
                switch (sexpr.*) {
                    .list => |list| {
                        self.allocator.free(list);
                    },
                    .atom => |name| {
                        self.allocator.free(name);
                    },
                    .string => |str| {
                        self.allocator.free(str);
                    },
                    else => {},
                }
                self.allocator.destroy(sexpr);
            }
            self.sexprs.deinit(self.allocator);
        }

        pub fn parseAny(self: *@This(), input: []const u8) anyerror![] *Sexp {
            var parser = Parser {
                .ctx = self,
                .input = input,
            };
            return try parser.parseMany();
        }

        pub const Parser = struct {
            ctx: *ParserContext,
            input: []const u8,

            pub fn parseMany(self: *@This()) anyerror![] *Sexp {
                var exprs = std.ArrayList(*Sexp).init(self.ctx.allocator);
                while (self.input.len > 0) {
                    self.skipSpaces();
                    const expr = try self.parseExpr();

                    try exprs.append(expr);
                    self.skipSpaces();
                }
                return try exprs.toOwnedSlice();
            }

            pub fn skipSpaces(self: *@This()) void {
                while (self.input.len > 0) {
                    switch (self.input[0]) {
                        ' ', '\t', '\n' => {
                            self.eatChar();
                        },
                        ';' => {
                            while (self.input.len > 0) {
                                switch (self.input[0]) {
                                    '\n' => {
                                        self.eatChar();
                                        break;
                                    },
                                    else => {
                                        self.eatChar();
                                    },
                                }
                            }
                        },
                        else => return,
                    }
                }
            }

            pub fn parseExpr(self: *@This()) anyerror!*Sexp {
                switch (self.input[0]) {
                    ' ', '\t', '\n' => {
                        dump_and_fail(self);
                    },
                    '(' => {
                        return try self.parseList();
                    },
                    else => {
                        return try self.parseAtom();
                    },
                }
            }

            fn eatChar(self: *@This()) void {
                if (self.input.len > 0) {
                    self.input = self.input[1..];
                }
            }

            fn parseList(self: *@This()) anyerror!*Sexp {
                if (self.input[0] != '(') {
                    return error.ExpectedOpeningParenthesis;
                }
                self.eatChar();

                var list = std.ArrayList(*Sexp).init(self.ctx.allocator);

                self.skipSpaces();

                while (self.input.len > 0) {
                    switch (self.input[0]) {
                        ')' => {
                            break;
                        },
                        else => {
                            const item = try self.parseExpr();
                            try list.append(item);
                            self.skipSpaces();
                        },
                    }
                }

                if (self.input.len == 0 or self.input[0] != ')') {
                    return error.ExpectedClosingParenthesis;
                }
                self.eatChar();
                return try self.ctx.allocSexp(Sexp {
                    .list = try list.toOwnedSlice(),
                });
            }

            fn parseAtom(self: *@This()) anyerror!*Sexp {
                self.skipSpaces();

                switch (self.input[0]) {
                    '\'', '"' => |c| {
                        self.eatChar();
                        var str = std.ArrayList(u8).init(self.ctx.allocator);

                        while (self.input.len > 0) {
                            switch (self.input[0]) {
                                '\\' => {
                                    assert(self.input.len >= 2);
                                    switch (self.input[1]) {
                                        '\\' => {
                                            try str.append('\\');
                                        },
                                        'n' => {
                                            try str.append('\n');
                                        },
                                        else => {
                                            try str.append(self.input[1]);
                                        },
                                    }
                                    self.eatChar();
                                    self.eatChar();
                                },
                                else => |nc| {
                                    if (nc == c) {
                                        break;
                                    }

                                    // std.debug.print("nc: {c}\n", .{nc});
                                    try str.append(nc);
                                    self.eatChar();
                                },
                            }
                        }
                        assert(self.input.len > 0);
                        assert(self.input[0] == c);
                        self.eatChar();

                        return try self.ctx.allocSexp(Sexp {
                            .string = try str.toOwnedSlice(),
                        });
                    },
                    '0'...'9' => {
                        var i: usize = 0;
                        while (self.input.len > 0) {
                            switch (self.input[0]) {
                                '0'...'9' => {
                                    i = i * 10 + (self.input[0] - '0');
                                    self.eatChar();
                                },
                                else => break,
                            }
                        }

                        return try self.ctx.allocSexp(Sexp {
                            .integer = i,
                        });
                    },
                    'a'...'z', 'A'...'Z', '_', '-', '+', '=', '?', '!', '@', '#', '$', '%', '^', '&', '*', '/', '<', '>', '.', '~', '|', ',' => {
                        var atom = std.ArrayList(u8).init(self.ctx.allocator);

                        while (self.input.len > 0) {
                            switch (self.input[0]) {
                                'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '+', '=', '?', '!', '@', '#', '$', '%', '^', '&', '*', '/', '<', '>', '.', '~', '|', ',' => {
                                    try atom.append(self.input[0]);
                                    self.eatChar();
                                },
                                else => break,
                            }
                        }

                        if (atom.items.len == 0) {
                            return error.NotAnAtom;
                        }

                        return try self.ctx.allocSexp(Sexp {
                            .atom = try atom.toOwnedSlice(),
                        });
                    },
                    else => return error.NotAnAtom,
                }
            }
        };

        pub fn allocSexp(self: *@This(), sexpr: Sexp) anyerror!*Sexp {
            const ptr = try self.allocator.create(Sexp);
            ptr.* = sexpr;
            try self.sexprs.append(self.allocator, ptr);
            return ptr;
        }
    };

};
