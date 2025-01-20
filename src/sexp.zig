const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Sexp = struct {
    tag: Tag,
    data: Data,

    pub const Tag = enum(u8) {
        list,
        symbol,
        string,
        int_value,
        float_value,
        bool_value,
    };

    pub const Data = union {
        list: ParsingContext.Index.List,
        symbol: ParsingContext.Index.String,
        string: ParsingContext.Index.String,
        int_value: u32,
        float_value: f32,
        bool_value: bool,
    };

    pub const ParsingContext = struct {
        pub const Index = struct {
            pub const Node = enum(u32) {_};
            pub const String = enum(u32) {_};
            pub const List = enum(u32) {_};
        };

        pub const Slice = struct {
            start: usize,
            size: usize,
        };

        allocator: Allocator,
        impl: struct {
            strings_raw: std.ArrayList(u8),
            lists_raw: std.ArrayList(Index.Node),

            lists: std.ArrayList(Slice),
            strings: std.ArrayList(Slice),

            string_interner: std.StringHashMap(Index.String),

            nodes: std.MultiArrayList(Sexp),
            free_nodes: std.ArrayList(Index.Node),
        },

        pub fn init(allocator: Allocator) @This() {
            return .{
                .allocator = allocator,
                .impl = .{
                    .free_nodes = std.ArrayList(Index.Node).init(allocator),
                    .lists_raw = std.ArrayList(Index.Node).init(allocator),
                    .strings_raw = std.ArrayList(u8).init(allocator),
                    .lists = std.ArrayList(Slice).init(allocator),
                    .strings = std.ArrayList(Slice).init(allocator),
                    .string_interner = std.StringHashMap(Index.String).init(allocator),
                    .nodes = .{},
                },
            };
        }

        pub fn deinit(self: *@This()) void {
            self.impl.lists_raw.deinit();
            self.impl.strings_raw.deinit();
            self.impl.lists.deinit();
            self.impl.strings.deinit();
            self.impl.string_interner.deinit();
            self.impl.nodes.deinit(self.allocator);
            self.impl.free_nodes.deinit();
        }

        pub const Field = std.meta.FieldEnum(Sexp);

        fn FieldType(comptime field: Field) type {
            return std.meta.fieldInfo(Sexp, field).type;
        }

        pub fn IndexedBy(comptime indexT: anytype, comptime elementT: type) type {
            return struct {
                items: []elementT,
                pub inline fn get(self: *const @This(), idx: indexT) elementT {
                    return self.items[@intFromEnum(idx)];
                }
            };
        }

        pub inline fn listsItems(self: *@This()) IndexedBy(Index.List, Slice) {
            return .{ .items = self.impl.lists.items };
        }

        pub inline fn stringsItems(self: *@This()) IndexedBy(Index.String, Slice) {
            return .{ .items = self.impl.strings.items };
        }

        pub inline fn nodesItems(self: *@This(), comptime field: Field) IndexedBy(Index.Node, FieldType(field)) {
            return .{ .items = self.impl.nodes.items(field) };
        }

        pub inline fn getNode(self: *@This(), idx: Index.Node) Sexp {
            return self.impl.nodes.get(@intFromEnum(idx));
        }

        pub inline fn getString(self: *@This(), idx: Index.String) []const u8 {
            const slice = self.stringsItems().get(idx);
            return self.impl.strings_raw.items[slice.start..slice.start + slice.size];
        }

        pub inline fn getList(self: *@This(), idx: Index.List) []Index.Node {
            const slice = self.listsItems().get(idx);
            return self.impl.lists_raw.items[slice.start..slice.start + slice.size];
        }

        pub fn print(self: *@This(), idx: Index.Node, indent: usize) void {
            const indent_raw = " " ** 30;
            const indent_str = indent_raw[0..indent];
            const node = self.getNode(idx);
            std.debug.print("{s}", .{indent_str});
            switch (node.tag) {
                .list => {
                    const list_idx = node.data.list;
                    const items = self.getList(list_idx);
                    std.debug.print("(", .{});
                    for (items, 0..) |item, i| {
                        if (i > 0) {
                            std.debug.print(" ", .{});
                        }
                        self.print(item, 0);
                    }
                    std.debug.print(")", .{});
                },
                .symbol => {
                    std.debug.print("[symbol: {s}]", .{self.getString(node.data.symbol)});
                },
                .string => {
                    std.debug.print("[string: {s}]", .{self.getString(node.data.string)});
                },
                .int_value => {
                    std.debug.print("{}", .{node.data.int_value});
                },
                .float_value => {
                    std.debug.print("{}", .{node.data.float_value});
                },
                .bool_value => {
                    std.debug.print("{}", .{node.data.bool_value});
                },
            }
        }

        pub fn freeNode(self: *@This(), idx: Index.Node) !void {
            for (self.impl.free_nodes.items) |free_idx| {
                std.debug.assert(free_idx != idx);
            }

            self.impl.free_nodes.append(idx) catch unreachable;
            const node = self.getNode(idx);
            switch (node.tag) {
                .list => {
                    const list_idx = node.data.list;
                    const items = self.getList(list_idx);
                    for (items) |item| {
                        try self.freeNode(item);
                    }
                },
                .symbol => {},
                .string => {},
                .int_value => {},
                .float_value => {},
                .bool_value => {},
            }
        }

        pub fn createTopsIter(self: *@This(), source: []u8) SexpIter {
            return SexpIter.init(self, source);
        }

        pub fn push_list(self: *@This(), list: []Index.Node) Slice {
            const start = self.impl.lists_raw.items.len;
            self.impl.lists_raw.appendSlice(list) catch unreachable;
            return .{ .start = start, .size = @intCast(self.impl.lists_raw.items.len - start) };
        }

        pub fn push_slice(self: *@This(), list: []Index.Node) Index.List {
            const slice = self.push_list(list);
            const listidx = self.impl.lists.items.len;
            self.impl.lists.append(slice) catch unreachable;
            return @enumFromInt(listidx);
        }

        pub fn push_string(self: *@This(), str: []u8) Index.String {
            if (str.len < 16) {
                if (self.impl.string_interner.get(str)) |idx| {
                    return idx;
                }
            }
            const start = self.impl.strings_raw.items.len;
            self.impl.strings_raw.appendSlice(str) catch unreachable;
            const string_idx = self.impl.strings.items.len;
            self.impl.strings.append(.{ .start = start, .size = str.len }) catch unreachable;
            if (str.len < 16) {
                self.impl.string_interner.put(str, @enumFromInt(string_idx)) catch unreachable;
            }
            return @enumFromInt(string_idx);
        }

        pub fn push_node(self: *@This(), node: Sexp) Index.Node {
            if (self.impl.free_nodes.items.len > 0) {
                return self.impl.free_nodes.pop();
            }
            const idx = self.impl.nodes.len;
            self.impl.nodes.append(self.allocator, node) catch unreachable;
            return @enumFromInt(idx);
        }

        pub const SexpIter = struct {
            ctx: *ParsingContext,
            lexer: Lexer,
            temp_list: std.ArrayList(Index.Node),
            temp_scopes: std.ArrayList(usize),

            pub fn new_temp_scope(self: *@This()) !void {
                try self.temp_scopes.append(@intCast(self.temp_list.items.len));
            }

            pub fn current_temp_list(self: *@This()) []Index.Node {
                const scope_start = self.temp_scopes.items[self.temp_scopes.items.len - 1];
                return self.temp_list.items[scope_start..self.temp_list.items.len];
            }

            pub fn close_temp_scope(self: *@This()) void {
                const idx = self.temp_scopes.pop();
                while (self.temp_list.items.len > idx) {
                    _ = self.temp_list.pop();
                }
            }

            pub fn init(ctx: *ParsingContext, source: []u8) @This() {
                return .{
                    .ctx = ctx,
                    .lexer = Lexer.init(source, ctx.allocator),
                    .temp_list = std.ArrayList(Index.Node).init(ctx.allocator),
                    .temp_scopes = std.ArrayList(usize).init(ctx.allocator),
                };
            }

            pub fn deinit(self: *@This(), allocator: Allocator) void {
                self.temp_list.deinit();
                self.temp_scopes.deinit();
                self.lexer.deinit(allocator);
            }

            pub fn next(self: *@This()) !?Index.Node {
                if (try self.lexer.peek()) |_| {
                    return try self.parse();
                } else {
                    return null;
                }
            }

            pub fn parse(self: *@This()) !Index.Node {
                while (try self.lexer.next()) |token| {
                    switch (token) {
                        .int_value => {
                            return self.ctx.push_node(Sexp { .tag = .int_value, .data = .{ .int_value = token.int_value } });
                        },
                        .float_value => {
                            return self.ctx.push_node(Sexp { .tag = .float_value, .data = .{ .float_value = token.float_value } });
                        },
                        .bool_value => {
                            return self.ctx.push_node(Sexp { .tag = .bool_value, .data = .{ .bool_value = token.bool_value } });
                        },
                        .symbol => {
                            const x = self.ctx.push_string(self.lexer.string.?);
                            return self.ctx.push_node(Sexp { .tag = .symbol, .data = .{ .symbol = x } });
                        },
                        .str => {
                            return self.ctx.push_node(Sexp { .tag = .string, .data = .{ .string = self.ctx.push_string(self.lexer.string.?) } });
                        },
                        .r_paren => {
                            return error.UnexpectedRParen;
                        },
                        .l_paren => {
                            try self.new_temp_scope();

                            while (try self.lexer.peek()) |tok| {
                                switch (tok) {
                                    .r_paren => {
                                        _ = try self.lexer.next();
                                        const list_items = self.current_temp_list();
                                        const listidx = self.ctx.push_slice(list_items);
                                        self.close_temp_scope();
                                        const idx = self.ctx.push_node(.{ .tag = .list, .data = .{ .list = listidx } });
                                        return idx;
                                    },
                                    else => {
                                        const x = try self.parse();
                                        self.temp_list.append(x) catch unreachable;
                                    },
                                }
                            } else {
                                return error.ExpectedRParen;
                            }
                        },
                    }
                } else {
                    return error.NoMoreTokens;
                }
            }

            pub const Lexer = struct {
                const Self = @This();

                pub const Token = union(enum) {
                    l_paren: void,
                    r_paren: void,
                    symbol: void,
                    str: void,
                    bool_value: bool,
                    int_value: u32,
                    float_value: f32,
                };

                source: []u8,

                string: ?[]u8,
                previewed_tokens: std.ArrayListUnmanaged(Token),

                pub fn init(source: []u8, allocator: Allocator) Self {
                    const self: Self = .{
                        .source = source,
                        .string = null,
                        .previewed_tokens = std.ArrayListUnmanaged(Token).initCapacity(allocator, 8) catch unreachable,
                    };
                    return self;
                }

                pub fn deinit(self: *Self, allocator: Allocator) void {
                    self.previewed_tokens.deinit(allocator);
                }

                pub fn skip_bytes(self: *Self, n: usize) void {
                    self.source = self.source[n..];
                }

                pub fn skip_whitespaces(self: *Self) void {
                    if (self.source.len == 0) {
                        return;
                    }
                    if (self.source[0] == ';') {
                        const i = blk: for (0..self.source.len) |i| {
                            if (self.source[i] == '\n') {
                                break :blk i;
                            }
                        } else {
                            unreachable;
                        };
                        self.skip_bytes(i);
                    }
                    if (self.source.len == 0) {
                        return;
                    }
                    var i: usize = 0;
                    while (i < self.source.len) {
                        switch (self.source[i]) {
                            ' ', '\n', '\r' => {
                                i += 1;
                            },
                            else => break,
                        }
                    }
                    self.skip_bytes(i);
                }

                pub fn next(self: *Self) !?Token {
                    if (self.previewed_tokens.items.len > 0) {
                        return self.previewed_tokens.orderedRemove(0);
                    }

                    self.skip_whitespaces();

                    if (self.source.len == 0) {
                        return null;
                    }

                    const c = self.source[0];
                    switch (c) {
                        '(' => {
                            self.skip_bytes(1);
                            return .l_paren;
                        },
                        ')' => {
                            self.skip_bytes(1);
                            return .r_paren;
                        },
                        '#' => switch (self.source[1]) {
                            't' => {
                                self.skip_bytes(2);
                                return .{ .bool_value = true };
                            },
                            'f' => {
                                self.skip_bytes(2);
                                return .{ .bool_value = false };
                            },
                            else => return error.InvalidToken,
                        },
                        '0'...'9' => {
                            var i: usize = 0;
                            const end = blk: while (i < self.source.len) : (i += 1) {
                                switch (self.source[i]) {
                                    '0'...'9' => {},
                                    else => break :blk i,
                                }
                            } else {
                                return error.InvalidToken;
                            };
                            const str = self.source[0..end];
                            self.skip_bytes(end);
                            return .{ .int_value = std.fmt.parseInt(u32, str, 10) catch unreachable };
                        },
                        'a'...'z', 'A'...'Z', '_', '-', '+', '*', '`', '/' => {
                            var i: usize = 0;
                            const end = blk: while (i < self.source.len) : (i += 1) {
                                switch (self.source[i]) {
                                    'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '+', '*', '`', '/' => {},
                                    else => break :blk i,
                                }
                            } else {
                                return error.InvalidToken;
                            };
                            const str = self.source[0..end];
                            self.skip_bytes(end);
                            self.string = str;
                            return .{ .symbol = void{} };
                        },
                        '"', '\'' => {
                            const start = self.source[1..];
                            var i: usize = 0;
                            const end = blk: while (i < start.len) : (i += 1){
                                if (start[i] == '\\') {
                                    i += 2;
                                }
                                if (start[i] == c) {
                                    break :blk i;
                                }
                            } else {
                                return error.InvalidToken;
                            };
                            const str = self.source[1..end + 1];
                            self.skip_bytes(end + 2);
                            self.string = str;
                            return .{ .str = void{} };
                        },
                        else => {
                            std.debug.print("Invalid token: {}\n", .{self.source[0]});
                            return error.InvalidToken;
                        },
                    }
                }

                pub fn peek(self: *Self) !?Token {
                    if (self.previewed_tokens.items.len > 0) {
                      return error.AlreadyPeeked;
                    }
                    const t = try self.next();
                    if (t) |token| {
                        self.previewed_tokens.appendAssumeCapacity(token);
                        return token;
                    }
                    return t;
                }
            };
        };
    };
};
