"""BridgeExpress type notation - small, language neutral, easy to turn into Luau, Python, TypeScript, Java ...

    number  integer  string  boolean  nil  any          basic types
    list<T>                                             list of T            e.g. list<number>
    map<T>                                              text keys -> T       e.g. map<boolean>
    {name: T, level?: T}                                object, ? = optional
    T | U                                               one of them          e.g. string | nil
    "fire"                                              exactly this text    e.g. "fire" | "ice"
    (T)                                                 grouping             e.g. list<(number | string)>

Every type is also given as a tree, so extensions do not need their own parser:
    {"kind": "number"}  {"kind": "list", "of": T}  {"kind": "map", "of": T}
    {"kind": "object", "fields": [{"name", "optional", "type": T}]}
    {"kind": "union", "of": [T, ...]}  {"kind": "literal", "value": "fire"}
"""
import re

BASIC_TYPES = ("number", "integer", "string", "boolean", "nil", "any")
CONTAINER_TYPES = ("list", "map")
MAX_TYPE_LENGTH = 500
MAX_DEPTH = 8
MAX_FIELDS = 50
MAX_LITERAL_LENGTH = 64
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_TOKEN = re.compile(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*)|("(?:[^"\\]|\\.)*")|(.))')


class TypeError_(ValueError):
    """The type text is not valid. The message says where."""


# region parsing
def _tokens(text):
    position = 0
    tokens = []
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None or match.end() == position:
            break
        position = match.end()
        word, literal, symbol = match.groups()
        if word:
            tokens.append(("word", word))
        elif literal:
            tokens.append(("literal", literal[1:-1].replace('\\"', '"').replace("\\\\", "\\")))
        elif symbol and not symbol.isspace():
            tokens.append(("symbol", symbol))
    return tokens


class _Parser:
    def __init__(self, text):
        self.tokens = _tokens(text)
        self.index = 0

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else (None, None)

    def take(self, kind=None, value=None):
        token = self.peek()
        if token[0] is None or (kind and token[0] != kind) or (value and token[1] != value):
            expected = value or kind or "more"
            found = token[1] if token[0] else "the end"
            raise TypeError_(f"expected {expected!r} but found {found!r}")
        self.index += 1
        return token

    def parse(self):
        tree = self.union(0)
        if self.peek()[0] is not None:
            raise TypeError_(f"unexpected {self.peek()[1]!r}")
        return tree

    def union(self, depth):
        if depth > MAX_DEPTH:
            raise TypeError_(f"types can be nested at most {MAX_DEPTH} levels deep")
        options = [self.primary(depth)]
        while self.peek() == ("symbol", "|"):
            self.take()
            options.append(self.primary(depth))
        if len(options) == 1:
            return options[0]
        flat = []
        for option in options:
            for item in (option["of"] if option["kind"] == "union" else [option]):
                if item not in flat:
                    flat.append(item)
        return {"kind": "union", "of": flat} if len(flat) > 1 else flat[0]

    def primary(self, depth):
        kind, value = self.peek()
        if kind == "literal":
            self.take()
            if len(value) > MAX_LITERAL_LENGTH:
                raise TypeError_(f"text literals can have up to {MAX_LITERAL_LENGTH} characters")
            return {"kind": "literal", "value": value}
        if (kind, value) == ("symbol", "("):
            self.take()
            inner = self.union(depth + 1)
            self.take("symbol", ")")
            return inner
        if (kind, value) == ("symbol", "{"):
            return self.object(depth)
        if kind == "word":
            self.take()
            if value in BASIC_TYPES:
                return {"kind": value}
            if value in CONTAINER_TYPES:
                self.take("symbol", "<")
                inner = self.union(depth + 1)
                self.take("symbol", ">")
                return {"kind": value, "of": inner}
            raise TypeError_(f"unknown type {value!r} (known: {', '.join(BASIC_TYPES + CONTAINER_TYPES)})")
        found = value if kind else "the end"
        raise TypeError_(f"expected a type but found {found!r}")

    def object(self, depth):
        self.take("symbol", "{")
        fields = []
        names = set()
        while self.peek() != ("symbol", "}"):
            _, name = self.take("word")
            if not IDENTIFIER.fullmatch(name):
                raise TypeError_(f"invalid field name {name!r}")
            if name in names:
                raise TypeError_(f"field {name!r} is there twice")
            optional = False
            if self.peek() == ("symbol", "?"):
                self.take()
                optional = True
            self.take("symbol", ":")
            fields.append({"name": name, "optional": optional, "type": self.union(depth + 1)})
            names.add(name)
            if len(fields) > MAX_FIELDS:
                raise TypeError_(f"objects can have up to {MAX_FIELDS} fields")
            if self.peek() == ("symbol", ","):
                self.take()
            elif self.peek() != ("symbol", "}"):
                raise TypeError_(f"expected ',' or '}}' after field {name!r}")
        self.take("symbol", "}")
        return {"kind": "object", "fields": fields}


def parse_type(text):
    """Type text -> tree. Raises TypeError_ with a readable reason."""
    if not isinstance(text, str) or not text.strip():
        raise TypeError_("a type must be a non-empty text")
    if len(text) > MAX_TYPE_LENGTH:
        raise TypeError_(f"a type can have up to {MAX_TYPE_LENGTH} characters")
    return _Parser(text).parse()


def to_text(tree, top=True):
    """Tree -> canonical type text (same spacing everywhere, used for comparing signatures)."""
    kind = tree["kind"]
    if kind in BASIC_TYPES:
        return kind
    if kind in CONTAINER_TYPES:
        return f"{kind}<{to_text(tree['of'])}>"
    if kind == "literal":
        return '"' + tree["value"].replace("\\", "\\\\").replace('"', '\\"') + '"'
    if kind == "object":
        fields = ", ".join(f"{field['name']}{'?' if field['optional'] else ''}: {to_text(field['type'])}"
                           for field in tree["fields"])
        return "{" + fields + "}"
    if kind == "union":
        text = " | ".join(to_text(option, top=False) for option in tree["of"])
        return text if top else f"({text})"
    raise TypeError_(f"unknown kind {kind!r}")
# endregion parsing


# region checking values
def _name_of(value):
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


# A check visits at most this many values (unions visit a value once per alternative) - a huge argument list
# with a long union type would otherwise block the server for many seconds. High enough that a normal large
# argument (a flat list/map that fills an allowed message) still fits; only pathological union blow-up is cut.
MAX_CHECK_VISITS = 1_000_000


def check_value(value, tree, path="value", budget=None):
    """Returns a list of problems (empty = the value fits the type)."""
    if budget is None:
        budget = [MAX_CHECK_VISITS]
    budget[0] -= 1
    if budget[0] < 0:
        return [f"{path}: too big to check (more than {MAX_CHECK_VISITS} values)"]
    kind = tree["kind"]
    if kind == "any":
        return []
    if kind == "nil":
        return [] if value is None else [f"{path}: expected nil, got {_name_of(value)}"]
    if kind == "boolean":
        return [] if isinstance(value, bool) else [f"{path}: expected boolean, got {_name_of(value)}"]
    if kind == "number":
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        return [] if ok else [f"{path}: expected number, got {_name_of(value)}"]
    if kind == "integer":
        ok = (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())
        return [] if ok else [f"{path}: expected integer, got {_name_of(value) if not isinstance(value, float) else value}"]
    if kind == "string":
        return [] if isinstance(value, str) else [f"{path}: expected string, got {_name_of(value)}"]
    if kind == "literal":
        return [] if value == tree["value"] else [f"{path}: expected {to_text(tree)}, got {value!r}"[:200]]
    if kind == "list":
        if not isinstance(value, list):
            return [f"{path}: expected list, got {_name_of(value)}"]
        problems = []
        for index, item in enumerate(value):
            problems += check_value(item, tree["of"], f"{path}[{index + 1}]", budget)
            if len(problems) >= 10 or budget[0] < 0:
                break
        return problems
    if kind == "map":
        if not isinstance(value, dict):
            return [f"{path}: expected map, got {_name_of(value)}"]
        problems = []
        for key, item in value.items():
            problems += check_value(item, tree["of"], f"{path}.{key}", budget)
            if len(problems) >= 10 or budget[0] < 0:
                break
        return problems
    if kind == "object":
        if not isinstance(value, dict):
            return [f"{path}: expected object, got {_name_of(value)}"]
        return check_fields(value, tree["fields"], path, budget)
    if kind == "union":
        for option in tree["of"]:
            if not check_value(value, option, path, budget):
                return []
            if budget[0] < 0:
                return [f"{path}: too big to check (more than {MAX_CHECK_VISITS} values)"]
        return [f"{path}: expected {to_text(tree)}, got {_name_of(value)}"]
    return [f"{path}: unknown type"]


def accepts_nil(tree):
    if tree["kind"] in ("nil", "any"):
        return True
    return tree["kind"] == "union" and any(accepts_nil(option) for option in tree["of"])


def check_fields(value, fields, path="args", budget=None):
    """Object fields: required ones must be there, optional ones may be missing or nil, unknown ones are a problem."""
    if budget is None:
        budget = [MAX_CHECK_VISITS]
    problems = []
    known = {field["name"] for field in fields}
    for field in fields:
        name = field["name"]
        if name not in value or value[name] is None:
            if not field["optional"] and not accepts_nil(field["type"]):
                problems.append(f"{path}.{name}: missing")
            continue
        problems += check_value(value[name], field["type"], f"{path}.{name}", budget)
    for name in value:
        if name not in known:
            problems.append(f"{path}.{name}: unknown field")
    return problems[:10]
# endregion checking values
