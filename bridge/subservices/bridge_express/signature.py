"""Command signatures: what a host tells Bridge about a command.

Input (when hosting, all optional except the parameter names and types):
    {
        "params": [{"name": "a", "type": "number", "optional": false, "description": "first number"}],
        "returns": "number",
        "validate": "strict"
    }

With a signature, command_args are an object with the parameter names, e.g. {"a": 2, "b": 3}.

validate (chosen by the host):
    strict - wrong arguments -> 400 ARGS_INVALID, the task is not sent. A response that does not fit "returns"
             is rejected for the host (400 RESPONSE_INVALID) - so the types the caller sees are always true.
    warn   - the task is sent anyway, with "validation_problems" in the task for the host
    off    - no checks, the signature is only information (for /express/schema)
"""
from bridge.subservices.bridge_express.types import (IDENTIFIER, MAX_TYPE_LENGTH, TypeError_, check_fields, check_value,
                                                      parse_type, to_text)

VALIDATE_MODES = ("strict", "warn", "off")
MAX_PARAMS = 20
MAX_PARAM_DESCRIPTION = 200


def normalize_signature(raw):
    """Checks a signature from a host. Returns (signature, None) or (None, list of problems)."""
    if not isinstance(raw, dict):
        return None, ["signature must be an object"]
    unknown = set(raw) - {"params", "returns", "validate"}
    if unknown:
        return None, [f"unknown signature field(s): {', '.join(sorted(unknown))}"]
    params_in = raw.get("params") or []
    if not isinstance(params_in, list) or len(params_in) > MAX_PARAMS:
        return None, [f"params must be a list with up to {MAX_PARAMS} entries"]
    problems = []
    params = []
    names = set()
    for index, param in enumerate(params_in):
        where = f"params[{index + 1}]"
        if not isinstance(param, dict):
            problems.append(f"{where}: must be an object with name and type")
            continue
        name = param.get("name")
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name):
            problems.append(f"{where}: name must be letters, digits or _ (not starting with a digit, max 64)")
            continue
        if name in names:
            problems.append(f"{where}: name {name!r} is there twice")
            continue
        names.add(name)
        try:
            tree = parse_type(param.get("type"))
        except TypeError_ as error:
            problems.append(f"{where} ({name}): {error}")
            continue
        # We store the canonical form (to_text). It must also fit the limit, because every other server rebuilds
        # the signature from it (from_remote -> parse_type). Otherwise the checks would silently be skipped there.
        canonical_type = to_text(tree)
        if len(canonical_type) > MAX_TYPE_LENGTH:
            problems.append(f"{where} ({name}): the type is too long ({len(canonical_type)} characters after normalization, "
                            f"max {MAX_TYPE_LENGTH}) - use fewer options or a simpler type")
            continue
        description = param.get("description") or ""
        if not isinstance(description, str) or len(description) > MAX_PARAM_DESCRIPTION:
            problems.append(f"{where} ({name}): description must be a text with up to {MAX_PARAM_DESCRIPTION} characters")
            continue
        optional = param.get("optional", False)
        if not isinstance(optional, bool):
            problems.append(f"{where} ({name}): optional must be true or false")
            continue
        params.append({"name": name, "type": canonical_type, "type_tree": tree, "optional": optional,
                       "description": description})
    returns_text = raw.get("returns", "any")
    try:
        returns_tree = parse_type(returns_text)
        if len(to_text(returns_tree)) > MAX_TYPE_LENGTH:
            raise TypeError_(f"the type is too long after normalization (max {MAX_TYPE_LENGTH} characters)")
    except TypeError_ as error:
        problems.append(f"returns: {error}")
        returns_tree = None
    validate = raw.get("validate", "strict")
    if validate not in VALIDATE_MODES:
        problems.append(f"validate must be one of {', '.join(VALIDATE_MODES)}")
    if problems:
        return None, problems[:10]
    return {
        "params": params,
        "returns": to_text(returns_tree),
        "returns_tree": returns_tree,
        "validate": validate,
    }, None


def from_remote(signature):
    """A signature another server sent (realm server of a remote realm): built again from its texts, never used as it
    came - a broken or tricked type tree would break the checks. None if it is not valid."""
    if not isinstance(signature, dict) or not isinstance(signature.get("params"), list):
        return None
    raw = {
        "params": [{key: param.get(key) for key in ("name", "type", "optional", "description") if param.get(key) is not None}
                   for param in signature["params"] if isinstance(param, dict)],
        "returns": signature.get("returns", "any"),
        "validate": signature.get("validate", "strict"),
    }
    normalized, problems = normalize_signature(raw)
    return normalized if not problems else None


def same_shape(first, second):
    """Two hosts of a command must have the same signature (descriptions may differ)."""
    def shape(signature):
        if signature is None:
            return None
        return ([(param["name"], param["type"], param["optional"]) for param in signature["params"]],
                signature["returns"], signature["validate"])
    return shape(first) == shape(second)


def _fields(signature):
    return [{"name": param["name"], "optional": param["optional"], "type": param["type_tree"]}
            for param in signature["params"]]


def check_args(command_args, signature):
    """Problems of the arguments of a call (empty list = fine)."""
    if command_args is None or command_args == []:
        # No arguments at all: fine if every parameter is optional
        command_args = {}
    if not isinstance(command_args, dict):
        return ["args: expected an object with the parameter names, e.g. {\"a\": 1}"]
    return check_fields(command_args, _fields(signature), "args")


def check_response(content, signature):
    return check_value(content, signature["returns_tree"], "response")
