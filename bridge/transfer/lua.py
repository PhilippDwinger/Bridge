def normalize_lua_hybrid_tables(value):
    """Lua tables can mix array items and named keys. JSON encoders then produce {"1": a, "2": b, "name": c}.

    Taken over from Bridge 2: such hybrid tables are turned back into a list of their array items.
    Only used for command arguments (Roblox clients).
    """
    if isinstance(value, list):
        return [normalize_lua_hybrid_tables(item) for item in value]

    if not isinstance(value, dict):
        return value

    array_items = []
    has_keyed_items = False

    for key, item in value.items():
        if isinstance(key, str) and key.isdecimal() and int(key) > 0 and str(int(key)) == key:
            array_items.append((int(key), item))
        else:
            has_keyed_items = True

    if array_items and has_keyed_items:
        return [
            normalize_lua_hybrid_tables(item)
            for _, item in sorted(array_items)
        ]

    return {
        key: normalize_lua_hybrid_tables(item)
        for key, item in value.items()
    }
