def verify_http_call_arg(value):
    if value is not None and isinstance(value, bool):
        return value
    else:
        return None