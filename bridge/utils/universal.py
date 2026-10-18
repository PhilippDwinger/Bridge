from collections.abc import Hashable
from typing import Any
import base64
import json
import math
from decimal import Decimal
from datetime import date, datetime, time, timedelta, timezone
from uuid import UUID


class_registry = {}


def register_class(type_name, class_type, encoder=None, decoder=None):
    if not isinstance(type_name, str) or not type_name:
        raise ValueError("type_name must be a non-empty string")

    if not isinstance(class_type, type):
        raise TypeError("class_type must be a class")

    if type_name in class_registry:
        raise ValueError(f"Class name already registered: {type_name}")

    if any(entry["class"] is class_type for entry in class_registry.values()):
        raise ValueError(f"Class already registered: {class_type.__name__}")

    if encoder is not None and not callable(encoder):
        raise TypeError("encoder must be callable")

    if decoder is not None and not callable(decoder):
        raise TypeError("decoder must be callable")

    class_registry[type_name] = {
        "class": class_type,
        "encoder": encoder,
        "decoder": decoder
    }


def _encode_value(value, active):
    if value is None:
        return {"__bridge_type__": "none", "value": None}

    if isinstance(value, bool):
        return {"__bridge_type__": "bool", "value": value}

    if isinstance(value, int):
        return {"__bridge_type__": "int", "value": str(value)}

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite floats are not supported")

        return {"__bridge_type__": "float", "value": value}

    if isinstance(value, str):
        return {"__bridge_type__": "string", "value": value}

    if isinstance(value, bytes):
        return {
            "__bridge_type__": "bytes",
            "value": base64.b64encode(value).decode("ascii")
        }

    if isinstance(value, bytearray):
        return {
            "__bridge_type__": "bytearray",
            "value": base64.b64encode(value).decode("ascii")
        }

    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Non-finite decimals are not supported")

        return {
            "__bridge_type__": "decimal",
            "value": str(value)
        }

    if isinstance(value, datetime):
        return {
            "__bridge_type__": "datetime",
            "value": value.isoformat()
        }

    if isinstance(value, date):
        return {
            "__bridge_type__": "date",
            "value": value.isoformat()
        }

    if isinstance(value, time):
        return {
            "__bridge_type__": "time",
            "value": value.isoformat()
        }

    if isinstance(value, timedelta):
        return {
            "__bridge_type__": "timedelta",
            "value": {
                "days": value.days,
                "seconds": value.seconds,
                "microseconds": value.microseconds
            }
        }

    if isinstance(value, UUID):
        return {
            "__bridge_type__": "uuid",
            "value": str(value)
        }

    if isinstance(value, list):
        return _encode_container(
            value,
            "list",
            value,
            active
        )

    if isinstance(value, tuple):
        return _encode_container(
            value,
            "tuple",
            value,
            active
        )

    if isinstance(value, set):
        return _encode_container(
            value,
            "set",
            value,
            active
        )

    if isinstance(value, frozenset):
        return _encode_container(
            value,
            "frozenset",
            value,
            active
        )

    if isinstance(value, dict):
        return _encode_container(
            value,
            "dict",
            value.items(),
            active,
            is_dict=True
        )

    for type_name, entry in class_registry.items():
        if type(value) is entry["class"]:
            object_id = id(value)

            if object_id in active:
                raise ValueError("Circular references are not supported")

            active.add(object_id)

            try:
                if entry["encoder"] is None:
                    attributes = vars(value)
                else:
                    attributes = entry["encoder"](value)

                encoded_attributes = _encode_value(attributes, active)

                return {
                    "__bridge_type__": "class",
                    "name": type_name,
                    "value": encoded_attributes
                }
            finally:
                active.remove(object_id)

    raise TypeError(f"Unsupported type: {type(value).__name__}")


def _encode_container(value, type_name, items, active, is_dict=False):
    object_id = id(value)

    if object_id in active:
        raise ValueError("Circular references are not supported")

    active.add(object_id)

    try:
        if is_dict:
            encoded_items = [
                [_encode_value(key, active), _encode_value(item, active)]
                for key, item in items
            ]
        else:
            encoded_items = [
                _encode_value(item, active)
                for item in items
            ]

        return {
            "__bridge_type__": type_name,
            "value": encoded_items
        }
    finally:
        active.remove(object_id)


def encode_value(value):
    return _encode_value(value, set())


def _get_value(data, expected_type):
    if not isinstance(data, dict):
        raise ValueError("Invalid Bridge value")

    if data.get("__bridge_type__") != expected_type:
        raise ValueError(f"Expected Bridge type: {expected_type}")

    if "value" not in data:
        raise ValueError("Missing value field")

    return data["value"]


def _decode_value(data):
    if not isinstance(data, dict):
        raise ValueError("Invalid Bridge value")

    type_name = data.get("__bridge_type__")

    if not isinstance(type_name, str):
        raise ValueError("Missing or invalid Bridge type")

    if type_name == "none":
        if _get_value(data, "none") is not None:
            raise ValueError("Invalid none value")
        return None

    if type_name == "bool":
        value = _get_value(data, "bool")

        if not isinstance(value, bool):
            raise ValueError("Invalid bool value")

        return value

    if type_name == "int":
        value = _get_value(data, "int")

        if not isinstance(value, str):
            raise ValueError("Invalid int value")

        try:
            return int(value)
        except ValueError:
            raise ValueError("Invalid int value") from None

    if type_name == "float":
        value = _get_value(data, "float")

        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Invalid float value")

        value = float(value)

        if not math.isfinite(value):
            raise ValueError("Non-finite floats are not supported")

        return value

    if type_name == "string":
        value = _get_value(data, "string")

        if not isinstance(value, str):
            raise ValueError("Invalid string value")

        return value

    if type_name in ("bytes", "bytearray"):
        value = _get_value(data, type_name)

        if not isinstance(value, str):
            raise ValueError("Invalid encoded byte data")

        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError("Invalid base64 data") from None

        return decoded if type_name == "bytes" else bytearray(decoded)

    if type_name == "decimal":
        value = _get_value(data, "decimal")

        if not isinstance(value, str):
            raise ValueError("Invalid decimal value")

        try:
            decoded = Decimal(value)
        except Exception:
            raise ValueError("Invalid decimal value") from None

        if not decoded.is_finite():
            raise ValueError("Non-finite decimals are not supported")

        return decoded

    if type_name == "datetime":
        value = _get_value(data, "datetime")

        if not isinstance(value, str):
            raise ValueError("Invalid datetime value")

        try:
            return datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("Invalid datetime value") from None

    if type_name == "date":
        value = _get_value(data, "date")

        if not isinstance(value, str):
            raise ValueError("Invalid date value")

        try:
            return date.fromisoformat(value)
        except ValueError:
            raise ValueError("Invalid date value") from None

    if type_name == "time":
        value = _get_value(data, "time")

        if not isinstance(value, str):
            raise ValueError("Invalid time value")

        try:
            return time.fromisoformat(value)
        except ValueError:
            raise ValueError("Invalid time value") from None

    if type_name == "timedelta":
        value = _get_value(data, "timedelta")

        if not isinstance(value, dict):
            raise ValueError("Invalid timedelta value")

        if set(value) != {"days", "seconds", "microseconds"}:
            raise ValueError("Invalid timedelta fields")

        if any(type(value[key]) is not int for key in value):
            raise ValueError("Invalid timedelta fields")

        return timedelta(
            days=value["days"],
            seconds=value["seconds"],
            microseconds=value["microseconds"]
        )

    if type_name == "uuid":
        value = _get_value(data, "uuid")

        if not isinstance(value, str):
            raise ValueError("Invalid UUID value")

        try:
            return UUID(value)
        except ValueError:
            raise ValueError("Invalid UUID value") from None

    if type_name in ("list", "tuple", "set", "frozenset"):
        value = _get_value(data, type_name)

        if not isinstance(value, list):
            raise ValueError(f"Invalid {type_name} value")

        items = [_decode_value(item) for item in value]

        if type_name == "list":
            return items

        if type_name == "tuple":
            return tuple(items)

        try:
            if type_name == "set":
                return set(items)

            return frozenset(items)
        except TypeError:
            raise ValueError(
                f"{type_name} contains an unhashable value"
            ) from None


    if type_name == "dict":
        value = _get_value(data, "dict")

        if not isinstance(value, list):
            raise ValueError("Invalid dict value")

        result = {}

        for pair in value:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Invalid dict entry")

            key: Any = _decode_value(pair[0])
            item = _decode_value(pair[1])

            if not isinstance(key, Hashable):
                raise ValueError(
                    f"Dictionary key is not hashable: {type(key).__name__}"
                )

            try:
                hash(key)
            except TypeError:
                raise ValueError(
                    f"Dictionary key is not hashable: {type(key).__name__}"
                ) from None

            result[key] = item

        return result

    if type_name == "class":
        registered_name = data.get("name")

        if not isinstance(registered_name, str):
            raise ValueError("Invalid class name")

        entry = class_registry.get(registered_name)

        if entry is None:
            raise ValueError(f"Unknown class: {registered_name}")

        attributes = _decode_value(_get_value(data, "class"))

        if entry["decoder"] is not None:
            return entry["decoder"](attributes)

        if not isinstance(attributes, dict):
            raise ValueError("Default class decoder requires a dictionary")

        if any(not isinstance(key, str) for key in attributes):
            raise ValueError("Class attribute names must be strings")

        instance = entry["class"].__new__(entry["class"])
        vars(instance).update(attributes)

        return instance

    raise ValueError(f"Unknown Bridge type: {type_name}")


def decode_value(data):
    return _decode_value(data)


def encode(value):
    return json.dumps(
        encode_value(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":")
    )


def decode(data):
    if isinstance(data, str):
        try:
            data = json.loads(
                data,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"Invalid JSON constant: {value}")
                )
            )
        except (json.JSONDecodeError, ValueError):
            raise ValueError("Invalid Bridge JSON") from None

    return decode_value(data)
