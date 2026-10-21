from dataclasses import dataclass

@dataclass(frozen=True)
class ExceptionInfo:
    name: str
    type: str
    status_code: int | None = None
    default_message: str | None = None

def is_exception(value: ExceptionInfo) -> bool:
    return any(
        Item is value
        for Item in vars(Exceptions).values()
    )


class Exceptions:
    KEY_ERROR = ExceptionInfo(
        name="Key Error",
        type="warning",
        status_code=400,
        default_message="A key error occurred!"
    )

    ARGUMENT_ERROR = ExceptionInfo(
        name="Argument Error",
        type="warning",
        status_code=400,
        default_message="A key error occurred!"
    )

    FAILED = ExceptionInfo(
        name="Process Failed",
        type="warning",
        status_code=500,
        default_message="A process failed!"
    )

    BRIDGE_PASSWORD_MISSING = ExceptionInfo(
        name="Bridge Password Missing",
        type="warning",
        status_code=400,
        default_message="The bridge password is missing!"
    )

    NOT_ALLOWED = ExceptionInfo(
        name="Not Allowed Error",
        type="warning",
        status_code=403,
        default_message="Access is not allowed!"
    )

    FOLLOWING_ERROR = ExceptionInfo(
        name="Following Error",
        type="warning",
        status_code=500,
        default_message="A key error that occurred after an other error!"
    )

    CLIENT_PAYLOAD_ERROR = ExceptionInfo(
        name="Payload is not valid!",
        type="warning",
        status_code=500,
        default_message="The payload may be incomplete or not as expected!"
    )

    UNKNOWN_ERROR = ExceptionInfo(
        name="Unknown Error",
        type="warning",
        status_code=500,
        default_message="An unknown error occurred!"
    )

    ERROR_HANDLING_ERROR = ExceptionInfo(
        name="Error Handling Error",
        type="error",
        status_code=500,
        default_message="An error occurred while handling an error!"
    )

    HARD_ERROR = ExceptionInfo(
        name="Cancel Runtime Error",
        type="error",
        status_code=500,
        default_message="Error is called and will cancel runtime!"
    )

    ERROR_TRACKING_ERROR = ExceptionInfo(
        name="Tracking Error",
        type="important",
        status_code=500,
        default_message="An error occurred while tracking error!"
    )

    ERROR_TRACKING_ERROR_DEPTH = ExceptionInfo(
        name="Tracking Error Depth",
        type="important",
        status_code=500,
        default_message="An error occurred while tracking error because of depth!"
    )