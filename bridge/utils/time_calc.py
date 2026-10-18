import datetime

from fastapi import HTTPException


def get_time_plus_minutes(minutes):
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes)

def is_expired(expires_at : datetime.datetime):
    if not isinstance(expires_at, datetime.datetime):
        raise HTTPException(status_code=404, detail="Incorrect type")
    return datetime.datetime.now(datetime.timezone.utc) > expires_at