from fastapi import APIRouter

from bridge.server.routes._helpers import authenticate, check, get_field
from bridge.subservices.bridge_express import schema

# BridgeExpress: all commands the client may call, with their signatures.
# The extension of each language turns this into its own type notation (Bridge writes no code).

Router = APIRouter(prefix="/express")


@Router.post("/schema")
async def get_schema(payload: dict):
    # if_version: the version of the last schema - if nothing changed, the answer is just {"changed": false}
    client_key = authenticate(payload)
    return check(await schema.build_schema(
        client_key,
        realm_address=get_field(payload, "realm_address", str, required=False),
        if_version=get_field(payload, "if_version", str, required=False),
    ))
