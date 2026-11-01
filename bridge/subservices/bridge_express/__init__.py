"""BridgeExpress: commands with typed signatures.

A host can describe a command when it hosts it: parameters with types, the return type and how strictly Bridge
checks calls (validate). Clients fetch every command they may call with /express/schema and their extension turns
it into the type notation of its language (e.g. typed functions in Roblox Studio). Bridge itself writes no code.
"""
from bridge.subservices.bridge_express.signature import (VALIDATE_MODES, check_args, check_response, from_remote,
                                                         normalize_signature, same_shape)
