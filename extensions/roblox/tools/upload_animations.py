"""Uploads the Minecraft animations of the MinecraftWorld game to Roblox (Open Cloud) and writes their asset ids.

    python extensions/roblox/tools/upload_animations.py <api key file> <roblox user id>

- api key file: a text file with an Open Cloud API key (create.roblox.com > Dashboard > Open Cloud > API Keys,
  permission "Assets": Read + Write). The key is only read from the file, never printed.
- roblox user id: the owner of the animations - the same account that owns the game (animations of another
  account do not play in it).

Uploads every examples/MinecraftWorld/animations/*.rbxm (KeyframeSequences, made by tools/make_animations.luau) as an
"Animation" asset and writes examples/MinecraftWorld/MinecraftAnimationIds.luau. Rojo then puts the ids into the
game - nothing else to do. Only Python's standard library is needed.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROBLOX = os.path.dirname(HERE)
ANIMATIONS = os.path.join(ROBLOX, "examples", "MinecraftWorld", "animations")
IDS = os.path.join(ROBLOX, "examples", "MinecraftWorld", "MinecraftAnimationIds.luau")
API = "https://apis.roblox.com/assets/v1/"
ORDER = ["idle", "walk", "sneak", "sneak_walk", "swing", "sneak_swing", "death"]


def request(method, url, key, body=None, content_type=None):
    headers = {"x-api-key": key}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as error:
        text = error.read().decode("utf-8", "replace")
        raise SystemExit(f"Roblox answered {error.code} for {url}: {text[:500]}")


def upload(name, path, key, user_id):
    boundary = "----bridge" + uuid.uuid4().hex
    meta = {
        "assetType": "Animation",
        "displayName": f"Minecraft {name}",
        "description": "Minecraft player animation for the Bridge MinecraftWorld game (made from Minecraft's code).",
        "creationContext": {"creator": {"userId": str(user_id)}},
    }
    with open(path, "rb") as handle:
        content = handle.read()
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"request\"\r\n\r\n".encode() + json.dumps(meta).encode() + b"\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"fileContent\"; filename=\"{name}.rbxm\"\r\n"
        f"Content-Type: model/x-rbxm\r\n\r\n".encode() + content + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    operation = request("POST", API + "assets", key, b"".join(parts), f"multipart/form-data; boundary={boundary}")
    path_name = operation.get("path") or ""
    operation_id = operation.get("operationId") or path_name.split("/")[-1]
    for _ in range(60):
        if operation.get("done"):
            break
        time.sleep(1)
        operation = request("GET", API + "operations/" + operation_id, key)
    if not operation.get("done"):
        raise SystemExit(f"{name}: Roblox did not finish the upload (operation {operation_id})")
    if operation.get("error"):
        raise SystemExit(f"{name}: upload failed: {operation['error']}")
    asset_id = (operation.get("response") or {}).get("assetId")
    if not asset_id:
        raise SystemExit(f"{name}: no asset id in the answer: {json.dumps(operation)[:500]}")
    return int(asset_id)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    key_file, user_id = sys.argv[1], sys.argv[2].strip()
    if not user_id.isdigit():
        raise SystemExit("the Roblox user id must be a number")
    with open(key_file, encoding="utf-8-sig") as handle:
        key = handle.read().strip()
    if len(key) < 20:
        raise SystemExit(f"{key_file} has no API key in it")
    ids = {}
    for name in ORDER:
        path = os.path.join(ANIMATIONS, name + ".rbxm")
        if not os.path.exists(path):
            raise SystemExit(f"missing {path} - run: lune run extensions/roblox/tools/make_animations.luau")
        ids[name] = upload(name, path, key, user_id)
        print(f"  {name:12} rbxassetid://{ids[name]}")
    lines = ["-- Asset ids of the Minecraft animations (written by tools/upload_animations.py - do not edit by hand)",
             "-- 0 = not uploaded yet: in Studio the KeyframeSequences in ReplicatedStorage.MinecraftAnimations are used.",
             "return {"]
    lines += [f"\t{name} = {ids[name]}," for name in ORDER]
    lines.append("}")
    with open(IDS, "w", encoding="utf-8", newline="\r\n") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"written: {IDS}")
    print("Done - Rojo syncs the ids into the game (Play in Studio again).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
