"""Uploads Minecraft's sounds for the MinecraftWorld game to Roblox (Open Cloud) and writes their asset ids.

    python extensions/roblox/tools/upload_sounds.py <api key file> <roblox user id or a file with it> [--assets <folder>] [--limit 95]

- api key file / roblox user id: the same as for tools/upload_animations.py (Open Cloud key with "Assets" Read +
  Write, the account that owns the game).
- --assets: Minecraft's asset folder (with indexes/ and objects/). Without it the usual places are searched: the
  launcher's %APPDATA%\\.minecraft\\assets and Fabric Loom's ~/.gradle/caches/fabric-loom/assets (runClient).
- --limit: at most this many new files per run (Roblox: 100 audio uploads per 30 days without ID verification,
  2000 with it). The most important sounds come first; run it again later for the rest - already uploaded files
  are skipped (tools/sound_uploads.json remembers them).

Minecraft's sounds.json says which file each sound event plays (the first of its variants is taken). Many events
share
a file (block.stone.break + block.stone.place = dig/stone1), so ~100 files cover several hundred events. Writes
examples/MinecraftWorld/MinecraftSoundIds.luau (event -> asset id) - Rojo puts it into the game.

Important: the sound files are Mojang's. Uploading them to Roblox is your decision - Roblox's moderation can reject
them (copyright). MinecraftSoundIds.luau also takes any other asset ids (e.g. free sounds from the Creator Store).
Only Python's standard library is needed.
"""
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROBLOX = os.path.dirname(HERE)
IDS = os.path.join(ROBLOX, "examples", "MinecraftWorld", "MinecraftSoundIds.luau")
DONE = os.path.join(HERE, "sound_uploads.json")
API = "https://apis.roblox.com/assets/v1/"

# The sound events, most important first (blocks of every sound group, then what you hear all the time)
GROUPS = ["stone", "wood", "grass", "gravel", "sand", "wool", "glass", "metal", "snow", "ladder"]
EVENTS = []
for _group in GROUPS:
    EVENTS += [f"block.{_group}.break", f"block.{_group}.step", f"block.{_group}.place", f"block.{_group}.hit",
               f"block.{_group}.fall"]
EVENTS += [
    "entity.player.hurt", "entity.generic.hurt", "entity.player.death", "entity.generic.eat", "entity.player.burp",
    "entity.item.pickup", "entity.experience_orb.pickup", "entity.player.levelup", "entity.generic.explode",
    "entity.tnt.primed", "block.chest.open", "block.chest.close", "block.wooden_door.open", "block.wooden_door.close",
    "block.wooden_trapdoor.open", "block.wooden_trapdoor.close", "block.fence_gate.open", "block.fence_gate.close",
    "block.iron_door.open", "block.iron_door.close", "block.lever.click", "block.stone_button.click_on",
    "block.wooden_button.click_on", "entity.player.attack.strong", "entity.player.attack.weak",
    "entity.player.attack.crit", "entity.player.attack.sweep", "entity.arrow.shoot", "entity.arrow.hit",
    "entity.arrow.hit_player", "item.shield.block", "entity.item.break", "entity.generic.drink",
    "entity.zombie.ambient", "entity.zombie.hurt", "entity.zombie.death", "entity.skeleton.ambient",
    "entity.skeleton.hurt", "entity.skeleton.death", "entity.creeper.primed", "entity.creeper.hurt",
    "entity.creeper.death", "entity.spider.ambient", "entity.spider.death", "entity.enderman.ambient",
    "entity.enderman.teleport", "entity.cow.ambient", "entity.cow.hurt", "entity.pig.ambient", "entity.pig.hurt",
    "entity.sheep.ambient", "entity.chicken.ambient", "entity.chicken.egg", "entity.horse.ambient",
    "entity.villager.ambient", "entity.villager.yes", "entity.villager.no", "entity.villager.trade",
    "item.bucket.fill", "item.bucket.empty", "item.bucket.fill_lava", "item.bucket.empty_lava",
    "entity.generic.splash", "entity.player.splash", "entity.generic.swim", "block.lava.pop", "block.fire.ambient",
    "block.fire.extinguish", "item.flintandsteel.use", "block.portal.trigger", "block.portal.travel",
    "block.anvil.use", "block.anvil.land", "block.furnace.fire_crackle", "block.enchantment_table.use",
    "entity.lightning_bolt.thunder", "entity.ender_pearl.throw", "entity.snowball.throw", "entity.egg.throw",
    "entity.fishing_bobber.throw", "entity.fishing_bobber.splash", "entity.boat.paddle_water",
    "entity.minecart.riding", "entity.horse.gallop", "entity.horse.saddle", "block.note_block.harp",
    "block.grindstone.use", "block.smithing_table.use", "block.brewing_stand.brew", "entity.firework_rocket.launch",
    "entity.witch.ambient", "entity.slime.squish", "entity.wolf.ambient", "entity.cat.ambient",
    "item.armor.equip_generic", "ui.button.click",
]


def find_assets(given):
    """Minecraft's asset folder (indexes/ + objects/)."""
    candidates = [given] if given else []
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(os.path.join(appdata, ".minecraft", "assets"))
    home = os.path.expanduser("~")
    candidates += [os.path.join(home, ".minecraft", "assets"), os.path.join(home, ".gradle", "caches", "fabric-loom", "assets")]
    candidates += glob.glob(os.path.join(home, ".gradle", "caches", "fabric-loom", "**", "assets"), recursive=True)
    for folder in candidates:
        if folder and os.path.isdir(os.path.join(folder, "indexes")) and os.path.isdir(os.path.join(folder, "objects")):
            return folder
    raise SystemExit("Minecraft's assets not found - start Minecraft once (launcher) or give --assets <folder>")


def load_index(assets):
    """The newest asset index that has sounds: {path: hash}."""
    best = None
    for path in glob.glob(os.path.join(assets, "indexes", "*.json")):
        with open(path, encoding="utf-8") as handle:
            objects = json.load(handle).get("objects", {})
        if "minecraft/sounds.json" in objects and (best is None or os.path.getmtime(path) > best[0]):
            best = (os.path.getmtime(path), path, objects)
    if not best:
        raise SystemExit(f"no asset index with sounds in {assets}/indexes")
    print(f"assets: {best[1]}")
    return {name: entry["hash"] for name, entry in best[2].items()}


def object_path(assets, digest):
    return os.path.join(assets, "objects", digest[:2], digest)


def first_file(sounds, event, depth=0):
    """The file of the first variant of a sound event ("dig/stone1") - following references to other events."""
    entry = sounds.get(event)
    if not entry or depth > 4:
        return None
    for sound in entry.get("sounds", []):
        name = sound if isinstance(sound, str) else sound.get("name")
        if isinstance(sound, dict) and sound.get("type") == "event":
            found = first_file(sounds, name.replace("minecraft:", ""), depth + 1)
            if found:
                return found
            continue
        if name:
            return name.replace("minecraft:", "")
    return None


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


def upload(name, data, key, user_id):
    boundary = "----bridge" + uuid.uuid4().hex
    meta = {
        "assetType": "Audio",
        "displayName": f"Minecraft {name}"[:50],
        "description": "Minecraft sound for the Bridge MinecraftWorld game.",
        "creationContext": {"creator": {"userId": str(user_id)}},
    }
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"request\"\r\nContent-Type: application/json\r\n\r\n".encode()
        + json.dumps(meta).encode() + b"\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"fileContent\"; filename=\"{os.path.basename(name)}.ogg\"\r\n"
        f"Content-Type: audio/ogg\r\n\r\n".encode() + data + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    operation = request("POST", API + "assets", key, b"".join(parts), f"multipart/form-data; boundary={boundary}")
    path = operation.get("path") or ("operations/" + operation.get("operationId", ""))
    for _ in range(60):
        if operation.get("done"):
            asset = operation.get("response", {})
            asset_id = asset.get("assetId")
            if not asset_id:
                raise SystemExit(f"{name}: no asset id ({json.dumps(operation)[:300]})")
            return int(asset_id)
        time.sleep(2)
        operation = request("GET", API + path, key)
    raise SystemExit(f"{name}: Roblox did not finish the upload in time")


def write_ids(event_ids):
    lines = ["-- Asset ids of Minecraft's sounds (written by tools/upload_sounds.py - do not edit by hand): event -> asset id.",
             "-- Empty = no sounds uploaded yet (the game is silent, everything else works).", "return {"]
    for event in sorted(event_ids):
        lines.append(f'\t["{event}"] = {event_ids[event]},')
    lines.append("}")
    with open(IDS, "w", encoding="utf-8", newline="\r\n") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        raise SystemExit(__doc__)
    key_file, user_id = args[0], args[1]
    assets_dir = args[args.index("--assets") + 1] if "--assets" in args else None
    limit = int(args[args.index("--limit") + 1]) if "--limit" in args else 95
    if os.path.isfile(user_id):  # (also a file with the id in it, like Bridge_Claude\roblox_user_id.txt)
        with open(user_id, encoding="utf-8") as handle:
            user_id = handle.read().strip()
    if not re.fullmatch(r"\d+", user_id):
        raise SystemExit("the roblox user id is a number")
    with open(key_file, encoding="utf-8") as handle:
        key = handle.read().strip()
    assets = find_assets(assets_dir)
    index = load_index(assets)
    with open(object_path(assets, index["minecraft/sounds.json"]), encoding="utf-8") as handle:
        sounds = json.load(handle)
    done = {}
    if os.path.exists(DONE):
        with open(DONE, encoding="utf-8") as handle:
            done = json.load(handle)
    event_ids = {}
    uploaded = 0
    unknown = []
    later = 0
    for event in EVENTS:
        name = first_file(sounds, event)
        digest = index.get(f"minecraft/sounds/{name}.ogg") if name else None
        if not digest:
            unknown.append(event)
            continue
        if name not in done:
            if uploaded >= limit:
                later += 1
                continue
            with open(object_path(assets, digest), "rb") as handle:
                data = handle.read()
            done[name] = upload(name, data, key, user_id)
            uploaded += 1
            with open(DONE, "w", encoding="utf-8") as handle:
                json.dump(done, handle, indent=1, sort_keys=True)
            print(f"  up    {event}: {name} -> {done[name]}")
        event_ids[event] = done[name]
    write_ids(event_ids)
    if unknown:
        print(f"not in this Minecraft version: {', '.join(unknown)}")
    print(f"{uploaded} files uploaded now, {len(event_ids)} sounds in MinecraftSoundIds.luau"
          + (f", {later} still to come (limit reached - run it again later)" if later else ""))


if __name__ == "__main__":
    main()
