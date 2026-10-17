versions = {
    "1.0": {
        "version": "1.0",
        "max_kb_per_chunk":  20,
    }
}
current_version = "1.0"

def get_current_version():
    return current_version

def get_current_version_data():
    return versions[current_version]