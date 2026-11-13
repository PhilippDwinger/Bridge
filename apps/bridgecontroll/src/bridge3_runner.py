"""Starts ONE Bridge 3 server for BridgeControll v2 (Bridge 4, docs/11 §8) - written by BridgeControll, do not edit.

Like Bridge's own main.py, with two differences: it listens on 127.0.0.1 only (the gate of BridgeControll is the
way in - nobody in the home network gets around it), and it stops cleanly when BridgeControll closes its standard
input (works on Windows too; Bridge makes its last backup to trusted servers then). Settings from the environment:

  BRIDGE_CODE_DIR        the Bridge 3 folder (branch bridge-3)
  PORT                   port on 127.0.0.1
  BRIDGE_PASSWORD        admin password
  BRIDGE_PUBLIC_URL      the address under which it is reached (its identity in Bridge 3)
  BRIDGE_TRUST_PROXY     "1": believe X-Forwarded-For ...
  BRIDGE_TRUST_PROXY_IPS ... only from these addresses ("127.0.0.1,::1": the gate)
"""
import os
import sys
import threading


def main():
    code_dir = os.environ["BRIDGE_CODE_DIR"]
    sys.path.insert(0, code_dir)
    os.chdir(code_dir)

    import bridge
    from bridge import ConnectionMode
    from bridge.core import protocol

    protocol.trust_proxy = os.environ.get("BRIDGE_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes")
    protocol.trust_proxy_ips = os.environ.get("BRIDGE_TRUST_PROXY_IPS", "").strip() or "127.0.0.1,::1"
    port = int(os.environ["PORT"])
    password = os.environ["BRIDGE_PASSWORD"]
    public_url = os.environ.get("BRIDGE_PUBLIC_URL") or None

    app = bridge.Bridge("127.0.0.1", port, password, public_url)

    def stop_when_stdin_closes():
        try:
            while sys.stdin.readline():
                pass
        except Exception:
            pass
        app.stop_server()

    threading.Thread(target=stop_when_stdin_closes, daemon=True).start()
    print(f"Bridge 3 auf 127.0.0.1:{port} als {public_url}", flush=True)
    app.start_server(ConnectionMode.UNSAFE)


if __name__ == "__main__":
    main()
