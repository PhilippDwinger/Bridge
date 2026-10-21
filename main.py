import bridge
import os

from bridge.core.clients import Client

host = "0.0.0.0"
port = int(os.getenv("PORT", 8000))
app = bridge.Bridge(host, port)
#app.start_server(ConnectionMode.UNSAFE)

client = Client("http://bridge", "Password", "Client1", True)
print(app.get_all_storages("BridgePassword"))
app.first_set_password("BridgePassword")
print(app.get_all_storages("BridgePassword"))