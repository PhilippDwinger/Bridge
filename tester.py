import bridge

app = bridge.Bridge("0.0.0.0", 5000)

app.start("unsafe")
