import asyncio

# Event loop of the running server. Lets Python code schedule async work (e.g. a handshake) on it.
loop = None
_tasks = set()

def set_loop(event_loop):
    global loop
    loop = event_loop

def schedule(coroutine):
    """Runs a coroutine on the server loop. If the server is not running yet, it is dropped -
    everything that needs to happen at start is done in the app lifespan."""
    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None
    if loop is not None and running_loop is loop:
        task = loop.create_task(coroutine)
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return True
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(coroutine, loop)
        return True
    coroutine.close()
    return False
