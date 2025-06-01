import multiprocessing as mp

class SocketIOProxy:
    def __init__(self, mp_queue: multiprocessing.Queue):
        self.mp_queue = mp_queue
        
    def emit(self, event: str, data: dict):
        """Proxy method that mimics sio.emit interface"""
        self.mp_queue.put(("sio_emit", {
            "event": event,
            "data": data
        }))