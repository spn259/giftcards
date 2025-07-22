# events.py
import queue
from threading import Lock

# a thread-safe FIFO for events
_event_queue = queue.Queue()
_queue_lock  = Lock()

def push_assignment_event(data: dict):
    """Call this whenever an insumo is assigned."""
    # data should include at least 'name' and 'assigned_to'
    with _queue_lock:
        _event_queue.put(data)

def assignment_event_stream():
    """Generator that yields SSE messages for each new assignment."""
    while True:
        # block until an event is available
        data = _event_queue.get()
        # format as SSE
        yield f"event: assigned\ndata: {json.dumps(data)}\n\n"
