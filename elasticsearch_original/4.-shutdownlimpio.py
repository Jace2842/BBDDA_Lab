import atexit
@atexit.register
def limpiar_logger():
    log_queue.put(None)
    thread.join()
