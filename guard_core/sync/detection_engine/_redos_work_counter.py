# The verdict of the reach-probe is a count of regex work, never a duration: CPython's
# matcher polls for signals once per 4096 opcode dispatches, so a signal that re-arms
# itself at every poll leaves one byte on the wakeup descriptor per 4096 dispatches.
# The count depends only on the pattern, the probe and the interpreter build, so no
# scheduler, core type or host load can move it. A child without ctypes, sockets or
# the CPython hook gets None and the caller falls back to measured CPU time.
WORK_UNIT_SECONDS = 3.4e-5

WORK_COUNTER_SOURCE = """\
def build_work_counter():
    try:
        import ctypes, signal, socket
        reader, writer = socket.socketpair()
        reader.setblocking(False)
        writer.setblocking(False)
        writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        rearm = ctypes.PYFUNCTYPE(None, ctypes.py_object, ctypes.py_object)(
            ('PyErr_SetInterrupt', ctypes.pythonapi))
        start = ctypes.pythonapi.PyErr_SetInterrupt
        signal.set_wakeup_fd(writer.fileno(), warn_on_full_buffer=False)
    except Exception:
        return None

    def idle(signum, frame):
        return None

    def drain():
        total = 0
        while True:
            try:
                chunk = reader.recv(1 << 20)
            except BlockingIOError:
                return total
            total += chunk.count(b'\\x02')

    def polls(compiled, probe):
        writer.fileno()
        drain()
        signal.signal(signal.SIGINT, rearm)
        start()
        compiled.search(probe)
        signal.signal(signal.SIGINT, idle)
        return drain()

    empty = re.compile('a')
    baseline = min(polls(empty, 'b') for _ in range(3))
    return lambda compiled, probe: max(polls(compiled, probe) - baseline, 0)
"""
