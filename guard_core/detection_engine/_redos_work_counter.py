# The verdict of the reach-probe is a count of retired instructions where the host can
# read one without privileges, never a duration: the same regex work retires the same
# instructions on a performance core and on an efficiency core (which takes about 2.4
# times longer), beside busy loops or alone. macOS reports the counter of the calling
# process through proc_pid_rusage. A child that cannot read it (any other platform, no
# ctypes) gets None and the caller falls back to measured CPU time. Linux opens a
# perf_event_open counter of its own user-space instructions when the kernel allows it
# (perf_event_paranoid and the container's seccomp profile often refuse), and only on an
# architecture whose seconds per instruction was calibrated with the D-122 band on a
# host that can count: the table below is empty until a host has measured one.
WORK_UNIT_SECONDS = 5.1e-11

# x86_64 has no calibrated unit (D-261): over 24 measured builds the window between the
# slowest safe row and the fastest mirror row is 3.7% wide (5.5307e-11 to 5.7337e-11
# seconds per instruction), so no single unit keeps the 5% margin on both sides. An
# architecture gets an entry only once its measured window is wide enough for it.
LINUX_UNIT_SECONDS: dict[str, float] = {}

_WORK_COUNTER_TEMPLATE = """\
def macos_retired(ctypes, os):
    names = (
        'ri_user_time ri_system_time ri_pkg_idle_wkups ri_interrupt_wkups '
        'ri_pageins ri_wired_size ri_resident_size ri_phys_footprint '
        'ri_proc_start_abstime ri_proc_exit_abstime ri_child_user_time '
        'ri_child_system_time ri_child_pkg_idle_wkups ri_child_interrupt_wkups '
        'ri_child_pageins ri_child_elapsed_abstime ri_diskio_bytesread '
        'ri_diskio_byteswritten ri_cpu_time_qos_default '
        'ri_cpu_time_qos_maintenance ri_cpu_time_qos_background '
        'ri_cpu_time_qos_utility ri_cpu_time_qos_legacy '
        'ri_cpu_time_qos_user_initiated ri_cpu_time_qos_user_interactive '
        'ri_billed_system_time ri_serviced_system_time ri_logical_writes '
        'ri_lifetime_max_phys_footprint ri_instructions ri_cycles '
        'ri_billed_energy ri_serviced_energy ri_interval_max_phys_footprint '
        'ri_runnable_time').split()

    class Usage(ctypes.Structure):
        _fields_ = [('ri_uuid', ctypes.c_uint8 * 16)] + [
            (name, ctypes.c_uint64) for name in names]

    library = ctypes.CDLL('libproc.dylib')
    usage = Usage()
    pid = os.getpid()

    def retired():
        if library.proc_pid_rusage(pid, 4, ctypes.byref(usage)) != 0:
            raise OSError('proc_pid_rusage failed')
        return usage.ri_instructions
    return retired


def linux_retired(ctypes, os):
    import struct
    machine = os.uname().machine
    number = {'x86_64': 298, 'aarch64': 241}.get(machine)
    unit = LINUX_UNITS.get(machine)
    if number is None or unit is None:
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.syscall.argtypes = [
        ctypes.c_long, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_ulong]
    attribute = struct.pack('=IIQQQQQIIQ', 0, 64, 1, 0, 0, 0, 0x60, 0, 0, 0)
    descriptor = libc.syscall(number, attribute, 0, -1, -1, 0)
    if descriptor < 0:
        return None
    scale = unit / MACOS_UNIT

    def retired():
        return int(struct.unpack('=Q', os.read(descriptor, 8))[0] * scale)

    return retired


def build_work_counter():
    try:
        import ctypes, os, sys
        if sys.platform == 'linux':
            retired = linux_retired(ctypes, os)
            if retired is None:
                return None
        elif sys.platform != 'darwin':
            return None
        else:
            retired = macos_retired(ctypes, os)
        if retired() <= 0:
            return None
    except Exception:
        return None

    def instructions(compiled, probe):
        before = retired()
        compiled.search(probe)
        return retired() - before

    empty = re.compile('a')
    baseline = min(instructions(empty, 'b') for _ in range(3))
    return lambda compiled, probe: max(instructions(compiled, probe) - baseline, 0)
"""


def work_counter_source(linux_units: dict[str, float]) -> str:
    return _WORK_COUNTER_TEMPLATE.replace("LINUX_UNITS", repr(linux_units)).replace(
        "MACOS_UNIT", repr(WORK_UNIT_SECONDS)
    )


WORK_COUNTER_SOURCE = work_counter_source(LINUX_UNIT_SECONDS)

# A host with no instruction counter (Linux where perf_event_open is refused by the
# default container profile or by perf_event_paranoid, or where no unit is calibrated,
# and every other Unix) still has one exact measure of dispatch-bound regex work:
# CPython's matcher polls for signals once per few thousand opcode dispatches, so a
# signal that re-arms itself at every poll leaves one byte on a wakeup descriptor per
# poll. The count depends only on the pattern, the probe and the interpreter build. It
# cannot see work done inside one
# opcode (a long scan), so the arbiter keeps the measured CPU time beside it and lets
# the time decide where it reads far above the count. One unit holds the v4.4.0 safe
# CDATA row (cap 10000) under the budget and the lowest mirror caps (3.10 cap 13000,
# 3.11 and later cap 12000) over it on every Python from 3.10 to 3.14.
POLL_UNIT_SECONDS = 3.4e-5

POLL_COUNTER_SOURCE = """\
def build_poll_counter():
    try:
        import ctypes, os, signal, sys
        if sys.platform == 'win32' or not hasattr(signal, 'set_wakeup_fd'):
            return None
        reader, writer = os.pipe()
        os.set_blocking(reader, False)
        os.set_blocking(writer, False)
        try:
            import fcntl
            fcntl.fcntl(writer, getattr(fcntl, 'F_SETPIPE_SZ', 1031), 1 << 20)
        except Exception:
            pass
        rearm = ctypes.PYFUNCTYPE(None, ctypes.py_object, ctypes.py_object)(
            ('PyErr_SetInterrupt', ctypes.pythonapi))
        start = ctypes.pythonapi.PyErr_SetInterrupt
        signal.set_wakeup_fd(writer, warn_on_full_buffer=False)
    except Exception:
        return None

    def idle(signum, frame):
        return None

    def drain():
        total = 0
        while True:
            try:
                chunk = os.read(reader, 1 << 20)
            except BlockingIOError:
                return total
            total += chunk.count(bytes([signal.SIGINT]))

    def polls(compiled, probe):
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

NO_POLL_COUNTER_SOURCE = """\
def build_poll_counter():
    return None
"""
