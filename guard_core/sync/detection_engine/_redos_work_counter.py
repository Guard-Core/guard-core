# The verdict of the reach-probe is a count of retired instructions where the host can
# read one without privileges, never a duration: the same regex work retires the same
# instructions on a performance core and on an efficiency core (which takes about 2.4
# times longer), beside busy loops or alone. macOS reports the counter of the calling
# process through proc_pid_rusage. A child that cannot read it (any other platform, no
# ctypes) gets None and the caller falls back to measured CPU time.
WORK_UNIT_SECONDS = 5.1e-11

WORK_COUNTER_SOURCE = """\
def build_work_counter():
    try:
        import ctypes, ctypes.util, os, sys
        if sys.platform != 'darwin':
            return None
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

        library = ctypes.CDLL(ctypes.util.find_library('proc'))
        usage = Usage()
        pid = os.getpid()

        def retired():
            if library.proc_pid_rusage(pid, 4, ctypes.byref(usage)) != 0:
                raise OSError('proc_pid_rusage failed')
            return usage.ri_instructions

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
