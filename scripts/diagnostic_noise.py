"""Boundary-only sender telemetry; never changes scheduler configuration."""
import time


def _read(path):
    try:
        with open(path, encoding='ascii') as source:
            value = source.read(16385)
        return value if len(value) <= 16384 else None
    except OSError:
        return None


def snapshot():
    import resource
    started = time.monotonic_ns()
    # Disabled schedstats can expose stale/zero values: never interpret them.
    enabled = _read('/proc/sys/kernel/sched_schedstats')
    schedstat = _read('/proc/self/schedstat') if enabled and enabled.strip() == '1' else None
    sched = _read('/proc/self/sched')
    migrations = None
    if sched:
        for line in sched.splitlines():
            name, separator, value = line.partition(':')
            if separator and name.strip() in ('se.nr_migrations', 'nr_migrations'):
                migrations = int(value.strip())
    stat = _read('/proc/self/stat')
    cpu_id = int(stat.rsplit(')', 1)[1].split()[36]) if stat else None
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result = dict(cpu_ns=time.process_time_ns(), user_ns=round(usage.ru_utime * 1e9),
                  system_ns=round(usage.ru_stime * 1e9), voluntary=usage.ru_nvcsw,
                  involuntary=usage.ru_nivcsw, minor_faults=usage.ru_minflt,
                  major_faults=usage.ru_majflt, migrations=migrations, cpu_id=cpu_id,
                  runqueue_ns=int(schedstat.split()[1]) if schedstat else None,
                  observed_start_ns=started)
    result['observed_end_ns'] = time.monotonic_ns()
    return result


def delta(before, after, elapsed_ns):
    if type(elapsed_ns) is not int or elapsed_ns <= 0:
        raise ValueError('invalid noise measurement interval')
    result = {}
    for key in ('cpu_ns', 'user_ns', 'system_ns', 'voluntary', 'involuntary',
                'minor_faults', 'major_faults', 'runqueue_ns', 'migrations'):
        left, right = before.get(key), after.get(key)
        if key in ('runqueue_ns', 'migrations') and left is None and right is None:
            result[key] = None
            continue
        if type(left) is not int or type(right) is not int or not 0 <= left <= right:
            raise ValueError('noise counter unavailable, changed or regressed: ' + key)
        result[key] = right - left
    times = [before.get('observed_start_ns'), before.get('observed_end_ns'),
             after.get('observed_start_ns'), after.get('observed_end_ns')]
    if any(type(t) is not int or t < 0 for t in times) or times != sorted(times):
        raise ValueError('invalid telemetry boundary order')
    overhead = times[3] - times[0] - elapsed_ns
    if overhead < 0:
        raise ValueError('telemetry does not bracket the measurement')
    result.update(boundary_overhead_upper_ns=overhead,
                  endpoint_cpu_ids=[before.get('cpu_id'), after.get('cpu_id')])
    return result
