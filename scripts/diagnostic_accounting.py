"""Acceptance-only boundary accounting; never a product or global tracing API."""
import ctypes
import os
import platform
import struct
import sys

EVENTS = (('task_clock', 1, 1), ('cycles', 0, 0),
          ('instructions', 0, 1), ('ref_cycles', 0, 9))


def _integers(values, count):
    return (isinstance(values, (list, tuple)) and len(values) == count
            and all(type(v) is int and v >= 0 for v in values))


def cpu_ticks(text, cpu):
    if type(cpu) is not int or cpu < 0 or not isinstance(text, str):
        raise ValueError('invalid CPU snapshot')
    rows = [line.split()[1:] for line in text.splitlines()
            if line.split() and line.split()[0] == 'cpu' + str(cpu)]
    if len(rows) != 1 or len(rows[0]) != 10:
        raise ValueError('missing, duplicate or malformed CPU row')
    values = [int(v) for v in rows[0]]
    if not _integers(values, 10):
        raise ValueError('invalid CPU counters')
    return values


def cpu_delta(before, after):
    if not _integers(before, 10) or not _integers(after, 10):
        raise ValueError('invalid CPU counter shape')
    values = [b-a for a, b in zip(before, after)]
    if min(values) < 0:
        raise ValueError('CPU counter regressed')
    # Guest and guest_nice are already included in user and nice.
    return dict(ticks=values, total_ticks=sum(values[:8]),
                irq_ticks=values[5], softirq_ticks=values[6])


def perf_delta(before, after):
    if before is None and after is None:
        return None
    if not _integers(before, 3) or not _integers(after, 3):
        raise ValueError('performance counter availability or shape changed')
    value, enabled, running = [b-a for a, b in zip(before, after)]
    if min(value, enabled, running) < 0 or running > enabled:
        raise ValueError('invalid performance counter delta')
    coverage = running / enabled if enabled else None
    return dict(value=value, enabled_ns=enabled, running_ns=running,
                coverage=coverage, usable=enabled > 0 and running == enabled)


def aligned_delta(before, after):
    if (type(before['cpu']) is not int or before['cpu'] < 0
            or before['cpu'] != after['cpu'] or before['hz'] != after['hz']
            or type(before['hz']) is not int or before['hz'] <= 0
            or set(before['perf']) != set(after['perf'])):
        raise ValueError('accounting identity changed')
    times = [before['start_ns'], before['end_ns'], after['start_ns'], after['end_ns']]
    if not _integers(times, 4) or times != sorted(times):
        raise ValueError('accounting boundaries changed order')
    return dict(cpu_id=before['cpu'], hz=before['hz'],
                cpu=cpu_delta(before['ticks'], after['ticks']),
                perf={name: perf_delta(before['perf'][name], after['perf'][name])
                      for name in before['perf']},
                boundary_read_spans_ns=[times[1]-times[0], times[3]-times[2]],
                boundary_start_interval_ns=times[2]-times[0])


def open_counter(kind, config, syscall=None):
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise OSError('counter ABI requires Linux x86_64')
    if (kind, config) not in [(k, c) for _, k, c in EVENTS]:
        raise ValueError('counter outside fixed diagnostic set')
    # VER0, counting only, no inheritance/exclusive/pinned/sampling flags.
    # Read value + enabled + running; no scaling or guessed unavailable zeros.
    attr = struct.pack('=IIQQQQQ', kind, 64, config, 0, 0, 3, 0) + bytes(16)
    buffer = ctypes.create_string_buffer(attr)
    if syscall is None:
        syscall = ctypes.CDLL(None, use_errno=True).syscall
        syscall.restype = ctypes.c_long
    # pid=0 is this thread; cpu=-1 follows this thread, never CPU-wide.
    fd = syscall(298, ctypes.byref(buffer), 0, -1, -1, 8)
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return fd


class PerfCounters:
    def __init__(self, opener=open_counter, reader=os.read, closer=os.close):
        self.fds = {}
        self.unavailable = {}
        self.reader, self.closer = reader, closer
        try:
            for name, kind, config in EVENTS:
                try:
                    self.fds[name] = opener(kind, config)
                except OSError as error:
                    self.fds[name] = None
                    self.unavailable[name] = error.errno
        except BaseException:
            self.close()
            raise

    def snapshot(self):
        result = {}
        for name, fd in self.fds.items():
            if fd is None:
                result[name] = None
                continue
            data = self.reader(fd, 24)
            if len(data) != 24:
                raise ValueError('short performance counter read')
            result[name] = list(struct.unpack('=QQQ', data))
        return result

    def close(self):
        owned, self.fds = self.fds, {}
        failure = None
        for fd in owned.values():
            if fd is not None:
                try:
                    self.closer(fd)
                except OSError as error:
                    failure = error
        if failure:
            raise failure
