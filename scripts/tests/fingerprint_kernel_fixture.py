"""CI-only readback of the fresh loader-owned Map, never a production command.

Linux UAPI: include/uapi/linux/bpf.h; x86 syscall_64.tbl (Linux v6.6).
Only GET_FD_BY_ID, GET_INFO_BY_FD, GET_NEXT_KEY and LOOKUP are issued.
"""
import ctypes
import errno
import os
import platform
import struct


def read_fingerprints(map_id):
    assert platform.machine() == "x86_64" and type(map_id) is int and map_id > 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def bpf(command, attributes):
        assert command in (1, 4, 14, 15)
        buffer = ctypes.create_string_buffer(attributes, len(attributes))
        result = libc.syscall(321, command, ctypes.byref(buffer), len(attributes))
        if result < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return result

    fd = bpf(14, struct.pack("<III", map_id, 0, 0))
    try:
        info = ctypes.create_string_buffer(88)
        bpf(15, struct.pack("<IIQ", fd, len(info), ctypes.addressof(info)))
        assert struct.unpack_from("<IIIIII", info.raw) == (9, map_id, 32, 48, 8192, 0)
        assert info.raw[24:40].split(b"\0", 1)[0] == b"FINGERPRINTS"
        records = {}
        previous = None
        for _ in range(8193):
            key = ctypes.create_string_buffer(32)
            try:
                bpf(4, struct.pack("<I4xQQQ", fd,
                                  ctypes.addressof(previous) if previous is not None else 0,
                                  ctypes.addressof(key), 0))
            except OSError as error:
                if error.errno == errno.ENOENT:
                    return records
                raise
            assert key.raw not in records, "Map changed during quiescent readback"
            value = ctypes.create_string_buffer(48)
            bpf(1, struct.pack("<I4xQQQ", fd, ctypes.addressof(key), ctypes.addressof(value), 0))
            records[key.raw] = value.raw
            previous = key
        raise AssertionError("Map read exceeded fixed capacity")
    finally:
        os.close(fd)


def frames(source, destination):
    source = bytes.fromhex(source.replace(":", ""))
    destination = bytes.fromhex(destination.replace(":", ""))
    for tagged in (False, True):
        ethernet = destination + source + (bytes.fromhex("810001230806") if tagged else bytes.fromhex("0806"))
        header = ethernet + bytes.fromhex("0001080006040001") + source + bytes(4) + destination + bytes(4)
        for variant in range(256):
            for length in (64, 512, 1514):
                yield header + bytes(59 - len(header)) + bytes([variant]) + bytes(length - 60), tagged


def expected_fingerprints(ifindex, host_mac, peer_mac):
    records = {}
    for direction, source, destination in ((2, host_mac, peer_mac), (1, peer_mac, host_mac)):
        for frame, tagged in frames(source, destination):
            hash_value = 0xcbf29ce484222325
            for byte in len(frame).to_bytes(2, "big") + frame[:60]:
                hash_value = ((hash_value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
            if hash_value & 15:
                continue
            key = struct.pack("<QQIHHHBBBB2x", 1, hash_value, ifindex,
                              0x123 if tagged else 0xffff, 0x0806, len(frame), direction, int(tagged), 0, 1)
            # Each frame is sent twice, exercising both insertion and update.
            records[key] = struct.pack("<QQ6s6s4x", 2, 2 * len(frame), frame[6:12], frame[:6])
    return records


SENDER = r'''
import socket,sys
from fingerprint_kernel_fixture import frames
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as channel:
 channel.settimeout(1)
 channel.bind((sys.argv[1],0))
 for frame,_ in frames(sys.argv[2],sys.argv[3]):
  for _ in range(2): assert channel.send(frame)==len(frame)
'''
