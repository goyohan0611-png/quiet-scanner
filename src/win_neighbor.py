"""Read a Windows IPv4 neighbor by IP/index without localized command output.

GetIpNetEntry2 / MIB_IPNET_ROW2:
https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getipnetentry2
"""
import ctypes as ct
import socket


class NeighborRow(ct.Structure):
    # SOCKADDR_INET occupies 28 bytes, aligned to 4 bytes.
    _fields_ = [
        ("address", ct.c_uint32 * 7), ("index", ct.c_uint32),
        ("luid", ct.c_uint64), ("mac", ct.c_ubyte * 32),
        ("mac_length", ct.c_uint32), ("state", ct.c_uint32),
        ("flags", ct.c_ubyte), ("reachability", ct.c_uint32),
    ]


def read_neighbor(ip, index):
    """None means definitely absent. Lookup errors raise; never mean 'released'."""
    if not index or int(index) <= 0:
        raise ValueError("인터페이스 인덱스를 확인할 수 없습니다.")
    row = NeighborRow()
    row.index = int(index)
    raw_address = ct.addressof(row)
    ct.c_uint16.from_address(raw_address).value = socket.AF_INET
    ct.memmove(raw_address + 4, socket.inet_pton(socket.AF_INET, ip), 4)
    api = ct.WinDLL("iphlpapi")
    api.GetIpNetEntry2.argtypes = [ct.POINTER(NeighborRow)]
    api.GetIpNetEntry2.restype = ct.c_uint32
    code = api.GetIpNetEntry2(ct.byref(row))
    if code == 1168:  # ERROR_NOT_FOUND; not the invalid-interface error (2).
        return None
    if code:
        raise OSError(code, "Windows 이웃 테이블 조회 실패")
    if row.mac_length > len(row.mac):
        raise ValueError("잘못된 MAC 주소 길이입니다.")
    return {"mac": ":".join("%02x" % b for b in row.mac[:row.mac_length]),
            "permanent": row.state == 6}

