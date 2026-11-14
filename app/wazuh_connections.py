"""Windows user-bound credential storage shared by Wazuh connection profiles."""

import ctypes
import os
from ctypes import wintypes


class _Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def protect(value, *, decrypt=False):
    if os.name != "nt":
        raise ValueError("Persistent browser-entered credentials require Windows. On this OS use the session or environment configuration.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    api = ctypes.WinDLL("crypt32", use_last_error=True)
    pointer = ctypes.POINTER(_Blob)
    signature = [pointer, ctypes.c_void_p, pointer, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, pointer]
    function = api.CryptUnprotectData if decrypt else api.CryptProtectData
    function.argtypes, function.restype = signature, wintypes.BOOL
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    source = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    original, result = _Blob(len(source), source), _Blob()
    if not function(ctypes.byref(original), None, None, None, None, 1, ctypes.byref(result)):
        raise ValueError("Windows could not access the protected Wazuh credential for this user.")
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        kernel.LocalFree(result.data)
