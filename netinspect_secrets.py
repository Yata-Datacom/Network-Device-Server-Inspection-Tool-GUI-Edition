"""Credential protection for Network Inspection Studio.

Profile passwords are encrypted with Windows DPAPI (current user) and stored as
``dpapi:1:<base64>``. On platforms without DPAPI we fall back to ``plain:1:<base64>``
so the JSON stays valid, but the UI clearly treats it as a downgrade.
"""

from __future__ import annotations

import base64
import ctypes
import sys

DPAPI_PREFIX = "dpapi:1:"
PLAIN_PREFIX = "plain:1:"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _make_blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buf


def _dpapi_available() -> bool:
    return sys.platform == "win32"


def _protect_dpapi(text: str) -> str | None:
    if not _dpapi_available():
        return None
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(_DataBlob), ctypes.c_wchar_p,
            ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(_DataBlob)]
        crypt32.CryptProtectData.restype = ctypes.c_bool
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        data = text.encode("utf-8")
        blob_in, _buf = _make_blob(data)
        blob_out = _DataBlob()
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), "Network Inspection Studio", None, None, None, 0x1,
            ctypes.byref(blob_out))
        if not ok:
            return None
        try:
            raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)
        return DPAPI_PREFIX + base64.b64encode(raw).decode("ascii")
    except Exception:
        return None


def _unprotect_dpapi(token: str) -> str | None:
    if not _dpapi_available():
        return None
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob), ctypes.c_void_p,
            ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(_DataBlob)]
        crypt32.CryptUnprotectData.restype = ctypes.c_bool
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        raw = base64.b64decode(token[len(DPAPI_PREFIX):])
        blob_in, _buf = _make_blob(raw)
        blob_out = _DataBlob()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0x1,
            ctypes.byref(blob_out))
        if not ok:
            return None
        try:
            data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)
        return data.decode("utf-8")
    except Exception:
        return None


def protect(text: str) -> str:
    text = "" if text is None else str(text)
    token = _protect_dpapi(text)
    if token:
        return token
    return PLAIN_PREFIX + base64.b64encode(text.encode("utf-8")).decode("ascii")


def unprotect(token: str) -> str:
    token = token or ""
    if token.startswith(DPAPI_PREFIX):
        value = _unprotect_dpapi(token)
        return value if value is not None else ""
    if token.startswith(PLAIN_PREFIX):
        try:
            return base64.b64decode(token[len(PLAIN_PREFIX):]).decode("utf-8")
        except Exception:
            return ""
    return token


def protection_kind(token: str) -> str:
    if token.startswith(DPAPI_PREFIX):
        return "dpapi"
    if token.startswith(PLAIN_PREFIX):
        return "plain"
    return "raw"


def protection_label() -> str:
    return "Windows DPAPI（当前用户）" if _dpapi_available() else "明文（当前平台无 DPAPI）"
