"""The macOS login Keychain as veil's SecretBackend (ADR-0025, macOS port).

Talks to Security.framework through ctypes: no pyobjc (about 100 ms of imports) and no
`security` subprocess (its `-w <secret>` argument would be visible in `ps`). The generic-password
calls used here take plain C strings, so no CoreFoundation dictionaries are needed.

The item's access list is the interpreter that created it. A different Python (after an
upgrade, or another venv) gets the system "veil wants to use your confidential information"
prompt, which is the macOS equivalent of an unlock prompt. Errors carry the OSStatus only,
never the secret.
"""

import ctypes
import functools
import sys

_SECURITY = "/System/Library/Frameworks/Security.framework/Security"
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

ERR_SEC_SUCCESS = 0
ERR_SEC_ITEM_NOT_FOUND = -25300
ERR_SEC_DUPLICATE_ITEM = -25299
ERR_SEC_AUTH_FAILED = -25293
ERR_SEC_INTERACTION_NOT_ALLOWED = -25308
ERR_SEC_USER_CANCELED = -128
_LOCKED_STATUSES = frozenset(
    {ERR_SEC_AUTH_FAILED, ERR_SEC_INTERACTION_NOT_ALLOWED, ERR_SEC_USER_CANCELED}
)


class KeychainError(Exception):
    """A Keychain call failed. Holds the OSStatus number only."""

    def __init__(self, status: int) -> None:
        super().__init__(f"OSStatus {status}")
        self.status = status


class KeychainLocked(KeychainError):
    """Locked keychain, a dismissed prompt, or no UI allowed (keystore maps it to "locked")."""


def _check(status: int) -> None:
    if status == ERR_SEC_SUCCESS:
        return
    raise (KeychainLocked if status in _LOCKED_STATUSES else KeychainError)(status)


@functools.cache
def _frameworks() -> tuple[ctypes.CDLL, ctypes.CDLL]:
    if sys.platform != "darwin":
        raise KeychainError(-4)  # unimplemented: only reachable on macOS
    sec = ctypes.CDLL(_SECURITY)
    cf = ctypes.CDLL(_CORE_FOUNDATION)
    u32, ptr, cstr = ctypes.c_uint32, ctypes.c_void_p, ctypes.c_char_p
    sec.SecKeychainFindGenericPassword.argtypes = (
        ptr, u32, cstr, u32, cstr, ctypes.POINTER(u32), ctypes.POINTER(ptr), ctypes.POINTER(ptr)
    )  # fmt: skip
    sec.SecKeychainAddGenericPassword.argtypes = (
        ptr, u32, cstr, u32, cstr, u32, ctypes.c_void_p, ctypes.POINTER(ptr)
    )  # fmt: skip
    sec.SecKeychainItemModifyAttributesAndData.argtypes = (ptr, ptr, u32, ctypes.c_void_p)
    sec.SecKeychainItemDelete.argtypes = (ptr,)
    sec.SecKeychainItemFreeContent.argtypes = (ptr, ptr)
    for fn in (
        sec.SecKeychainFindGenericPassword,
        sec.SecKeychainAddGenericPassword,
        sec.SecKeychainItemModifyAttributesAndData,
        sec.SecKeychainItemDelete,
        sec.SecKeychainItemFreeContent,
    ):
        fn.restype = ctypes.c_int32
    cf.CFRelease.argtypes = (ptr,)
    cf.CFRelease.restype = None
    return sec, cf


def _find(service: bytes, account: bytes, *, want_data: bool) -> tuple[bytes | None, int | None]:
    """(password bytes or None, item ref or None). Not found is (None, None)."""
    sec, _ = _frameworks()
    length = ctypes.c_uint32(0)
    data = ctypes.c_void_p()
    item = ctypes.c_void_p()
    status = sec.SecKeychainFindGenericPassword(
        None,
        len(service),
        service,
        len(account),
        account,
        ctypes.byref(length) if want_data else None,
        ctypes.byref(data) if want_data else None,
        ctypes.byref(item),
    )
    if status == ERR_SEC_ITEM_NOT_FOUND:
        return None, None
    _check(status)
    secret = None
    if want_data and data.value:
        try:
            secret = ctypes.string_at(data.value, length.value)
        finally:
            sec.SecKeychainItemFreeContent(None, data)
    return secret, item.value


class KeychainBackend:
    """SecretBackend over the default (login) keychain, generic-password items."""

    def get_password(self, service: str, username: str) -> str | None:
        secret, item = _find(service.encode(), username.encode(), want_data=True)
        _release(item)
        return None if secret is None else secret.decode("utf-8")

    def set_password(self, service: str, username: str, password: str) -> None:
        sec, _ = _frameworks()
        svc, acct, data = service.encode(), username.encode(), password.encode("utf-8")
        _, item = _find(svc, acct, want_data=False)
        try:
            if item is not None:
                _check(sec.SecKeychainItemModifyAttributesAndData(item, None, len(data), data))
                return
            _check(
                sec.SecKeychainAddGenericPassword(
                    None, len(svc), svc, len(acct), acct, len(data), data, None
                )
            )
        finally:
            _release(item)

    def delete_password(self, service: str, username: str) -> None:
        sec, _ = _frameworks()
        _, item = _find(service.encode(), username.encode(), want_data=False)
        if item is None:
            raise KeychainError(ERR_SEC_ITEM_NOT_FOUND)
        try:
            _check(sec.SecKeychainItemDelete(item))
        finally:
            _release(item)


def _release(item: int | None) -> None:
    if item:
        _frameworks()[1].CFRelease(item)
