"""
This is a thin FFI for a subset of the
[Native Wi-Fi wlanapi](https://learn.microsoft.com/en-us/windows/win32/api/_nwifi).

The only dependencies are Python 3 and a version of Windows somewhere north of
Vista (untested). Monitor mode is not needed. npcap and Wireshark are not
needed. Administrative mode is not needed. Any existing Wi-Fi connections will
(probably) not be interrupted.

When run as a script, it offers much of the same content as the Linux `iw` and
`iwlist` scan modes.
"""

import ctypes.wintypes
import datetime
import struct
from contextlib import contextmanager
from decimal import Decimal
from enum import Enum
from time import sleep
from typing import Any, Callable, Iterable, Iterator
from uuid import UUID

# https://docs.python.org/3/library/ctypes.html#ctypes-function-prototypes
IN = 1
OUT = 2
DEFAULT_ZERO = 4

# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/windot11.h#L48
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/windot11/ns-windot11-_dot11_mac_address
DOT11_MAC_ADDRESS = ctypes.c_ubyte * 6


def fslots(fields: Iterable[
    tuple[str, Any] | tuple[str, Any, int]
]) -> tuple[str, ...]:
    return tuple(field[0] for field in fields)


def check_win(result: ctypes.wintypes.DWORD) -> None:
    result = int(result)
    if result != 0:
        raise ctypes.WinError(code=result)


def format_hex(bytea) -> str:
    return ':'.join(
        f'{b:02x}' for b in bytes(bytea)
    )


def parse_ies(blob: bytes) -> Iterator[bytes]:
    """
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry

    > Information elements are defined in the IEEE 802.11 specifications to have a common general
    > format consisting of a 1-byte Element ID field, a 1-byte Length field, and a variable-length
    > element-specific information field. Each information element is assigned a unique Element ID
    > value as defined in this IEEE 802.11 standards. The Length field specifies the number of bytes
    > in the information field.
    """
    offset = 0
    while offset+1 < len(blob):
        ie_len = blob[offset + 1]
        next_offset = offset + 2 + ie_len
        yield blob[offset: next_offset]
        offset = next_offset


class GUID(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/guiddef.h#L15
    https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
    """
    _fields_ = (
        ('Data1', ctypes.c_ulong),
        ('Data2', ctypes.c_ushort),
        ('Data3', ctypes.c_ushort),
        ('Data4', ctypes.c_ubyte*8),
    )
    __slots__ = fslots(_fields_)

    @property
    def uuid(self) -> UUID:
        node, = struct.unpack('>Q', b'\0\0' + bytes(self.Data4[2:]))
        return UUID(
            fields=(
                int(self.Data1),
                int(self.Data2),
                int(self.Data3),
                int(self.Data4[0]),
                int(self.Data4[1]),
                node,
            ),
        )

    def __str__(self) -> str:
        return str(self.uuid)


class DOT11_BSS_TYPE(Enum):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/wlantypes.h#L23
    https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-bss-type
    """
    infrastructure = 1
    independent = 2
    any = 3


class DOT11_SSID(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/wlantypes.h#L30
    https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-ssid
    """

    # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/wlantypes.h#L29
    DOT11_SSID_MAX_LENGTH = 32

    _fields_ = (
        ('uSSIDLength', ctypes.c_ulong),
        ('ucSSID', ctypes.c_char * DOT11_SSID_MAX_LENGTH),
    )
    __slots__ = fslots(_fields_)


class DOT11_PHY_TYPE(Enum):
    """
    https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/windot11/ne-windot11-_dot11_phy_type
    Don't use the definition from wlanapi; that's incomplete
    """
    unknown = 0
    any = unknown
    fhss = 1
    dsss = 2
    irbaseband = 3
    ofdm = 4
    hrdsss = 5
    erp = 6
    ht = 7
    vht = 8
    dmg = 9
    he = 10
    eht = 11
    IHV_start = 0x80000000
    IHV_end = 0xffffffff


class WLAN_RATE(ctypes.LittleEndianStructure):
    """
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_rate_set
    Not an explicit structure in the original header
    """
    _fields_ = (
        ('rate', ctypes.wintypes.USHORT, 15),
        ('isBasic', ctypes.wintypes.USHORT, 1),
    )
    __slots__ = fslots(_fields_)

    @property
    def mbps(self) -> float:
        return self.rate * 0.5

    def __str__(self) -> str:
        return (
            f'{self.mbps:4.1f} Mbps'
            f'{" (basic)" if self.isBasic else ""}'
        )


class WLAN_RATE_SET(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L451
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_rate_set
    """

    # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/windot11.h#L94
    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_rate_set#members
    DOT11_RATE_SET_MAX_LENGTH = 126

    _fields_ = (
        ('uRateSetLength', ctypes.wintypes.ULONG),
        ('usRateSet', WLAN_RATE * DOT11_RATE_SET_MAX_LENGTH),
    )
    __slots__ = fslots(_fields_)

    @property
    def items(self) -> ctypes.Array[WLAN_RATE]:
        tnew = WLAN_RATE * (self.uRateSetLength // ctypes.sizeof(WLAN_RATE))
        return tnew.from_address(ctypes.addressof(self.usRateSet))

    def describe(self, prefix: str = '    Rate: ') -> Iterator[str]:
        for rate in self.items:
            yield f'{prefix}{rate}'


class WLAN_BSS_ENTRY(ctypes.LittleEndianStructure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L509
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry
    """
    _fields_ = (
        ('dot11Ssid', DOT11_SSID),
        ('uPhyId', ctypes.wintypes.ULONG),
        ('dot11Bssid', DOT11_MAC_ADDRESS),
        ('dot11BssType', ctypes.c_int),  # DOT11_BSS_TYPE
        ('dot11BssPhyType', ctypes.c_int),  # DOT11_PHY_TYPE
        ('lRssi', ctypes.wintypes.LONG),
        ('uLinkQuality', ctypes.wintypes.ULONG),
        ('bInRegDomain', ctypes.wintypes.BOOLEAN),
        ('usBeaconPeriod', ctypes.wintypes.USHORT),
        ('ullTimestamp', ctypes.c_ulonglong),
        ('ullHostTimestamp', ctypes.c_ulonglong),
        ('usCapabilityInformation_ESS', ctypes.wintypes.USHORT, 1),
        ('usCapabilityInformation_IBSS', ctypes.wintypes.USHORT, 1),
        ('usCapabilityInformation_CFPollable', ctypes.wintypes.USHORT, 1),
        ('usCapabilityInformation_CFPollRequest', ctypes.wintypes.USHORT, 1),
        ('usCapabilityInformation_Privacy', ctypes.wintypes.USHORT, 1),
        ('usCapabilityInformation_Reserved', ctypes.wintypes.USHORT, 11),
        ('ulChCenterFrequency', ctypes.wintypes.ULONG),  # kHz
        ('wlanRateSet', WLAN_RATE_SET),
        ('ulIeOffset', ctypes.wintypes.ULONG),
        ('ulIeSize', ctypes.wintypes.ULONG),
    )
    __slots__ = fslots(_fields_)

    @property
    def ie_blob(self) -> ctypes.Array[ctypes.c_ubyte]:
        blob_start = ctypes.addressof(self.dot11Ssid) + self.ulIeOffset
        tnew = ctypes.c_ubyte * self.ulIeSize
        return tnew.from_address(blob_start)

    @property
    def ies(self) -> Iterator[bytes]:
        return parse_ies(bytes(self.ie_blob))

    @property
    def phy_type(self) -> DOT11_PHY_TYPE:
        return DOT11_PHY_TYPE(self.dot11BssPhyType)

    @property
    def bss_type(self) -> DOT11_BSS_TYPE:
        return DOT11_BSS_TYPE(self.dot11BssType)

    def __str__(self) -> str:
        return format_hex(self.dot11Bssid)

    @property
    def summary(self) -> str:
        return f'BSSID: {format_hex(self.dot11Bssid)}'

    def cap_strs(self) -> Iterator[str]:
        if self.usCapabilityInformation_ESS: yield 'ESS'
        if self.usCapabilityInformation_IBSS: yield 'IBSS'
        if self.usCapabilityInformation_CFPollable: yield 'CFPollable'
        if self.usCapabilityInformation_CFPollRequest: yield 'CFPollRequest'
        if self.usCapabilityInformation_Privacy: yield 'Privacy'

    def describe_attrs(self, prefix='    ') -> Iterator[str]:
        if self.dot11Ssid.ucSSID:
            yield f'{prefix}SSID: "{self.dot11Ssid.ucSSID.decode()}"'
        yield f'{prefix}PHY ID: {self.uPhyId}'
        yield f'{prefix}BSS type: {self.bss_type.name}'
        yield f'{prefix}PHY type: {self.phy_type.name}'
        yield f'{prefix}RSSI: {self.lRssi} dBm'
        yield f'{prefix}Link quality: {self.uLinkQuality}%'
        yield f'{prefix}Country compliant or unavailable: {bool(self.bInRegDomain)}'
        yield f'{prefix}Frequency: {Decimal(self.ulChCenterFrequency)/1_000_000} GHz'
        yield f'{prefix}Beacon period: {self.usBeaconPeriod} * 1.024 ms'
        yield f'{prefix}Caps: {", ".join(self.cap_strs())}'
        yield f'{prefix}Uptime: {self.uptime}'
        yield f'{prefix}Capture time: {self.capture_time.astimezone()}'

    def describe_ies(self, prefix='    IE: ') -> Iterator[str]:
        for ie in self.ies:
            yield f'{prefix}Type {ie[0]:<3d} {format_hex(ie)}'

    @property
    def capture_time(self) -> datetime.datetime:
        # This member is a count of 100-nanosecond intervals since January 1, 1601.
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        offset = datetime.timedelta(seconds=self.ullHostTimestamp * 100e-9)
        return base + offset

    @property
    def uptime(self) -> datetime.timedelta:
        return datetime.timedelta(microseconds=self.ullTimestamp)


class WLAN_BSS_LIST(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L533
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_list
    """
    _fields_ = (
        ('dwTotalSize', ctypes.wintypes.DWORD),
        ('dwNumberOfItems', ctypes.wintypes.DWORD),
        ('wlanBssEntries', WLAN_BSS_ENTRY * 1),
    )
    __slots__ = fslots(_fields_)

    @property
    def items(self) -> ctypes.Array[WLAN_BSS_ENTRY]:
        tnew = WLAN_BSS_ENTRY * self.dwNumberOfItems
        return tnew.from_address(ctypes.addressof(self.wlanBssEntries))


class WLAN_INTERFACE_STATE(Enum):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L541
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ne-wlanapi-wlan_interface_state-r1
    """
    not_ready = 0
    connected = 1
    ad_hoc_network_formed = 2
    disconnecting = 3
    disconnected = 4
    associating = 5
    discovering = 6
    authenticating = 7


class WLAN_INTERFACE_INFO(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L570
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_interface_info
    """

    # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/l2cmn.h#L33
    # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L65
    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_connection_notification_data#members
    L2_PROFILE_MAX_NAME_LENGTH = 256
    WLAN_MAX_NAME_LENGTH = L2_PROFILE_MAX_NAME_LENGTH

    _fields_ = (
        ('InterfaceGuid', GUID),
        ('strInterfaceDescription', ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
        ('isState', ctypes.c_int),  # WLAN_INTERFACE_STATE
    )
    __slots__ = fslots(_fields_)

    @property
    def state(self) -> WLAN_INTERFACE_STATE:
        return WLAN_INTERFACE_STATE(self.isState)

    def __str__(self) -> str:
        return self.strInterfaceDescription

    @property
    def summary(self) -> str:
        return f'{self.InterfaceGuid} "{self.strInterfaceDescription}" state={self.state.name}'


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L717
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_interface_info_list
    """
    _fields_ = (
        ('dwNumberOfItems', ctypes.wintypes.DWORD),
        ('dwIndex', ctypes.wintypes.DWORD),
        ('InterfaceInfo', WLAN_INTERFACE_INFO*1),
    )
    __slots__ = fslots(_fields_)

    @property
    def items(self) -> ctypes.Array[WLAN_INTERFACE_INFO]:
        tnew = WLAN_INTERFACE_INFO * self.dwNumberOfItems
        return tnew.from_address(ctypes.addressof(self.InterfaceInfo))


class WLAN_NOTIFICATION_SOURCE(Enum):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L847
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/l2cmn.h#L40
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanregisternotification#parameters
    """
    NONE             = 0
    DOT3_AUTO_CONFIG = 0X00000001
    SECURITY         = 0X00000002
    ONEX             = 0X00000004
    WLAN_ACM         = 0X00000008
    WLAN_MSM         = 0X00000010
    WLAN_SECURITY    = 0X00000020
    WLAN_IHV         = 0X00000040
    WLAN_HNWK        = 0X00000080
    WCM              = 0X00000100
    WCM_CSP          = 0X00000200
    WFD              = 0X00000400
    ALL              = 0X0000FFFF


class WLAN_NOTIFICATION_ACM(Enum):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L859
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ne-wlanapi-wlan_notification_acm-r1
    """
    start                      = 0
    autoconf_enabled           = 1
    autoconf_disabled          = 2
    background_scan_enabled    = 3
    background_scan_disabled   = 4
    bss_type_change            = 5
    power_setting_change       = 6
    scan_complete              = 7
    scan_fail                  = 8
    connection_start           = 9
    connection_complete        = 10
    connection_attempt_fail    = 11
    filter_list_change         = 12
    interface_arrival          = 13
    interface_removal          = 14
    profile_change             = 15
    profile_name_change        = 16
    profiles_exhausted         = 17
    network_not_available      = 18
    network_available          = 19
    disconnecting              = 20
    disconnected               = 21
    adhoc_network_state_change = 22
    profile_unblocked          = 23
    screen_power_change        = 24
    profile_blocked            = 25
    scan_list_refresh          = 26
    operational_state_change   = 27
    end                        = 28


class WLAN_NOTIFICATION_DATA(ctypes.Structure):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L934
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/l2cmn.h#L85
    https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms706902(v=vs.85)
    """
    _fields_ = (
        ('NotificationSource', ctypes.wintypes.DWORD),  # WLAN_NOTIFICATION_SOURCE
        ('NotificationCode', ctypes.wintypes.DWORD),  # WLAN_NOTIFICATION_ACM
        ('InterfaceGuid', GUID),
        ('dwDataSize', ctypes.wintypes.DWORD),
        ('pData', ctypes.wintypes.LPVOID),
    )
    __slots__ = fslots(_fields_)

    @property
    def source(self) -> WLAN_NOTIFICATION_SOURCE:
        return WLAN_NOTIFICATION_SOURCE(self.NotificationSource)

    @property
    def notify_code(self) -> WLAN_NOTIFICATION_ACM:
        return WLAN_NOTIFICATION_ACM(self.NotificationCode)


# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L936
# https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nc-wlanapi-wlan_notification_callback
WLAN_NOTIFICATION_CALLBACK = ctypes.WINFUNCTYPE(
    None,
    ctypes.POINTER(WLAN_NOTIFICATION_DATA),
    ctypes.wintypes.LPVOID,
)


class WlanFreeMemoryT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1483
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanfreememory
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            None,
            ctypes.wintypes.LPVOID,
        )
        self.fun = proto(
            ('WlanFreeMemory', wlanapi),
            (
                (IN, 'pMemory'),
            ),
        )

    def __call__(self, memory: ctypes.wintypes.LPVOID) -> None:
        self.fun(pMemory=memory)


class WlanOpenHandleT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1159
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanopenhandle
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPVOID,
            ctypes.wintypes.PDWORD,
            ctypes.wintypes.PHANDLE,
        )
        self.fun = proto(
            ('WlanOpenHandle', wlanapi),
            (
                (IN, 'dwClientVersion'),
                (IN | DEFAULT_ZERO, 'pReserved'),
                (OUT, 'pdwNegotiatedVersion'),
                (OUT, 'phClientHandle'),
            ),
        )
        self.fun.errcheck = self.check

    @staticmethod
    def check(
        result: ctypes.wintypes.DWORD, func: Callable, args: tuple,
    ) -> tuple[ctypes.wintypes.PDWORD, ctypes.wintypes.PHANDLE]:
        check_win(result)
        return args[2:]

    @contextmanager
    def __call__(self, version: int = 2) -> Iterator[tuple[
        int, ctypes.wintypes.HANDLE,
    ]]:
        pdwNegotiatedVersion, phClientHandle = self.fun(dwClientVersion=version)
        try:
            yield int(pdwNegotiatedVersion.value), phClientHandle.value
        finally:
            WlanCloseHandle(phClientHandle.value)


class WlanCloseHandleT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1167
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanclosehandle
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.LPVOID,
        )
        self.fun = proto(
            ('WlanCloseHandle', wlanapi),
            (
                (IN, 'hClientHandle'),
                (IN | DEFAULT_ZERO, 'pReserved'),
            ),
        )

    def __call__(self, client: ctypes.wintypes.HANDLE) -> None:
        result = self.fun(hClientHandle=client)
        check_win(result)


class WlanEnumInterfacesT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1167
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.LPVOID,
            ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)),
        )
        self.fun = proto(
            ('WlanEnumInterfaces', wlanapi),
            (
                (IN, 'hClientHandle'),
                (IN | DEFAULT_ZERO, 'pReserved'),
                (OUT, 'ppInterfaceList'),
            ),
        )
        self.fun.errcheck = self.check

    @staticmethod
    def check(
        result: ctypes.wintypes.DWORD, func: Callable, args: tuple,
    ) -> ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)):
        check_win(result)
        return args[-1]

    @contextmanager
    def __call__(self, client: ctypes.wintypes.HANDLE) -> Iterator[
        ctypes.Array[WLAN_INTERFACE_INFO]
    ]:
        ifaces = self.fun(hClientHandle=client)
        try:
            yield ifaces.contents.items
        finally:
            WlanFreeMemory(ifaces)


class WlanRegisterNotificationT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1301
    https://learn.microsoft.com/en-us/windows/desktop/api/wlanapi/nf-wlanapi-wlanregisternotification
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL,
            WLAN_NOTIFICATION_CALLBACK,
            ctypes.wintypes.LPVOID,
            ctypes.wintypes.LPVOID,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        )
        self.fun = proto(
            ('WlanRegisterNotification', wlanapi),
            (
                (IN, 'hClientHandle'),
                (IN, 'dwNotifSource'),
                (IN, 'bIgnoreDuplicate'),
                (IN, 'funcCallback', None),
                (IN, 'pCallbackContext', None),
                (IN | DEFAULT_ZERO, 'pReserved'),
                (OUT, 'pdwPrevNotifSource'),
            ),
        )

    def __call__(
        self,
        client: ctypes.wintypes.HANDLE,
        notify_source: WLAN_NOTIFICATION_SOURCE,
        ignore_duplicate: bool,
        callback: WLAN_NOTIFICATION_CALLBACK,
        context: ctypes.POINTER = None,
    ) -> None:
        result = self.fun(
            hClientHandle=client,
            dwNotifSource=notify_source.value,
            bIgnoreDuplicate=ignore_duplicate,
            funcCallback=callback,
            pCallbackContext=context,
        )
        check_win(result)


class WlanScanT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1240
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanscan
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.POINTER(DOT11_SSID),
            ctypes.c_void_p,  # omitted
            ctypes.wintypes.LPVOID,
        )
        self.fun = proto(
            ('WlanScan', wlanapi),
            (
                (IN, 'hClientHandle'),
                (IN, 'pInterfaceGuid'),
                (IN, 'pDot11Ssid', None),
                (IN, 'pIeData', None),
                (IN | DEFAULT_ZERO, 'pReserved'),
            ),
        )

    def __call__(
        self,
        client: ctypes.wintypes.HANDLE,
        interface: GUID,
    ) -> None:
        result = self.fun(
            hClientHandle=client,
            pInterfaceGuid=ctypes.pointer(interface),
        )
        check_win(result)


class WlanGetNetworkBssListT:
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/wlanapi.h#L1267
    https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetnetworkbsslist
    """
    __slots__ = 'fun',

    def __init__(self) -> None:
        proto = ctypes.WINFUNCTYPE(
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.POINTER(DOT11_SSID),
            ctypes.c_int,  # DOT11_BSS_TYPE
            ctypes.wintypes.BOOL,
            ctypes.wintypes.LPVOID,
            ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST)),
        )
        self.fun = proto(
            ('WlanGetNetworkBssList', wlanapi),
            (
                (IN, 'hClientHandle'),
                (IN, 'pInterfaceGuid'),
                (IN, 'pDot11Ssid', None),
                (IN, 'dot11BssType'),
                (IN, 'bSecurityEnabled'),
                (IN | DEFAULT_ZERO, 'pReserved'),
                (OUT, 'ppWlanBssList'),
            ),
        )
        self.fun.errcheck = self.check

    @staticmethod
    def check(
        result: ctypes.wintypes.DWORD, func: Callable, args: tuple,
    ) -> ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST)):
        check_win(result)
        return args[-1]

    @contextmanager
    def __call__(
        self,
        client: ctypes.wintypes.HANDLE,
        interface: GUID,
        dot11BssType: DOT11_BSS_TYPE = DOT11_BSS_TYPE.any,
        bSecurityEnabled: bool = False,
    ) -> Iterator[ctypes.Array[WLAN_BSS_ENTRY]]:
        stations = self.fun(
            hClientHandle=client,
            pInterfaceGuid=ctypes.pointer(interface),
            dot11BssType=dot11BssType.value,
            bSecurityEnabled=bSecurityEnabled,
        )
        try:
            yield stations.contents.items
        finally:
            WlanFreeMemory(stations)


wlanapi = ctypes.windll.LoadLibrary('wlanapi')
WlanCloseHandle = WlanCloseHandleT()
WlanEnumInterfaces = WlanEnumInterfacesT()
WlanFreeMemory = WlanFreeMemoryT()
WlanGetNetworkBssList = WlanGetNetworkBssListT()
WlanOpenHandle = WlanOpenHandleT()
WlanRegisterNotification = WlanRegisterNotificationT()
WlanScan = WlanScanT()


@WLAN_NOTIFICATION_CALLBACK
def acm_callback(
    data: ctypes.POINTER(WLAN_NOTIFICATION_DATA),
    context: ctypes.wintypes.LPVOID,
) -> None:
    code = data.contents.notify_code
    print(f'Notify source={data.contents.source.name}'
          f' iface={data.contents.InterfaceGuid}'
          f' code={code.name}')
    if code != WLAN_NOTIFICATION_ACM.scan_list_refresh:
        return

    with WlanGetNetworkBssList(
        client=context,
        interface=data.contents.InterfaceGuid,
    ) as stations:
        for station in stations:
            print(station.summary)
            print('\n'.join(station.describe_attrs()))
            print('\n'.join(station.wlanRateSet.describe()))
            print('\n'.join(station.describe_ies()))
    print()


def first_iface(client: ctypes.wintypes.HANDLE) -> GUID:
    with WlanEnumInterfaces(client=client) as ifaces:
        print(f'Interfaces found: {len(ifaces)}')
        iface = ifaces[0]
        print(f'Using {iface.summary}')
        return GUID.from_buffer_copy(iface.InterfaceGuid)


def listen_forever(period: float = 5) -> None:
    with WlanOpenHandle() as (negotiated_version, client):
        print(f'wlanapi v{negotiated_version}')

        WlanRegisterNotification(
            client=client,
            notify_source=WLAN_NOTIFICATION_SOURCE.WLAN_ACM,
            ignore_duplicate=False,
            callback=acm_callback,
            context=client,
        )

        iface = first_iface(client)
        print()

        # Scans are mandated to take at most 4 seconds
        while True:
            WlanScan(client=client, interface=iface)
            sleep(period)


if __name__ == '__main__':
    try:
        listen_forever()
    except KeyboardInterrupt:
        pass
