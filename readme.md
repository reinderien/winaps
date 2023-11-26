This is a thin FFI for a subset of the
[Native Wi-Fi wlanapi](https://learn.microsoft.com/en-us/windows/win32/api/_nwifi).

Dependencies
------------

The only dependencies are a normally-configured Wi-Fi adaptor, Python 3.10+,
and a version of Windows that supports wlanapi 2 (i.e. at least Vista / Server
2008; untested).

Monitor/promiscuous mode is not needed. npcap and Wireshark are not needed.
Administrative mode is not needed. Any existing Wi-Fi connections will
(probably) not be interrupted.

Script mode
-----------

When run as a script, this offers much of the same content as the Linux
[`iw dev scan`](https://wireless.wiki.kernel.org/en/users/documentation/iw#scanning).
It runs forever, continuously performing scans and printing the results.

Library mode
------------

When imported, the top-level structs and methods are reusable.

Limitations
-----------

Compared to a monitor-mode solution (e.g. with npcap/tshark), the response rate
of the survey is likely to be slower. This solution also doesn't pin the
channel, leaving the interface to its default channel-hopping scan. You might
be able to pin the channel or enable background scan via
[`WlanSetInterface`](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetinterface)
but that's beyond the scope of this script.
