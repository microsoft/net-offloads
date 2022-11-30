# UDP Reassembly Offload (URO)

> **Note**
> This document is a work in progress.

This document describes an offload called URO which offloads coalescing and reassembly of multiple UDP datagrams into a single contiguous buffer.
In the absence of hardward support, the OS will attempt a best-effort software fallback.

## Table of Context

- [Winsock](#winsock)
- [TCPIP](#tcpip)
- [NDIS](#ndis)
- [Appendix](#appendix)

# Winsock

The Winsock API (currently only software fallback) already exists, and details on the API can be found [here](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options). Please see the info on `UDP_RECV_MAX_COALESCED_SIZE ` and `UDP_COALESCED_INFO`.

# TCPIP

This section describes necessary updates in the Windows network stack to support URO.

> **TODO**

# NDIS

The NDIS interface for URO is used for communication between TCPIP and the NDIS miniport driver.

> **TODO**

# Appendix
