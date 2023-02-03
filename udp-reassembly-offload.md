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

## Rules

URO can only be attempted on a batch of packets that meet all the following criteria:

- Unicast only (no broadcast or multicast)
- 5-tuple matches
- Payload length is identical for all datagrams
- ECN, DF bits must match on all packets (IPv4)
- NextHeader must be UDP (IPv6)
- The total length of the Single Coalesced Unit (SCU) must not exceed IP max length
- No more than 255 NBLs per SCU

The resulting SCU must have a single IP header first, then the UDP header, followed by just the UDP payload for all coalesced datagrams concatenated together. 
```
--------------------------------------------------------------------------------
| IP Header | UDP Header | UDP Payload 1 | UDP Payload 2 | ... | UDP Payload N |
--------------------------------------------------------------------------------
```

> **TODO**

# Appendix
