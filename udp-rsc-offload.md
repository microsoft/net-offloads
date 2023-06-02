# UDP Receive Segment Coalescing Offload (URO)

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

- If hardware URO is enabled, and a socket opts-in to URO with a max coalesced size the same as, or larger than, the hardare offload, then TCPIP will deliver the NBLs from hardware unmodified.
- If hardware URO is enabled, but a socket opts-in to a smaller max coalesced size, TCPIP/AFD will break the coalesced receive into the smaller size for the socket.
- If hardware URO is enabled, but a socket does not opt-in to URO, then TCPIP will resegment receives for that socket.
- If hardware URO is not available, but a socket opts-in to URO with the Winsock API, software URO will be used for that socket. Software coalescing will follow the same rules as NDIS, except for the following:
    - Software coalescing may decide to use multiple NBLs in a chain of up to 255, instead of a single NBL.
    - Software coalescing will not coalesce IP fragments, broadcast or multicast datagrams, or datagrams with IP extension headers.
- TCPIP will disable the hardware offload, and the software fallback, if any WFP/LWF filters that are URO-incompatible are installed on the system.

# NDIS

The NDIS interface for URO is used for communication between TCPIP and the NDIS miniport driver.

## Rules

URO can only be attempted on a batch of packets that meet **all** the following criteria:

- 5-tuple matches.
- Payload length is identical for all datagrams, except the last datagram which may be less.
- The UDP checksums on pre-coalesced packets must be correct. This means checksum offload must be enabled and set the checksum OOB info.
- TTL, ToS/ECN, Protocol, and DF bit must match on all packets (IPv4).
- TC/ECN, FlowLabel, and HopLimit must match, and NextHeader must be UDP (IPv6).
- The total length of the Single Coalesced Unit (SCU) is allowed to exceed IP max length.
- When the SCU length is larger than the max IP length:
  - Set NB->DataLength to the coalesced size (up to 0xFFFFFFFF).
  - Set IP total length field to 0.
  - Set UDP length field to 0 when UDP length is greater than max UDP length.
  - Set UDP checksum field to 0.

The coalesced IP length field and the UDP length field must reflect the new coalesced length. The coalesced IPv4 checksum field must include the new length. The coalesced UDP checksum field is ignored and does not need to be calculated (since it was already validated individually).

The resulting SCU must have a single IP header first, then the UDP header, followed by just the UDP payload for all coalesced datagrams concatenated together. 
```
--------------------------------------------------------------------------------
| IP Header | UDP Header | UDP Payload 1 | UDP Payload 2 | ... | UDP Payload N |
--------------------------------------------------------------------------------
```
Fig. 1 - A Single Coalesced Unit.


## Headers

### ntddndis.h

These structures are new for this offload.
```
#if (NDIS_SUPPORT_NDIS690)
//
// values used in UDP RSC offload
//
#define NDIS_OFFLOAD_PARAMETERS_URO_DISABLED            1
#define NDIS_OFFLOAD_PARAMETERS_URO_ENABLED             2
#endif // (NDIS_SUPPORT_NDIS690)

...

#if (NDIS_SUPPORT_NDIS690)
    struct
    {
        UCHAR               Enabled;
    } UdpRsc;
#endif // (NDIS_SUPPORT_NDIS690)
} NDIS_OFFLOAD_PARAMETERS, *PNDIS_OFFLOAD_PARAMETERS;

...

#if (NDIS_SUPPORT_NDIS690)
typedef struct _NDIS_UDP_RSC_OFFLOAD
{
    BOOLEAN Enabled;
} NDIS_UDP_RSC_OFFLOAD, *PNDIS_UDP_RSC_OFFLOAD;
#endif
...

#if (NDIS_SUPPORT_NDIS690)
    //
    // UDP RSC offload.
    //
    NDIS_UDP_RSC_OFFLOAD              UdpRsc;
#endif

} NDIS_OFFLOAD, *PNDIS_OFFLOAD;
```

### nbluro.w

This header already exists today.
```
#if NDIS_SUPPORT_NDIS684

//
// Per-NetBufferList information for UdpRecvSegCoalesceOffloadInfo.
//
typedef struct _NDIS_UDP_RSC_OFFLOAD_NET_BUFFER_LIST_INFO
{
    union
    {
        struct
        {
            USHORT SegCount;
            USHORT SegSize;
        } Receive;

        PVOID Value;
    };
} NDIS_UDP_RSC_OFFLOAD_NET_BUFFER_LIST_INFO, *PNDIS_UDP_RSC_OFFLOAD_NET_BUFFER_LIST_INFO;

#endif
```

# Appendix
