# UDP Receive Segment Coalescing Offload (URO)

> **Note**
> This document is a work in progress.

This document describes an offload called URO which offloads coalescing and reassembly of multiple UDP datagrams into a single contiguous buffer.
In the absence of hardware support, the OS will attempt a best-effort software fallback.

## Table of Context

- [Winsock](#winsock)
- [TCPIP](#tcpip)
- [NDIS](#ndis)

# Winsock

The Winsock API (currently only software fallback) already exists, and details on the API can be found [here](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options). Please see the info on `UDP_RECV_MAX_COALESCED_SIZE ` and `UDP_COALESCED_INFO`.

# TCPIP

This section describes necessary updates in the Windows network stack (TCPIP & AFD) when hardware URO support is enabled:

- If a socket opts-in to URO with a max coalesced size greater than or equal to the hardware offload size, then the OS will deliver the NBLs from hardware unmodified to the socket.
- If a socket opts-in to a smaller max coalesced size, the OS will break the coalesced receive into the smaller size for the socket.
- If a socket does not opt-in to URO, then the OS will resegment receives for that socket.
- If an incompatible WFP filter is encountered, then the OS will resegment receives for that filter.

In the absence of hardware URO, the existing software URO feature will continue to be available.

# NDIS

The NDIS interface for URO is used for communication between TCPIP and the NDIS miniport driver.

## Rules

URO can only be attempted on a batch of packets that meet **all** the following criteria:

- 5-tuple matches, i.e., IP source and destination address, IP protocol/next header, UDP source and destination port.
- Payload length is identical for all datagrams, except the last datagram, which may be less.
- The UDP checksums on pre-coalesced packets must be correct. This means checksum offload must be enabled and set the checksum OOB info.
- The IPv4 header checksum on pre-coalesced packets must be correct. This means checksum offload must be enabled and set the checksum OOB info.
- TTL, ToS/ECN, Protocol, and DF bit must match on all packets (IPv4).
- TC/ECN, FlowLabel, and HopLimit must match, and NextHeader must be UDP (IPv6).

The resulting Single Coalesced Unit (SCU) must have a single IP header and UDP header, followed by the UDP payload for all coalesced datagrams concatenated together.

URO indications should set the IP length, IPv4 checksum, UDP length, and UDP checksum fields to zero, and components handling these indications must ignore these fields.

If L2 headers are present in coalesced datagrams, the SCU must contain a valid L2 header. The contents of the L2 header in each coalesced datagram may vary; the L2 header in the SCU should resemble the L2 header of at least one of the coalesced datagrams.

The full SCU size must be set in the NB->DataLength field. The size of SCUs should not exceed 256KB.

```
+------------------------------------------------------------------------------------------+
| L2 Header | IP Header | UDP Header | UDP Payload 1 | UDP Payload 2 | ... | UDP Payload N |
+------------------------------------------------------------------------------------------+
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
