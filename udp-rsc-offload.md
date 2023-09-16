# UDP Receive Segment Coalescing Offload (URO)

UDP RSC Offload (URO) is a hardware offload where the NIC coalesces UDP datagrams from the same flow that match a set of rules into a logically contiguous buffer. These are then indicated to the Windows networking stack as a single large packet. The benefit from coalescing is reduced CPU cost to process packets in high-bandwidth flows, resulting in higher throughput and lower cycles per byte. UDP protocols that transfer bulk data with their own headers can benefit from URO, however, the implementation will need to be updated to take advantage of URO. One such protocol, which already benefits from software URO, is QUIC.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", “MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/bcp/bcp14) [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.


## Table of Context

- [Rules](#rules)
- [Winsock](#winsock)
- [TCPIP](#tcpip)
- [NDIS](#ndis)
- [NetAdapter](#netadapter)

# Rules
URO coalescing can only be attempted on packets that meet all the following criteria:
- IpHeader.Version is identical for all packets.
- IpHeader.SourceAddress and IpHeader.DestinationAddress are identical for all packets.
- UdpHeader.SourcePort and UdpHeader.DestinationPort are identical for all packets.
- UdpHeader.Length is identical for all packets, except the last packet, which may be less.
- UdpHeader.Length MUST be non-zero.
- UdpHeader.Checksum, if non-zero, MUST be correct on all packets. This means checksum offload must be enabled and set the checksum OOB info.
- Layer 2 headers must be identical for all packets.
  
If the packets are IPv4, they MUST also meet the following criteria:
- IPv4Header.Protocol == 17 (UDP) for all packets.
- EthernetHeader.EtherType == 0x0800 for all packets.
- The IPv4Header.HeaderChecksum on received packets MUST be correct. This means checksum offload must be enabled and set the checksum OOB info.
- IPv4Header.HeaderLength == 5 (no IPv4 Option Headers) for all packets.
- IPv4Header.ToS is identical for all packets.
- IPv4Header.ECN is identical for all packets.
- IPv4Header.DontFragment is identical for all packets.
- IPv4Header.TTL is identical for all packets.
- IPv4Header.TotalLength == UdpHeader.Length + length(IPv4Header) for all packets.
  
If the packets are IPv6, they MUST also meet the following criteria:
- IPv6Header.NextHeader == 17 (UDP) for all packets (No extension headers).
- EthernetHeader.EtherType == 0x86dd (IPv6) for all packets.
- IPv6Header.TrafficClass and IPv6Header.ECN are identical for all packets.
- IPv6Header.FlowLabel is identical for all packets.
- IPv6Header.HopLimit is identical for all packets.
- IPv6Header.PayloadLength == UdpHeader.Length for all packets.

The resulting Single Coalesced Unit (SCU) MUST have a single IP header and UDP header, followed by the UDP payload for all coalesced datagrams concatenated together.

URO indications MUST correctly calculate the IPv4Header.HeaderChecksum and UdpHeader.Checksum fields on the SCU.

URO indications MUST set the IPv4Header.TotalLength field to the total length of the SCU, or IPv6Header.PayloadLength field to the length of the UDP payload, and UdpHeader.Length field to the length of coalesced payloads.

If Layer 2 (L2) headers are present in coalesced datagrams, the SCU MUST contain a valid L2 header. The L2 header in the SCU MUST resemble the L2 header of the coalesced datagrams.

Packets from multiple flows may be coalesced in parallel, as hardware and memory permit. Packets from different flows MUST NEVER be coalesced together.

Packets from multiple receives interleaved may be separated and coalesced with their respective flows. i.e. Given flows A, B, and C, if packets arrive in the following order; A, A, B, C, B, A; the packets from the A flow may be coalesced into AAA, and the packets from the B flow coalesced into BB, while the packet from the C flow may be indicated normally or coalesced with a pending SCU from flow C.

The packets within a given flow MUST NOT be reordered with respect to each other, i.e. the packets from the A flow must be coalesced in the order received, regardless of the packets from the B and C flows received in between.

```
+------------------------------------------------------------------------------------------+
| L2 Header | IP Header | UDP Header | UDP Payload 1 | UDP Payload 2 | ... | UDP Payload N |
+------------------------------------------------------------------------------------------+
```
Fig. 1 - A Single Coalesced Unit.


# Winsock

The Winsock API (currently only software URO) already exists, and details on the API can be found [here](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options). Please see the info on `UDP_RECV_MAX_COALESCED_SIZE ` and `UDP_COALESCED_INFO`.

# TCPIP

This section describes necessary updates in the Windows network stack (TCPIP & AFD) when hardware URO support is enabled.

The Windows TCPIP stack will need to be updated to enable/disable this offload. TCPIP should enable URO at bind time with NDIS, unless configuration prevents it from doing so.

WFP callouts can use [FWP_CALLOUT_FLAG_ALLOW_URO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout2_) to advertise their support for URO. In the case where an incompatible WFP callout is registered at a URO-sensitive layer, then the OS will disable URO while the callout is active.

- If a socket opts-in to URO with a max coalesced size greater than or equal to the hardware offload size, then the stack will deliver the NBLs from hardware unmodified to the socket.
- If a socket opts-in to a smaller max coalesced size, the stack will break the coalesced receive into the smaller size for the socket.
- If a socket does not opt-in to URO, then the stack will resegment receives for that socket.

In the absence of hardware URO, the existing software URO feature will continue to be available.

# NDIS

The NDIS interface for URO is used for communication between TCPIP and the NDIS miniport driver.

The NDIS layer will provide [OID_TCP_OFFLOAD_PARAMETERS](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-parameters) for upper layers to enable/disable URO, and the status of URO can be queried via [OID_TCP_OFFLOAD_CURRENT_CONFIG](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-current-config).
This is how RSC is controlled at the NDIS layer and should be familiar to implementors of NDIS drivers.

Like RSC, URO will require the NIC to wait to complete the **OID_TCP_OFFLOAD_PARAMETERS** request with **NDIS_OFFLOAD_PARAMETERS_UDP_RSC_DISABLED** flag set until it indicates existing coalesced segments and all outstanding URO indications are completed.  This simplifies support for all NDIS components, so they don’t have to invent their own solution to synchronizing URO enable/disable events.  After the miniport driver processes the **OID_TCP_OFFLOAD_PARAMETERS** OID request, it must give an NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG status indication with the updated offload state.

The **NDIS_OFFLOAD_PARAMETERS_SKIP_REGISTRY_UPDATE** flag will be documented to allow URO to be disabled only at runtime, and not persisted to registry. [OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-tcp-offload-hardware-capabilities) will be used to advertise a miniport’s support of URO.

All NDIS drivers which target NDIS 6.90 are assumed to at least understand URO packets and can handle them gracefully.
The **NDIS_FILTER_DRIVER_UDP_RSC_OPT_OUT** and **NDIS_PROTOCOL_DRIVER_UDP_RSC_OPT_OUT** flags can be set on the **NDIS_FILTER_DRIVER_CHARACTERISTICS**/**NDIS_PROTOCOL_DRIVER_CHARACTERISTICS** structs used when a LWF or protocol driver registers with NDIS to indicate opt-out of URO support for drivers targeting 6.90 or higher.
This ensures that any component that doesn’t understand URO won’t receive URO NBLs.
NDIS will disable URO on the miniport during binding when an LWF or protocol driver that doesn’t support URO is present. 

## Headers

### ndis.h
```c
//
// Protocol driver flags
//
...
#if NDIS_SUPPORT_NDIS690
#define NDIS_PROTOCOL_DRIVER_UDP_RSC_OPT_OUT 0x00000008
#endif // NDIS_SUPPORT_NDIS690

//
// Filter driver flags
//
...
#if NDIS_SUPPORT_NDIS690
#define NDIS_FILTER_DRIVER_UDP_RSC_OPT_OUT 0x00000008
#endif //NDIS_SUPPORT_NDIS690
```

### ntddndis.h

```c
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
    //
    // UDP RSC offload.
    //
    NDIS_UDP_RSC_OFFLOAD              UdpRsc;
#endif
} NDIS_OFFLOAD, *PNDIS_OFFLOAD;
```

### nbluro.h

```c
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

#if (NDIS_SUPPORT_NDIS690)

//
// values used in UDP RSC offload
//
#define NDIS_OFFLOAD_PARAMETERS_UDP_RSC_NO_CHANGE       0
#define NDIS_OFFLOAD_PARAMETERS_UDP_RSC_DISABLED        1
#define NDIS_OFFLOAD_PARAMETERS_UDP_RSC_ENABLED         2

typedef struct _NDIS_UDP_RSC_OFFLOAD
{
    BOOLEAN Enabled;
} NDIS_UDP_RSC_OFFLOAD, *PNDIS_UDP_RSC_OFFLOAD;

#endif // (NDIS_SUPPORT_NDIS690)

...

#endif
```

# NetAdapter
NetAdapter client drivers can use the existing RSC structures and RSC API for URO. The Layer4Flags now accept UDP as a valid input. Behavior is the same as RSC, except when the `EvtAdapterOffloadSetRsc` callback disables URO, the driver is expected to indicate existing coalesced segments and wait until all outstanding URO indications are completed. This ensures there are no URO indications active once the callback returns.
## Headers
### NetAdapterOffload.h
```cpp
typedef struct _NET_ADAPTER_OFFLOAD_RSC_CAPABILITIES
{
    ...
    //
    // Flags specifying on what layer 4 protocols the hardware can perform RSC
    // NetAdapterOffloadLayer4FlagTcpNoOptions and NetAdapterOffloadLayer4FlagUdp are the only valid flag values,
    // to indicate TCP and UDP support.
    //
    NET_ADAPTER_OFFLOAD_LAYER4_FLAGS
        Layer4Flags;
    ...

} NET_ADAPTER_OFFLOAD_RSC_CAPABILITIES;
```

### RscTypes.h
```cpp
typedef struct _NET_PACKET_RSC
{
    union {
        struct {
            UINT16
                CoalescedSegmentCount;

            UINT16
                DuplicateAckCount;
        } TCP;
        struct {
            UINT16
                CoalescedSegmentCount;

            UINT16
                CoalescedSegmentSize;
        } UDP;
    } DUMMYUNIONNAME;
} NET_PACKET_RSC;

C_ASSERT(sizeof(NET_PACKET_RSC) == 4);


#define NET_PACKET_EXTENSION_RSC_VERSION_2 2U
```

