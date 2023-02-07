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

ntddndis.h
```
#if (NDIS_SUPPORT_NDIS690)
//
// values used in UDP receive offload
//
#define NDIS_OFFLOAD_PARAMETERS_URO_DISABLED            1
#define NDIS_OFFLOAD_PARAMETERS_URO_ENABLED             2
#endif // (NDIS_SUPPORT_NDIS690)

...

#if (NDIS_SUPPORT_NDIS690)
    struct
    {
        UCHAR               Enabled;
    } UdpReceiveOffload;
#endif // (NDIS_SUPPORT_NDIS690)
} NDIS_OFFLOAD_PARAMETERS, *PNDIS_OFFLOAD_PARAMETERS;

...

#if (NDIS_SUPPORT_NDIS690)
typedef struct _NDIS_UDP_RECV_OFFLOAD
{
    BOOLEAN Enabled;
} NDIS_UDP_RECV_OFFLOAD, *PNDIS_UDP_RECV_OFFLOAD;
#endif
...

#if (NDIS_SUPPORT_NDIS690)
  //
  // UDP Receive Offload
  //
  NDIS_UDP_RECV_OFFLOAD        UdpRecvOffload;
#endif

} NDIS_OFFLOAD, *PNDIS_OFFLOAD;
```

nbluro.w
```


#if NDIS_SUPPORT_NDIS690

//
// Per-NetBufferList information for UdpRecvSegCoalesceOffloadInfo.
//
typedef struct _NDIS_UDP_RSC_OFFLOAD_NET_BUFFER_LIST_INFO
{
    union
    {
        struct
        {
            ULONG SegCount: 16;
            ULONG SegSize: 16;
            ULONG Reserved: 32;
        } Receive;

        PVOID Value;
    };
} NDIS_UDP_RSC_OFFLOAD_NET_BUFFER_LIST_INFO, *PNDIS_UDP_RSC_OFFLOAD_NET_BUFFER_LIST_INFO;

#endif
```

# Appendix
