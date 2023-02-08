# Time based Packet Transmission Offload (TPTO)

> **Note**
> This document is a work in progress.

This document describes an offload called TPTO which offloads per packet transmission timestamps.
These timestamps can be used to schedule packets to be sent at a future time, which can be leveraged to more effectively pace sends at a rate not otherwise achievable in the OS.
Because of the time-fidelity requirements of this feature, there will not be software fallback in the OS.

## Table of Contents

- [Time based Packet Transmission Offload (TPTO)](#time-based-packet-transmission-offload-tpto)
  - [Table of Contents](#table-of-contents)
- [Prerequisite](#prerequisite)
- [Winsock](#winsock)
  - [set/get TPTO capability](#setget-tpto-capability)
  - [Scheduler](#scheduler)
  - [Sending Packets](#sending-packets)
- [TCPIP](#tcpip)
- [NDIS](#ndis)
- [NIC](#nic)
- [Registry value based setting](#registry-value-based-setting)
- [Appendix](#appendix)
  - [Linux](#linux)

# Prerequisite

The NIC (and its driver) need to support PTP (IEEE 1588-2008 and/or 1588-2019) for precise timestamping to System clock and PHC clock need to be synchronized.  
Code below is to check the such capability
```C
INTERFACE_TIMESTAMP_CAPABILITIES timestampCapabilities;
SupportedTimestampType supportedType = TimestampTypeNone;

result = GetInterfaceActiveTimestampCapabilities(
              &interfaceLuid,
              &timestampCapabilities);

if (!timestampCapabilities.SupportsCrossTimestamp) {
  // Cannot use TPTO
}
```

It's up to app to synchronize system and PHC clock.  
The way to get timestamp information is as bellow.
```C
INTERFACE_HARDWARE_CROSSTIMESTAMP crossTimestamp;

result = CaptureInterfaceHardwareCrossTimestamp(
              &interfaceLuid,
              &crossTimestamp);

// Up to app. Use crossTimestamp to synchronize clocks
```

# Winsock

The proposed Winsock API for TPTO is as follows.

## set/get TPTO capability
An app first check for TPTO support by querying the `SO_TXTIME` socket option.  
`SOCKET_ERROR` indicate `setsockopt()` or `getsockopt()` don't support `SO_TXTIME` feature.   and then `WSAGetLastError()` returns `WSAENOPROTOOPT`
```C
int optVal = 1; // enable TPTO
int optLen = sizeof(int);
if(setsockopt(sock, SOL_SOCKET, SO_TXTIME, (char*)&optVal, optLen) == SOCKET_ERROR) {
  if (WSAGetLastError() == WSAENOPROTOOPT) {
    // SO_TXTIME is not supported
  } else {
    // other error
  }
}
```

## Scheduler
> Discussion: which component care this queuing/sorting/scheduling https://github.com/microsoft/quic-offloads/issues/50  

An app should be able to specify scheduler by `SO_TXTIME_SCHED`. Default should be ETF
- ETF (Earliest Txtime First)
- TAPRIO (Time-Aware Priority Scheduler)

```C
typedef enum _SO_TXTIME_SCHED_FLAGS {
    SO_TXTIME_SCHED_ETF       = 0x00
    SO_TXTIME_SCHED_TAPRIO    = 0x01
} SO_TXTIME_SCHED_FLAGS;
```

```C
int optVal = SO_TXTIME_SCHED_ETF;
int optLen = sizeof(int);
if(setsockopt(sock, SOL_SOCKET, SO_TXTIME_SCHED, (char*)&optVal, optLen) == SOCKET_ERROR) {
  if (WSAGetLastError() == WSAENOPROTOOPT) {
    // the scheduling method is not supported
  } else {
    // other error
  }
}
```

## Sending Packets
The app calls `WSASendMsg`.   
The app passes ancillary data in the form of `TPTO_ANCILLARY_DATA`.
```C
typedef struct _TPTO_ANCILLARY_DATA {
    uint64_t TxTime;
    uint64_t TimeDelta;
} TPTO_ANCILLARY_DATA;
```

- TxTime to indicate when the associated packet is sent
- TimeDelta is an interval, starting at `TxTime`, to transmit individual packets that have been coalesced into a single send (by LSO/USO)

To avoid costly behavior like packet recovery, just send immediately if the packet's TxTime has passed already. (Do not use DropIfLate flag)

> **TODO**

# TCPIP

This section describes necessary updates in the Windows network stack to support TPTO.

TCPIP doesn't expect SW fallback. If hardware state changed dynamically, TCPIP just sends without ancillary data.

> **TODO**

# NDIS

The NDIS interface for TPTO is used for communication between TCPIP and the NDIS miniport driver.

`NDIS_OFFLOAD` structure need to have new member 
```C
typedef struct _NDIS_TCP_IP_TXTIME_OFFLOAD {
    struct {
        BOOLEAN Enabled;
    } IPv4;
    struct {
        BOOLEAN Enabled;
    } IPv6;
} NDIS_TCP_IP_TXTIME_OFFLOAD, *PNDIS_TCP_IP_TXTIME_OFFLOAD;

typedef struct _NDIS_OFFLOAD {
    ...
    NDIS_TCP_IP_TXTIME_OFFLOAD TxTime;
} NDIS_OFFLOAD, *PNDIS_OFFLOAD;
```

When a miniport driver receives an `OID_TCP_OFFLOAD_PARAMETERS` set request, it must use the contents of the `NDIS_OFFLOAD_PARAMETERS` structure
```C
typedef struct _NDIS_OFFLOAD_PARAMETERS
{
    NDIS_OBJECT_HEADER        Header;
    // Header.Revision = NDIS_OFFLOAD_REVISION_8
    // Header.Size     = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_8
    // Header.Type     = ?

    // ...
#if (NDIS_SUPPORT_NDIS68X)
    struct
    {
        UCHAR               IPv4;
        UCHAR               IPv6;
    } Txtime;
#endif // (NDIS_SUPPORT_NDIS68X)
} NDIS_OFFLOAD_PARAMETERS, *PNDIS_OFFLOAD_PARAMETERS;

#if (NDIS_SUPPORT_NDIS68X)

#define NDIS_OFFLOAD_PARAMETERS_TXTIME_ENABLED        1
#define NDIS_OFFLOAD_PARAMETERS_TXTIME_DISABLED       2

#endif // (NDIS_SUPPORT_NDIS68X)
```

```C
// This is if hardware support queuing/sorting
typedef enum _NDIS_TXTIME_SUPPORT_FLAGS {
    NDIS_TXTIME_SUPPORT_FLAG_NONE       = 0x00,
    NDIS_TXTIME_SUPPORT_SCHED_ETF       = 0x01,
    NDIS_TXTIME_SUPPORT_SCHED_TAPRIO    = 0x02,
}
```

To obtain the `NDIS_TCP_IP_TXTIME_NET_BUFFER_LIST_INFO` structure, a driver should call the `NET_BUFFER_LIST_INFO` macro with an _Id of `TcpIpTxTimeNetBufferListInfo`
```C
typedef struct _NDIS_TCP_IP_TXTIME_NET_BUFFER_LIST_INFO {
    ULONGLONG TxTime;
    ULONGLONG TimeDelta;
} NDIS_TCP_IP_TXTIME_NET_BUFFER_LIST_INFO, *PNDIS_TCP_IP_TXTIME_NET_BUFFER_LIST_INFO;

typedef enum _NDIS_NET_BUFFER_LIST_INFO
{
    // ...
    TcpIpTxTimeNetBufferListInfo,
} NDIS_NET_BUFFER_LIST_INFO, *PNDIS_NET_BUFFER_LIST_INFO;
```

> **TODO**

# NIC
- Transmit packet at TxTime (nanoseconds)
- Batch send, Transmit set of packets which start at TxTime, then transmit with TimeDelta interval
```
---TxTime----|------ TimeDelta -----|------ TimeDelta -----|---
             |  Packet 1 |          | Packet 2 |           | Packet 3 | ... | Packet N |
```
- Queue? Sorting?

# Registry value based setting

> **TODO**

# Appendix

[Packet timestamping](https://learn.microsoft.com/en-us/windows/win32/iphlp/packet-timestamping)

## Linux

This [article](https://lwn.net/Articles/748744/) describes the equivalent interface that was added to Linux.
