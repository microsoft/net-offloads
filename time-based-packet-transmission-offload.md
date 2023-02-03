# Time based Packet Transmission Offload (TPTO)

> **Note**
> This document is a work in progress.

This document describes an offload called TPTO which offloads per packet transmission timestamps.
These timestamps can be used to schedule packets to be sent at a future time, which can be leveraged to more effectively pace sends at a rate not otherwise achievable in the OS.
Because of the time-fidelity requirements of this feature, there will not be software fallback in the OS.

## Table of Contents

- [Time based Packet Transmission Offload (TPTO)](#time-based-packet-transmission-offload-tpto)
  - [Table of Contents](#table-of-contents)
- [Winsock](#winsock)
  - [set/get TPTO capability](#setget-tpto-capability)
  - [Scheduler](#scheduler)
  - [Sending Packets](#sending-packets)
- [TCPIP](#tcpip)
- [NDIS](#ndis)
  - [Clock synchronization](#clock-synchronization)
- [Appendix](#appendix)
  - [Linix](#linix)

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
The app passes ancillary data in the form of `TPTO_ANCILLARY_DATA`
```C
typedef struct _TPTO_ANCILLARY_DATA {
    uint64_t TxTime;
    uint8_t  DropIfRate
} TPTO_ANCILLARY_DATA;
```

- TxTime to indicate when the associated packet is sent
- DropIfRate to indicate whether to drop packet if it cannot be transmitted by the given deadline

> **TODO**

# TCPIP

This section describes necessary updates in the Windows network stack to support TPTO.

TCPIP doesn't expect SW fallback. If hardware state changed dynamically, TCPIP just sends without ancillary data.

> **TODO**

# NDIS

The NDIS interface for TPTO is used for communication between TCPIP and the NDIS miniport driver.

NDIS to use parameter bellow to enable the feature.

```C
typedef struct _NDIS_OFFLOAD_PARAMETERS
{
    ...
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
typedef enum _NDIS_TXTIME_SUPPORT_FLAGS {
    NDIS_TXTIME_SUPPORT_FLAG_NONE       = 0x00,
    NDIS_TXTIME_SUPPORT_SCHED_ETF       = 0x01,
    NDIS_TXTIME_SUPPORT_SCHED_TAPRIO    = 0x02,
}

```

## Clock synchronization
System clock and PHC need to be synchronized to scheduler to transmit packet as expected


> **TODO**

# Appendix

## Linix

This [article](https://lwn.net/Articles/748744/) describes the equivalent interface that was added to Linux.
