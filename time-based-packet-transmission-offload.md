# Time based Packet Transmission Offload (TPTO)

> **Note**
> This document is a work in progress.

This document describes an offload called TPTO which offloads per packet transmission timestamps.
These timestamps can be used to schedule packets to be sent at a future time, which can be leveraged to more effectively pace sends at a rate not otherwise achievable in the OS.
Because of the time-fidelity requirements of this feature, there will not be software fallback in the OS.

## Table of Context

- [Time based Packet Transmission Offload (TPTO)](#time-based-packet-transmission-offload-tpto)
  - [Table of Context](#table-of-context)
- [Winsock](#winsock)
  - [Checking for TPTO Capability](#checking-for-tpto-capability)
  - [Enable TPTO](#enable-tpto)
  - [Sending Packets](#sending-packets)
- [TCPIP](#tcpip)
  - [Queue](#queue)
    - [Unknown](#unknown)
- [NDIS](#ndis)
- [Appendix](#appendix)
  - [Linix](#linix)

# Winsock

The proposed Winsock API for TPTO is as follows.

## Checking for TPTO Capability

An app first checks for TPTO support by querying the `SO_TPTO_SUPPORT` socket option.  
The option value is a `TPTO_SUPPORT_FLAGS` enum with flags describing the supported capabilities:

```C
typedef enum _TPTO_SUPPORT_FLAGS {
    TPTO_SUPPORT_FLAG_NONE          = 0x00,
    TPTO_SUPPORT_FLAG_SUPPORTED     = 0x01,
} TPTO_SUPPORT_FLAGS;
```

## Enable TPTO
setsockopt with SO_TXTIME

## Sending Packets
The app calls `WSASendMsg`.   
The app passes ancillary data in the form of `TPTO_ANCILLARY_DATA`
```C
typedef struct _TPTO_ANCILLARY_DATA {
    uint64_t TxTime;
    uint64_t ClockId;
    uint8_t  DropIfRate
} TPTO_ANCILLARY_DATA;
```

- TxTime to indicate when the associated packet is sent
- ClockId to indicate which of several system clocks to be used
- DropIfRate to indicate whether to drop packet if it cannot be transmitted by the given deadline

- sendmsg with control-message header of type SCM_DROP_IF_LATE to simply drop a packet
- SCM_CLOCKID which clock should be used for packet timing, default is CLOCK_MONOTONIC


> **TODO**

# TCPIP

This section describes necessary updates in the Windows network stack to support TPTO.

## Queue
- qdisc
  - ETF (earliest txtime first) qdisc
  - TAPRIO (time-aware priority scheduler) qdisc?
- Enqueue
  - Drop if a packet scheduled to be sent in the past
  - Drop if ClockId associated with the packet doesn't match
- Dequeue
  - Drop if a packet missed its deadline
- ClockId
- Sorting
  - Software: rbtree to be always sorted
  - Hardware: just enqueue and sorted on hardware?
- HW offload
  - implicitly use PHC (Physical Hardware Clock) on interface

### Unknown
- This layer?

> **TODO**

# NDIS

The NDIS interface for TPTO is used for communication between TCPIP and the NDIS miniport driver.

```C
typedef struct _NDIS_OFFLOAD_PARAMETERS
{
    ...
#if (NDIS_SUPPORT_NDIS68X)
    struct
    {
        UCHAR               IPv4;
        UCHAR               IPv6;
    } Tpto;
#endif // (NDIS_SUPPORT_NDIS68X)
} NDIS_OFFLOAD_PARAMETERS, *PNDIS_OFFLOAD_PARAMETERS;


#if (NDIS_SUPPORT_NDIS68X)

#define NDIS_OFFLOAD_PARAMETERS_TPTO_ENABLED        1
#define NDIS_OFFLOAD_PARAMETERS_TPTO_DISABLED       2

#endif // (NDIS_SUPPORT_NDIS68X)
```


```C
typedef enum _NDIS_TPTO_SUPPORT_FLAGS {
    NDIS_TPTO_SUPPORT_FLAG_NONE          = 0x00,
    NDIS_TPTO_SUPPORT_FLAG_SUPPORTED     = 0x01,
}

```



> **TODO**

# Appendix

## Linix

This [article](https://lwn.net/Articles/748744/) describes the equivalent interface that was added to Linux.
