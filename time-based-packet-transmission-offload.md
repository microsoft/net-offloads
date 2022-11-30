# Time based Packet Transmission Offload (TPTO)

> **Note**
> This document is a work in progress.

This document describes an offload called TPTO which offloads per packet transmission timestamps.
These timestamps can be used to schedule packets to be sent at a future time, which can be leveraged to more effectively pace sends at a rate not otherwise achievable in the OS.
Because of the time-fidelity requirements of this feature, there will not be software fallback in the OS.

## Table of Context

- [Winsock](#winsock)
- [TCPIP](#tcpip)
- [NDIS](#ndis)
- [Appendix](#appendix)

# Winsock

The proposed Winsock API for TPTO is as follows.

> **TODO**

# TCPIP

This section describes necessary updates in the Windows network stack to support TPTO.

> **TODO**

# NDIS

The NDIS interface for TPTO is used for communication between TCPIP and the NDIS miniport driver.

> **TODO**

# Appendix

## Linix

This [article](https://lwn.net/Articles/748744/) describes the equivalent interface that was added to Linux.
