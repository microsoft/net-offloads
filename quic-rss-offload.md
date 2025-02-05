# Adding QUIC Connection ID Hashing Support to NDIS RSS

An In-Depth Guide

## Introduction

The Network Driver Interface Specification (NDIS) provides a standardized API for network interface cards (NICs) to communicate with the Windows operating system. Receive Side Scaling (RSS) is a crucial feature of NDIS, which enables the distribution of network processing across multiple CPUs to enhance performance. With the advent of QUIC (Quick UDP Internet Connections), a next-generation protocol developed by Google, there is an increasing need to integrate QUIC connection ID hashing support into NDIS RSS to leverage its benefits.

## Overview of QUIC and NDIS RSS

### What is QUIC?

QUIC is a transport protocol designed for modern internet usage. It builds upon UDP, adding features traditionally associated with TCP, such as reliable delivery and congestion control, but with lower latency and improved security. One of the key features of QUIC is its connection ID, which allows connections to remain established even if the client's IP address changes.

### What is NDIS RSS?

NDIS RSS is a mechanism that allows NICs to distribute network receive processing across multiple CPUs. This distribution is achieved by hashing packet headers (e.g., IP and TCP/UDP headers) to determine the appropriate CPU for processing. By distributing the load, RSS significantly improves the system’s network throughput and scalability.

## Need for QUIC Connection ID Hashing

Traditional RSS uses hash functions based on the IP and TCP/UDP headers, which is not sufficient for QUIC traffic. The connection ID in QUIC serves as the primary identifier and is essential for maintaining the state of a connection, especially in scenarios involving IP address changes. Integrating QUIC connection ID hashing into NDIS RSS will ensure efficient load balancing and processing for QUIC traffic, thereby enhancing overall system performance.

## Implementation Details

### Architectural Changes

To support QUIC connection ID hashing in NDIS RSS, several architectural changes are required:

- Update Hashing Algorithm: Modify the existing hashing algorithm to include QUIC connection IDs in addition to IP and transport layer headers.

- Driver Updates: NIC drivers need to be updated to recognize and process QUIC packets, extracting the connection ID for hashing purposes.

- RSS Configuration: Update the RSS configuration to support the new hashing mechanism, ensuring backward compatibility with traditional protocols.

### NDIS Driver API Changes

#### NDIS\_RECEIVE\_SCALE\_CAPABILITIES

1. Add new `NDIS_RSS_CAPS_FLAGS` definition(s) for QUIC CID hashing capabilities.

2. Add any new fields needed, if some capabilities are inexpressible via simple flags

3. Create new struct revision and size macros.

####  NDIS\_RECEIVE\_SCALE\_PARAMETERS

1. Add new `NDIS_HASH_FLAGS` definition(s) for QUIC CID hashing configuration.

2. Add any new fields needed, such as CID hash offset and size, or perhaps an array of CID hash offsets and size based on local IP/port tuple.

3. Create new struct revision and size macros.

## NDIS.sys Changes

NDIS needs to become aware of the new struct revisions – this is just an exercise in boilerplate.

## Winsock API Changes

TBD – should bound UDP sockets have a socket option to configure a CID hashing rule?

## NSI/IPHLPAPI/WMI/PowerShell API Changes

TBD – should administrators/apps be able to set CID policies on a per-interface or system-wide basis?

## TCPIP.sys Changes

TCPIP may set the RSS configuration bits if an administrator configures a per-interface or system-global CID hashing scheme, or update a table of per-local-endpoint CID rules based on socket options.

## Non-Inbox Changes

Some components (e.g. XDP-for-Windows) may use the new NDIS structures via NDIS driver APIs (i.e., OIDs and status indications) to query RSS capabilities and configure NICs.

## Steps to Implement QUIC Connection ID Hashing

1. Identify QUIC Packets: Modify the NIC driver to identify QUIC packets. This involves inspecting the packet headers to recognize the QUIC protocol and extract the connection ID.

2. Extract Connection ID: Implement logic within the driver to extract the QUIC connection ID from the packet header.

3. Hash Function Update: Update the RSS hash function to incorporate the QUIC connection ID. The hash output should determine the appropriate CPU for processing.

4. Configuration and Tuning: Update the RSS configuration settings to enable QUIC connection ID hashing. This may include tuning parameters to optimize performance for specific workloads.

5. Testing and Validation: Conduct thorough testing to validate the implementation. This includes performance benchmarks, compatibility checks with existing protocols, and stress testing under various network conditions.

## Challenges and Considerations

### Security Implications

The security of the hashing mechanism must be considered to prevent potential attacks, such as hash collision attacks, which could lead to uneven load distribution and degraded performance. Proper validation and testing are essential to mitigate these risks.

## Benefits of QUIC Connection ID Hashing

### Improved Load Balancing

By incorporating QUIC connection ID hashing, the load distribution across CPUs becomes more balanced, leading to enhanced network performance and reduced bottlenecks.

### Enhanced Scalability

With efficient load balancing, the system can handle a larger number of concurrent QUIC connections, improving scalability and overall system capacity.

### Reduced Latency

Optimized processing of QUIC packets through RSS results in lower latency, providing a better user experience for applications relying on the QUIC protocol.

## Conclusion

Integrating QUIC connection ID hashing support into NDIS RSS is a significant step toward modernizing network processing for contemporary internet protocols. This enhancement not only improves load balancing and scalability but also reduces latency, ensuring optimal performance for QUIC traffic. By following the outlined implementation steps and addressing the associated challenges, NDIS RSS can effectively support QUIC, paving the way for a more efficient and robust network infrastructure.

## Future Work

As QUIC continues to evolve, further enhancements to the hashing mechanism and RSS configuration may be required to keep pace with new features and protocols. Continuous monitoring, testing, and optimization will be essential to maintain peak performance and security.
