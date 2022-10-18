# QUIC Encryption Offload (QEO)

> **Note**
> This document is a work in progress.

This document describes a proposed NDIS offload called QEO which offloads the encryption of QUIC packets to hardware. The perspective is mainly that of MsQuic, but the offload will be usable by other QUIC implementations.

Today, MsQuic builds each packet by writing headers and copying application data into an MTU-sized buffer, uses an encryption library (bcrypt or openssl) to encrypt the packet in place, and then posts the packet (alone or in a batch) to the kernel.

Developers of other QUIC implementations have claimed a 5-8% memory bandwidth reduction from combining the application data copy with encryption. Moreover, if the work can be offloaded to hardware, those developers have claimed the main CPU can be relieved of 7% of the CPU utilization of QUIC. The CPU requirement of encryption (and therefore the potential benefit of offloading it) has an even larger proportion in MsQuic.

> **TODO -** Mention in appropriate places that offload is only for short header packets.

> **TODO -** Add RX offload (at least add a "tx/rx" boolean to API signatures so that "in" can be supported in the future).


## UDP Segmentation Offload (USO)

This section is not directly about QEO, but provides context on an existing offload with which there may be interactions.

Today MsQuic uses USO to send a batch of UDP packets in a single syscall. On Windows, it first calls getsockopt with option UDP_SEND_MSG_SIZE to query for support of USO, and then calls setsockopt with UDP_SEND_MSG_SIZE to tell the USO provider the MTU size to use to split a buffer into multiple packets. Once the MTU has been set, QUIC calls WSASendMsg with a buffer (or a chain of buffers according to WSASendMsg gather semantics) containing multiple packets. The kernel creates a large UDP datagram from this buffer and posts it to the NDIS miniport, which breaks down the large datagram into a set of MTU-sized datagrams.

Windows USO spec: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-segmentation-offload-uso-

Linux also provides this feature, but calls it “GSO” rather than “USO”.

QEO is orthogonal to USO and usable either with or without it: if USO is enabled, then the app can post multiple packets in a single WSASend call; and if QEO is enabled, the packet[s] are posted unencrypted.


## Linux API

Linux developers are working on a send-side kernel/hardware encryption offload: https://lore.kernel.org/all/97789971-7cf5-ede1-11e2-df6494e75e44@gmail.com/ The focus on sender side is justified by the claim that server-side networking is typically send-dominant.

The general API in linux is:

-The app associates a connection ID with encryption params (key, iv, cipher) with socket option UDP_QUIC_ADD_TX_CONNECTION. This state is removed when the socket is closed, or it can be removed explicitly with UDP_QUIC_DEL_TX_CONNECTION (**TODO**: there is discussion ongoing about using tuples instead of or alongside connection ID).

-GSO is optionally set up with socket option UDP_SEGMENT (this value can be overridden per-send with ancillary data).

-Sendmsg is called with some ancillary data: the connection ID length, the next packet number, and a flags field.

-On key rollover, the app plumbs the new key.

If a hardware offload is supported by the network interface, then it is used; otherwise the kernel takes care of the encryption and segmentation for usermode.


## Winsock API

The proposed Winsock API for QEO is as follows.


### Checking for QEO capability

An app first checks for QEO support by querying the `SO_QEO_SUPPORT` socket option. The option value is a `QEO_SUPPORT` structure describing the supported algorithms:

```C
typedef struct {
    // TODO: QUIC version
    uint8_t AesGcm128 : 1;
    uint8_t AesGcm256 : 1;
    uint8_t ChaCha20Poly1305 : 1;
    uint8_t AesCcm128 : 1;
} QEO_SUPPORT;
```

If QEO is not supported by the operating system, then the getsockopt call will fail with status `WSAEINVAL`. This should be treated the same as the case where no cipher types are supported (i.e. the app should encrypt its own QUIC packets).

> **TODO -** consider how interface cipher support should interact with the cipher negotiation that happens with the peer.


### Establishing encryption parameters for a connection

> **TODO -** support adding N and removing M connections in one request for key update?

If QEO is supported, the app then establishes crypto parameters for a connection by setting the `SO_QEO_CONNECTION` socket option with an option value of type `QEO_CONNECTION`.

> **TODO -** Destination IP/port must be added to QEO_CONNECTION as part of the lookup key.

```C
typedef enum {
    AesGcm128,
    AesGcm256,
    ChaCha20Poly1305,
    AesCcm128
} QEO_CIPHER_TYPE;

typedef struct {
    // TODO: QUIC version
    NDIS_QUIC_CIPHER_TYPE CipherType;
    uint8_t PayloadKey[16];
    uint8_t PayloadIv[12];
    uint8_t HeaderKey[16];
    uint8_t ConnectionIdLength;
    uint8_t ConnectionId[0]; // Variable length
} QEO_CONNECTION;
```


### Sending packets

The app then calls `WSASendMsg` with an unencrypted packet (or, if USO is also being used, a set of unencrypted packets). The packet[s] must be smaller than the current MTU by the size of the authentication tag, which is currently 16 bytes for all supported ciphers. This leaves space for the tag to be added to the packet during encryption.

The app passes ancillary data to `WSASendMsg` in the form of `QEO_ANCILLARY_DATA`:

```C
typedef struct { 
    uint64_t NextPacketNumber; 
    uint8_t ConnectionIdLength;  
} QEO_ANCILLARY_DATA;
```

NextPacketNumber is the uncompressed packet number of the packet (or of the first packet in the batch). This is passed because the uncompressed packet number is an input for encryption and because the offload provider cannot read the packet number from the packet buffer without dealing with packet number compression.

The ConnectionIdLength is passed to help the offload provider read the connection ID (which is used as a lookup key for the previously-established encryption parameters) from the packet buffer.


## TCPIP updates for QEO

This section describes necessary updates in the Windows network stack to support QEO.

> **TODO -** When doing S/W USO and H/W QEO, don’t do xsum in UDP.

> **TODO -** Need to maintain mirror table of plumbed connections in TCPIP for when we switch to and from S/W offload.


## NDIS API

The NDIS interface for QEO is used for communication between TCPIP (which posts NBLs containing unencrypted QUIC packets) and the NDIS miniport driver (which encrypts and sends the QUIC packets).


### Configuring and advertising QEO capability

The miniport driver advertises QEO capability during initialization with the `QuicEncryption` field of an `NDIS_OFFLOAD` structure (with `Header.Revision = NDIS_OFFLOAD_REVISION_8` and `Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_8`), which is passed to `NdisMSetMiniportAttributes`. The `QuicEncryption` field is of type `NDIS_QUIC_ENCRYPTION_OFFLOAD`:

```C
typedef struct {
    // TODO: QUIC version
    uint8_t AesGcm128 : 1;
    uint8_t AesGcm256 : 1;
    uint8_t ChaCha20Poly1305 : 1;
    uint8_t AesCcm128 : 1;
 } NDIS_QUIC_ENCRYPTION_OFFLOAD;
```

QEO can be enabled or disabled using `OID_TCP_OFFLOAD_PARAMETERS` with the `QuicEncryption` field of the `NDIS_OFFLOAD_PARAMETERS` struct. The `QuicEncryption` field is of type `NDIS_QUIC_ENCRYPTION_OFFLOAD`, described above. After the miniport driver handles the OID, it must send an `NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG` status indication with the updated configuration.

The current QEO configuration can be queried with `OID_TCP_OFFLOAD_CURRENT_CONFIG`. NDIS handles this OID and does not pass it down to the miniport driver.

> **TODO -** what happens to existing plumbed connections when the config changes? (e.g. what if a connection was using a cipher type and that cipher type has been removed?)


### Establishing encryption parameters for a connection

> **TODO -** what type of OID to use for `OID_QUIC_CONNECTION_ENCRYPTION_ADD` / `OID_QUIC_CONNECTION_ENCRYPTION_DELETE`? Some OIDs have high latency. If no type of OID is fast enough, perhaps instead of OID to plumb a connection, use a special OOB in first packet.

> **TODO -** specify how many connections can be offloaded?

Before the NDIS protocol driver posts packets for QEO, it first establishes encryption parameters for the associated QUIC connection by issuing `OID_QUIC_CONNECTION_ENCRYPTION_ADD`. The `InformationBuffer` field of the `NDIS_OID_REQUEST` for this OID contains a pointer to an `NDIS_QUIC_CONNECTION`:

> **TODO -** Destination IP/port must be added to `NDIS_QUIC_CONNECTION` as part of the lookup key.

```C
typedef enum {
    AesGcm128,
    AesGcm256,
    ChaCha20Poly1305,
    AesCcm128
} NDIS_QUIC_CIPHER_TYPE;

typedef struct _NDIS_QUIC_CONNECTION {
    NDIS_QUIC_CIPHER_TYPE CipherType;
    uint8_t PayloadKey[16]; // TODO: is this enough?
    uint8_t PayloadIv[12];
    uint8_t HeaderKey[16];
    uint8_t ConnectionIdLength;
    uint8_t ConnectionId[0]; // Variable length
} NDIS_QUIC_CONNECTION;
```

The protocol driver later deletes the state for the connection with `OID_QUIC_CONNECTION_ENCRYPTION_DELETE`. The InformationBuffer field of the NDIS_OID_REQUEST for this OID also contains a pointer to an `NDIS_QUIC_CONNECTION`, but only the `ConnectionIdLength` and `ConnectionId` fields are used (**TODO**: and the destination port/ip).


### Sending packets

> **TODO -** packet coalescing (multiple QUIC packets per datagram)??

The NDIS protocol driver posts packets for QEO with OOB data (which can be queried using the `NET_BUFFER_LIST_INFO` macro with an `_Id` of `QuicEncryptionOffloadInfo`) with the following format:

```C
typedef struct _NDIS_QUIC_ENCRYPTION_NET_BUFFER_LIST_INFO {
    uint64_t NextPacketNumber;
    uint8_t ConnectionIdLength;
} NDIS_QUIC_ENCRYPTION_NET_BUFFER_LIST_INFO;
```

NOTE: Normally the encryption parameters for the associated connection will have been established with `OID_QUIC_CONNECTION_ENCRYPTION` for every QEO packet that is posted, but this is not guaranteed. If a QEO packet is posted and no matching encryption parameters are established, the `NET_BUFFER_LIST` must be immediately completed by the miniport without transmitting the packet. (**TODO**: with what status code?)

> **TODO -** Miniport will have to compute checksums

> **TODO -** Explicitly mention that usage of QEO with USO must be supported.

> **TODO -** What about nonsequential packets? If we’re just passing a “NextPacketNumber” then how will that work?

> **TODO -** For RX- when decryption fails, what to do? (two cases: connection hasn't been plumbed, and connection has been plumbed but decryption fails due to invalid packet)
