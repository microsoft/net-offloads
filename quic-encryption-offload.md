# QUIC Encryption Offload (QEO)

> **Note**
> This document is a work in progress.

This document describes a proposed NDIS offload called QEO which offloads the encryption (and decryption) of QUIC short header packets to hardware.
The perspective is mainly that of MsQuic, but the offload will be usable by other QUIC implementations.

Today, MsQuic builds each QUIC packet by writing headers and copying application data into an MTU-sized (or larger in the case of USO) buffer, uses an encryption library (bcrypt or openssl) to encrypt the packet in place, and then posts the packet (alone or in a batch) to the kernel.
When running MsQuic in "max throughput" mode (which parallelizes QUIC and UDP work), for bulk throughput scenarios (i.e., large file transfers), as much as 70% of a single CPU may be consumed by encryption.
This constitutes the largest CPU bottleneck in the scenario.


# Winsock API

The proposed Winsock API for QEO is as follows.


## Checking for QEO Capability

An app first checks for QEO support by querying the `SO_QEO_SUPPORT` socket option.
The option value is a `QEO_SUPPORT_FLAGS` enum with flags describing the supported capabilities:

```C
typedef enum _QEO_SUPPORT_FLAGS {
    QEO_SUPPORT_FLAG_NONE                   = 0x0000,
    QEO_SUPPORT_FLAG_AEAD_AES_128_GCM       = 0x0001,
    QEO_SUPPORT_FLAG_AEAD_AES_256_GCM       = 0x0002,
    QEO_SUPPORT_FLAG_AEAD_CHACHA20_POLY1305 = 0x0004,
    QEO_SUPPORT_FLAG_AEAD_AES_128_CCM       = 0x0008,
} QEO_SUPPORT_FLAGS;
```

Value | Meaning
--- | ---
**QEO_SUPPORT_FLAG_AEAD_AES_128_GCM**<br> | The AEAD_AES_128_GCM cryptographic algorithm is supported.
**QEO_SUPPORT_FLAG_AEAD_AES_256_GCM**<br> | The AEAD_AES_256_GCM cryptographic algorithm is supported.
**QEO_SUPPORT_FLAG_AEAD_CHACHA20_POLY1305**<br> | The AEAD_CHACHA20_POLY1305 cryptographic algorithm is supported.
**QEO_SUPPORT_FLAG_AEAD_AES_128_CCM**<br> | The AEAD_AES_128_CCM cryptographic algorithm is supported.

### Return value

If no error occurs, `getsockopt` returns zero.
If QEO is not supported by the operating system, then the `getsockopt` call will fail with status `WSAEINVAL`.

### Remarks

Not all flags are required to be set, and some very likely will not be set, depending on the capabilities of the system.
But if the `getsockopt` call does succeed, at least one non-zero flag (not `QEO_SUPPORT_FLAG_NONE`) must be set.
Note that the capabilities returned by this do not necessarily map to any particular network interface support since the OS provides software fallback.

Future OS versions may introduce additional support flags.
Applications should not error on unexpected support flags being included, but instead, should silently ignore them.


## Establishing Encryption Parameters for a Connection

Before sending or receiving packets, the app establishes crypto parameters for a connection by setting the `SO_QEO_CONNECTION` socket option with an option value of type `QEO_CONNECTION`.

```C
typedef enum {
    AesGcm128,
    AesGcm256,
    ChaCha20Poly1305,
    AesCcm128
} QEO_CIPHER_TYPE;

typedef struct {
    BOOLEAN IsAdd;
    BOOLEAN IsTransmit;
    NDIS_QUIC_CIPHER_TYPE CipherType;
    uint8_t PayloadKeyLength;
    uint8_t PayloadKey[32];
    uint8_t HeaderKeyLength;
    uint8_t HeaderKey[32];
    uint8_t PayloadIv[12];
    uint16_t Port;
    ADDRESS_FAMILY AddressFamily;
    uint8_t Address[16];
    uint8_t ConnectionIdLength;
    uint8_t ConnectionId[MAX_CID_LENGTH];
} QEO_CONNECTION;
```

> **TODO -** Explain meaning of fields.

> **TODO -** support adding N and removing M connections in one request for key update


## Sending Packets

The app calls `WSASendMsg` with an unencrypted QUIC packet (or, if USO is also being used, a set of unencrypted QUIC packets).
The packet(s) must be smaller than the current MTU by the size of the authentication tag, which is currently 16 bytes for all supported ciphers.
This leaves space for the tag to be added to the packet during encryption.

The app passes ancillary data to `WSASendMsg` in the form of `QEO_TX_ANCILLARY_DATA`:

```C
typedef struct { 
    uint64_t NextPacketNumber; 
    uint8_t ConnectionIdLength;  
} QEO_TX_ANCILLARY_DATA;
```

`NextPacketNumber` is the uncompressed QUIC packet number of the packet (or of the first packet in the batch).
This is passed down because the uncompressed packet number is an input for encryption and because the offload provider cannot read the packet number from the packet buffer without dealing with packet number compression.

The `ConnectionIdLength` is passed to help the offload provider read the connection ID (which is used as a lookup key for the previously-established encryption parameters) from the packet buffer.

## Receiving Packets

> **TODO -** Expand the bullets below with full details.

- The app sets the new `SO_QEO_CONNECTION` socket option to offload RX of a connection.
- The app allocates space for RX ancillary data struct: `QEO_RX_ANCILLARY_DATA`
  - Has an enum of the following possible states: `{ QEO_RX_ENCRYPTED, QEO_RX_DECRYPTED, QEO_RX_DECRYPT_FAILED }`
  - When the state is `QEO_RX_ENCRYPTED` it means the received QUIC packet is still encrypted
  - When the stats is `QEO_RX_DECRYPTED` it means the received QUIC packet has been successfully decrypted and the trailing 16-byte tag has been elided
  - When the state is `QEO_RX_DECRYPT_FAILED` it means the received QUIC packet failed to be decrypted, even though it was offloaded
- When considering how this interacts with URO, the only requirement is that ancillary data correctly applies to all URO packets


# TCPIP Updates for QEO

This section describes necessary updates in the Windows network stack to support QEO.

TCPIP will support graceful software fallback in the many cases where the hardware capability isn't fully supported.
Some of these scenarios include:

- Only partial feature support from the HW (e.g. supports only TX or only a particular algorithm).
- Only partial support across all available hardware (e.g. only NIC A supports offload, but not NIC B).
- Limited memory available for hardware offload (e.g. NIC only supports N offloaded connected, but app has N + M).
- Suprise removal/disable of feature support from the hardware.
- Loopback interface support.

To simplify the interface at the socket layer, TCPIP will support the SW fallback to hide the complexity of the scenarios above.
To support SW fallback, the following will have to be added to TCPIP:

- All offload state must be mirrored in TCPIP.
- Support capabilities can only be advertised for features that can be implemented in software. Any missing SW features (e.g. ChaCha20-Poly1305) cannot be advertised, even if the HW supports it.
- In addition to the offloaded connection state passed by the app, TCPIP must also track if the state has been succeessfully offloaded to the NIC.
- When an app offloads a connection, it should first go into the local mirror (synchronously) and then be offloaded to the NIC (likely async).
- In the TX path, any app-offloaded connection that hasn't been successfully offloaded to the NIC must be handled by the SW fallback.
- In the RX path, any app-offloaded connection that hasn't been successfully offloaded to the NIC must be handled by the SW fallback.
- In the case of dynamic NIC feature enablement, TCPIP should replumb all offloaded connections.

Some other requirements:

- When doing sofware USO combined with hardware QEO, TCPIP must not compute checksums, since the payload will change.
- Loopback support must be handled as well.


# NDIS API

The NDIS interface for QEO is used for communication between TCPIP (which posts NBLs containing unencrypted QUIC short header packets) and the NDIS miniport driver (which encrypts and sends the QUIC packets).


## Configuring and Advertising QEO Capability

The miniport driver advertises QEO capability during initialization with the `QuicEncryption` field of an `NDIS_OFFLOAD` structure (with `Header.Revision = NDIS_OFFLOAD_REVISION_8` and `Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_8`), which is passed to `NdisMSetMiniportAttributes`.
The `QuicEncryption` field is of type `NDIS_QEO_SUPPORT_FLAGS`:

```C
typedef enum _NDIS_QEO_SUPPORT_FLAGS {
    NDIS_QEO_SUPPORT_FLAG_NONE                   = 0x0000,
    NDIS_QEO_SUPPORT_FLAG_AEAD_AES_128_GCM       = 0x0001,
    NDIS_QEO_SUPPORT_FLAG_AEAD_AES_256_GCM       = 0x0002,
    NDIS_QEO_SUPPORT_FLAG_AEAD_CHACHA20_POLY1305 = 0x0004,
    NDIS_QEO_SUPPORT_FLAG_AEAD_AES_128_CCM       = 0x0008,
    NDIS_QEO_SUPPORT_FLAG_RECEIVE                = 0x0010,
    NDIS_QEO_SUPPORT_FLAG_TRANSMIT               = 0x0020,
} NDIS_QEO_SUPPORT_FLAGS;
```

QEO can be enabled or disabled using `OID_TCP_OFFLOAD_PARAMETERS` with the `QuicEncryption` field of the `NDIS_OFFLOAD_PARAMETERS` struct.
The `QuicEncryption` field is of type `NDIS_QEO_SUPPORT_FLAGS`, described above.
After the miniport driver handles the OID, it must send an `NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG` status indication with the updated configuration.

The current QEO configuration can be queried with `OID_TCP_OFFLOAD_CURRENT_CONFIG`.
NDIS handles this OID and does not pass it down to the miniport driver.

Every time the miniport indicates an updated configuration via a new status indication, it is considered a reset of all previously offloaded connections.
TCPIP is expected to re-plumb any offloaded connections that still can be offloaded with the new configuration.


## Establishing Encryption Parameters for a Connection

> **TODO -** what type of OID to use for `OID_QUIC_CONNECTION_ENCRYPTION`? Some OIDs have high latency. If no type of OID is fast enough, perhaps instead of OID to plumb a connection, use a special OOB in first packet. Overview of the three available OID types (normal, direct, and synchronous): https://learn.microsoft.com/en-us/windows-hardware/drivers/network/synchronous-oid-request-interface-in-ndis-6-80


Before the NDIS protocol driver posts any packets for a QEO connection, it first establishes encryption parameters for the connection by issuing `OID_QUIC_CONNECTION_ENCRYPTION`.
The `InformationBuffer` field of the `NDIS_OID_REQUEST` for this OID contains a pointer to an `NDIS_QUIC_CONNECTION`:

```C
typedef enum {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Ccm
} NDIS_QUIC_CIPHER_TYPE;

typedef struct _NDIS_QUIC_CONNECTION {
    BOOLEAN IsAdd;
    BOOLEAN IsTransmit;
    NDIS_QUIC_CIPHER_TYPE CipherType;
    uint8_t PayloadKeyLength;
    uint8_t PayloadKey[32];
    uint8_t HeaderKeyLength;
    uint8_t HeaderKey[32];
    uint8_t PayloadIv[12];
    uint16_t Port; // Destination port.
    ADDRESS_FAMILY AddressFamily;
    uint8_t Address[16]; // Destination IP address.
    uint8_t ConnectionIdLength;
    uint8_t ConnectionId[MAX_CID_LENGTH];
} NDIS_QUIC_CONNECTION;
```

The protocol driver later deletes the state for the connection with `OID_QUIC_CONNECTION_ENCRYPTION`.
The `InformationBuffer` field of the `NDIS_OID_REQUEST` for this OID also contains a pointer to an `NDIS_QUIC_CONNECTION`, but only the `Port`, `Address Family`, `Address`, `ConnectionIdLength`, and `ConnectionId` fields are used.


## Sending Packets

The NDIS protocol driver posts packets for QEO with OOB data (which can be queried using the `NET_BUFFER_LIST_INFO` macro with an `_Id` of `QuicEncryptionOffloadInfo`) with the following format:

```C
typedef struct _NDIS_QUIC_ENCRYPTION_NET_BUFFER_LIST_INFO {
    uint64_t NextPacketNumber;
    uint8_t ConnectionIdLength;
} NDIS_QUIC_ENCRYPTION_NET_BUFFER_LIST_INFO;
```

NOTE: Normally the encryption parameters for the associated connection will have been established with `OID_QUIC_CONNECTION_ENCRYPTION` for every QEO packet that is posted, but this is not guaranteed.
If a QEO packet is posted and no matching encryption parameters are established, the `NET_BUFFER_LIST` must be immediately completed by the miniport with status NDIS_STATUS_INVALID_PACKET without transmitting the packet.

First, the miniport encrypts the packet (the process for which is outlined in the Appendix), adding the AEAD tag to the end of the packet.

Then, the miniport computes the UDP checksum (if the UDP header checksum field in the packet is nonzero) and the IP checksum, as specified in RFC 768 and RFC 2460.

> **Note**
> If both USO and QEO are in use, then a posted `NET_BUFFER_LIST` will contain multiple unencrypted QUIC packets. The `MSS` field of `NDIS_UDP_SEGMENTATION_OFFLOAD_NET_BUFFER_LIST_INFO` will indicate the size of each *unencrypted* packet (including the MAC, IP and UDP headers and QUIC packet but not including the AEAD tag). The miniport must encrypt each packet in the `NET_BUFFER_LIST`, adding the AEAD tag to each, before continuing with USO processing (such as packet checksum computation). See Appendix for more information on USO.


## Receiving Packets

When the miniport receives a packet from the network, if the packet matches a connection that has already been set up with `OID_QUIC_CONNECTION_ENCRYPTION`, the miniport decrypts the packet (using the process outlined in the Appendix).
The miniport then indicates the packet with OOB data in the format `NDIS_QUIC_ENCRYPTION_RECEIVE_NET_BUFFER_LIST_INFO`:

> **TODO** Should we use the same OOB "Id" as for TX, or a different one?

```C
typedef enum {
    NdisQuicDecryptionSucceeded;
    NdisQuicDecryptionFailed;
} NDIS_QUIC_DECRYPTION_STATUS;

typedef struct _NDIS_QUIC_ENCRYPTION_RECEIVE_NET_BUFFER_LIST_INFO {
    uint8_t DecryptionStatus;
} NDIS_QUIC_ENCRYPTION_RECEIVE_NET_BUFFER_LIST_INFO;
```

`NdisQuicDecryptionFailed` is set as the `DecryptionStatus` if a connection record was found matching the packet but packet decryption failed.

> **TODO** instead of indicating a packet with status NdisQuicDecryptionFailed that will very likely fail to be decrypted by the upper layer, should we add an interface perf counter (is that something that we can do?) and have the miniport increment that and not indicate the packet at all?

> **TODO** specify interaction with URO
 
# Appendix

## QUIC Encryption
 
The following section outlines how the offloaded connection keys should be used to encrypt or decrypt QUIC short header packets.
The full details can be found in [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001#name-packet-protection).
The `PayloadKey` and `HeaderKey` fields are the keys used directly in the AEAD functions to encrypt/decrypt the payload and header.
They are not the traffic secrets derived by the TLS handshake.

For packet encryption, the steps are detailed [here](https://www.rfc-editor.org/rfc/rfc9001#name-aead-usage), with key sections quoted below.

> The nonce, N, is formed by combining the packet protection IV with the packet number. The 62 bits of the reconstructed QUIC packet number in network byte order are left-padded with zeros to the size of the IV. The exclusive OR of the padded packet number and the IV forms the AEAD nonce.
>
> The associated data, A, for the AEAD is the contents of the QUIC header, starting from the first byte of either the short or long header, up to and including the unprotected packet number.
>
> The input plaintext, P, for the AEAD is the payload of the QUIC packet, as described in [QUIC-TRANSPORT](https://www.rfc-editor.org/rfc/rfc9000).
>
> The output ciphertext, C, of the AEAD is transmitted in place of P.

After packet encryption, header encryption is performed.
The steps are detailed [here](https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-applicati), with key sections quoted below.

> Header protection is applied after packet protection is applied (see [Section 5.3](https://www.rfc-editor.org/rfc/rfc9001#aead)). The ciphertext of the packet is sampled and used as input to an encryption algorithm. The algorithm used depends on the negotiated AEAD.
>
> The output of this algorithm is a 5-byte mask that is applied to the protected header fields using exclusive OR. The least significant bits of the first byte of the packet are masked by the least significant bits of the first mask byte, and the packet number is masked with the remaining bytes. Any unused bytes of mask that might result from a shorter packet number encoding are unused.

Decryption is the reverse process: the header and then the payload is decrypted.

## UDP Segmentation Offload (USO)

> **Note**
> This section is not directly about QEO, but provides context on an existing offload with which there are interactions.

Today, MsQuic uses USO on Windows to send a batch of UDP datagrams in a single syscall
It first calls `getsockopt` with option `UDP_SEND_MSG_SIZE` to query for support of USO, and then calls `setsockopt` with `UDP_SEND_MSG_SIZE` to tell the USO provider the MTU size to use to split a buffer into multiple datagrams.
Once the MTU has been set, QUIC calls `WSASendMsg` with a buffer (or a chain of buffers according to `WSASendMsg` gather semantics) containing multiple datagrams.
The kernel creates a large UDP datagram from this buffer and posts it to the NDIS miniport, which breaks down the large datagram into a set of MTU-sized datagrams.

QEO is orthogonal to USO and usable either with or without it: if USO is enabled, then the app can post multiple datagrams in a single send call; and if QEO is enabled, the datagram[s] are posted unencrypted.

Windows documentation can be found [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-segmentation-offload-uso-).
MsQuic also uses the equivalent Linux API ([GSO](https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html#generic-segmentation-offload)).

## Linux API for QUIC encryption offload

> **Note**
> The Linux interface is also a work in progress. The following indicates the current state of the proposal.

Linux developers are working on a send-side kernel/hardware encryption offload.
See [here](https://lore.kernel.org/all/97789971-7cf5-ede1-11e2-df6494e75e44@gmail.com/).
The focus on sender side is justified by the claim that server-side networking is typically send-dominant.

The general API in Linux is:

- The app associates a connection ID with encryption params (key, iv, cipher) with socket option `UDP_QUIC_ADD_TX_CONNECTION`. This state is removed when the socket is closed, or it can be removed explicitly with `UDP_QUIC_DEL_TX_CONNECTION` (there is discussion ongoing about using tuples instead of or alongside connection ID).

- GSO is optionally set up with socket option `UDP_SEGMENT` (this value can be overridden per-send with ancillary data).

- Sendmsg is called with some ancillary data: the connection ID length, the next packet number, and a flags field.

- On key rollover, the app plumbs the new key.

If a hardware offload is supported by the network interface, then it is used; otherwise the kernel takes care of the encryption and segmentation for usermode.

