# QUIC Encryption Offload (QEO)

> **Note**
> This document is a work in progress.

This document describes an offload called QEO which offloads the encryption (and decryption) of QUIC short header packets.
The primary goal is an NDIS offload to the miniport for hardware support, but the OS will provide software fallback when hardware support is not available.
The perspective is mainly that of MsQuic, but the offload will be usable by other QUIC implementations.

Today, MsQuic builds each QUIC packet by writing headers and copying application data into an MTU-sized (or larger in the case of USO) buffer, uses an encryption library (bcrypt or openssl) to encrypt the packet in place, and then posts the packet (alone or in a batch) to the kernel.
When running MsQuic in "max throughput" mode (which parallelizes QUIC and UDP work), for bulk throughput scenarios (i.e., large file transfers), as much as 70% of a single CPU may be consumed by encryption.
This constitutes the largest CPU bottleneck in the scenario.

## Table of Contents

- [Winsock](#winsock)
- [TCPIP](#tcpip)
- [NDIS](#ndis)
- [Appendix](#appendix)

# Winsock

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

If the `getsockopt` call succeeds, at least one flag will be set.
Note that the returned capabilities do not necessarily indicate that a network interface supports QEO: the encryption offload may happen in software if the interface on which the socket sends packets does not support it.

Future OS versions may introduce new flags.
Therefore, applications should silently ignore unrecognized support flags.

## Establishing Encryption Parameters for a Connection

Before sending or receiving packets, the app establishes crypto parameters for a connection by setting the `SO_QEO_CONNECTION` socket option with an option value that is an array of type `QEO_CONNECTION`. Each element in the array describes a transmit or receive connection offload to be established (to set up the offload for a single connection for both transmit and receive, two `QEO_CONNECTION`s must be passed).

```C
typedef enum _QEO_OPERATION {
    QEO_OPERATION_ADD,     // Add (or modify) a QUIC connection offload
    QEO_OPERATION_REMOVE,  // Remove a QUIC connection offload
} QEO_OPERATION;

typedef enum _QEO_DIRECTION {
    QEO_DIRECTION_TRANSMIT, // An offload for the transmit path
    QEO_DIRECTION_RECEIVE,  // An offload for the receive path
} QEO_DIRECTION;

typedef enum _QEO_DECRYPT_FAILURE_ACTION {
    QEO_DECRYPT_FAILURE_ACTION_DROP,     // Drop the packet on decryption failure
    QEO_DECRYPT_FAILURE_ACTION_CONTINUE, // Continue and pass the packet up on decryption failure
} QEO_DECRYPT_FAILURE_ACTION;

typedef enum _QEO_CIPHER_TYPE {
    QEO_CIPHER_TYPE_AEAD_AES_128_GCM,
    QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
    QEO_CIPHER_TYPE_AEAD_CHACHA20_POLY1305,
    QEO_CIPHER_TYPE_AEAD_AES_128_CCM
} QEO_CIPHER_TYPE;

typedef struct _QEO_CONNECTION {
    UINT32 Operation            : 1;  // QEO_OPERATION
    UINT32 Direction            : 1;  // QEO_DIRECTION
    UINT32 DecryptFailureAction : 1;  // QEO_DECRYPT_FAILURE_ACTION
    UINT32 KeyPhase             : 1;
    UINT32 RESERVED             : 12; // Must be set to 0. Don't read.
    UINT32 CipherType           : 16; // QEO_CIPHER_TYPE
    ADDRESS_FAMILY AddressFamily;
    UINT16 UdpPort;
    UINT64 NextPacketNumber;
    UINT8 ConnectionIdLength;
    UINT8 Address[16];
    UINT8 ConnectionId[20]; // Limit to max of QUIC v1 & v2
    UINT8 PayloadKey[32];   // Length determined by CipherType
    UINT8 HeaderKey[32];    // Length determined by CipherType
    UINT8 PayloadIv[12];
} QEO_CONNECTION;
```

### QEO_CONNECTION Parameters

#### Operation

Indicates whether the connection offload is being added (`QEO_OPERATION_ADD`) or removed (`QEO_OPERATION_REMOVE`).

#### Direction

Indicates whether the offload is for connection transmit (`QEO_DIRECTION_TRANSMIT`) or receive (`QEO_DIRECTION_RECEIVE`).

#### DecryptFailureAction

Indicates whether a packet that fails to decrypt should be dropped (`QEO_DECRYPT_FAILURE_ACTION_DROP`) or continued up the stack (`QEO_DECRYPT_FAILURE_ACTION_CONTINUE`).

#### KeyPhase

Indicates the key phase bit for the connection.

#### RESERVED

Reserved for future use. Must be set to `0`.

#### CipherType

Indicates the cipher type to be used.

#### AddressFamily

Indicates the family (IPv4 or IPv6) of the IP address contained in the `Address` field.

#### UdpPort

The destination UDP port of the connection, in network byte order.

#### NextPacketNumber

This contains expected full packet number for the next packet to be sent or recieved.
For the `QEO_DIRECTION_RECEIVE` direction, this generally will be zero if no short header packets have been received yet.

#### ConnectionIdLength

The length of the QUIC connection ID in the `ConnectionId` field. May be zero.

#### Address

The IPv4 or IPv6 (depending on `AddressFamily`) destination address of the connection.

#### ConnectionId

The QUIC connection ID.

#### PayloadKey

The AEAD key (not traffic secret) for the QUIC packet payload encryption or decryption (depending on `Direction`).

#### HeaderKey

The AEAD key (not traffic secret) for the QUIC packet header encryption or decryption (depending on `Direction`).

#### PayloadIv

The AEAD IV for the QUIC packet payload encryption or decryption (depending on `Direction`).

### Return value

If no error occurs, `setsockopt` returns zero.
If QEO or the specific `CipherType` is not supported by the operating system, then the `setsockopt` call will fail with status `WSAEINVAL`.

## Sending Packets

The app calls `WSASendMsg` with an unencrypted QUIC packet (or, if USO is also being used, a set of unencrypted QUIC packets).
The packet(s) must be smaller than the current MTU by the size of the authentication tag, which is currently 16 bytes for all supported ciphers.
This leaves space for the tag to be added to the packet during encryption.

The app passes ancillary data to `WSASendMsg` in the form of `QEO_TX_ANCILLARY_DATA`:

```C
typedef struct _QEO_TX_ANCILLARY_DATA {
    uint8_t ConnectionIdLength;
} QEO_TX_ANCILLARY_DATA;
```

The `ConnectionIdLength` is passed to help the offload provider read the connection ID (which is used as a lookup key for the previously-established encryption parameters) from the packet buffer.

The next packet number was previous configured in the `QEO_CONNECTION`, and is used as the starting place to fully expand all QUIC packet numbers, which is then used to encrypt the packets.
The offload is stateful and keeps track of the most recent packet number of expand future sent packets.

## Receiving Packets

The app calls `WSARecvMsg` with enough space for the `QEO_DECRYPTION_STATUS` ancillary data in the `Control` buffer.
The returned ancillary data indicates whether the packet was successfully decrypted.

```C
typedef enum _QEO_DECRYPTION_STATUS {
    QEO_DECRYPTION_SUCCESS,
    QEO_DECRYPTION_FAILED,
} QEO_DECRYPTION_STATUS;
```

Value | Meaning
--- | ---
**QEO_DECRYPTION_SUCCESS**<br> | The packet has been decrypted and the trailing AEAD tag has been removed.
**QEO_DECRYPTION_FAILED**<br> | The packet could not be decrypted, even though the connection was offloaded.

### Remarks

If the `QEO_DECRYPTION_STATUS` ancillary data is not present then there was no offloaded connection that matched the QUIC packet(s).

The payload of a decryption failure is not the original payload sent on the wire, but the result of the failed decryption.
The authentication tag at the end of the QUIC packet must not be modified.

When QEO is used with URO, the ancillary data must correctly apply to all URO packets.
So all coalesced QUIC packets indicated in a single URO must have the same decryption status to be indicated together.

The offload is stateful and keeps track of the most recent packet number of expand future sent packets.

# TCPIP

This section describes necessary updates in the Windows network stack (mostly in `tcpip.sys`) to support QEO.

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
- TCPIP must keep the packet number state up to date so long as the connection is offloaded, by inspecting packets numbers sent and received on the datapath.
- Support capabilities can only be advertised for features that can be implemented in software. Any missing SW features (e.g. ChaCha20-Poly1305) cannot be advertised, even if the HW supports it.
- In addition to the offloaded connection state passed by the app, TCPIP must also track if the state has been successfully offloaded to the NIC.
- When an app offloads a connection, it should first go into the local mirror (synchronously) and then be offloaded to the NIC (likely async).
- In the TX path, any app-offloaded connection that hasn't been successfully offloaded to the NIC must be handled by the SW fallback.
- In the RX path, any app-offloaded connection that hasn't been successfully offloaded to the NIC must be handled by the SW fallback.
- In the case of dynamic NIC feature enablement, TCPIP should replumb all offloaded connections.

Some other requirements:

- When doing software USO combined with hardware QEO, TCPIP must not compute checksums, since the payload will change.
- Loopback support must be handled as well.

# NDIS

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

Before the NDIS protocol driver posts any packets for a QEO connection, it first establishes encryption parameters for the connection by issuing the Direct OID `OID_QUIC_CONNECTION_ENCRYPTION`.
The OID RequestType must be NdisRequestMethod to ensure input/output support.
The `InformationBuffer` field of the `NDIS_OID_REQUEST` for this OID contains an array of type `NDIS_QUIC_CONNECTION`.
The `InformationBufferLength` field contains the length of the array in bytes.

> **Note** For development on Windows versions older than ***TBD*** prototype
> miniport drivers may handle `OID_QUIC_CONNECTION_ENCRYPTION_PROTOTYPE`
> requests in the same manner as `OID_QUIC_CONNECTION_ENCRYPTION`. The prototype
> OID must not be supported in any official or released miniport driver
> versions.
>
> **Note** Miniport drivers installed on Windows versions older than ***TBD***
> must reject any `OID_QUIC_CONNECTION_ENCRYPTION` requests submitted to the
> regular, i.e., non-direct, miniport OID handler.

```C
typedef enum _NDIS_QUIC_OPERATION {
    NDIS_QUIC_OPERATION_ADD,     // Add (or modify) a QUIC connection offload
    NDIS_QUIC_OPERATION_REMOVE,  // Remove a QUIC connection offload
} NDIS_QUIC_OPERATION;

typedef enum _NDIS_QUIC_DIRECTION {
    NDIS_QUIC_DIRECTION_TRANSMIT, // An offload for the transmit path
    NDIS_QUIC_DIRECTION_RECEIVE,  // An offload for the receive path
} NDIS_QUIC_DIRECTION;

typedef enum _NDIS_QUIC_DECRYPT_FAILURE_ACTION {
    NDIS_QUIC_DECRYPT_FAILURE_ACTION_DROP,     // Drop the packet on decryption failure
    NDIS_QUIC_DECRYPT_FAILURE_ACTION_CONTINUE, // Continue and pass the packet up on decryption failure
} NDIS_QUIC_DECRYPT_FAILURE_ACTION;

typedef enum _NDIS_QUIC_CIPHER_TYPE {
    NDIS_QUIC_CIPHER_TYPE_AEAD_AES_128_GCM,
    NDIS_QUIC_CIPHER_TYPE_AEAD_AES_256_GCM,
    NDIS_QUIC_CIPHER_TYPE_AEAD_CHACHA20_POLY1305,
    NDIS_QUIC_CIPHER_TYPE_AEAD_AES_128_CCM,
} NDIS_QUIC_CIPHER_TYPE;

typedef enum _NDIS_QUIC_ADDRESS_FAMILY {
    NDIS_QUIC_ADDRESS_FAMILY_INET4,
    NDIS_QUIC_ADDRESS_FAMILY_INET6,
} NDIS_QUIC_ADDRESS_FAMILY;

typedef struct _NDIS_QUIC_CONNECTION {
    UINT32 Operation            : 1;  // NDIS_QUIC_OPERATION
    UINT32 Direction            : 1;  // NDIS_QUIC_DIRECTION
    UINT32 DecryptFailureAction : 1;  // NDIS_QUIC_DECRYPT_FAILURE_ACTION
    UINT32 KeyPhase             : 1;
    UINT32 RESERVED             : 12; // Must be set to 0. Don't read.
    UINT32 CipherType           : 16; // NDIS_QUIC_CIPHER_TYPE
    NDIS_QUIC_ADDRESS_FAMILY AddressFamily;
    UINT16 UdpPort;         // Destination port.
    UINT64 NextPacketNumber;
    UINT8 ConnectionIdLength;
    UINT8 Address[16];      // Destination IP address.
    UINT8 ConnectionId[20]; // QUIC v1 and v2 max CID size
    UINT8 PayloadKey[32];   // Length determined by CipherType
    UINT8 HeaderKey[32];    // Length determined by CipherType
    UINT8 PayloadIv[12];
    NDIS_STATUS Status;       // The result of trying to offload this connection.
} NDIS_QUIC_CONNECTION;
```

The return status of the OID must be `NDIS_STATUS_SUCCESS` even if some of the offloaded connections might have failed.

The protocol driver later deletes the state for the connection with `OID_QUIC_CONNECTION_ENCRYPTION`.
The `InformationBuffer` field of the `NDIS_OID_REQUEST` for this OID also contains a pointer to an `NDIS_QUIC_CONNECTION`, but only the `Port`, `Address Family`, `Address`, `ConnectionIdLength`, and `ConnectionId` fields are used.

The `Operation` field of each `NDIS_QUIC_CONNECTION` in the OID `InformationBuffer` array determines whether that connection is being added or removed. A single OID can therefore both add and remove connections.

The `Status` field of each `NDIS_QUIC_CONNECTION` is an output from the miniport to reflect the result of trying to offload the connection. This allows for individual connections to succeed or fail, without failing the entire OID. The `NDIS_QUIC_CONNECTION` array output of a successful OID request must be identical in layout to the input array, i.e., connections must not be reordered or realigned, and identifying fields within each connection entry must be preserved.

## Sending Packets

The NDIS protocol driver posts packets for QEO with OOB data (which can be queried using the `NET_BUFFER_LIST_INFO` macro with an `_Id` of `QuicEncryptionOffloadInfo`) with the following format:

```C
typedef struct _NDIS_QUIC_ENCRYPTION_NET_BUFFER_LIST_INFO {
    uint8_t ConnectionIdLength;
} NDIS_QUIC_ENCRYPTION_NET_BUFFER_LIST_INFO;
```

NOTE: Normally the encryption parameters for the associated connection will have been established with `OID_QUIC_CONNECTION_ENCRYPTION` for every QEO packet that is posted, but this is not guaranteed.
If a QEO packet is posted and no matching encryption parameters are established, the `NET_BUFFER_LIST` must be immediately completed by the miniport with status NDIS_STATUS_INVALID_PACKET without transmitting the packet.

First, the miniport encrypts the packet (the process for which is outlined in the Appendix), adding the AEAD tag to the end of the packet.

Then, the miniport computes the UDP checksum (if the UDP header checksum field in the packet is nonzero) and the IP checksum, as specified in RFC 768 and RFC 2460.

> **Note**
> If both USO and QEO are in use, then a posted `NET_BUFFER_LIST` will contain multiple unencrypted QUIC packets. The `MSS` field of `NDIS_UDP_SEGMENTATION_OFFLOAD_NET_BUFFER_LIST_INFO` will indicate the size of each *unencrypted* QUIC packet (i.e., the size of the UDP payload before the AEAD tag is added). The miniport must encrypt each packet in the `NET_BUFFER_LIST`, adding the AEAD tag to each, before continuing with USO processing (such as packet checksum computation). See Appendix for more information on USO.

## Receiving Packets

When the miniport receives a packet from the network, if the packet matches a connection that has already been set up with `OID_QUIC_CONNECTION_ENCRYPTION`, the miniport decrypts the packet (using the process outlined in the Appendix).
The miniport then indicates the packet with OOB data in the format `NDIS_QUIC_ENCRYPTION_RECEIVE_NET_BUFFER_LIST_INFO`:
The OOB data uses the same `_Id` as the transmit path.

```C
typedef enum _NDIS_QUIC_DECRYPTION_STATUS {
    NdisQuicDecryptionSucceeded;
    NdisQuicDecryptionFailed;
} NDIS_QUIC_DECRYPTION_STATUS;

typedef struct _NDIS_QUIC_ENCRYPTION_RECEIVE_NET_BUFFER_LIST_INFO {
    uint8_t DecryptionStatus;
} NDIS_QUIC_ENCRYPTION_RECEIVE_NET_BUFFER_LIST_INFO;
```

`NdisQuicDecryptionFailed` is set as the `DecryptionStatus` if a connection record was found matching the packet but packet decryption failed.

### Changes to URO

When QEO is combined with URO (UDP RSC Offload), the requirements for coalescing are amended to include:

- The QUIC connection IDs must match
- The QUIC decryption status must match

### Psuedocode

```c++
enum Action {
    Continue, // Pass packet up
    Drop
};

Action ProcessUdpPacket(_Inout_ Packet* packet) {
    if (!packet->IsQuicShortHeader()) return Continue; // Not QUIC short header packet

    uint8_t CidLength = ConnectionIdLengthTable.Lookup(packet->DestinationIpAddress(), packet->DestinationUdpPort());
    if (CidLength == INVALID_CID) return Continue; // No match

    QeoConnection* Connection = QeoRxTable.Lookup(
        packet->DestinationIpAddress(), packet->DestinationUdpPort(),
        packet->QuicCidStartPtr(), CidLength, packet->QuicKeyPhase());
    if (!Connection) return Continue; // No match

    Action action = Connection->TryDecryptPacket(packet); // Updates the contents of packet with result of decryption.

    Connection->Release(); // Release ref on connection, which may clean it up if another thread removed the offload.

    return action;
}

Action QeoConnection::TryDecryptPacket(_Inout_ Packet* packet) {
    packet->DecryptPacketHeader(this->KeyMaterial);

    uint64_t PacketNumber = packet->DecodePacketNumber(this->NextPacketNumber);

    if (!this->TryDecryptPacketPayload(this->KeyMaterial, PacketNumber)) {
        Packet->QuicDecryptionResult == DecryptFailure;
        return this->DecryptFailureAction;
    }

    Packet->QuicDecryptionResult == DecryptSuccess;
    if (PacketNumber > this->NextPacketNumber) this->NextPacketNumber = PacketNumber;

    return Continue;
}
```

# Appendix

## QUIC Encryption

> **Note**
> This section only outlines how QUIC encryption works. For the full details, [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001#name-packet-protection) should be consulted.

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
