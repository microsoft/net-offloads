//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

//
// OID_QUIC_CONNECTION_ENCRYPTION is a direct OID used for QUIC connection
// encryption offload.
//
#ifndef OID_QUIC_CONNECTION_ENCRYPTION
#define OID_QUIC_CONNECTION_ENCRYPTION      0xFC010215
#else
C_ASSERT(OID_QUIC_CONNECTION_ENCRYPTION ==  0xFC010215);
#endif

//
// Temporarily repurpose the OID_TCP_TASK_IPSEC_OFFLOAD_V2_UPDATE_SA OID
// until NDIS changes are released.
//
#define OID_QUIC_CONNECTION_ENCRYPTION_PROTOTYPE OID_TCP_TASK_IPSEC_OFFLOAD_V2_UPDATE_SA

typedef enum _NDIS_QEO_SUPPORT_FLAGS {
    NDIS_QEO_SUPPORT_FLAG_NONE                   = 0x0000,
    NDIS_QEO_SUPPORT_FLAG_AEAD_AES_128_GCM       = 0x0001,
    NDIS_QEO_SUPPORT_FLAG_AEAD_AES_256_GCM       = 0x0002,
    NDIS_QEO_SUPPORT_FLAG_AEAD_CHACHA20_POLY1305 = 0x0004,
    NDIS_QEO_SUPPORT_FLAG_AEAD_AES_128_CCM       = 0x0008,
    NDIS_QEO_SUPPORT_FLAG_RECEIVE                = 0x0010,
    NDIS_QEO_SUPPORT_FLAG_TRANSMIT               = 0x0020,
} NDIS_QEO_SUPPORT_FLAGS;

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

/*
    TODO - Eventually remove this once prototyping is complete.

    The follow outlines some psuedocode for how to implement the logic for a
    prototype QEO solution.

struct offload_info {
    int operation;
    int direction;
    int next_packet_number;
    addr ip_address;
    byte cid[];
    key_info key;
}

offload_info[] rx_offload_table;
offload_info[] tx_offload_table;

int rx_cid_length = -1;
int tx_cid_length = -1;

void update_offload(offload_info offloads[]) {
    foreach (auto offload in offloads) {
        if (offload.operation == "add") {
            if (offload.direction == "tx") {
                if (tx_cid_length == -1) tx_cid_length = offload.cid.length;
            } else {
                if (rx_cid_length == -1) rx_cid_length = offload.cid.length;
            }
        } else {
            if (offload.direction == "tx") {
                tx_offload_table.remove(offload);
            } else {
                rx_offload_table.remove(offload);
            }
        }
    }
}

void on_packet_tx(packet packet) {
    if (packet.udp_payload[0] == "long header") return;
    byte[] cid = packet.udp_payload[1 .. tx_cid_length+1];
    byte packet_number = packet.udp_payload[tx_cid_length+2 .. tx_cid_length+6]; // 4 bytes
    offload_info offload = tx_offload_table.find(packet.ip_address, cid);
    encrypt_quic_packet(packet, offload, packet_number)
}

void on_packet_rx(packet packet) {
    if (packet.udp_payload[0] == "long header") return;
    byte[] cid = packet.udp_payload[1 .. rx_cid_length+1];
    byte packet_number = packet.udp_payload[rx_cid_length+2 .. rx_cid_length+6]; // 4 bytes
    offload_info offload = rx_offload_table.find(packet.ip_address, cid);
    decrypt_quic_packet(packet, offload, packet_number)
}

*/
