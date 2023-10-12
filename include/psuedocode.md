The follow outlines some psuedocode for how to implement the logic for a prototype QEO solution.

```csharp
struct offload_info {
    uint operation;
    uint direction;
    ulong next_packet_number;
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
                tx_offload_table.add(offload); // eventually will support update too, but simplifying things for now
            } else {
                if (rx_cid_length == -1) rx_cid_length = offload.cid.length;
                rx_offload_table.add(offload); // eventually will support update too, but simplifying things for now
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

// Based on https://github.com/microsoft/msquic/blob/main/src/core/packet.h#L372
void decompress_packet_number(ulong expected_packet_number, uint compressed_packet_number) {
    ulong Mask = 0xFFFFFFFF00000000;
    ulong PacketNumberInc = (~Mask) + 1;
    ulong PacketNumber = (Mask & expected_packet_number) | compressed_packet_number;
    if (PacketNumber < expected_packet_number) {
        ulong High = expected_packet_number - PacketNumber;
        ulong Low = PacketNumberInc - High;
        if (Low < High) {
            PacketNumber += PacketNumberInc;
        }

    } else {
        ulong Low = PacketNumber - expected_packet_number;
        ulong High = PacketNumberInc - Low;
        if (High <= Low && PacketNumber >= PacketNumberInc) {
            PacketNumber -= PacketNumberInc;
        }
    }
    return PacketNumber;
}

void encrypt_quic_packet(packet packet, offload_info offload) {
    // Decompress the full packet number
    ulong packet_number =
        decompress_packet_number(
            offload.next_packet_number,
            packet.udp_payload[tx_cid_length+1 .. tx_cid_length+4]); // 4 bytes after the CID

    // Update the next full packet number for the next TX/encrypt call
    offload.next_packet_number = packet_number + 1;

    // TODO - Encrypt the packet payload
    // TODO - Encrypt the packet header
}

void on_packet_tx(packet packet) {
    if (packet.udp_payload[0] == "long header") return;

    // Find the offload info based on the destination IP:port and CID.
    offload_info offload =
        rx_offload_table.find(
            packet.dest_ip_address,
            packet.udp_payload[1 .. tx_cid_length]); // tx_cid_length bytes after the first byte

    encrypt_quic_packet(packet, offload);
}

void decrypt_quic_packet(packet packet, offload_info offload) {
    // TODO - Decrypt packet header

    // Decompress the full packet number
    ulong packet_number =
        decompress_packet_number(
            offload.next_packet_number,
            packet.udp_payload[rx_cid_length+1 .. rx_cid_length+4]); // 4 bytes after the CID

    // Update the next full packet number for the next RX/decrypt call
    if (packet_number >= offload.next_packet_number) {
        offload.next_packet_number = packet_number + 1;
    }

    // TODO - Decrypt packet payload
}

void on_packet_rx(packet packet) {
    if (packet.udp_payload[0] == "long header") return;

    // Find the offload info based on the destination IP:port and CID.
    offload_info offload =
        rx_offload_table.find(
            packet.dest_ip_address,
            packet.udp_payload[1 .. rx_cid_length]); // rx_cid_length bytes after the first byte

    decrypt_quic_packet(packet, offload);
}
```
