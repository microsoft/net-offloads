The follow outlines some psuedocode for how to implement the logic for a prototype QEO solution.

```
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
```
