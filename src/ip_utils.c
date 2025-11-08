#include "../include/virtual_tap_internal.h"

// ============================================================================
// IP Utility Functions
// ============================================================================

uint32_t ipv4_to_u32(const uint8_t ip[4]) {
    if (!ip) return 0;
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8) | ip[3];
}

void u32_to_ipv4(uint32_t ip, uint8_t out[4]) {
    if (!out) return;
    out[0] = (ip >> 24) & 0xFF;
    out[1] = (ip >> 16) & 0xFF;
    out[2] = (ip >> 8) & 0xFF;
    out[3] = ip & 0xFF;
}

uint32_t extract_dest_ip_from_packet(const uint8_t* ip_packet, uint32_t len) {
    if (!ip_packet || len < 20) return 0;
    
    // Check IPv4
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    if (version != 4) return 0;
    
    // Destination IP at bytes 16-19
    return read_u32_be(ip_packet + 16);
}
