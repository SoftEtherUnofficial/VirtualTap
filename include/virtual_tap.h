#ifndef VIRTUAL_TAP_H
#define VIRTUAL_TAP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
typedef struct VirtualTap VirtualTap;

// Configuration
typedef struct {
    uint8_t our_mac[6];
    uint32_t our_ip;           // Network byte order, 0 if unknown
    uint32_t gateway_ip;       // Network byte order, 0 if unknown
    uint8_t gateway_mac[6];    // All zeros if unknown
    bool handle_arp;
    bool learn_ip;
    bool learn_gateway_mac;
    bool verbose;
} VirtualTapConfig;

// Statistics
typedef struct {
    uint64_t ip_to_eth_packets;
    uint64_t eth_to_ip_packets;
    uint64_t arp_requests_handled;
    uint64_t arp_replies_sent;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t arp_packets;
    uint64_t icmpv6_packets;
    uint64_t dhcp_packets;
    uint64_t arp_table_entries;
    uint64_t other_packets;
} VirtualTapStats;

// API Functions

/// Create a new VirtualTap instance
/// Returns NULL on error
VirtualTap* virtual_tap_create(const VirtualTapConfig* config);

/// Destroy a VirtualTap instance
void virtual_tap_destroy(VirtualTap* tap);

/// Convert IP packet to Ethernet frame
/// Returns length of Ethernet frame (>= 0), or negative error code
/// Caller must provide output buffer of at least input_len + 14 bytes
int32_t virtual_tap_ip_to_ethernet(
    VirtualTap* tap,
    const uint8_t* ip_packet,
    uint32_t ip_len,
    uint8_t* eth_frame_out,
    uint32_t out_capacity
);

/// Convert Ethernet frame to IP packet
/// Returns length of IP packet (> 0), 0 if frame was handled internally (ARP),
/// or negative error code
/// Caller must provide output buffer
int32_t virtual_tap_ethernet_to_ip(
    VirtualTap* tap,
    const uint8_t* eth_frame,
    uint32_t eth_len,
    uint8_t* ip_packet_out,
    uint32_t out_capacity
);

/// Get learned IP address
/// Returns IP in network byte order, or 0 if not learned yet
uint32_t virtual_tap_get_learned_ip(VirtualTap* tap);

/// Get learned gateway MAC address
/// Returns true if gateway MAC is known, false otherwise
/// If true, copies MAC to mac_out
bool virtual_tap_get_gateway_mac(VirtualTap* tap, uint8_t mac_out[6]);

/// Get statistics
void virtual_tap_get_stats(VirtualTap* tap, VirtualTapStats* stats);

/// Check if there are pending ARP replies to send back to server
bool virtual_tap_has_pending_arp_reply(VirtualTap* tap);

/// Get next pending ARP reply
/// Returns length of ARP reply (> 0), or 0 if no pending replies
/// Caller must provide output buffer of at least 42 bytes
int32_t virtual_tap_pop_arp_reply(
    VirtualTap* tap,
    uint8_t* arp_reply_out,
    uint32_t out_capacity
);

#ifdef __cplusplus
}
#endif

#endif // VIRTUAL_TAP_H
