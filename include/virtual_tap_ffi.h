/**
 * VirtualTap C FFI Interface
 * 
 * C interface for the VirtualTap Layer 2 virtualization module.
 * Allows integration with existing C/C++ codebases.
 */

#ifndef VIRTUAL_TAP_FFI_H
#define VIRTUAL_TAP_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque VirtualTap handle
 */
typedef struct VirtualTapHandle VirtualTapHandle;

/**
 * VirtualTap configuration
 */
typedef struct {
    uint8_t our_mac[6];           // Our virtual MAC address
    uint32_t our_ip;              // Our IP address (0 if unknown)
    uint32_t gateway_ip;          // Gateway IP address (0 if unknown)
    uint8_t gateway_mac[6];       // Gateway MAC address
    bool has_gateway_mac;         // Whether gateway_mac is valid
    bool handle_arp;              // Handle ARP internally
    bool learn_ip;                // Learn IP addresses from packets
    bool learn_gateway_mac;       // Learn gateway MAC from incoming frames
    bool verbose;                 // Verbose logging
    size_t arp_table_size;        // ARP table size
    uint64_t arp_timeout_ms;      // ARP entry timeout (milliseconds)
} VirtualTapConfig;

/**
 * VirtualTap statistics
 */
typedef struct {
    uint64_t ip_to_eth_packets;
    uint64_t ip_to_eth_bytes;
    uint64_t ip_to_eth_errors;
    uint64_t eth_to_ip_packets;
    uint64_t eth_to_ip_bytes;
    uint64_t eth_to_ip_drops;
    uint64_t arp_requests_handled;
    uint64_t arp_replies_sent;
    uint64_t arp_table_hits;
    uint64_t arp_table_misses;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t arp_packets;
    uint64_t other_packets;
} VirtualTapStats;

/**
 * Initialize VirtualTap
 * 
 * @param config Configuration structure
 * @return Handle to VirtualTap instance, or NULL on error
 */
VirtualTapHandle* virtual_tap_init(const VirtualTapConfig* config);

/**
 * Clean up VirtualTap
 * 
 * @param handle VirtualTap handle
 */
void virtual_tap_deinit(VirtualTapHandle* handle);

/**
 * Convert IP packet to Ethernet frame (Platform → SoftEther)
 * 
 * @param handle VirtualTap handle
 * @param ip_packet Input IP packet
 * @param ip_len Length of IP packet
 * @param out_buffer Output buffer for Ethernet frame
 * @param out_buffer_size Size of output buffer
 * @return Length of Ethernet frame, or negative on error
 */
int virtual_tap_ip_to_ethernet(
    VirtualTapHandle* handle,
    const uint8_t* ip_packet,
    size_t ip_len,
    uint8_t* out_buffer,
    size_t out_buffer_size
);

/**
 * Convert Ethernet frame to IP packet (SoftEther → Platform)
 * 
 * @param handle VirtualTap handle
 * @param eth_frame Input Ethernet frame
 * @param eth_len Length of Ethernet frame
 * @param out_buffer Output buffer for IP packet
 * @param out_buffer_size Size of output buffer
 * @return Length of IP packet, 0 if handled internally (ARP), or negative on error
 */
int virtual_tap_ethernet_to_ip(
    VirtualTapHandle* handle,
    const uint8_t* eth_frame,
    size_t eth_len,
    uint8_t* out_buffer,
    size_t out_buffer_size
);

/**
 * Add ARP entry to table
 * 
 * @param handle VirtualTap handle
 * @param ip IP address (network byte order)
 * @param mac MAC address
 * @param is_static Whether entry is static (doesn't age out)
 * @return 0 on success, negative on error
 */
int virtual_tap_add_arp_entry(
    VirtualTapHandle* handle,
    uint32_t ip,
    const uint8_t mac[6],
    bool is_static
);

/**
 * Lookup MAC address in ARP table
 * 
 * @param handle VirtualTap handle
 * @param ip IP address (network byte order)
 * @param out_mac Output MAC address (6 bytes)
 * @return 1 if found, 0 if not found, negative on error
 */
int virtual_tap_lookup_arp(
    VirtualTapHandle* handle,
    uint32_t ip,
    uint8_t out_mac[6]
);

/**
 * Get statistics
 * 
 * @param handle VirtualTap handle
 * @param out_stats Output statistics structure
 * @return 0 on success, negative on error
 */
int virtual_tap_get_stats(
    VirtualTapHandle* handle,
    VirtualTapStats* out_stats
);

/**
 * Reset statistics
 * 
 * @param handle VirtualTap handle
 */
void virtual_tap_reset_stats(VirtualTapHandle* handle);

/**
 * Update gateway MAC address
 * 
 * @param handle VirtualTap handle
 * @param mac New gateway MAC address
 */
void virtual_tap_set_gateway_mac(
    VirtualTapHandle* handle,
    const uint8_t mac[6]
);

/**
 * Update our IP address
 * 
 * @param handle VirtualTap handle
 * @param ip New IP address (network byte order)
 */
void virtual_tap_set_our_ip(
    VirtualTapHandle* handle,
    uint32_t ip
);

/**
 * Update gateway IP address
 * 
 * @param handle VirtualTap handle
 * @param ip New gateway IP address (network byte order)
 */
void virtual_tap_set_gateway_ip(
    VirtualTapHandle* handle,
    uint32_t ip
);

#ifdef __cplusplus
}
#endif

#endif // VIRTUAL_TAP_FFI_H
