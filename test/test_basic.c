#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/virtual_tap.h"

void test_create_destroy() {
    printf("Test 1: Create and destroy... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_ip_to_ethernet() {
    printf("Test 2: IP to Ethernet conversion... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // Simple IPv4 packet (20 bytes minimum header)
    uint8_t ip_packet[20] = {
        0x45, 0x00, 0x00, 0x14,  // Version, IHL, TOS, Total Length
        0x00, 0x00, 0x00, 0x00,  // ID, Flags, Fragment Offset
        0x40, 0x11, 0x00, 0x00,  // TTL, Protocol (UDP), Checksum
        0xC0, 0xA8, 0x01, 0x64,  // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01   // Dest IP: 192.168.1.1
    };
    
    uint8_t eth_frame[2048];
    int32_t result = virtual_tap_ip_to_ethernet(tap, ip_packet, 20, eth_frame, sizeof(eth_frame));
    
    assert(result == 34);  // 20 + 14
    
    // Check Ethernet header
    assert(eth_frame[12] == 0x08 && eth_frame[13] == 0x00);  // EtherType IPv4
    assert(eth_frame[6] == 0x02 && eth_frame[11] == 0x30);   // Source MAC
    
    // Check IP packet is intact
    assert(memcmp(eth_frame + 14, ip_packet, 20) == 0);
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.ip_to_eth_packets == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_ethernet_to_ip() {
    printf("Test 3: Ethernet to IP conversion... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // Ethernet frame with IPv4 packet
    uint8_t eth_frame[34] = {
        // Ethernet header
        0x02, 0x00, 0x5E, 0x10, 0x20, 0x30,  // Dest MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src MAC
        0x08, 0x00,                          // EtherType IPv4
        // IP packet
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,  // Source IP: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x64   // Dest IP: 192.168.1.100
    };
    
    uint8_t ip_packet[2048];
    int32_t result = virtual_tap_ethernet_to_ip(tap, eth_frame, 34, ip_packet, sizeof(ip_packet));
    
    assert(result == 20);  // 34 - 14
    
    // Check IP packet
    assert(ip_packet[0] == 0x45);  // Version + IHL
    assert(memcmp(ip_packet, eth_frame + 14, 20) == 0);
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.eth_to_ip_packets == 1);
    assert(stats.ipv4_packets == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_arp_handling() {
    printf("Test 4: ARP request handling... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0xC0A80164,  // 192.168.1.100 in network byte order
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = false,
        .learn_gateway_mac = true,
        .verbose = false
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // ARP request: Who has 192.168.1.100?
    uint8_t arp_request[42] = {
        // Ethernet header
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Dest MAC (broadcast)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src MAC
        0x08, 0x06,                          // EtherType ARP
        // ARP packet
        0x00, 0x01,                          // Hardware type: Ethernet
        0x08, 0x00,                          // Protocol type: IPv4
        0x06,                                // Hardware size: 6
        0x04,                                // Protocol size: 4
        0x00, 0x01,                          // Operation: Request
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Sender MAC
        0xC0, 0xA8, 0x01, 0x01,              // Sender IP: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Target MAC (unknown)
        0xC0, 0xA8, 0x01, 0x64               // Target IP: 192.168.1.100
    };
    
    uint8_t ip_packet[2048];
    int32_t result = virtual_tap_ethernet_to_ip(tap, arp_request, 42, ip_packet, sizeof(ip_packet));
    
    // ARP should be handled internally (return 0)
    assert(result == 0);
    
    // Should have pending ARP reply
    assert(virtual_tap_has_pending_arp_reply(tap));
    
    // Pop the reply
    uint8_t arp_reply[2048];
    result = virtual_tap_pop_arp_reply(tap, arp_reply, sizeof(arp_reply));
    assert(result == 42);
    
    // Check reply
    assert(arp_reply[12] == 0x08 && arp_reply[13] == 0x06);  // EtherType ARP
    assert(arp_reply[20] == 0x00 && arp_reply[21] == 0x02);  // Operation: Reply
    
    // Check sender is us
    assert(memcmp(arp_reply + 22, config.our_mac, 6) == 0);
    assert(arp_reply[28] == 0xC0 && arp_reply[31] == 0x64);  // Our IP
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.arp_packets == 1);
    assert(stats.arp_requests_handled == 1);
    assert(stats.arp_replies_sent == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

int main() {
    printf("=== VirtualTap C Implementation Tests ===\n\n");
    
    test_create_destroy();
    test_ip_to_ethernet();
    test_ethernet_to_ip();
    test_arp_handling();
    
    printf("\n✅ All tests passed!\n");
    return 0;
}
