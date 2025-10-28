#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "virtual_tap.h"

int main() {
    printf("=== VirtualTap C FFI Test ===\n\n");

    // Create configuration
    VirtualTapConfig config = {
        .our_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        .our_ip = 0xC0A80164,  // 192.168.1.100
        .gateway_ip = 0xC0A80101,  // 192.168.1.1
        .gateway_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false
    };

    // Create VirtualTap instance
    printf("1. Creating VirtualTap instance...\n");
    VirtualTap *vtap = virtual_tap_create(&config);
    if (!vtap) {
        printf("   ERROR: Failed to create VirtualTap\n");
        return 1;
    }
    printf("   SUCCESS: VirtualTap created\n\n");

    // Test IP to Ethernet conversion
    printf("2. Testing IP to Ethernet conversion...\n");
    uint8_t ip_packet[] = {
        0x45, 0x00, 0x00, 0x54,  // Version, IHL, TOS, Length
        0x00, 0x00, 0x40, 0x00,  // ID, Flags
        0x40, 0x01, 0x00, 0x00,  // TTL, Protocol (ICMP), Checksum
        0xC0, 0xA8, 0x01, 0x64,  // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01,  // Dest IP: 192.168.1.1
    };
    
    uint8_t eth_frame[2048];
    int32_t eth_len = virtual_tap_ip_to_ethernet(
        vtap,
        ip_packet,
        sizeof(ip_packet),
        eth_frame,
        sizeof(eth_frame)
    );
    
    if (eth_len < 0) {
        printf("   ERROR: IP to Ethernet conversion failed (code: %d)\n", eth_len);
        virtual_tap_destroy(vtap);
        return 1;
    }
    
    printf("   SUCCESS: Converted %zu byte IP packet → %d byte Ethernet frame\n", 
           sizeof(ip_packet), eth_len);
    printf("   Ethernet header: ");
    for (int i = 0; i < 14 && i < eth_len; i++) {
        printf("%02X ", eth_frame[i]);
    }
    printf("\n\n");

    // Test Ethernet to IP conversion
    printf("3. Testing Ethernet to IP conversion...\n");
    uint8_t ip_out[2048];
    int32_t ip_len = virtual_tap_ethernet_to_ip(
        vtap,
        eth_frame,
        eth_len,
        ip_out,
        sizeof(ip_out)
    );
    
    if (ip_len < 0) {
        printf("   ERROR: Ethernet to IP conversion failed (code: %d)\n", ip_len);
        virtual_tap_destroy(vtap);
        return 1;
    }
    
    printf("   SUCCESS: Converted %d byte Ethernet frame → %d byte IP packet\n", 
           eth_len, ip_len);
    printf("   IP header: ");
    for (int i = 0; i < 20 && i < ip_len; i++) {
        printf("%02X ", ip_out[i]);
    }
    printf("\n\n");

    // Get statistics
    printf("4. Checking statistics...\n");
    VirtualTapStats stats;
    virtual_tap_get_stats(vtap, &stats);
    
    printf("   IP → Ethernet packets: %llu\n", stats.ip_to_eth_packets);
    printf("   Ethernet → IP packets: %llu\n", stats.eth_to_ip_packets);
    printf("   ARP requests handled: %llu\n", stats.arp_requests_handled);
    printf("   ARP replies sent: %llu\n\n", stats.arp_replies_sent);

    // Test learned IP retrieval
    printf("5. Testing learned IP retrieval...\n");
    uint32_t learned_ip = virtual_tap_get_learned_ip(vtap);
    if (learned_ip != 0) {
        printf("   Learned IP: %u.%u.%u.%u\n", 
               (learned_ip >> 24) & 0xFF,
               (learned_ip >> 16) & 0xFF,
               (learned_ip >> 8) & 0xFF,
               learned_ip & 0xFF);
    } else {
        printf("   No IP learned yet\n");
    }
    printf("\n");

    // Test gateway MAC retrieval
    printf("6. Testing gateway MAC retrieval...\n");
    uint8_t gw_mac[6];
    if (virtual_tap_get_gateway_mac(vtap, gw_mac)) {
        printf("   Gateway MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               gw_mac[0], gw_mac[1], gw_mac[2],
               gw_mac[3], gw_mac[4], gw_mac[5]);
    } else {
        printf("   No gateway MAC available\n");
    }
    printf("\n");

    // Cleanup
    printf("7. Cleaning up...\n");
    virtual_tap_destroy(vtap);
    printf("   SUCCESS: VirtualTap destroyed\n\n");

    printf("=== All tests passed! ===\n");
    return 0;
}
