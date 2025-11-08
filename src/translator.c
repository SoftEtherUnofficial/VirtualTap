#include "../include/virtual_tap_internal.h"

// ============================================================================
// Translator Implementation
// ============================================================================

Translator* translator_create(const uint8_t our_mac[6], bool handle_arp,
                              bool learn_gateway_mac, bool verbose) {
    if (!our_mac) return NULL;
    
    Translator* t = (Translator*)calloc(1, sizeof(Translator));
    if (!t) return NULL;
    
    memcpy(t->our_mac, our_mac, 6);
    t->our_ip = 0;
    t->gateway_ip = 0;
    memset(t->gateway_mac, 0, 6);
    memset(t->our_ipv6, 0, 16);
    memset(t->gateway_ipv6, 0, 16);
    t->has_ipv6 = false;
    t->has_ipv6_gateway = false;
    t->last_gateway_learn_ms = 0;
    t->handle_arp = handle_arp;
    t->learn_gateway_mac = learn_gateway_mac;
    t->verbose = verbose;
    t->packets_l2_to_l3 = 0;
    t->packets_l3_to_l2 = 0;
    t->arp_replies_learned = 0;
    
    return t;
}

void translator_destroy(Translator* t) {
    if (t) {
        free(t);
    }
}

// ============================================================================
// IP to Ethernet (L3 → L2)
// ============================================================================

int translator_ip_to_ethernet(Translator* t, const uint8_t* ip_packet, uint32_t ip_len,
                              const uint8_t* dest_mac, uint8_t* eth_out, uint32_t out_capacity) {
    if (!t || !ip_packet || !eth_out || ip_len == 0) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    if (out_capacity < ip_len + ETHERNET_HEADER_SIZE) {
        return VTAP_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Detect IP version from first byte
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    uint16_t ethertype;
    
    if (version == 4) {
        ethertype = ETHERTYPE_IPV4;
        
        // Learn our IP from source IP field (bytes 12-15)
        if (ip_len >= 20 && t->our_ip == 0) {
            t->our_ip = read_u32_be(ip_packet + 12);
            if (t->verbose) {
                printf("[Translator] Learned our IPv4 from outgoing packet\n");
            }
        }
    } else if (version == 6) {
        ethertype = ETHERTYPE_IPV6;
        
        // Learn our IPv6 from source address (bytes 8-23)
        if (ip_len >= 40 && !t->has_ipv6) {
            extract_ipv6_address(ip_packet, 8, t->our_ipv6);
            // Don't learn link-local addresses as primary
            if (!is_ipv6_link_local(t->our_ipv6)) {
                t->has_ipv6 = true;
                if (t->verbose) {
                    printf("[Translator] Learned our IPv6 from outgoing packet\n");
                }
            }
        }
    } else {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Determine destination MAC
    uint8_t dest[6];
    if (dest_mac) {
        memcpy(dest, dest_mac, 6);
    } else {
        // Check if gateway MAC is known
        bool has_gateway = false;
        for (int i = 0; i < 6; i++) {
            if (t->gateway_mac[i] != 0) {
                has_gateway = true;
                break;
            }
        }
        
        if (has_gateway) {
            memcpy(dest, t->gateway_mac, 6);
        } else {
            // Use broadcast
            memset(dest, 0xFF, 6);
        }
    }
    
    // Build Ethernet frame: [6 dest][6 src][2 type][IP payload]
    memcpy(eth_out, dest, 6);
    memcpy(eth_out + 6, t->our_mac, 6);
    write_u16_be(eth_out + 12, ethertype);
    memcpy(eth_out + ETHERNET_HEADER_SIZE, ip_packet, ip_len);
    
    t->packets_l3_to_l2++;
    
    return ip_len + ETHERNET_HEADER_SIZE;
}

// ============================================================================
// Ethernet to IP (L2 → L3)
// ============================================================================

int translator_ethernet_to_ip(Translator* t, const uint8_t* eth_frame, uint32_t eth_len,
                              uint8_t* ip_out, uint32_t out_capacity) {
    if (!t || !eth_frame || !ip_out || eth_len < ETHERNET_HEADER_SIZE) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Extract EtherType
    uint16_t ethertype = read_u16_be(eth_frame + 12);
    
    // Learn gateway MAC from source MAC if this is from gateway
    if (t->learn_gateway_mac && t->gateway_ip != 0) {
        // Check if source IP (for IPv4) matches gateway
        if (ethertype == ETHERTYPE_IPV4 && eth_len >= ETHERNET_HEADER_SIZE + 20) {
            uint32_t src_ip = read_u32_be(eth_frame + ETHERNET_HEADER_SIZE + 12);
            if (src_ip == t->gateway_ip) {
                const uint8_t* src_mac = eth_frame + 6;
                bool different = false;
                for (int i = 0; i < 6; i++) {
                    if (t->gateway_mac[i] != src_mac[i]) {
                        different = true;
                        break;
                    }
                }
                if (different) {
                    memcpy(t->gateway_mac, src_mac, 6);
                    t->last_gateway_learn_ms = get_time_ms();
                    if (t->verbose) {
                        printf("[Translator] Learned gateway MAC from incoming IPv4 packet\n");
                    }
                }
            }
        }
        
        // Check if source IPv6 matches gateway
        if (ethertype == ETHERTYPE_IPV6 && eth_len >= ETHERNET_HEADER_SIZE + 40 && t->has_ipv6_gateway) {
            uint8_t src_ipv6[16];
            extract_ipv6_address(eth_frame + ETHERNET_HEADER_SIZE, 8, src_ipv6);
            if (memcmp(src_ipv6, t->gateway_ipv6, 16) == 0) {
                const uint8_t* src_mac = eth_frame + 6;
                bool different = false;
                for (int i = 0; i < 6; i++) {
                    if (t->gateway_mac[i] != src_mac[i]) {
                        different = true;
                        break;
                    }
                }
                if (different) {
                    memcpy(t->gateway_mac, src_mac, 6);
                    t->last_gateway_learn_ms = get_time_ms();
                    if (t->verbose) {
                        printf("[Translator] Learned gateway MAC from incoming IPv6 packet\n");
                    }
                }
            }
        }
    }
    
    // Handle by EtherType
    if (ethertype == ETHERTYPE_IPV4 || ethertype == ETHERTYPE_IPV6) {
        uint32_t ip_len = eth_len - ETHERNET_HEADER_SIZE;
        
        if (out_capacity < ip_len) {
            return VTAP_ERROR_BUFFER_TOO_SMALL;
        }
        
        memcpy(ip_out, eth_frame + ETHERNET_HEADER_SIZE, ip_len);
        t->packets_l2_to_l3++;
        return ip_len;
    } else if (ethertype == ETHERTYPE_ARP) {
        // ARP handled separately
        return 0;
    } else {
        // Unknown protocol
        return 0;
    }
}

// ============================================================================
// Getters and Setters
// ============================================================================

uint32_t translator_get_our_ip(Translator* t) {
    return t ? t->our_ip : 0;
}

void translator_set_our_ip(Translator* t, uint32_t ip) {
    if (t) {
        t->our_ip = ip;
    }
}

uint32_t translator_get_gateway_ip(Translator* t) {
    return t ? t->gateway_ip : 0;
}

void translator_set_gateway_ip(Translator* t, uint32_t ip) {
    if (t) {
        t->gateway_ip = ip;
    }
}

bool translator_get_gateway_mac(Translator* t, uint8_t mac_out[6]) {
    if (!t || !mac_out) return false;
    
    bool has_mac = false;
    for (int i = 0; i < 6; i++) {
        if (t->gateway_mac[i] != 0) {
            has_mac = true;
            break;
        }
    }
    
    if (has_mac) {
        memcpy(mac_out, t->gateway_mac, 6);
    }
    
    return has_mac;
}

void translator_set_gateway_mac(Translator* t, const uint8_t mac[6]) {
    if (t && mac) {
        memcpy(t->gateway_mac, mac, 6);
        t->last_gateway_learn_ms = get_time_ms();
    }
}
