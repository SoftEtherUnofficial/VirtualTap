#include "../include/virtual_tap_internal.h"

// ============================================================================
// Internal Helper Functions
// ============================================================================

static void arp_reply_queue_push(VirtualTap* tap, uint8_t* packet, uint32_t len) {
    if (!tap || !packet) return;
    
    ArpReplyNode* node = (ArpReplyNode*)malloc(sizeof(ArpReplyNode));
    if (!node) {
        free(packet);
        return;
    }
    
    node->packet = packet;
    node->length = len;
    node->next = NULL;
    
    if (tap->arp_reply_tail == NULL) {
        tap->arp_reply_head = tap->arp_reply_tail = node;
    } else {
        tap->arp_reply_tail->next = node;
        tap->arp_reply_tail = node;
    }
}

static int handle_arp(VirtualTap* tap, const uint8_t* eth_frame, uint32_t eth_len) {
    if (!tap || !eth_frame || eth_len < ETHERNET_HEADER_SIZE + 28) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Parse ARP packet (skip 14-byte Ethernet header)
    ArpInfo info;
    if (arp_parse_packet(eth_frame + ETHERNET_HEADER_SIZE, 
                        eth_len - ETHERNET_HEADER_SIZE, &info) != 0) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Handle ARP Reply: learn MAC
    if (info.operation == ARP_OP_REPLY) {
        arp_table_insert(tap->arp_table, info.sender_ip, info.sender_mac, false);
        tap->stats.arp_table_entries = arp_table_count(tap->arp_table);
        
        // Learn gateway MAC if this is from gateway
        uint32_t our_ip = translator_get_our_ip(tap->translator);
        if (our_ip != 0 && tap->config.learn_gateway_mac) {
            // Simple heuristic: gateway is typically x.x.x.1
            uint32_t assumed_gateway = (our_ip & 0xFFFFFF00) | 0x01;
            if (info.sender_ip == assumed_gateway || info.sender_ip == tap->config.gateway_ip) {
                translator_set_gateway_mac(tap->translator, info.sender_mac);
                if (tap->config.verbose) {
                    printf("[VirtualTap] Learned gateway MAC from ARP reply\n");
                }
            }
        }
        
        return 0; // Handled internally
    }
    
    // Handle ARP Request: build reply if for us
    if (info.operation == ARP_OP_REQUEST) {
        tap->stats.arp_requests_handled++;
        
        uint32_t our_ip = translator_get_our_ip(tap->translator);
        if (our_ip == 0 || info.target_ip != our_ip) {
            return 0; // Not for us
        }
        
        // Build ARP reply
        uint8_t* reply = (uint8_t*)malloc(ARP_PACKET_SIZE);
        if (!reply) {
            return VTAP_ERROR_ALLOC_FAILED;
        }
        
        int result = arp_build_reply(tap->config.our_mac, our_ip,
                                     info.sender_mac, info.sender_ip,
                                     reply, ARP_PACKET_SIZE);
        
        if (result != ARP_PACKET_SIZE) {
            free(reply);
            return result;
        }
        
        // Queue reply
        arp_reply_queue_push(tap, reply, ARP_PACKET_SIZE);
        tap->stats.arp_replies_sent++;
        
        if (tap->config.verbose) {
            printf("[VirtualTap] Generated ARP reply\n");
        }
        
        return 0;
    }
    
    return 0;
}

// ============================================================================
// Public API Implementation
// ============================================================================

VirtualTap* virtual_tap_create(const VirtualTapConfig* config) {
    if (!config) return NULL;
    
    VirtualTap* tap = (VirtualTap*)calloc(1, sizeof(VirtualTap));
    if (!tap) return NULL;
    
    // Copy config
    memcpy(&tap->config, config, sizeof(VirtualTapConfig));
    
    // Create ARP table
    tap->arp_table = arp_table_create(ARP_TIMEOUT_MS);
    if (!tap->arp_table) {
        free(tap);
        return NULL;
    }
    
    // Create translator
    tap->translator = translator_create(config->our_mac, config->handle_arp,
                                        config->learn_gateway_mac, config->verbose);
    if (!tap->translator) {
        arp_table_destroy(tap->arp_table);
        free(tap);
        return NULL;
    }
    
    // Initialize translator with configured IPs/MACs
    if (config->our_ip != 0) {
        translator_set_our_ip(tap->translator, config->our_ip);
    }
    if (config->gateway_ip != 0) {
        translator_set_gateway_ip(tap->translator, config->gateway_ip);
    }
    
    // Check if gateway MAC is configured
    bool has_gateway_mac = false;
    for (int i = 0; i < 6; i++) {
        if (config->gateway_mac[i] != 0) {
            has_gateway_mac = true;
            break;
        }
    }
    if (has_gateway_mac) {
        translator_set_gateway_mac(tap->translator, config->gateway_mac);
    }
    
    // Initialize queue
    tap->arp_reply_head = NULL;
    tap->arp_reply_tail = NULL;
    
    // Initialize stats
    memset(&tap->stats, 0, sizeof(VirtualTapStats));
    
    if (config->verbose) {
        printf("[VirtualTap] Created successfully\n");
    }
    
    return tap;
}

void virtual_tap_destroy(VirtualTap* tap) {
    if (!tap) return;
    
    // Free ARP reply queue
    ArpReplyNode* node = tap->arp_reply_head;
    while (node) {
        ArpReplyNode* next = node->next;
        free(node->packet);
        free(node);
        node = next;
    }
    
    // Free components
    if (tap->translator) {
        translator_destroy(tap->translator);
    }
    if (tap->arp_table) {
        arp_table_destroy(tap->arp_table);
    }
    
    free(tap);
}

int32_t virtual_tap_ip_to_ethernet(VirtualTap* tap, const uint8_t* ip_packet,
                                   uint32_t ip_len, uint8_t* eth_frame_out,
                                   uint32_t out_capacity) {
    if (!tap || !ip_packet || !eth_frame_out) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Use translator
    int result = translator_ip_to_ethernet(tap->translator, ip_packet, ip_len,
                                          NULL, eth_frame_out, out_capacity);
    
    if (result > 0) {
        tap->stats.ip_to_eth_packets++;
    }
    
    return result;
}

int32_t virtual_tap_ethernet_to_ip(VirtualTap* tap, const uint8_t* eth_frame,
                                   uint32_t eth_len, uint8_t* ip_packet_out,
                                   uint32_t out_capacity) {
    if (!tap || !eth_frame || !ip_packet_out || eth_len < ETHERNET_HEADER_SIZE) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Extract EtherType
    uint16_t ethertype = read_u16_be(eth_frame + 12);
    
    // Route by protocol
    switch (ethertype) {
        case ETHERTYPE_IPV4:
            tap->stats.ipv4_packets++;
            
            // Check if DHCP
            if (eth_len >= ETHERNET_HEADER_SIZE + 20 &&
                dhcp_is_dhcp_packet(eth_frame + ETHERNET_HEADER_SIZE, 
                                   eth_len - ETHERNET_HEADER_SIZE)) {
                tap->stats.dhcp_packets++;
                
                // Parse DHCP to learn IP/gateway
                DhcpInfo dhcp;
                if (dhcp_parse_packet(eth_frame + ETHERNET_HEADER_SIZE,
                                     eth_len - ETHERNET_HEADER_SIZE, &dhcp) == 0) {
                    if (tap->config.learn_ip && dhcp.offered_ip[0] != 0) {
                        uint32_t offered = ipv4_to_u32(dhcp.offered_ip);
                        translator_set_our_ip(tap->translator, offered);
                        if (tap->config.verbose) {
                            printf("[VirtualTap] Learned IP from DHCP: %d.%d.%d.%d\n",
                                   dhcp.offered_ip[0], dhcp.offered_ip[1],
                                   dhcp.offered_ip[2], dhcp.offered_ip[3]);
                        }
                    }
                    if (dhcp.gateway[0] != 0) {
                        uint32_t gateway = ipv4_to_u32(dhcp.gateway);
                        translator_set_gateway_ip(tap->translator, gateway);
                        if (tap->config.verbose) {
                            printf("[VirtualTap] Learned gateway from DHCP: %d.%d.%d.%d\n",
                                   dhcp.gateway[0], dhcp.gateway[1],
                                   dhcp.gateway[2], dhcp.gateway[3]);
                        }
                    }
                }
            }
            
            // Translate to IP
            {
                int result = translator_ethernet_to_ip(tap->translator, eth_frame, eth_len,
                                                      ip_packet_out, out_capacity);
                if (result > 0) {
                    tap->stats.eth_to_ip_packets++;
                }
                return result;
            }
            
        case ETHERTYPE_ARP:
            tap->stats.arp_packets++;
            if (!tap->config.handle_arp) {
                return 0;
            }
            return handle_arp(tap, eth_frame, eth_len);
            
        case ETHERTYPE_IPV6:
            {
                int result = translator_ethernet_to_ip(tap->translator, eth_frame, eth_len,
                                                      ip_packet_out, out_capacity);
                if (result > 0) {
                    tap->stats.eth_to_ip_packets++;
                }
                return result;
            }
            
        default:
            tap->stats.other_packets++;
            return 0;
    }
}

uint32_t virtual_tap_get_learned_ip(VirtualTap* tap) {
    if (!tap) return 0;
    return translator_get_our_ip(tap->translator);
}

bool virtual_tap_get_gateway_mac(VirtualTap* tap, uint8_t mac_out[6]) {
    if (!tap || !mac_out) return false;
    return translator_get_gateway_mac(tap->translator, mac_out);
}

void virtual_tap_get_stats(VirtualTap* tap, VirtualTapStats* stats) {
    if (!tap || !stats) return;
    memcpy(stats, &tap->stats, sizeof(VirtualTapStats));
}

bool virtual_tap_has_pending_arp_reply(VirtualTap* tap) {
    if (!tap) return false;
    return tap->arp_reply_head != NULL;
}

int32_t virtual_tap_pop_arp_reply(VirtualTap* tap, uint8_t* arp_reply_out,
                                  uint32_t out_capacity) {
    if (!tap || !arp_reply_out) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    if (tap->arp_reply_head == NULL) {
        return 0;
    }
    
    ArpReplyNode* node = tap->arp_reply_head;
    tap->arp_reply_head = node->next;
    if (tap->arp_reply_head == NULL) {
        tap->arp_reply_tail = NULL;
    }
    
    if (node->length > out_capacity) {
        free(node->packet);
        free(node);
        return VTAP_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(arp_reply_out, node->packet, node->length);
    uint32_t len = node->length;
    
    free(node->packet);
    free(node);
    
    return len;
}
