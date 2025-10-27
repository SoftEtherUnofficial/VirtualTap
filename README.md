# VirtualTap - Universal Layer 2 Virtualization Module

## Overview

VirtualTap is a cross-platform Layer 2 (Ethernet) virtualization module designed to bridge the gap between Layer 2 networking protocols (like SoftEther VPN) and Layer 3-only platforms (like iOS PacketTunnelProvider).

## Problem Statement

Modern VPN protocols like SoftEther operate at Layer 2 (Ethernet), using ARP for address resolution and expecting full Ethernet frame handling. However, many mobile platforms and modern networking APIs only support Layer 3 (IP):

- **iOS**: `NEPacketTunnelProvider` only handles IP packets
- **Android VpnService**: IP-only interface
- **WireGuard**: IP-only by design
- **Modern VPN APIs**: Trend towards IP-only tunnels

This creates a fundamental incompatibility when trying to run Layer 2 VPN protocols on Layer 3-only platforms.

## Solution Architecture

VirtualTap provides a **virtual Ethernet adapter** that:

1. **Presents a complete Layer 2 interface** to the VPN protocol (SoftEther)
2. **Handles ARP internally** without requiring platform support
3. **Translates to/from Layer 3** for platform communication
4. **Cross-platform design** works on any L3-only system

### Key Features

- **Internal ARP Handling**: Responds to ARP requests locally, no platform ARP needed
- **MAC Address Management**: Virtual MAC addresses for gateway, DHCP server, etc.
- **Broadcast Handling**: Simulates broadcast by learning peer addresses
- **Zero Platform Dependency**: Pure protocol translation, no OS-specific code
- **Performance Optimized**: Minimal overhead, direct packet translation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SoftEther VPN Server                    │
│                  (Expects Layer 2 Ethernet)                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ Ethernet Frames (ARP, IP, etc.)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                        VirtualTap                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               Virtual Ethernet Layer                 │   │
│  │  • ARP Table (IP ↔ MAC mapping)                      │   │
│  │  • ARP Request/Reply Handler                         │   │
│  │  • MAC Address Generator                             │   │
│  │  • Broadcast Simulator                               │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            L2 ↔ L3 Translation Engine                │   │
│  │  • Ethernet Header Add/Strip                         │   │
│  │  • EtherType Detection (0x0800, 0x0806, 0x86dd)      │   │
│  │  • Checksum Recalculation                            │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │ IP Packets only
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Platform Layer 3 Interface                     │
│  (iOS PacketTunnelProvider / Android VpnService)            │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. ARP Responder
- Maintains virtual ARP table
- Responds to ARP requests without platform support
- Learns MAC addresses from incoming packets
- Generates virtual MAC addresses for peers

### 2. Ethernet Frame Handler
- Adds/removes Ethernet headers (14 bytes)
- Sets source/destination MAC addresses
- Handles EtherType field (IPv4, IPv6, ARP)

### 3. Address Manager
- Generates unique virtual MAC addresses
- Maintains IP ↔ MAC mappings
- Handles special addresses (gateway, DHCP server, broadcast)

### 4. Packet Translator
- Bidirectional L2 ↔ L3 conversion
- Zero-copy where possible
- Minimal allocation overhead

## Usage Example

```zig
const VirtualTap = @import("virtual_tap");

// Initialize VirtualTap
var vtap = try VirtualTap.init(allocator, .{
    .our_mac = randomMacAddress(),
    .handle_arp_internally = true,
    .verbose = true,
});
defer vtap.deinit();

// Incoming: IP packet from platform → Ethernet frame for SoftEther
const ip_packet = getPacketFromPlatform();
const eth_frame = try vtap.ipToEthernet(ip_packet);
sendToSoftEther(eth_frame);

// Outgoing: Ethernet frame from SoftEther → IP packet for platform
const eth_frame = getPacketFromSoftEther();
if (try vtap.ethernetToIp(eth_frame)) |ip_packet| {
    sendToPlatform(ip_packet);
} else {
    // ARP or other L2 packet handled internally
}
```

## Differences from TapTun

While TapTun provided L2↔L3 translation, VirtualTap is a clean separation:

| Aspect | TapTun | VirtualTap |
|--------|--------|------------|
| **Scope** | Platform-specific TUN/TAP + Translation | Pure protocol translation |
| **Platform Code** | Mixed with translation logic | Zero platform dependencies |
| **ARP Handling** | Partial, relied on platform | Complete internal handling |
| **Reusability** | Tied to Unix TUN/TAP | Universal, any L3 platform |
| **Architecture** | Monolithic | Modular, composable |

## Design Principles

1. **Zero Platform Coupling**: Works on any system that can send/receive IP packets
2. **Protocol Correctness**: Full RFC compliance for ARP, Ethernet
3. **Performance**: Minimal overhead, cache-friendly data structures
4. **Debuggability**: Comprehensive logging and statistics
5. **Composability**: Can be used standalone or with other modules

## Benefits

- **iOS Support**: Native L3-only platform support
- **Android Support**: Clean VpnService integration
- **Future-Proof**: Works with any IP-only VPN API
- **Cross-Platform**: Same code on all platforms
- **Maintainable**: Clean separation of concerns
- **Testable**: Pure functions, no platform dependencies

## Implementation Notes

- Written in Zig for safety and performance
- Zero unsafe operations
- Comprehensive error handling
- Memory-safe by design
- No dynamic allocation in fast path (optional)

## Roadmap

- [x] Core architecture design
- [ ] ARP table implementation
- [ ] ARP request/reply handlers
- [ ] Ethernet frame builder/parser
- [ ] IP packet validator
- [ ] MAC address generator
- [ ] Statistics and monitoring
- [ ] Integration with iOS adapter
- [ ] Unit tests
- [ ] Performance benchmarks
- [ ] Documentation

## License

Part of SoftEther VPN client project
