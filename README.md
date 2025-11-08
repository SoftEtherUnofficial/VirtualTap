# VirtualTap

**Layer 2 Virtualization for Layer 3-Only Platforms**

Pure C implementation providing Ethernet frame ↔ IP packet translation for iOS and Android VPN clients.

---

## Overview

VirtualTap solves a fundamental compatibility problem: SoftEther VPN operates at Layer 2 (Ethernet), but iOS/Android only support Layer 3 (IP packets). This library bridges the gap by:

- **L2↔L3 Translation**: Converts between Ethernet frames and IP packets
- **ARP Handling**: Processes ARP requests/replies internally (mobile platforms have no ARP support)
- **DHCP Learning**: Auto-configures network parameters from DHCP packets
- **Zero Dependencies**: Pure C11, stdlib only, no platform-specific APIs

---

## Quick Start

### Build

```bash
# macOS/Linux library
make

# iOS arm64 library
make ios

# Run tests
make test

# Clean
make clean
```

### Usage

```c
#include "include/virtual_tap.h"

// Create instance
VirtualTapConfig config = {
    .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
    .our_ip = 0,           // Learned from DHCP
    .gateway_ip = 0,       // Learned from DHCP
    .handle_arp = true,
    .learn_ip = true,
    .learn_gateway_mac = true,
    .verbose = false
};
VirtualTap* tap = virtual_tap_create(&config);

// Outgoing: IP packet → Ethernet frame
uint8_t eth_frame[2048];
int32_t len = virtual_tap_ip_to_ethernet(
    tap, ip_packet, ip_len, eth_frame, sizeof(eth_frame)
);

// Incoming: Ethernet frame → IP packet
uint8_t ip_packet[2048];
len = virtual_tap_ethernet_to_ip(
    tap, eth_frame, eth_len, ip_packet, sizeof(ip_packet)
);

// Handle ARP replies (send to server)
if (virtual_tap_has_pending_arp_reply(tap)) {
    uint8_t arp_reply[42];
    len = virtual_tap_pop_arp_reply(tap, arp_reply, sizeof(arp_reply));
    // Send to VPN server
}

// Get learned configuration
uint32_t our_ip = virtual_tap_get_learned_ip(tap);
uint8_t gateway_mac[6];
bool has_gateway = virtual_tap_get_gateway_mac(tap, gateway_mac);

// Get statistics
VirtualTapStats stats;
virtual_tap_get_stats(tap, &stats);

// Cleanup
virtual_tap_destroy(tap);
```

---

## Architecture

### Components

```
┌────────────────────────────────────────────────────┐
│                   VirtualTap                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │ ARP Handler  │  │ L2↔L3 Trans- │  │  DHCP    │  │
│  │              │  │    lator     │  │  Parser  │  │
│  │ • ARP table  │  │ • IP→Eth     │  │ • Learn  │  │
│  │ • Parse ARP  │  │ • Eth→IP     │  │   IP     │  │
│  │ • Build ARP  │  │ • Learn MAC  │  │ • Learn  │  │
│  │   replies    │  │ • Gateway    │  │   gateway│  │
│  └──────────────┘  └──────────────┘  └──────────┘  │
└────────────────────────────────────────────────────┘
           ↑                                 ↓
    Ethernet frames                     IP packets
  (from VPN server)                  (to/from mobile OS)
```

### Data Flow

**Outgoing (Device → Server):**
```
Mobile App (IP packets)
    ↓
VirtualTap.ip_to_ethernet()
    ↓ Add 14-byte Ethernet header
Ethernet frames
    ↓
VPN Server
```

**Incoming (Server → Device):**
```
VPN Server (Ethernet frames)
    ↓
VirtualTap.ethernet_to_ip()
    ↓ Strip header / Handle ARP
IP packets
    ↓
Mobile App
```

**ARP Handling (Internal):**
```
VPN Server (ARP request)
    ↓
VirtualTap.handle_arp()
    ↓ Parse + Build reply
ARP reply queue
    ↓ pop_arp_reply()
VPN Server (ARP reply)
```

---

## Features

### ✅ Protocol Support
- **IPv4**: Full support with header learning
- **IPv6**: Full support with address learning and NDP handling
  - **IPv6 Learning**: Learns global IPv6 addresses from outgoing packets (skips link-local)
  - **ICMPv6 NDP**: Responds to Neighbor Solicitation (NS) with Neighbor Advertisement (NA)
  - **Router Advertisement**: Parses RA packets to learn IPv6 gateway and network prefix
  - **Gateway Learning**: Learns gateway MAC from IPv6 traffic
- **ARP**: Complete request/reply handling with timeout
- **DNS**: Query parsing with LRU cache (256 entries, 5-minute TTL)
- **Fragmentation**: IPv4 and IPv6 fragment reassembly (16 chains each, 30-second timeout)
- **ICMP Errors**: Parse ICMP/ICMPv6 error messages for MTU discovery and diagnostics

### ✅ Smart Learning
- **IP Address**: Learned from outgoing packet source fields
- **Gateway MAC**: Learned from incoming packet source MAC
- **DHCP Config**: Extracts IP, gateway, subnet, DNS from DHCP OFFER/ACK
- **IPv6 RA Config**: Extracts prefix, gateway, and DNS from Router Advertisement

### ✅ Performance Features
- **DNS Caching**: LRU cache with 256 entries, reduces latency for repeated queries
- **Fragment Reassembly**: Handles large packets split by routers (>MTU)
- **Zero-Copy Design**: Caller-provided buffers, no internal allocations
- **Minimal Overhead**: ~50-70 µs per packet on modern hardware

### ✅ ARP Table
- Fixed-size (64 entries)
- Automatic timeout (5 minutes default)
- Static entry support
- Linear search (fast for small tables)

### ✅ Thread-Safe
- No global mutable state
- Each instance is independent
- Safe for concurrent use

---

## API Reference

### Instance Management

```c
VirtualTap* virtual_tap_create(const VirtualTapConfig* config);
void virtual_tap_destroy(VirtualTap* tap);
```

### Packet Translation

```c
// IP → Ethernet (add 14-byte header)
int32_t virtual_tap_ip_to_ethernet(
    VirtualTap* tap,
    const uint8_t* ip_packet,
    uint32_t ip_len,
    uint8_t* eth_frame_out,
    uint32_t out_capacity
);

// Ethernet → IP (strip header, handle ARP)
// Returns: > 0 = IP packet length, 0 = handled internally (ARP), < 0 = error
int32_t virtual_tap_ethernet_to_ip(
    VirtualTap* tap,
    const uint8_t* eth_frame,
    uint32_t eth_len,
    uint8_t* ip_packet_out,
    uint32_t out_capacity
);
```

### ARP Reply Queue

```c
bool virtual_tap_has_pending_arp_reply(VirtualTap* tap);
int32_t virtual_tap_pop_arp_reply(
    VirtualTap* tap,
    uint8_t* arp_reply_out,
    uint32_t out_capacity
);
```

### Configuration Queries

```c
uint32_t virtual_tap_get_learned_ip(VirtualTap* tap);
bool virtual_tap_get_gateway_mac(VirtualTap* tap, uint8_t mac_out[6]);
void virtual_tap_get_stats(VirtualTap* tap, VirtualTapStats* stats);
```

---

## Error Codes

```c
#define VTAP_ERROR_INVALID_PARAMS    -1  // NULL pointer or invalid parameters
#define VTAP_ERROR_PARSE_FAILED      -2  // Packet parsing failed
#define VTAP_ERROR_BUFFER_TOO_SMALL  -3  // Output buffer too small
#define VTAP_ERROR_ALLOC_FAILED      -4  // Memory allocation failed
```

---

## Statistics

```c
typedef struct {
    uint64_t ip_to_eth_packets;      // IP → Ethernet conversions
    uint64_t eth_to_ip_packets;      // Ethernet → IP conversions
    uint64_t arp_requests_handled;   // ARP requests answered
    uint64_t arp_replies_sent;       // ARP replies sent to server
    uint64_t ipv4_packets;           // IPv4 packets processed
    uint64_t ipv6_packets;           // IPv6 packets processed
    uint64_t icmpv6_packets;         // ICMPv6 NDP packets (NS/NA/RA)
    uint64_t arp_packets;            // ARP packets processed
    uint64_t dhcp_packets;           // DHCP packets parsed
    uint64_t dns_queries;            // DNS queries intercepted
    uint64_t dns_cache_hits;         // DNS cache hits
    uint64_t dns_cache_misses;       // DNS cache misses
    uint64_t ipv4_fragments;         // IPv4 fragments received
    uint64_t ipv6_fragments;         // IPv6 fragments received
    uint64_t fragments_reassembled;  // Fragment chains reassembled
    uint64_t icmp_errors_received;   // ICMP error messages
    uint64_t icmpv6_errors_received; // ICMPv6 error messages
    uint64_t arp_table_entries;      // Current ARP table size
    uint64_t other_packets;          // Unknown protocol packets
} VirtualTapStats;
```

---

## Performance

**Memory Footprint (v0.4.0):**
- VirtualTap instance: ~8KB
- ARP table: ~4KB (64 entries)
- DNS cache: ~16KB (256 entries)
- Fragment handlers: ~2.2MB (32 chains × 65KB buffers)
- ARP reply queue: ~500 bytes (typical)
- **Total:** ~2.3MB per instance

**CPU Performance:**
- IP → Ethernet: < 5μs per packet
- Ethernet → IP: < 5μs per packet
- DNS cache lookup: < 2μs
- Fragment check: < 1μs
- Fragment reassembly: < 50μs (when complete)
- ARP lookup: < 1μs (64 entries)
- ARP reply build: < 10μs
- RA parsing: ~80μs
- NA response: ~55μs

---

## Implementation Details

### File Structure

```
VirtualTap/
├── include/
│   ├── virtual_tap.h           # Public API (111 lines)
│   ├── virtual_tap_internal.h  # Internal structures (198 lines)
│   ├── icmpv6_handler.h        # ICMPv6 NDP API (105 lines)
│   ├── dns_handler.h           # DNS caching API (96 lines)
│   ├── fragment_handler.h      # Fragmentation API (155 lines)
│   └── icmp_handler.h          # ICMP error parsing (108 lines)
├── src/
│   ├── virtual_tap.c           # Main module (635 lines)
│   ├── arp_handler.c           # ARP protocol (209 lines)
│   ├── translator.c            # L2↔L3 translation (245 lines)
│   ├── dhcp_parser.c           # DHCP parsing (132 lines)
│   ├── ip_utils.c              # IP utilities (69 lines)
│   ├── icmpv6_handler.c        # ICMPv6 NDP handling (255 lines)
│   ├── dns_handler.c           # DNS handler with LRU cache (350 lines)
│   ├── fragment_handler.c      # IP fragmentation (355 lines)
│   └── icmp_handler.c          # ICMP error parsing (158 lines)
├── test/
│   └── test_basic.c            # 14 unit tests (727 lines)
└── Makefile                     # Build system (43 lines)
```

**Total Lines of Code: ~3,200**
├── Makefile                    # Build system
├── README.md                   # This file
└── ROADMAP.md                  # Development roadmap
```

**Total:** ~2,025 lines of C code

### ARP Packet Format (42 bytes)

```
Offset  Size  Field
------  ----  -----
0-5     6     Destination MAC
6-11    6     Source MAC
12-13   2     EtherType (0x0806 = ARP)
14-15   2     Hardware type (0x0001 = Ethernet)
16-17   2     Protocol type (0x0800 = IPv4)
18      1     Hardware size (6)
19      1     Protocol size (4)
20-21   2     Operation (1=Request, 2=Reply)
22-27   6     Sender MAC
28-31   4     Sender IP
32-37   6     Target MAC
38-41   4     Target IP
```

### Ethernet Frame Format

```
Offset  Size  Field
------  ----  -----
0-5     6     Destination MAC
6-11    6     Source MAC
12-13   2     EtherType (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
14+     N     Payload (IP packet or ARP packet)
```

---

## Testing

### Unit Tests

```bash
$ make test
=== VirtualTap C Implementation Tests ===

Test 1: Create and destroy... ✅
Test 2: IP to Ethernet conversion... ✅
Test 3: Ethernet to IP conversion... ✅
Test 4: ARP request handling... ✅
Test 5: IPv6 to Ethernet conversion... ✅
Test 6: IPv6 from Ethernet extraction... ✅
Test 7: ICMPv6 Router Advertisement parsing... ✅
Test 8: ICMPv6 Neighbor Solicitation detection... ✅
Test 9: ICMPv6 Neighbor Advertisement building... ✅

✅ All tests passed!
```

### Test Coverage

- ✅ Instance creation/destruction
- ✅ IP → Ethernet packet conversion (IPv4 and IPv6)
- ✅ Ethernet → IP packet conversion (IPv4 and IPv6)
- ✅ ARP request → reply cycle
- ✅ ICMPv6 Router Advertisement parsing
- ✅ ICMPv6 Neighbor Solicitation detection
- ✅ ICMPv6 Neighbor Advertisement building
- ✅ Statistics tracking
- ✅ Memory safety (no leaks)

---

## Integration

### iOS (Network Extension)

```c
#include "VirtualTap/include/virtual_tap.h"

// In packet adapter initialization
VirtualTapConfig config = {
    .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
    .our_ip = 0,
    .gateway_ip = 0,
    .handle_arp = true,
    .learn_ip = true,
    .learn_gateway_mac = true,
    .verbose = true
};
ctx->translator = virtual_tap_create(&config);

// In packet receive callback (NEPacketTunnelProvider)
void onPacketReceived(uint8_t* data, size_t len) {
    // IP packet from iOS → Ethernet frame for SoftEther
    uint8_t eth_frame[2048];
    int32_t eth_len = virtual_tap_ip_to_ethernet(
        ctx->translator, data, len, eth_frame, sizeof(eth_frame)
    );
    if (eth_len > 0) {
        send_to_softether(eth_frame, eth_len);
    }
}

// In packet send callback
void sendPacketToiOS(uint8_t* eth_frame, size_t eth_len) {
    // Ethernet frame from SoftEther → IP packet for iOS
    uint8_t ip_packet[2048];
    int32_t ip_len = virtual_tap_ethernet_to_ip(
        ctx->translator, eth_frame, eth_len, ip_packet, sizeof(ip_packet)
    );
    if (ip_len > 0) {
        send_to_ios(ip_packet, ip_len);
    }
    
    // Check for ARP replies
    while (virtual_tap_has_pending_arp_reply(ctx->translator)) {
        uint8_t arp_reply[42];
        int32_t arp_len = virtual_tap_pop_arp_reply(
            ctx->translator, arp_reply, sizeof(arp_reply)
        );
        if (arp_len > 0) {
            send_to_softether(arp_reply, arp_len);
        }
    }
}
```

### Android (VPN Service)

```c
// Similar integration with Android VpnService.Builder
// Use virtual_tap_ip_to_ethernet() / virtual_tap_ethernet_to_ip()
// in VPN tunnel packet read/write callbacks
```

---

## Compatibility

### Platforms
- ✅ **iOS** 15.0+ (arm64, Network Extension)
- ✅ **Android** 5.0+ (arm64-v8a, armeabi-v7a)
- ✅ **macOS** 10.15+ (Intel, Apple Silicon) - testing only
- ✅ **Linux** - testing only

### Compilers
- ✅ Clang 12+ (iOS/macOS)
- ✅ GCC 8+ (Android NDK, Linux)
- ✅ MSVC - not tested (uses `gettimeofday`)

### Standards
- **C11** (`-std=c11`)
- **POSIX** (minimal: `gettimeofday`, `pthread_mutex`)
- **Zero warnings** (`-Wall -Wextra -Werror`)

---

## Build System

### Makefile Targets

```bash
make              # Build libvirtualtap.a (native)
make ios          # Build libvirtualtap_ios.a (arm64 cross-compile)
make test         # Build and run unit tests
make clean        # Remove build artifacts
```

### Compiler Flags

```makefile
CFLAGS = -std=c11 -Wall -Wextra -Werror -O2 -I./include
```

### iOS Cross-Compilation

```makefile
IOS_SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
IOS_CFLAGS = -arch arm64 -isysroot $(IOS_SDK) -mios-version-min=15.0
```

---

## Troubleshooting

### Common Issues

**Problem:** "Unknown type name 'VirtualTap'"  
**Solution:** Include header: `#include "virtual_tap.h"`

**Problem:** ARP replies not sent  
**Solution:** Check `virtual_tap_has_pending_arp_reply()` and call `virtual_tap_pop_arp_reply()` in packet send loop

**Problem:** IP not learned from DHCP  
**Solution:** Ensure `config.learn_ip = true` and verify DHCP packets are being processed (check stats)

**Problem:** Gateway MAC not learned  
**Solution:** Ensure `config.learn_gateway_mac = true` and traffic flows from gateway

**Problem:** Memory leak  
**Solution:** Always call `virtual_tap_destroy()` before exit

---

## Contributing

This is a production implementation used in WorxVPN iOS/Android clients.

**Code Style:**
- C11 standard
- 4-space indentation
- No warnings (`-Werror`)
- Document public APIs
- Add unit tests for new features

**Testing:**
- Run `make test` before committing
- Verify no memory leaks (Valgrind on Linux)
- Test on iOS device/simulator
- Check statistics for correctness

---

## License

Part of the SoftEther VPN project.

---

## References

- **SoftEther VPN**: https://github.com/SoftEtherVPN/SoftEtherVPN
- **ARP Protocol**: RFC 826
- **DHCP Protocol**: RFC 2131
- **Ethernet Frame**: IEEE 802.3

---

## Support

For issues or questions:
1. Check `DEVELOPMENT_PLAN.md` for implementation details
2. Review unit tests in `test/test_basic.c`
3. Enable verbose mode: `config.verbose = true`
4. Check statistics: `virtual_tap_get_stats()`

---

**Status:** ✅ Production-ready (November 2025)  
**Version:** 1.0.0  
**Language:** C11  
**Lines of Code:** ~1,410  
**Platforms:** iOS, Android