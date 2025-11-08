# VirtualTap Development Roadmap

## Current Status (v0.2.0 - November 2025)

**Implemented Features:**
- ✅ Core L2↔L3 translation (IPv4 and IPv6)
- ✅ ARP table with 64 entries, 5-minute timeout
- ✅ ARP request/reply handling
- ✅ DHCP packet parsing (IP, gateway, DNS extraction)
- ✅ IPv4 and IPv6 address learning
- ✅ Gateway MAC learning (IPv4 and IPv6)
- ✅ ICMPv6 NDP packet detection
- ✅ Comprehensive statistics tracking
- ✅ Thread-safe operation
- ✅ Zero-copy where possible
- ✅ iOS and Android compatible

---

## Priority 1: Critical for Production VPN (Next Sprint)

### 1. IPv6 Router Advertisement (RA) Parsing
**Status:** Not Started  
**Priority:** CRITICAL  
**Effort:** 3-4 hours  

**Why:** IPv6 networks use RA (ICMPv6 type 134) to advertise network configuration. Without this, IPv6 VPN connections can't auto-configure.

**Requirements:**
- Parse RA packets (similar to `dhcp_parser.c`)
- Extract:
  - IPv6 prefix and prefix length
  - Default gateway IPv6 address
  - DNS servers (RDNSS option 25)
  - MTU (option 5)
  - Valid lifetime, preferred lifetime
- Store in Translator struct
- Add statistics counter (`ra_packets`)

**Files to Create:**
- `src/icmpv6_handler.c`
- `include/icmpv6_handler.h`

**API:**
```c
typedef struct {
    uint8_t prefix[16];
    uint8_t prefix_length;
    uint8_t gateway[16];
    uint8_t dns_servers[3][16];  // Up to 3 DNS servers
    uint32_t mtu;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    bool has_prefix;
    bool has_gateway;
    uint8_t dns_count;
} IPv6RAInfo;

bool parse_router_advertisement(const uint8_t* icmpv6_packet, uint32_t len, IPv6RAInfo* out);
```

---

### 2. ICMPv6 Neighbor Advertisement (NA) Responses
**Status:** Not Started  
**Priority:** CRITICAL  
**Effort:** 2-3 hours  

**Why:** Neighbor Solicitation (NS, type 135) is IPv6's ARP. We must respond with Neighbor Advertisement (NA, type 136) or devices can't reach us.

**Requirements:**
- Detect NS packets asking for our IPv6
- Build NA response with:
  - Target address (our IPv6)
  - Target link-layer address option (our MAC)
  - S flag (solicited response)
  - O flag (override cache)
- Calculate ICMPv6 checksum
- Add to `icmpv6_handler.c`

**API:**
```c
int32_t build_neighbor_advertisement(
    const uint8_t target_ipv6[16],
    const uint8_t target_mac[6],
    const uint8_t solicitor_ipv6[16],
    uint8_t* out_packet,
    uint32_t out_max_len
);
```

---

### 3. DNS Query/Response Handling (Optional but Recommended)
**Status:** Not Started  
**Priority:** HIGH  
**Effort:** 4-5 hours  

**Why:** Apps won't work without DNS resolution. Currently we extract DNS servers but don't use them.

**Requirements:**
- Intercept DNS queries (UDP port 53)
- Forward to extracted DNS servers
- Cache responses (simple LRU cache, 256 entries)
- Return cached responses for repeated queries
- Handle A, AAAA, CNAME record types

**Files to Create:**
- `src/dns_handler.c`
- `include/dns_handler.h`

---

## Priority 2: Robustness Features (Week 2)

### 4. IP Fragmentation Handling
**Status:** Not Started  
**Priority:** MEDIUM  
**Effort:** 5-6 hours  

**Why:** Large packets (>MTU) get fragmented. Without reassembly, they're dropped.

**Requirements:**
- Track fragment IDs and offsets
- Reassemble buffer (per-fragment-id)
- Timeout fragments after 30 seconds
- Support IPv4 and IPv6 fragmentation
- Max 16 concurrent fragment chains

---

### 5. ICMP/ICMPv6 Error Message Handling
**Status:** Not Started  
**Priority:** MEDIUM  
**Effort:** 2-3 hours  

**Why:** Path MTU discovery, unreachable hosts, time exceeded errors.

**Requirements:**
- Parse ICMP types 3 (unreachable), 11 (time exceeded)
- Parse ICMPv6 types 1 (unreachable), 3 (time exceeded)
- Extract embedded packet info
- Update statistics
- Optionally log errors

---

### 6. Multicast Address Handling
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 2 hours  

**Why:** IPv6 uses multicast heavily (ff02::1 all-nodes, ff02::2 all-routers).

**Requirements:**
- Detect multicast MAC (01:00:5e for IPv4, 33:33 for IPv6)
- Detect multicast IPv6 (ff00::/8)
- Handle specially (don't learn as unicast addresses)
- Statistics counter

---

## Priority 3: Advanced Features (Future)

### 7. TCP/UDP Checksum Validation
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 3 hours  

**Requirements:**
- Validate IPv4/IPv6 TCP/UDP checksums
- Drop corrupted packets
- Statistics counter for checksum errors

---

### 8. VLAN Support (802.1Q)
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 3-4 hours  

**Requirements:**
- Detect VLAN tags (EtherType 0x8100)
- Extract VLAN ID
- Support multiple VLANs
- Strip/add tags as needed

---

### 9. DHCPv6 Support
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 4-5 hours  

**Why:** Some networks use DHCPv6 instead of SLAAC (RA).

**Requirements:**
- Parse DHCPv6 messages (UDP port 546/547)
- Extract: IPv6 address, DNS servers, domain search list
- Similar to `dhcp_parser.c`

---

### 10. IPv6 Extension Headers
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 4-5 hours  

**Requirements:**
- Parse hop-by-hop, routing, fragment, destination options
- Skip over extension headers to find payload
- Handle fragment header specially (see #4)

---

### 11. Connection Tracking
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 6-8 hours  

**Requirements:**
- Track TCP connections (SYN/FIN/RST)
- Track UDP pseudo-connections (timeout-based)
- Per-connection statistics
- Useful for NAT-like behavior

---

### 12. QoS/DSCP Support
**Status:** Not Started  
**Priority:** LOW  
**Effort:** 2 hours  

**Requirements:**
- Preserve DSCP bits from IP header
- Optionally remark DSCP based on policy
- Statistics per DSCP class

---

## Testing & Documentation

### Unit Tests Needed:
- ✅ Basic IP↔Ethernet conversion
- ✅ ARP handling
- ✅ IPv6 conversion
- ⏳ IPv6 RA parsing
- ⏳ ICMPv6 NA responses
- ⏳ DNS caching
- ⏳ Fragmentation reassembly
- ⏳ Multicast handling

### Documentation Needed:
- ⏳ IPv6 RA/NA architecture guide
- ⏳ DNS caching algorithm
- ⏳ Fragmentation state machine
- ⏳ Performance benchmarks (with DNS/RA enabled)

---

## Performance Targets

**Current (v0.2.0):**
- ~50 µs per packet (IPv4)
- ~55 µs per packet (IPv6)

**Target (v0.3.0 with RA/NA/DNS):**
- <80 µs per packet (with DNS cache hit)
- <150 µs per packet (with DNS cache miss)
- <100 µs for RA parsing
- <60 µs for NA response

---

## Release Plan

**v0.3.0 (Target: Week 1)** - IPv6 Complete
- IPv6 RA parsing
- ICMPv6 NA responses
- Updated unit tests
- Documentation

**v0.4.0 (Target: Week 2)** - Robustness
- DNS caching
- Fragmentation handling
- ICMP error messages

**v1.0.0 (Target: Month 1)** - Production Ready
- All Priority 1 & 2 features
- Comprehensive test suite
- Performance benchmarks
- Full documentation
- Mobile device testing (iOS + Android)

---

## Known Limitations

1. **No NAT support** - VirtualTap is L2↔L3 translation, not NAT
2. **No encryption** - Encryption handled by VPN protocol (SoftEther)
3. **No routing** - Single subnet only
4. **No IPv4 ICMP replies** - Pass-through only
5. **No DHCPv6** - Only SLAAC (RA-based) for IPv6
6. **No QoS enforcement** - Only marking/preservation
7. **No deep packet inspection** - Only header parsing

---

## Contributing

Priority order for community contributions:
1. IPv6 RA parsing (#1)
2. ICMPv6 NA responses (#2)
3. DNS caching (#3)
4. Unit tests for new features
5. Performance optimizations

See `CONTRIBUTING.md` for guidelines.
