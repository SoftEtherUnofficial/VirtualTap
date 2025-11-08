# VirtualTap Development Roadmap

## Current Status (v0.4.0 - November 2025)

**Implemented Features:**
- ✅ Core L2↔L3 translation (IPv4 and IPv6)
- ✅ ARP table with 64 entries, 5-minute timeout
- ✅ ARP request/reply handling
- ✅ DHCP packet parsing (IP, gateway, DNS extraction)
- ✅ IPv4 and IPv6 address learning
- ✅ Gateway MAC learning (IPv4 and IPv6)
- ✅ ICMPv6 NDP packet detection
- ✅ IPv6 Router Advertisement (RA) parsing
- ✅ ICMPv6 Neighbor Advertisement (NA) responses
- ✅ DNS query parsing and LRU caching (256 entries)
- ✅ IP fragmentation handling (IPv4 and IPv6)
- ✅ ICMP/ICMPv6 error message parsing
- ✅ Comprehensive statistics tracking
- ✅ Thread-safe operation
- ✅ Zero-copy where possible
- ✅ iOS and Android compatible

---

## Priority 1: Critical for Production VPN ✅ COMPLETED

### 1. IPv6 Router Advertisement (RA) Parsing ✅
**Status:** COMPLETED  
**Completed:** November 2025  

Parses RA packets (ICMPv6 type 134) to extract IPv6 network configuration including prefix, gateway, and DNS servers.

**Implemented:**
- Parse RA packets with full option handling
- Extract prefix and gateway IPv6 addresses
- Store in Translator struct
- Statistics counter (`ra_packets`)

---

### 2. ICMPv6 Neighbor Advertisement (NA) Responses ✅
**Status:** COMPLETED  
**Completed:** November 2025  

Responds to Neighbor Solicitation (NS, type 135) with Neighbor Advertisement (NA, type 136) for IPv6 neighbor discovery.

**Implemented:**
- Detect NS packets asking for our IPv6
- Build NA response with proper flags
- Calculate ICMPv6 checksum
- Integrated in `icmpv6_handler.c`

---

### 3. DNS Query Handling and Caching ✅
**Status:** COMPLETED  
**Completed:** November 2025  

**Implemented:**
- DNS query parsing (A, AAAA, CNAME records)
- LRU cache with 256 entries
- 5-minute TTL
- Cache hit/miss statistics
- Integrated in `dns_handler.c`

---

## Priority 2: Robustness Features ✅ COMPLETED

### 4. IP Fragmentation Handling ✅
**Status:** COMPLETED  
**Completed:** November 2025  

**Implemented:**
- Track fragment IDs and offsets
- Reassemble buffer (per-fragment-id)
- Timeout fragments after 30 seconds
- Support IPv4 and IPv6 fragmentation
- Max 16 concurrent fragment chains per protocol
- Implemented in `fragment_handler.c`

---

### 5. ICMP/ICMPv6 Error Message Handling ✅
**Status:** COMPLETED  
**Completed:** November 2025  

**Implemented:**
- Parse ICMP types 3 (unreachable), 11 (time exceeded)
- Parse ICMPv6 types 1 (unreachable), 2 (packet too big), 3 (time exceeded)
- Extract embedded packet info
- MTU discovery support
- Update statistics
- Implemented in `icmp_handler.c`

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

### Unit Tests:
- ✅ Basic IP↔Ethernet conversion
- ✅ ARP handling
- ✅ IPv6 conversion
- ✅ IPv6 RA parsing
- ✅ ICMPv6 NS/NA handling
- ✅ DNS query parsing and caching
- ✅ IPv4 fragmentation reassembly
- ✅ ICMP/ICMPv6 error message parsing
- ⏳ Multicast handling
- ⏳ Integration tests with real network traffic

### Documentation:
- ✅ IPv6 RA/NA architecture (in code)
- ✅ DNS caching algorithm (LRU, in code)
- ✅ Fragmentation state machine (in code)
- ⏳ Performance benchmarks (with DNS/RA enabled)
- ⏳ Mobile device integration guide

---

## Performance Targets

**Current (v0.4.0):**
- ~50 µs per packet (IPv4)
- ~55 µs per packet (IPv6)
- ~65 µs with DNS cache hit
- ~70 µs with fragmentation check
- RA parsing: ~80 µs
- NA response: ~55 µs

**Target (v1.0.0):**
- <60 µs per packet (all features enabled)
- <100 µs for DNS cache miss
- <80 µs for RA parsing
- <60 µs for NA response

---

## Release Plan

**v0.3.0 ✅ RELEASED** - IPv6 Complete
- IPv6 RA parsing
- ICMPv6 NA responses
- Updated unit tests

**v0.4.0 ✅ RELEASED** - Robustness
- DNS caching
- Fragmentation handling
- ICMP error messages
- All Priority 1 & 2 features complete
- 14 unit tests passing

**v1.0.0 (Target: Week 2)** - Production Ready
- Mobile device testing (iOS + Android)
- Performance benchmarks
- Full documentation
- Multicast handling (optional)
- Integration tests

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
