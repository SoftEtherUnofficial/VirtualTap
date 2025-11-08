# VirtualTap C Development - Roadmap

**Goal:** Port VirtualTapZig (Zig implementation) to pure C for iOS/Android integration

**Status:** Planning Phase  
**Target Platform:** iOS (primary), Android (future)  
**Language:** C11 (maximum compatibility)  
**Dependencies:** None (pure C stdlib only)

---

## 1. Project Structure

```
VirtualTap/
├── README.md                    # Project overview
├── DEVELOPMENT_PLAN.md          # This file
├── Makefile                     # Build system
├── include/
│   ├── virtual_tap.h            # Public API (from VirtualTapZig)
│   └── virtual_tap_internal.h   # Internal structures
├── src/
│   ├── virtual_tap.c            # Main module (~400 lines)
│   ├── arp_handler.c            # ARP protocol (~300 lines)
│   ├── translator.c             # L2↔L3 translation (~350 lines)
│   ├── dhcp_parser.c            # DHCP parsing (~200 lines)
│   └── ip_utils.c               # IP utilities (~150 lines)
├── test/
│   ├── test_ffi.c               # FFI compatibility tests
│   ├── test_arp.c               # ARP handler tests
│   └── test_translator.c        # Translator tests
└── examples/
    └── simple_usage.c           # Usage example
```

---

## 2. Architecture Overview

### 2.1 Core Components (from VirtualTapZig analysis)

1. **VirtualTap Main Module** (`virtual_tap.c`)
   - Orchestrates all components
   - Manages statistics
   - Handles packet routing (IP vs ARP vs IPv6)
   - ARP reply queue management

2. **ARP Handler** (`arp_handler.c`)
   - Parse ARP packets (28 bytes)
   - Build ARP replies (42 bytes = 14 Ethernet + 28 ARP)
   - Maintain ARP table (IP→MAC mappings)
   - Entry timeout management (5 minutes default)

3. **L2↔L3 Translator** (`translator.c`)
   - `ipToEthernet()`: Add 14-byte Ethernet header to IP packets
   - `ethernetToIp()`: Strip Ethernet header, extract IP packets
   - Learn our IP from outgoing packets (source IP field)
   - Learn gateway MAC from incoming packets

4. **DHCP Parser** (`dhcp_parser.c`)
   - Detect DHCP packets (UDP port 67/68)
   - Parse DHCP OFFER/ACK messages
   - Extract: offered IP, gateway, DNS, subnet mask
   - Feed learned info to translator

5. **IP Utils** (`ip_utils.c`)
   - IP address string parsing/formatting
   - Extract destination IP from packets
   - Network byte order conversions

---

## 3. Data Structures

### 3.1 Main Structure (replaces Zig's VirtualTap)

```c
typedef struct VirtualTap {
    // Configuration
    uint8_t our_mac[6];
    uint32_t our_ip;        // Learned or configured
    uint32_t gateway_ip;    // Learned or configured
    uint8_t gateway_mac[6]; // Learned or configured
    bool handle_arp;
    bool learn_ip;
    bool learn_gateway_mac;
    bool verbose;
    
    // Components
    ArpTable* arp_table;
    Translator* translator;
    
    // ARP reply queue (simple linked list)
    ArpReplyNode* arp_reply_head;
    ArpReplyNode* arp_reply_tail;
    
    // Statistics
    VirtualTapStats stats;
} VirtualTap;
```

### 3.2 ARP Table (replaces Zig's std.AutoHashMap)

```c
#define ARP_TABLE_SIZE 64  // Fixed size for simplicity

typedef struct ArpEntry {
    uint32_t ip;           // 0 = empty slot
    uint8_t mac[6];
    int64_t timestamp_ms;  // Unix timestamp in milliseconds
    bool is_static;
} ArpEntry;

typedef struct ArpTable {
    ArpEntry entries[ARP_TABLE_SIZE];
    int64_t timeout_ms;
} ArpTable;
```

### 3.3 ARP Reply Queue (replaces Zig's std.ArrayList)

```c
typedef struct ArpReplyNode {
    uint8_t* packet;       // Dynamically allocated (42 bytes)
    uint32_t length;
    struct ArpReplyNode* next;
} ArpReplyNode;
```

### 3.4 Translator State (replaces Zig's L2L3Translator)

```c
typedef struct Translator {
    uint8_t our_mac[6];
    uint32_t our_ip;       // Learned from outgoing packets
    uint32_t gateway_ip;   // Set or learned from DHCP
    uint8_t gateway_mac[6]; // Learned from incoming packets
    int64_t last_gateway_learn_ms;
    
    bool handle_arp;
    bool learn_gateway_mac;
    bool verbose;
    
    // Statistics
    uint64_t packets_l2_to_l3;
    uint64_t packets_l3_to_l2;
    uint64_t arp_replies_learned;
} Translator;
```

---

## 4. API Compatibility Matrix

| Function | VirtualTapZig (Zig) | VirtualTap (C) | Status |
|----------|---------------------|----------------|--------|
| `virtual_tap_create()` | ✅ Implemented | ⏳ TODO | Port from c_ffi.zig |
| `virtual_tap_destroy()` | ✅ Implemented | ⏳ TODO | Port from c_ffi.zig |
| `virtual_tap_ip_to_ethernet()` | ✅ Implemented | ⏳ TODO | Port from translator.zig |
| `virtual_tap_ethernet_to_ip()` | ✅ Implemented | ⏳ TODO | Port from translator.zig |
| `virtual_tap_get_learned_ip()` | ✅ Implemented | ⏳ TODO | Simple getter |
| `virtual_tap_get_gateway_mac()` | ✅ Implemented | ⏳ TODO | Simple getter |
| `virtual_tap_get_stats()` | ✅ Implemented | ⏳ TODO | Copy struct |
| `virtual_tap_has_pending_arp_reply()` | ✅ Implemented | ⏳ TODO | Check queue |
| `virtual_tap_pop_arp_reply()` | ✅ Implemented | ⏳ TODO | Dequeue + copy |

**100% API compatibility guaranteed** - C implementation will match Zig API exactly.

---

## 5. Implementation Phases

### Phase 1: Foundation (Day 1, 4 hours)

**Goal:** Basic structure and build system

- [x] Create directory structure
- [ ] Write `include/virtual_tap.h` (copy from VirtualTapZig)
- [ ] Write `include/virtual_tap_internal.h`
- [ ] Create `Makefile` with:
  - Static library target (`libvirtualtap.a`)
  - Test targets
  - iOS cross-compilation support
- [ ] Write basic `virtual_tap.c` skeleton:
  ```c
  VirtualTap* virtual_tap_create(const VirtualTapConfig* config) {
      // Allocate and initialize
  }
  
  void virtual_tap_destroy(VirtualTap* tap) {
      // Free all resources
  }
  ```

**Deliverable:** Compiles, links, runs (does nothing yet)

---

### Phase 2: ARP Handler (Day 1-2, 6 hours)

**Goal:** Port `arp_handler.zig` to C

**Reference:** VirtualTapZig/src/protocol/arp_handler.zig (273 lines)

#### 2.1 ARP Table Implementation

```c
// Create ARP table
ArpTable* arp_table_create(int64_t timeout_ms);

// Lookup MAC for IP (returns true if found)
bool arp_table_lookup(ArpTable* table, uint32_t ip, uint8_t mac_out[6]);

// Insert or update entry
void arp_table_insert(ArpTable* table, uint32_t ip, const uint8_t mac[6], bool is_static);

// Remove expired entries (called periodically)
void arp_table_cleanup(ArpTable* table);

// Free table
void arp_table_destroy(ArpTable* table);
```

**Translation Strategy:**
- Replace `std.AutoHashMap` with fixed-size array (64 entries)
- Use linear search (fast enough for small tables)
- Replace `std.time.milliTimestamp()` with:
  ```c
  #include <sys/time.h>
  int64_t get_time_ms() {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
  }
  ```

#### 2.2 ARP Packet Parsing

```c
typedef struct ArpInfo {
    uint16_t operation;  // 1=Request, 2=Reply
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
} ArpInfo;

// Parse ARP packet (returns 0 on success, -1 on error)
int arp_parse_packet(const uint8_t* arp_packet, uint32_t len, ArpInfo* info);
```

**Port from:** Lines 107-136 in `arp_handler.zig`

#### 2.3 ARP Reply Building

```c
// Build ARP reply (42 bytes = 14 Ethernet + 28 ARP)
// Returns length of packet written (42), or -1 on error
int arp_build_reply(
    const uint8_t our_mac[6],
    uint32_t our_ip,
    const uint8_t target_mac[6],
    uint32_t target_ip,
    uint8_t* packet_out,
    uint32_t out_capacity
);
```

**Port from:** Lines 146-182 in `arp_handler.zig`

**Byte Layout (42 bytes):**
```
[0-5]   Dest MAC (target)
[6-11]  Src MAC (us)
[12-13] EtherType: 0x0806 (ARP)
[14-15] Hardware type: 0x0001 (Ethernet)
[16-17] Protocol type: 0x0800 (IPv4)
[18]    Hardware size: 6
[19]    Protocol size: 4
[20-21] Opcode: 0x0002 (Reply)
[22-27] Sender MAC (us)
[28-31] Sender IP (us)
[32-37] Target MAC (them)
[38-41] Target IP (them)
```

**Tests:**
- Parse valid ARP request
- Parse valid ARP reply
- Build ARP reply
- Reject malformed packets

---

### Phase 3: L2↔L3 Translator (Day 2, 6 hours)

**Goal:** Port `translator.zig` to C

**Reference:** VirtualTapZig/src/protocol/translator.zig (269 lines)

#### 3.1 Translator Initialization

```c
Translator* translator_create(
    const uint8_t our_mac[6],
    bool handle_arp,
    bool learn_gateway_mac,
    bool verbose
);

void translator_destroy(Translator* t);
```

#### 3.2 IP to Ethernet (L3→L2)

```c
// Add 14-byte Ethernet header to IP packet
// Returns length of Ethernet frame, or -1 on error
int translator_ip_to_ethernet(
    Translator* t,
    const uint8_t* ip_packet,
    uint32_t ip_len,
    const uint8_t* dest_mac,  // NULL = use gateway or broadcast
    uint8_t* eth_out,
    uint32_t out_capacity
);
```

**Port from:** Lines 58-110 in `translator.zig`

**Algorithm:**
1. Detect IPv4 (0x4x) or IPv6 (0x6x) from first byte
2. Learn our IP from source IP field (bytes 12-15 for IPv4)
3. Determine destination MAC:
   - Use provided `dest_mac` if not NULL
   - Else use gateway MAC if known
   - Else use broadcast (FF:FF:FF:FF:FF:FF)
4. Build frame: `[6 dest][6 src][2 type][payload]`
5. For IPv4: type = 0x0800, IPv6: type = 0x86DD

**Tests:**
- Convert IPv4 packet with known gateway MAC
- Convert IPv4 packet with broadcast
- Convert IPv6 packet
- Learn our IP from outgoing packet

#### 3.3 Ethernet to IP (L2→L3)

```c
// Strip Ethernet header, extract IP packet
// Returns:
//   > 0: Length of IP packet
//   = 0: Non-IP frame (ARP, etc.) - handled internally
//   < 0: Error
int translator_ethernet_to_ip(
    Translator* t,
    const uint8_t* eth_frame,
    uint32_t eth_len,
    uint8_t* ip_out,
    uint32_t out_capacity
);
```

**Port from:** Lines 128-183 in `translator.zig`

**Algorithm:**
1. Extract EtherType from bytes 12-13
2. If 0x0800 (IPv4) or 0x86DD (IPv6):
   - Learn gateway MAC from source MAC if packet from gateway IP
   - Copy IP packet (skip 14-byte header)
3. If 0x0806 (ARP):
   - Return 0 (caller will handle)
4. Else:
   - Return 0 (unknown protocol)

**Tests:**
- Extract IPv4 packet from frame
- Learn gateway MAC from incoming packet
- Return 0 for ARP frame
- Reject malformed frames

---

### Phase 4: DHCP Parser (Day 3, 4 hours)

**Goal:** Port `dhcp_handler.zig` to C

**Reference:** VirtualTapZig/src/protocol/dhcp_handler.zig (~200 lines)

#### 4.1 DHCP Detection

```c
// Check if IP packet is DHCP (UDP ports 67/68)
bool dhcp_is_dhcp_packet(const uint8_t* ip_packet, uint32_t len);
```

**Algorithm:**
1. Check IP header: protocol = 17 (UDP)
2. Check UDP ports: 67 (server) or 68 (client)

#### 4.2 DHCP Parsing

```c
typedef struct DhcpInfo {
    uint8_t offered_ip[4];     // Offered/ACK'd IP address
    uint8_t gateway[4];        // Router option (3)
    uint8_t subnet_mask[4];    // Subnet mask option (1)
    uint8_t dns1[4];           // DNS server 1 (6)
    uint8_t dns2[4];           // DNS server 2 (6)
    uint8_t message_type;      // 2=OFFER, 5=ACK
    bool valid;
} DhcpInfo;

// Parse DHCP packet
// Returns 0 on success, -1 if not DHCP or parse error
int dhcp_parse_packet(const uint8_t* ip_packet, uint32_t len, DhcpInfo* info);
```

**DHCP Options Parsing:**
- Option 53 (DHCP Message Type): 1 byte
- Option 1 (Subnet Mask): 4 bytes
- Option 3 (Router/Gateway): 4 bytes
- Option 6 (DNS Servers): 4+ bytes (read first 2)

**Tests:**
- Parse DHCP OFFER
- Parse DHCP ACK
- Extract gateway, DNS, subnet
- Reject non-DHCP packets

---

### Phase 5: Main VirtualTap Module (Day 3-4, 8 hours)

**Goal:** Integrate all components

**Reference:** VirtualTapZig/src/virtual_tap.zig (418 lines)

#### 5.1 Packet Routing

```c
int32_t virtual_tap_ethernet_to_ip(
    VirtualTap* tap,
    const uint8_t* eth_frame,
    uint32_t eth_len,
    uint8_t* ip_out,
    uint32_t out_capacity
) {
    // 1. Check EtherType
    uint16_t ethertype = read_u16_be(eth_frame + 12);
    
    // 2. Route by protocol
    switch (ethertype) {
        case 0x0800: // IPv4
            tap->stats.ipv4_packets++;
            
            // Check if DHCP
            if (dhcp_is_dhcp_packet(eth_frame + 14, eth_len - 14)) {
                tap->stats.dhcp_packets++;
                DhcpInfo dhcp;
                if (dhcp_parse_packet(eth_frame + 14, eth_len - 14, &dhcp) == 0) {
                    // Learn IP and gateway
                    if (tap->config.learn_ip) {
                        translator_set_our_ip(tap->translator, 
                            ipv4_to_u32(dhcp.offered_ip));
                    }
                    if (dhcp.gateway[0] != 0) {
                        translator_set_gateway_ip(tap->translator,
                            ipv4_to_u32(dhcp.gateway));
                    }
                }
            }
            
            // Translate to IP
            return translator_ethernet_to_ip(tap->translator,
                eth_frame, eth_len, ip_out, out_capacity);
            
        case 0x0806: // ARP
            tap->stats.arp_packets++;
            if (!tap->config.handle_arp) return 0;
            return handle_arp(tap, eth_frame, eth_len);
            
        case 0x86DD: // IPv6
            return translator_ethernet_to_ip(tap->translator,
                eth_frame, eth_len, ip_out, out_capacity);
            
        default:
            tap->stats.other_packets++;
            return 0;
    }
}
```

**Port from:** Lines 192-267 in `virtual_tap.zig`

#### 5.2 ARP Handling

```c
static int handle_arp(VirtualTap* tap, const uint8_t* eth_frame, uint32_t eth_len) {
    // 1. Parse ARP packet
    ArpInfo info;
    if (arp_parse_packet(eth_frame + 14, eth_len - 14, &info) != 0) {
        return -1;
    }
    
    // 2. If ARP Reply: learn MAC
    if (info.operation == 2) {
        arp_table_insert(tap->arp_table, info.sender_ip, info.sender_mac, false);
        tap->stats.arp_table_entries = arp_table_count(tap->arp_table);
        
        // Learn gateway MAC
        uint32_t our_ip = translator_get_our_ip(tap->translator);
        if (our_ip != 0) {
            uint32_t gateway_ip = (our_ip & 0xFFFFFF00) | 0x01; // x.x.x.1
            if (info.sender_ip == gateway_ip) {
                translator_set_gateway_mac(tap->translator, info.sender_mac);
            }
        }
        
        return 0; // Handled internally
    }
    
    // 3. If ARP Request for us: build reply
    if (info.operation == 1) {
        tap->stats.arp_requests_handled++;
        
        uint32_t our_ip = translator_get_our_ip(tap->translator);
        if (our_ip == 0 || info.target_ip != our_ip) {
            return 0; // Not for us
        }
        
        // Build and queue reply
        uint8_t* reply = malloc(42);
        if (reply == NULL) return -1;
        
        if (arp_build_reply(tap->config.our_mac, our_ip,
                           info.sender_mac, info.sender_ip,
                           reply, 42) != 42) {
            free(reply);
            return -1;
        }
        
        // Queue reply
        arp_reply_queue_push(tap, reply, 42);
        tap->stats.arp_replies_sent++;
        
        return 0;
    }
    
    return 0;
}
```

**Port from:** Lines 277-320 in `virtual_tap.zig`

#### 5.3 ARP Reply Queue

```c
// Simple linked list queue
static void arp_reply_queue_push(VirtualTap* tap, uint8_t* packet, uint32_t len) {
    ArpReplyNode* node = malloc(sizeof(ArpReplyNode));
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

bool virtual_tap_has_pending_arp_reply(VirtualTap* tap) {
    return tap->arp_reply_head != NULL;
}

int32_t virtual_tap_pop_arp_reply(
    VirtualTap* tap,
    uint8_t* arp_reply_out,
    uint32_t out_capacity
) {
    if (tap->arp_reply_head == NULL) return 0;
    
    ArpReplyNode* node = tap->arp_reply_head;
    tap->arp_reply_head = node->next;
    if (tap->arp_reply_head == NULL) {
        tap->arp_reply_tail = NULL;
    }
    
    if (node->length > out_capacity) {
        free(node->packet);
        free(node);
        return -3; // Buffer too small
    }
    
    memcpy(arp_reply_out, node->packet, node->length);
    uint32_t len = node->length;
    
    free(node->packet);
    free(node);
    
    return len;
}
```

---

### Phase 6: Testing (Day 4, 4 hours)

#### 6.1 Unit Tests

**File:** `test/test_arp.c`
- ARP table operations (insert, lookup, timeout)
- ARP packet parsing
- ARP reply building

**File:** `test/test_translator.c`
- IP→Ethernet conversion
- Ethernet→IP conversion
- IP learning
- Gateway MAC learning

**File:** `test/test_integration.c`
- Full packet flow: IP→Ethernet→IP
- ARP request→reply cycle
- DHCP learning

#### 6.2 FFI Compatibility Test

**File:** `test/test_ffi.c` (already exists in VirtualTapZig)
- Copy from VirtualTapZig/test_ffi.c
- Should compile and run identically with C implementation

---

### Phase 7: iOS Integration (Day 5, 8 hours)

#### 7.1 Add to iOS Project

1. Copy files to WorxVPN-iOS:
   ```
   WorxVPN-iOS/
   └── VirtualTap/
       ├── virtual_tap.h
       ├── virtual_tap.c
       ├── arp_handler.c
       ├── translator.c
       ├── dhcp_parser.c
       └── ip_utils.c
   ```

2. Add to Xcode project (both app and extension targets)

3. Update `Bridge/softether_bridge.c`:
   ```c
   #include "VirtualTap/virtual_tap.h"
   
   PACKET_ADAPTER* NewIosPacketAdapter(void* param) {
       LOG_DEBUG("IOS_ADAPTER", "Creating iOS packet adapter with VirtualTap");
       
       VirtualTapConfig config = {
           .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
           .our_ip = 0,
           .gateway_ip = 0,
           .handle_arp = true,
           .learn_ip = true,
           .learn_gateway_mac = true,
           .verbose = true
       };
       
       VirtualTap* vtap = virtual_tap_create(&config);
       if (!vtap) {
           LOG_ERROR("IOS_ADAPTER", "Failed to create VirtualTap");
           return NULL;
       }
       
       PACKET_ADAPTER* pa = ZeroMalloc(sizeof(PACKET_ADAPTER));
       pa->Param = vtap;
       pa->Init = ios_vtap_adapter_init;
       pa->GetNextPacket = ios_vtap_get_packet;
       pa->PutPacket = ios_vtap_put_packet;
       pa->Free = ios_vtap_free;
       
       return pa;
   }
   ```

#### 7.2 Packet Adapter Callbacks

```c
bool ios_vtap_adapter_init(void* param) {
    VirtualTap* vtap = (VirtualTap*)param;
    LOG_DEBUG("IOS_ADAPTER", "iOS VirtualTap adapter initialized");
    return true;
}

UINT ios_vtap_get_packet(void* param, void** data) {
    VirtualTap* vtap = (VirtualTap*)param;
    
    // Check if there's a pending ARP reply
    if (virtual_tap_has_pending_arp_reply(vtap)) {
        uint8_t* packet = Malloc(42);
        int32_t len = virtual_tap_pop_arp_reply(vtap, packet, 42);
        if (len > 0) {
            *data = packet;
            return len;
        }
        Free(packet);
    }
    
    // Read packet from iOS packetFlow (via global callback)
    return ios_packet_flow_read(data);
}

bool ios_vtap_put_packet(void* param, void* data, UINT size) {
    VirtualTap* vtap = (VirtualTap*)param;
    
    // Convert Ethernet→IP
    uint8_t ip_packet[2048];
    int32_t ip_len = virtual_tap_ethernet_to_ip(vtap, data, size,
                                                 ip_packet, sizeof(ip_packet));
    
    if (ip_len > 0) {
        // Write IP packet to iOS packetFlow
        return ios_packet_flow_write(ip_packet, ip_len);
    }
    
    return true; // Handled internally (ARP)
}

void ios_vtap_free(void* param) {
    VirtualTap* vtap = (VirtualTap*)param;
    virtual_tap_destroy(vtap);
    LOG_DEBUG("IOS_ADAPTER", "iOS VirtualTap adapter freed");
}
```

#### 7.3 iOS PacketFlow Bridge

Update `WorxVPNExtension/PacketTunnelProvider.swift`:

```swift
// Global callbacks for C bridge
var globalPacketFlowRead: (() -> Data?)? = nil
var globalPacketFlowWrite: ((Data) -> Bool)? = nil

// In startTunnel():
globalPacketFlowRead = { [weak self] in
    guard let self = self else { return nil }
    // Read from NEPacketTunnelFlow
    return self.readNextPacket()
}

globalPacketFlowWrite = { [weak self] data in
    guard let self = self else { return false }
    // Write to NEPacketTunnelFlow
    return self.writePacket(data)
}
```

---

## 6. Memory Management Strategy

### 6.1 Allocation Rules

**VirtualTap Structure:**
- Allocated once in `virtual_tap_create()`
- Freed once in `virtual_tap_destroy()`

**ARP Table:**
- Fixed-size array (64 entries) allocated with VirtualTap
- No dynamic allocation per entry

**ARP Reply Queue:**
- Each node dynamically allocated when ARP reply built
- Freed when reply popped by caller

**Translator:**
- Allocated once with VirtualTap
- No dynamic allocations during operation

**Packet Buffers:**
- **ZERO-COPY STRATEGY**: All functions write to caller-provided buffers
- No internal allocations for packets
- Caller must ensure buffer is large enough:
  - IP→Ethernet: `ip_len + 14` bytes
  - Ethernet→IP: `eth_len - 14` bytes maximum

### 6.2 Buffer Sizes

```c
#define MAX_PACKET_SIZE 2048
#define ETHERNET_HEADER_SIZE 14
#define ARP_PACKET_SIZE 42
#define ARP_REPLY_QUEUE_MAX 16  // Limit queue size
```

### 6.3 Error Handling

**Return Conventions:**
- **> 0**: Success, value = length of data
- **= 0**: Success, no data (handled internally)
- **< 0**: Error code:
  - `-1`: Invalid parameters
  - `-2`: Packet parsing error
  - `-3`: Output buffer too small
  - `-4`: Memory allocation failed

---

## 7. Build System

### 7.1 Makefile Targets

```makefile
CC = clang
CFLAGS = -std=c11 -Wall -Wextra -O2 -I./include
LDFLAGS = 

# iOS cross-compilation
IOS_SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
IOS_CFLAGS = -arch arm64 -isysroot $(IOS_SDK) -mios-version-min=15.0

SRCS = src/virtual_tap.c src/arp_handler.c src/translator.c \
       src/dhcp_parser.c src/ip_utils.c
OBJS = $(SRCS:.c=.o)

all: libvirtualtap.a test_ffi

libvirtualtap.a: $(OBJS)
	ar rcs $@ $^

libvirtualtap_ios.a: $(SRCS)
	$(CC) $(IOS_CFLAGS) $(CFLAGS) -c $(SRCS)
	ar rcs $@ *.o
	rm -f *.o

test_ffi: test/test_ffi.c libvirtualtap.a
	$(CC) $(CFLAGS) -o $@ $< -L. -lvirtualtap

clean:
	rm -f $(OBJS) libvirtualtap.a libvirtualtap_ios.a test_ffi

.PHONY: all clean
```

---

## 8. Testing Checklist

### 8.1 Unit Tests

- [ ] ARP table insert/lookup
- [ ] ARP table timeout/cleanup
- [ ] ARP packet parsing
- [ ] ARP reply building
- [ ] IP→Ethernet conversion
- [ ] Ethernet→IP conversion
- [ ] IP address learning
- [ ] Gateway MAC learning
- [ ] DHCP packet detection
- [ ] DHCP info extraction

### 8.2 Integration Tests

- [ ] Full packet flow (IP→Eth→IP round-trip)
- [ ] ARP request→reply cycle
- [ ] DHCP learning flow
- [ ] Multiple packet types (IPv4, IPv6, ARP)
- [ ] ARP reply queue operations

### 8.3 iOS Device Tests

- [ ] VPN session starts (ClientThread launches)
- [ ] Packet adapter creates successfully
- [ ] IP packets converted to Ethernet
- [ ] Ethernet packets converted to IP
- [ ] ARP requests answered
- [ ] DHCP configuration learned
- [ ] VPN connects and stays connected
- [ ] Network traffic flows bidirectionally

---

## 9. Success Criteria

### 9.1 Functional Requirements

✅ **Must Have:**
- [ ] API 100% compatible with VirtualTapZig
- [ ] All unit tests pass
- [ ] FFI test (test_ffi.c) passes
- [ ] iOS VPN session starts successfully
- [ ] Packets flow through VirtualTap
- [ ] ARP handling works
- [ ] DHCP learning works

🎯 **Should Have:**
- [ ] Zero memory leaks (Valgrind clean)
- [ ] Thread-safe (mutex protection for shared state)
- [ ] Performance: < 10μs per packet conversion

💡 **Nice to Have:**
- [ ] Android integration
- [ ] Comprehensive documentation
- [ ] Example programs

### 9.2 Performance Targets

| Operation | Target | Acceptable |
|-----------|--------|------------|
| IP→Ethernet | < 5μs | < 20μs |
| Ethernet→IP | < 5μs | < 20μs |
| ARP lookup | < 1μs | < 5μs |
| ARP reply build | < 10μs | < 30μs |
| Memory per VirtualTap | < 10KB | < 50KB |

---

## 10. Risk Analysis

### 10.1 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **ARP table hash collisions** | Medium | Use linear probing or linked list per bucket |
| **Memory leaks in ARP queue** | High | Strict ownership rules, unit tests with Valgrind |
| **Endianness issues** | Medium | Consistent use of network byte order functions |
| **iOS threading issues** | High | Document thread safety, use mutex if needed |
| **Packet corruption** | High | Extensive validation, checksums where applicable |

### 10.2 Integration Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **SoftEther callback lifecycle** | High | Match existing adapter patterns exactly |
| **iOS memory pressure** | Medium | Use static buffers, minimize allocations |
| **Xcode build issues** | Low | Test early with minimal code |
| **Zig→C translation bugs** | Medium | Compare behavior with Zig version byte-by-byte |

---

## 11. Timeline

| Phase | Duration | Cumulative | Deliverable |
|-------|----------|------------|-------------|
| **Phase 1: Foundation** | 4h | 4h | Skeleton compiles |
| **Phase 2: ARP Handler** | 6h | 10h | ARP tests pass |
| **Phase 3: Translator** | 6h | 16h | Translator tests pass |
| **Phase 4: DHCP Parser** | 4h | 20h | DHCP tests pass |
| **Phase 5: Main Module** | 8h | 28h | FFI test passes |
| **Phase 6: Testing** | 4h | 32h | All tests pass |
| **Phase 7: iOS Integration** | 8h | 40h | VPN connects |

**Total Estimate:** 40 hours (5 days @ 8h/day)

---

## 12. Next Steps

1. **Review this plan** - Get approval before starting
2. **Set up environment** - Clone repo, install tools
3. **Start Phase 1** - Create directory structure
4. **Daily check-ins** - Report progress, blockers
5. **Test continuously** - Don't wait until Phase 6

---

## 13. References

- **VirtualTapZig Source:** `/Volumes/EXT/SoftEther/VirtualTapZig/`
- **iOS Project:** `/Volumes/EXT/SoftEther/WorxVPN-iOS/`
- **SoftEther Docs:** `SoftEtherVPN/src/Cedar/`
- **ARP RFC:** RFC 826
- **DHCP RFC:** RFC 2131

---

**Status:** ✅ PLAN COMPLETE - Ready for implementation  
**Last Updated:** November 9, 2025  
**Next Action:** Begin Phase 1 - Foundation
