//! VirtualTap - Universal Layer 2 Virtualization Module
//!
//! Provides a virtual Ethernet adapter that bridges Layer 2 VPN protocols
//! (like SoftEther) with Layer 3-only platforms (like iOS).
//!
//! Key Features:
//! - Internal ARP handling (no platform support needed)
//! - Virtual MAC address management
//! - L2 ↔ L3 bidirectional translation
//! - Zero platform dependencies
//! - High performance, minimal allocations

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Ethernet frame constants
pub const ETHER_ADDR_LEN = 6;
pub const ETHER_TYPE_LEN = 2;
pub const ETHER_HEADER_LEN = 14;
pub const ETHER_CRC_LEN = 4;

/// EtherType values
pub const ETHERTYPE_IP = 0x0800; // IPv4
pub const ETHERTYPE_ARP = 0x0806; // ARP
pub const ETHERTYPE_IPV6 = 0x86DD; // IPv6

/// ARP operation codes
pub const ARP_OP_REQUEST = 1;
pub const ARP_OP_REPLY = 2;

/// MAC address type
pub const MacAddr = [ETHER_ADDR_LEN]u8;

/// Broadcast MAC address
pub const MAC_BROADCAST: MacAddr = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/// Zero MAC address
pub const MAC_ZERO: MacAddr = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/// ARP table entry
pub const ArpEntry = struct {
    ip: u32, // Network byte order
    mac: MacAddr,
    timestamp: u64, // For aging
    is_static: bool, // Static entries don't age out
};

/// VirtualTap configuration
pub const Config = struct {
    /// Our virtual MAC address
    our_mac: MacAddr,

    /// Our IP address (if known)
    our_ip: ?u32 = null,

    /// Gateway IP address (if known)
    gateway_ip: ?u32 = null,

    /// Gateway MAC address (if known, otherwise use broadcast)
    gateway_mac: ?MacAddr = null,

    /// Handle ARP requests internally
    handle_arp: bool = true,

    /// Learn IP addresses from incoming packets
    learn_ip: bool = true,

    /// Learn gateway MAC from incoming frames
    learn_gateway_mac: bool = true,

    /// Verbose logging
    verbose: bool = false,

    /// ARP table size
    arp_table_size: usize = 256,

    /// ARP entry timeout (milliseconds)
    arp_timeout_ms: u64 = 300_000, // 5 minutes
};

/// VirtualTap statistics
pub const Stats = struct {
    // Incoming (Platform → VirtualTap → SoftEther)
    ip_to_eth_packets: u64 = 0,
    ip_to_eth_bytes: u64 = 0,
    ip_to_eth_errors: u64 = 0,

    // Outgoing (SoftEther → VirtualTap → Platform)
    eth_to_ip_packets: u64 = 0,
    eth_to_ip_bytes: u64 = 0,
    eth_to_ip_drops: u64 = 0,

    // ARP statistics
    arp_requests_handled: u64 = 0,
    arp_replies_sent: u64 = 0,
    arp_table_hits: u64 = 0,
    arp_table_misses: u64 = 0,

    // Packet type counters
    ipv4_packets: u64 = 0,
    ipv6_packets: u64 = 0,
    arp_packets: u64 = 0,
    other_packets: u64 = 0,
};

/// VirtualTap main structure
pub const VirtualTap = struct {
    allocator: Allocator,
    config: Config,
    stats: Stats,
    arp_table: std.ArrayList(ArpEntry),
    arp_reply_queue: std.ArrayList([]u8), // Queue for generated ARP replies

    /// Initialize VirtualTap
    pub fn init(allocator: Allocator, config: Config) !*VirtualTap {
        const self = try allocator.create(VirtualTap);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .config = config,
            .stats = .{},
            .arp_table = .{},
            .arp_reply_queue = .{},
        };

        try self.arp_table.ensureTotalCapacity(allocator, config.arp_table_size);

        // Add static ARP entries if known
        if (config.gateway_ip) |gw_ip| {
            if (config.gateway_mac) |gw_mac| {
                try self.addArpEntry(gw_ip, gw_mac, true);
            }
        }

        if (config.verbose) {
            std.log.info("[VirtualTap] Initialized with MAC {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                config.our_mac[0], config.our_mac[1], config.our_mac[2],
                config.our_mac[3], config.our_mac[4], config.our_mac[5],
            });
        }

        return self;
    }

    /// Clean up VirtualTap
    pub fn deinit(self: *VirtualTap, allocator: std.mem.Allocator) void {
        // Free any pending ARP replies
        for (self.arp_reply_queue.items) |reply| {
            allocator.free(reply);
        }
        self.arp_reply_queue.deinit(allocator);
        self.arp_table.deinit(allocator);
        allocator.destroy(self);
    }

    /// Convert IP packet to Ethernet frame (Platform → SoftEther)
    ///
    /// Takes an IP packet and wraps it in an Ethernet frame.
    /// Caller owns returned memory and must free it.
    pub fn ipToEthernet(self: *VirtualTap, ip_packet: []const u8) ![]u8 {
        if (ip_packet.len == 0) return error.EmptyPacket;
        if (ip_packet.len < 20) return error.PacketTooShort; // Minimum IP header

        // Determine IP version
        const version = ip_packet[0] >> 4;
        const ethertype: u16 = switch (version) {
            4 => ETHERTYPE_IP,
            6 => ETHERTYPE_IPV6,
            else => return error.InvalidIpVersion,
        };

        // Extract destination IP for ARP lookup
        const dest_ip = if (version == 4) blk: {
            if (ip_packet.len < 20) return error.PacketTooShort;
            break :blk std.mem.readInt(u32, ip_packet[16..20], .big);
        } else null;

        // Determine destination MAC
        const dest_mac = if (dest_ip) |ip| blk: {
            // Try ARP table first
            if (self.lookupArp(ip)) |entry| {
                self.stats.arp_table_hits += 1;
                break :blk entry.mac;
            }
            self.stats.arp_table_misses += 1;

            // Use gateway MAC if available, otherwise broadcast
            if (self.config.gateway_mac) |gw_mac| {
                break :blk gw_mac;
            }
            break :blk MAC_BROADCAST;
        } else MAC_BROADCAST; // IPv6 or unknown, use broadcast

        // Allocate buffer for Ethernet frame
        const eth_frame = try self.allocator.alloc(u8, ETHER_HEADER_LEN + ip_packet.len);
        errdefer self.allocator.free(eth_frame);

        // Build Ethernet header
        @memcpy(eth_frame[0..6], &dest_mac); // Destination MAC
        @memcpy(eth_frame[6..12], &self.config.our_mac); // Source MAC
        std.mem.writeInt(u16, eth_frame[12..14], ethertype, .big); // EtherType

        // Copy IP packet
        @memcpy(eth_frame[14..], ip_packet);

        // Update stats
        self.stats.ip_to_eth_packets += 1;
        self.stats.ip_to_eth_bytes += eth_frame.len;
        if (version == 4) {
            self.stats.ipv4_packets += 1;
        } else {
            self.stats.ipv6_packets += 1;
        }

        if (self.config.verbose) {
            std.log.info("[VirtualTap] IP→ETH: {d} bytes IP → {d} bytes Ethernet (EtherType: 0x{x:0>4})", .{
                ip_packet.len, eth_frame.len, ethertype,
            });
        }

        return eth_frame;
    }

    /// Convert Ethernet frame to IP packet (SoftEther → Platform)
    ///
    /// Takes an Ethernet frame and extracts the IP packet.
    /// Returns null if the frame is ARP or handled internally.
    /// Caller owns returned memory and must free it.
    pub fn ethernetToIp(self: *VirtualTap, eth_frame: []const u8) !?[]u8 {
        if (eth_frame.len < ETHER_HEADER_LEN) return error.FrameTooShort;

        // Parse Ethernet header
        _ = eth_frame[0..6]; // dest_mac (not needed for processing)
        const src_mac = eth_frame[6..12];
        const ethertype = std.mem.readInt(u16, eth_frame[12..14], .big);

        // Learn source MAC if needed
        if (self.config.learn_gateway_mac) {
            if (eth_frame.len >= 34) { // Has IP header
                const ip_header = eth_frame[14..];
                if (ip_header.len >= 20) {
                    const src_ip = std.mem.readInt(u32, ip_header[12..16], .big);
                    _ = try self.learnMac(src_ip, src_mac[0..6].*);
                }
            }
        }

        // Handle based on EtherType
        switch (ethertype) {
            ETHERTYPE_ARP => {
                if (self.config.handle_arp) {
                    // Handle ARP - may generate and queue a reply
                    try self.handleArp(eth_frame);
                    self.stats.arp_packets += 1;
                    // ARP handled internally, no IP packet to return
                    return null;
                }
                return error.ArpNotHandled;
            },

            ETHERTYPE_IP, ETHERTYPE_IPV6 => {
                // Extract IP packet (skip Ethernet header)
                const ip_packet = eth_frame[ETHER_HEADER_LEN..];
                if (ip_packet.len == 0) return error.EmptyIpPacket;

                // Allocate buffer and copy
                const result = try self.allocator.alloc(u8, ip_packet.len);
                @memcpy(result, ip_packet);

                // Update stats
                self.stats.eth_to_ip_packets += 1;
                self.stats.eth_to_ip_bytes += ip_packet.len;
                if (ethertype == ETHERTYPE_IP) {
                    self.stats.ipv4_packets += 1;
                } else {
                    self.stats.ipv6_packets += 1;
                }

                if (self.config.verbose) {
                    std.log.info("[VirtualTap] ETH→IP: {d} bytes Ethernet → {d} bytes IP (EtherType: 0x{x:0>4})", .{
                        eth_frame.len, ip_packet.len, ethertype,
                    });
                }

                return result;
            },

            else => {
                self.stats.other_packets += 1;
                self.stats.eth_to_ip_drops += 1;
                if (self.config.verbose) {
                    std.log.warn("[VirtualTap] Unknown EtherType: 0x{x:0>4}, dropping packet", .{ethertype});
                }
                return null;
            },
        }
    }

    /// Handle ARP packet internally - queues ARP reply if we need to respond
    fn handleArp(self: *VirtualTap, eth_frame: []const u8) !void {
        if (eth_frame.len < ETHER_HEADER_LEN + 28) return error.ArpPacketTooShort;

        const arp_packet = eth_frame[ETHER_HEADER_LEN..];

        // Parse ARP header
        const hw_type = std.mem.readInt(u16, arp_packet[0..2], .big);
        const proto_type = std.mem.readInt(u16, arp_packet[2..4], .big);
        const hw_len = arp_packet[4];
        const proto_len = arp_packet[5];
        const operation = std.mem.readInt(u16, arp_packet[6..8], .big);

        // Validate ARP packet
        if (hw_type != 1) return; // Ethernet only
        if (proto_type != ETHERTYPE_IP) return; // IPv4 only
        if (hw_len != 6 or proto_len != 4) return;

        // Extract addresses
        const sender_mac = arp_packet[8..14];
        const sender_ip = std.mem.readInt(u32, arp_packet[14..18], .big);
        const target_ip = std.mem.readInt(u32, arp_packet[24..28], .big);

        // Learn sender's MAC
        _ = try self.learnMac(sender_ip, sender_mac[0..6].*);

        // Handle ARP request
        if (operation == ARP_OP_REQUEST) {
            self.stats.arp_requests_handled += 1;

            // Check if request is for us
            if (self.config.our_ip) |our_ip| {
                if (target_ip == our_ip) {
                    // Build and queue ARP reply
                    self.stats.arp_replies_sent += 1;
                    if (self.config.verbose) {
                        std.log.info("[VirtualTap] 🎯 ARP Request for us (IP: {}.{}.{}.{}), queueing reply!", .{
                            (target_ip >> 24) & 0xFF,
                            (target_ip >> 16) & 0xFF,
                            (target_ip >> 8) & 0xFF,
                            target_ip & 0xFF,
                        });
                    }
                    const reply = try self.buildArpReply(sender_mac[0..6].*, sender_ip, our_ip);
                    try self.arp_reply_queue.append(self.allocator, reply);
                }
            }
        }
    }

    /// Build ARP reply packet (Ethernet + ARP)
    fn buildArpReply(self: *VirtualTap, target_mac: MacAddr, target_ip: u32, our_ip: u32) ![]u8 {
        // Total: 14 (Ethernet) + 28 (ARP) = 42 bytes minimum, padded to 60
        const frame_size = 60; // Minimum Ethernet frame size
        const reply = try self.allocator.alloc(u8, frame_size);
        @memset(reply, 0); // Zero-fill for padding

        // Ethernet header
        @memcpy(reply[0..6], &target_mac); // Destination MAC
        @memcpy(reply[6..12], &self.config.our_mac); // Source MAC
        std.mem.writeInt(u16, reply[12..14], ETHERTYPE_ARP, .big); // EtherType

        // ARP packet
        const arp = reply[14..];
        std.mem.writeInt(u16, arp[0..2], 1, .big); // Hardware type: Ethernet
        std.mem.writeInt(u16, arp[2..4], ETHERTYPE_IP, .big); // Protocol type: IPv4
        arp[4] = 6; // Hardware address length
        arp[5] = 4; // Protocol address length
        std.mem.writeInt(u16, arp[6..8], ARP_OP_REPLY, .big); // Operation: Reply

        // Sender (us)
        @memcpy(arp[8..14], &self.config.our_mac); // Sender MAC
        std.mem.writeInt(u32, arp[14..18], our_ip, .big); // Sender IP

        // Target (requester)
        @memcpy(arp[18..24], &target_mac); // Target MAC
        std.mem.writeInt(u32, arp[24..28], target_ip, .big); // Target IP

        return reply;
    }

    /// Add ARP entry to table
    pub fn addArpEntry(self: *VirtualTap, ip: u32, mac: MacAddr, is_static: bool) !void {
        // Check if entry already exists
        for (self.arp_table.items) |*entry| {
            if (entry.ip == ip) {
                entry.mac = mac;
                entry.timestamp = @intCast(std.time.milliTimestamp());
                entry.is_static = is_static;
                return;
            }
        }

        // Add new entry
        try self.arp_table.append(self.allocator, .{
            .ip = ip,
            .mac = mac,
            .timestamp = @intCast(std.time.milliTimestamp()),
            .is_static = is_static,
        });

        if (self.config.verbose) {
            std.log.info("[VirtualTap] ARP: Added {}.{}.{}.{} → {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                mac[0],            mac[1],            mac[2],           mac[3],
                mac[4],            mac[5],
            });
        }
    }

    /// Learn MAC address from packet
    fn learnMac(self: *VirtualTap, ip: u32, mac: MacAddr) !bool {
        if (!self.config.learn_ip) return false;

        // Don't learn zero or broadcast MACs
        if (std.mem.eql(u8, &mac, &MAC_ZERO) or std.mem.eql(u8, &mac, &MAC_BROADCAST)) {
            return false;
        }

        // If this is the gateway IP, automatically set gateway_mac
        if (self.config.gateway_ip) |gateway_ip| {
            if (ip == gateway_ip and self.config.learn_gateway_mac) {
                self.config.gateway_mac = mac;
                if (self.config.verbose) {
                    std.log.info("[VirtualTap] 🎯 LEARNED GATEWAY MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} for IP {d}.{d}.{d}.{d}", .{
                        mac[0],            mac[1],            mac[2],           mac[3],    mac[4], mac[5],
                        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                    });
                }
            }
        }

        try self.addArpEntry(ip, mac, false);
        return true;
    }

    /// Lookup MAC address in ARP table
    pub fn lookupArp(self: *VirtualTap, ip: u32) ?ArpEntry {
        const now = @as(u64, @intCast(std.time.milliTimestamp()));

        for (self.arp_table.items) |entry| {
            if (entry.ip == ip) {
                // Check if entry is expired (unless static)
                if (!entry.is_static) {
                    if (now - entry.timestamp > self.config.arp_timeout_ms) {
                        continue; // Expired
                    }
                }
                return entry;
            }
        }
        return null;
    }

    /// Get statistics
    pub fn getStats(self: *VirtualTap) Stats {
        return self.stats;
    }

    /// Reset statistics
    pub fn resetStats(self: *VirtualTap) void {
        self.stats = .{};
    }

    /// Update gateway MAC address
    pub fn setGatewayMac(self: *VirtualTap, mac: MacAddr) void {
        self.config.gateway_mac = mac;
        if (self.config.gateway_ip) |gw_ip| {
            self.addArpEntry(gw_ip, mac, true) catch {};
        }
    }

    /// Update our IP address
    pub fn setOurIp(self: *VirtualTap, ip: u32) void {
        self.config.our_ip = ip;
    }

    /// Update gateway IP address
    pub fn setGatewayIp(self: *VirtualTap, ip: u32) void {
        self.config.gateway_ip = ip;
    }

    /// Check if there are pending ARP replies
    pub fn hasPendingArpReply(self: *const VirtualTap) bool {
        return self.arp_reply_queue.items.len > 0;
    }

    /// Pop an ARP reply from the queue (caller owns the memory)
    pub fn popArpReply(self: *VirtualTap) ?[]u8 {
        if (self.arp_reply_queue.items.len == 0) return null;
        return self.arp_reply_queue.orderedRemove(0);
    }
};

/// Generate a random MAC address with local bit set
pub fn generateRandomMac(random: std.Random) MacAddr {
    var mac: MacAddr = undefined;
    random.bytes(&mac);

    // Set locally administered bit (bit 1 of first octet)
    mac[0] = (mac[0] & 0xFE) | 0x02;

    // Clear multicast bit (bit 0 of first octet)
    mac[0] &= 0xFE;

    return mac;
}

// Test VirtualTap basic functionality
test "VirtualTap basic" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create VirtualTap
    var vtap = try VirtualTap.init(allocator, .{
        .our_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .our_ip = 0x0A_15_FB_71, // 10.21.251.113
        .gateway_ip = 0x0A_15_00_01, // 10.21.0.1
        .handle_arp = true,
        .verbose = false,
    });
    defer vtap.deinit();

    // Test IP→Ethernet
    const ip_packet = [_]u8{
        0x45, 0x00, 0x00, 0x3C, // IPv4 header start
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0A, 0x15, 0xFB, 0x71, // Source: 10.21.251.113
        0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
    } ++ ([_]u8{0} ** 40); // Rest of packet

    const eth_frame = try vtap.ipToEthernet(&ip_packet);
    defer allocator.free(eth_frame);

    try testing.expectEqual(eth_frame.len, ETHER_HEADER_LEN + ip_packet.len);
    try testing.expectEqual(std.mem.readInt(u16, eth_frame[12..14], .big), ETHERTYPE_IP);

    // Test Ethernet→IP
    const ip_packet_back = try vtap.ethernetToIp(eth_frame);
    if (ip_packet_back) |pkt| {
        defer allocator.free(pkt);
        try testing.expectEqualSlices(u8, &ip_packet, pkt);
    } else {
        try testing.expect(false); // Should return IP packet
    }
}
