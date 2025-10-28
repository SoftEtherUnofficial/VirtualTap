//! VirtualTap - Universal Layer 2 Virtualization Module
//!
//! Provides a virtual Ethernet adapter that bridges Layer 2 VPN protocols
//! (like SoftEther) with Layer 3-only platforms (like iOS, Android).
//!
//! This is the complete integrated version that uses all protocol modules.

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import protocol modules
const ArpHandler = @import("arp_handler.zig").ArpHandler;
const ArpTable = @import("arp_handler.zig").ArpTable;
const ArpInfo = @import("arp_handler.zig").ArpInfo;
const L2L3Translator = @import("translator.zig").L2L3Translator;
const DhcpHandler = @import("dhcp_handler.zig").DhcpHandler;
const ip_utils = @import("ip_utils.zig");

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

    /// Learn IP addresses from outgoing packets
    learn_ip: bool = true,

    /// Learn gateway MAC from incoming frames
    learn_gateway_mac: bool = true,

    /// Verbose logging
    verbose: bool = false,

    /// ARP entry timeout (milliseconds)
    arp_timeout_ms: i64 = 300_000, // 5 minutes
};

/// VirtualTap statistics
pub const Stats = struct {
    // Translation counters
    ip_to_eth_packets: u64 = 0,
    eth_to_ip_packets: u64 = 0,

    // ARP statistics
    arp_requests_handled: u64 = 0,
    arp_replies_sent: u64 = 0,
    arp_table_entries: u64 = 0,

    // Packet type counters
    ipv4_packets: u64 = 0,
    arp_packets: u64 = 0,
    dhcp_packets: u64 = 0,
    other_packets: u64 = 0,
};

/// VirtualTap main structure
pub const VirtualTap = struct {
    allocator: Allocator,
    config: Config,
    stats: Stats,

    // Components
    arp_handler: ArpHandler,
    arp_table: ArpTable,
    translator: L2L3Translator,

    // ARP reply queue (for replies that need to be sent back to server)
    arp_reply_queue: std.ArrayList([]const u8),

    const Self = @This();

    /// Initialize VirtualTap
    pub fn init(allocator: Allocator, config: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Initialize components
        const arp_handler = try ArpHandler.init(allocator, config.our_mac);
        errdefer arp_handler.deinit();

        const arp_table = ArpTable.init(allocator, config.arp_timeout_ms);
        errdefer arp_table.deinit();

        const translator_options = @import("translator.zig").TranslatorOptions{
            .our_mac = config.our_mac,
            .handle_arp = config.handle_arp,
            .learn_gateway_mac = config.learn_gateway_mac,
            .verbose = config.verbose,
        };
        const translator = try L2L3Translator.init(allocator, translator_options);

        self.* = VirtualTap{
            .allocator = allocator,
            .config = config,
            .stats = .{},
            .arp_handler = arp_handler,
            .arp_table = arp_table,
            .translator = translator,
            .arp_reply_queue = .{},
        }; // Set initial IP/gateway if provided
        if (config.our_ip) |ip| {
            self.translator.setOurIp(ip);
        }
        if (config.gateway_ip) |gw_ip| {
            self.translator.setGatewayIp(gw_ip);
        }
        if (config.gateway_mac) |gw_mac| {
            self.translator.setGatewayMac(gw_mac);
        }

        return self;
    }

    /// Deinitialize VirtualTap
    pub fn deinit(self: *VirtualTap) void {
        // Free all pending ARP replies
        for (self.arp_reply_queue.items) |reply| {
            self.allocator.free(reply);
        }
        self.arp_reply_queue.deinit(self.allocator);
        self.arp_table.deinit();

        // Free the VirtualTap instance itself
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Convert IP packet to Ethernet frame (Platform → Server)
    ///
    /// **Memory Management:**
    /// Returns an allocated Ethernet frame. Caller must free it!
    pub fn ipToEthernet(self: *Self, ip_packet: []const u8) ![]const u8 {
        if (ip_packet.len == 0) return error.InvalidPacket;

        // Get destination IP to determine destination MAC
        const dest_ip = ip_utils.getDestIp(ip_packet);
        var dest_mac: ?MacAddr = null;

        if (dest_ip) |dip| {
            // Look up in ARP table
            if (self.arp_table.lookup(dip)) |mac| {
                dest_mac = mac;
            }
        }

        // Use translator to build Ethernet frame
        const eth_frame = try self.translator.ipToEthernet(ip_packet, dest_mac);
        self.stats.ip_to_eth_packets += 1;

        return eth_frame;
    }

    /// Convert Ethernet frame to IP packet (Server → Platform)
    ///
    /// **Memory Management:**
    /// - Returns null if frame was handled internally (ARP)
    /// - Returns allocated IP packet if successful. Caller must free it!
    pub fn ethernetToIp(self: *Self, eth_frame: []const u8) !?[]const u8 {
        if (eth_frame.len < 14) return error.InvalidPacket;

        const ethertype = std.mem.readInt(u16, eth_frame[12..14], .big);

        switch (ethertype) {
            ETHERTYPE_IP => {
                // IPv4 packet
                self.stats.ipv4_packets += 1;

                // Check if it's DHCP
                if (eth_frame.len > 14) {
                    const ip_packet = eth_frame[14..];
                    if (DhcpHandler.isDhcpPacket(ip_packet)) {
                        self.stats.dhcp_packets += 1;
                        // Parse DHCP info for IP learning
                        if (try DhcpHandler.parseDhcpPacket(self.allocator, ip_packet)) |dhcp_info| {
                            // Learn our IP from DHCP offer/ACK
                            if (self.config.learn_ip) {
                                const ip_u32 = (@as(u32, dhcp_info.offered_ip[0]) << 24) |
                                    (@as(u32, dhcp_info.offered_ip[1]) << 16) |
                                    (@as(u32, dhcp_info.offered_ip[2]) << 8) |
                                    @as(u32, dhcp_info.offered_ip[3]);
                                self.translator.setOurIp(ip_u32);

                                if (self.config.verbose) {
                                    std.debug.print("[VirtualTap] DHCP: Learned IP {d}.{d}.{d}.{d}\n", .{
                                        dhcp_info.offered_ip[0],
                                        dhcp_info.offered_ip[1],
                                        dhcp_info.offered_ip[2],
                                        dhcp_info.offered_ip[3],
                                    });
                                }
                            }

                            // Learn gateway from DHCP
                            if (dhcp_info.gateway) |gw| {
                                const gw_u32 = (@as(u32, gw[0]) << 24) |
                                    (@as(u32, gw[1]) << 16) |
                                    (@as(u32, gw[2]) << 8) |
                                    @as(u32, gw[3]);
                                self.translator.setGatewayIp(gw_u32);
                            }
                        }
                    }
                }

                // Translate to IP packet
                const ip_packet = try self.translator.ethernetToIp(eth_frame);
                if (ip_packet != null) {
                    self.stats.eth_to_ip_packets += 1;
                }
                return ip_packet;
            },

            ETHERTYPE_ARP => {
                // ARP packet
                self.stats.arp_packets += 1;

                if (!self.config.handle_arp) {
                    return null; // Not handling ARP
                }

                return try self.handleArp(eth_frame);
            },

            ETHERTYPE_IPV6 => {
                // IPv6 - pass through for now
                const ip_packet = try self.translator.ethernetToIp(eth_frame);
                if (ip_packet != null) {
                    self.stats.eth_to_ip_packets += 1;
                }
                return ip_packet;
            },

            else => {
                // Unknown protocol
                self.stats.other_packets += 1;
                return null;
            },
        }
    }

    /// Handle ARP packet internally
    fn handleArp(self: *Self, eth_frame: []const u8) !?[]const u8 {
        if (eth_frame.len < 42) return error.InvalidPacket;

        const arp_packet = eth_frame[14..]; // Skip Ethernet header
        const arp_info = try ArpHandler.parseArpPacket(arp_packet);

        if (arp_info.operation == ARP_OP_REPLY) {
            // ARP reply - learn MAC address
            try self.arp_table.insert(arp_info.sender_ip, arp_info.sender_mac, false);
            self.stats.arp_table_entries = self.arp_table.count();

            // If it's from gateway, update translator
            if (self.translator.getLearnedIp()) |our_ip| {
                const gateway_ip = (our_ip & 0xFFFFFF00) | 0x01; // Assume x.x.x.1
                if (arp_info.sender_ip == gateway_ip) {
                    self.translator.setGatewayMac(arp_info.sender_mac);
                }
            }

            return null; // Handled internally
        } else if (arp_info.operation == ARP_OP_REQUEST) {
            // ARP request
            self.stats.arp_requests_handled += 1;

            const our_ip = self.translator.getLearnedIp() orelse self.config.our_ip;
            if (our_ip == null) {
                return null; // Don't know our IP yet
            }

            if (arp_info.target_ip == our_ip.?) {
                // Request is for us - build ARP reply
                const reply = try self.arp_handler.buildArpReply(
                    our_ip.?,
                    arp_info.sender_mac,
                    arp_info.sender_ip,
                );

                // Queue reply to be sent back to server
                try self.arp_reply_queue.append(self.allocator, reply);
                self.stats.arp_replies_sent += 1;

                return null; // Handled internally
            }
        }

        return null;
    }

    /// Check if there are pending ARP replies to send back to server
    pub fn hasPendingArpReply(self: *const Self) bool {
        return self.arp_reply_queue.items.len > 0;
    }

    /// Get next ARP reply to send (caller takes ownership and must free)
    pub fn popArpReply(self: *Self) ?[]const u8 {
        if (self.arp_reply_queue.items.len == 0) {
            return null;
        }
        return self.arp_reply_queue.orderedRemove(0);
    }

    /// Get learned IP address
    pub fn getLearnedIp(self: *const Self) ?u32 {
        return self.translator.getLearnedIp();
    }

    /// Get learned gateway MAC
    pub fn getGatewayMac(self: *const Self) ?MacAddr {
        return self.translator.getGatewayMac();
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }

    /// Manually set our IP address
    pub fn setOurIp(self: *Self, ip: u32) void {
        self.translator.setOurIp(ip);
    }

    /// Manually set gateway IP
    pub fn setGatewayIp(self: *Self, ip: u32) void {
        self.translator.setGatewayIp(ip);
    }

    /// Manually set gateway MAC
    pub fn setGatewayMac(self: *Self, mac: MacAddr) void {
        self.translator.setGatewayMac(mac);
    }
};

// Tests
test "VirtualTap basic creation" {
    const allocator = std.testing.allocator;

    const config = Config{
        .our_mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false,
    };

    const vtap = try VirtualTap.init(allocator, config);
    defer vtap.deinit();

    const stats = vtap.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.ip_to_eth_packets);
}

test "VirtualTap IP to Ethernet" {
    const allocator = std.testing.allocator;

    const config = Config{
        .our_mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .our_ip = try ip_utils.ipToU32("192.168.1.100"),
        .gateway_ip = try ip_utils.ipToU32("192.168.1.1"),
        .gateway_mac = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    };

    const vtap = try VirtualTap.init(allocator, config);
    defer vtap.deinit();

    // Sample ICMP ping packet
    const ip_packet = [_]u8{
        0x45, 0x00, 0x00, 0x54, // Version, IHL, TOS, Length
        0x00, 0x00, 0x40, 0x00, // ID, Flags
        0x40, 0x01, 0x00, 0x00, // TTL, Protocol (ICMP), Checksum
        0xC0, 0xA8, 0x01, 0x64, // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01, // Dest IP: 192.168.1.1
    };

    const eth_frame = try vtap.ipToEthernet(&ip_packet);
    defer allocator.free(eth_frame);

    try std.testing.expectEqual(@as(usize, 14 + ip_packet.len), eth_frame.len);
    try std.testing.expectEqual(@as(u16, ETHERTYPE_IP), std.mem.readInt(u16, eth_frame[12..14], .big));

    const stats = vtap.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.ip_to_eth_packets);
}
