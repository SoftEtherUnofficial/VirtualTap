//! L2↔L3 Protocol Translator
//!
//! Handles bidirectional conversion between Layer 2 (Ethernet frames) and Layer 3 (IP packets).
//! Pure protocol implementation with no platform dependencies.

const std = @import("std");

/// Translator configuration
pub const TranslatorOptions = struct {
    our_mac: [6]u8,
    handle_arp: bool = true,
    learn_gateway_mac: bool = true,
    verbose: bool = false,
};

/// L2↔L3 Translator
pub const L2L3Translator = struct {
    allocator: std.mem.Allocator,
    options: TranslatorOptions,

    // Learned network information
    our_ip: ?u32, // Our IP address (learned from outgoing packets)
    gateway_ip: ?u32, // Gateway IP address
    gateway_mac: ?[6]u8, // Gateway MAC address (learned from packets)
    last_gateway_learn: i64, // Timestamp of last gateway MAC learn

    // Statistics
    packets_translated_l2_to_l3: u64,
    packets_translated_l3_to_l2: u64,
    arp_replies_learned: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: TranslatorOptions) !Self {
        return .{
            .allocator = allocator,
            .options = options,
            .our_ip = null,
            .gateway_ip = null,
            .gateway_mac = null,
            .last_gateway_learn = 0,
            .packets_translated_l2_to_l3 = 0,
            .packets_translated_l3_to_l2 = 0,
            .arp_replies_learned = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Convert IP packet (L3) to Ethernet frame (L2)
    /// Used when sending packets from TUN device to network/VPN that expects Ethernet frames
    ///
    /// **Memory Management:**
    /// This function allocates a new buffer for the Ethernet frame.
    /// The caller is responsible for freeing the returned slice using the same allocator.
    ///
    /// Returns: Allocated Ethernet frame (14-byte header + IP packet)
    /// Errors: InvalidPacket if the IP packet is malformed
    pub fn ipToEthernet(self: *Self, ip_packet: []const u8, dest_mac: ?[6]u8) ![]const u8 {
        if (ip_packet.len == 0) return error.InvalidPacket;

        // Determine EtherType and destination MAC
        var ethertype: u16 = undefined;
        var dst_mac: [6]u8 = undefined;

        if (ip_packet.len > 0 and (ip_packet[0] & 0xF0) == 0x40) {
            // IPv4 packet
            ethertype = 0x0800;

            // Learn our IP from source IP field (if not already known)
            if (self.our_ip == null and ip_packet.len >= 20) {
                const src_ip = std.mem.readInt(u32, ip_packet[12..16], .big);
                self.our_ip = src_ip;
                if (self.options.verbose) {
                    std.debug.print("[VirtualTap] Learned our IP: {}.{}.{}.{}\n", .{
                        (src_ip >> 24) & 0xFF,
                        (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF,
                        src_ip & 0xFF,
                    });
                }
            }

            // Use provided dest MAC, otherwise gateway MAC, otherwise broadcast
            if (dest_mac) |dmac| {
                dst_mac = dmac;
            } else if (self.gateway_mac) |gw_mac| {
                dst_mac = gw_mac;
            } else {
                @memset(&dst_mac, 0xFF); // Broadcast
            }
        } else if (ip_packet.len > 0 and (ip_packet[0] & 0xF0) == 0x60) {
            // IPv6 packet
            ethertype = 0x86DD;
            if (dest_mac) |dmac| {
                dst_mac = dmac;
            } else {
                @memset(&dst_mac, 0xFF); // Broadcast for IPv6
            }
        } else {
            return error.InvalidPacket;
        }

        // Build Ethernet frame: [6 dest MAC][6 src MAC][2 EtherType][payload]
        const frame_size = 14 + ip_packet.len;
        const frame = try self.allocator.alloc(u8, frame_size);
        errdefer self.allocator.free(frame);

        @memcpy(frame[0..6], &dst_mac); // Destination MAC
        @memcpy(frame[6..12], &self.options.our_mac); // Source MAC
        std.mem.writeInt(u16, frame[12..14], ethertype, .big); // EtherType
        @memcpy(frame[14..], ip_packet); // IP packet

        self.packets_translated_l3_to_l2 += 1;

        return frame;
    }

    /// Convert Ethernet frame (L2) to IP packet (L3)
    /// Used when receiving Ethernet frames from network/VPN to write to TUN device
    ///
    /// **Memory Management:**
    /// - Returns `null` if the frame is non-IP (will be handled elsewhere, e.g., ARP)
    /// - Returns an **allocated** IP packet slice if conversion succeeded
    /// - The caller is responsible for freeing the returned slice using the same allocator
    ///
    /// Returns: Optional allocated IP packet slice (null if non-IP frame)
    /// Errors: InvalidPacket if the Ethernet frame is malformed
    pub fn ethernetToIp(self: *Self, eth_frame: []const u8) !?[]const u8 {
        if (eth_frame.len < 14) return error.InvalidPacket;

        const ethertype = std.mem.readInt(u16, eth_frame[12..14], .big);

        // Only handle IP packets, return null for ARP (caller handles it)
        if (ethertype != 0x0800 and ethertype != 0x86DD) {
            return null; // Not IP - will be handled by caller (ARP, etc.)
        }

        // Extract IP packet (strip 14-byte Ethernet header)
        const ip_packet = eth_frame[14..];

        // Learn gateway MAC from any packet from gateway IP
        if (ethertype == 0x0800 and ip_packet.len >= 20 and self.options.learn_gateway_mac) {
            const src_ip = std.mem.readInt(u32, ip_packet[12..16], .big);

            // If this packet is from our gateway, learn its MAC address
            if (self.gateway_ip) |gw_ip| {
                if (src_ip == gw_ip) {
                    var new_mac: [6]u8 = undefined;
                    @memcpy(&new_mac, eth_frame[6..12]); // Source MAC from Ethernet header

                    const changed = if (self.gateway_mac) |old_mac|
                        !std.mem.eql(u8, &old_mac, &new_mac)
                    else
                        true;

                    if (changed) {
                        self.gateway_mac = new_mac;
                        self.last_gateway_learn = std.time.milliTimestamp();
                        self.arp_replies_learned += 1;
                        if (self.options.verbose) {
                            std.debug.print("[VirtualTap] Learned gateway MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n", .{
                                new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5],
                            });
                        }
                    }
                }
            }
        }

        // Allocate copy of IP packet
        const result = try self.allocator.alloc(u8, ip_packet.len);
        @memcpy(result, ip_packet);

        self.packets_translated_l2_to_l3 += 1;

        return result;
    }

    /// Extract source IP from IP packet (for learning)
    pub fn extractSourceIp(ip_packet: []const u8) ?u32 {
        if (ip_packet.len < 20) return null;
        if ((ip_packet[0] & 0xF0) != 0x40) return null; // Not IPv4
        return std.mem.readInt(u32, ip_packet[12..16], .big);
    }

    /// Extract destination IP from IP packet
    pub fn extractDestIp(ip_packet: []const u8) ?u32 {
        if (ip_packet.len < 20) return null;
        if ((ip_packet[0] & 0xF0) != 0x40) return null; // Not IPv4
        return std.mem.readInt(u32, ip_packet[16..20], .big);
    }

    /// Check if IP packet is valid
    pub fn isValidIpPacket(packet: []const u8) bool {
        if (packet.len < 20) return false;
        const version = packet[0] >> 4;
        return version == 4 or version == 6;
    }

    /// Manually set our IP address
    pub fn setOurIp(self: *Self, ip: u32) void {
        self.our_ip = ip;
    }

    /// Manually set gateway IP
    pub fn setGatewayIp(self: *Self, gateway_ip: u32) void {
        self.gateway_ip = gateway_ip;
    }

    /// Manually set gateway MAC
    pub fn setGatewayMac(self: *Self, gateway_mac: [6]u8) void {
        self.gateway_mac = gateway_mac;
    }

    /// Get learned IP address
    pub fn getLearnedIp(self: *const Self) ?u32 {
        return self.our_ip;
    }

    /// Get learned gateway MAC
    pub fn getGatewayMac(self: *const Self) ?[6]u8 {
        return self.gateway_mac;
    }

    /// Get translation statistics
    pub fn getStats(self: *const Self) struct {
        l2_to_l3: u64,
        l3_to_l2: u64,
        arp_learned: u64,
    } {
        return .{
            .l2_to_l3 = self.packets_translated_l2_to_l3,
            .l3_to_l2 = self.packets_translated_l3_to_l2,
            .arp_learned = self.arp_replies_learned,
        };
    }
};

// Tests
test "L2L3Translator basic" {
    const allocator = std.testing.allocator;

    var translator = try L2L3Translator.init(allocator, .{
        .our_mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .handle_arp = true,
        .learn_gateway_mac = true,
        .verbose = false,
    });
    defer translator.deinit();

    // Test IP to Ethernet
    const ip_packet = [_]u8{
        0x45, 0x00, 0x00, 0x54, // Version, IHL, TOS, Length
        0x00, 0x00, 0x40, 0x00, // ID, Flags
        0x40, 0x01, 0x00, 0x00, // TTL, Protocol, Checksum
        0xC0, 0xA8, 0x01, 0x64, // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01, // Dest IP: 192.168.1.1
    };

    const eth_frame = try translator.ipToEthernet(&ip_packet, null);
    defer allocator.free(eth_frame);

    try std.testing.expectEqual(@as(usize, 14 + ip_packet.len), eth_frame.len);
    try std.testing.expectEqual(@as(u16, 0x0800), std.mem.readInt(u16, eth_frame[12..14], .big));
}
