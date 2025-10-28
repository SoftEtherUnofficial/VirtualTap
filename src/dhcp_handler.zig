//! DHCP Handler
//!
//! Provides DHCP packet parsing and information extraction.
//! Pure protocol implementation with no platform dependencies.

const std = @import("std");

/// DHCP packet information
pub const DhcpInfo = struct {
    offered_ip: [4]u8,
    server_id: [4]u8,
    gateway: ?[4]u8,
    subnet_mask: ?[4]u8,
    dns_servers: ?[][4]u8,
};

/// DHCP message types
pub const DhcpMessageType = enum(u8) {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
};

/// DHCP Handler
pub const DhcpHandler = struct {
    const Self = @This();

    /// Check if UDP packet is a DHCP packet (port 67/68)
    pub fn isDhcpPacket(ip_packet: []const u8) bool {
        if (ip_packet.len < 28) return false; // Min IP + UDP header

        // Check if it's UDP (protocol 17)
        if (ip_packet[9] != 17) return false;

        // Get header length
        const ihl = (ip_packet[0] & 0x0F) * 4;
        if (ip_packet.len < ihl + 8) return false; // Need UDP header

        // Check UDP ports (67=server, 68=client)
        const udp_header = ip_packet[ihl..];
        const src_port = std.mem.readInt(u16, udp_header[0..2], .big);
        const dst_port = std.mem.readInt(u16, udp_header[2..4], .big);

        return (src_port == 67 or src_port == 68) and (dst_port == 67 or dst_port == 68);
    }

    /// Parse DHCP offer or ACK packet
    pub fn parseDhcpPacket(allocator: std.mem.Allocator, ip_packet: []const u8) !?DhcpInfo {
        if (!isDhcpPacket(ip_packet)) return null;

        const ihl = (ip_packet[0] & 0x0F) * 4;
        if (ip_packet.len < ihl + 8) return null;

        const udp_header = ip_packet[ihl..];
        const udp_len = std.mem.readInt(u16, udp_header[4..6], .big);
        if (udp_len < 8) return null;

        const dhcp_packet = udp_header[8..];
        if (dhcp_packet.len < 240) return null; // Min DHCP packet size

        // Extract offered IP (yiaddr field at offset 16)
        var offered_ip: [4]u8 = undefined;
        @memcpy(&offered_ip, dhcp_packet[16..20]);

        // Parse DHCP options (starting at offset 240)
        if (dhcp_packet.len < 244) return null;

        // Check magic cookie (0x63825363)
        const magic = std.mem.readInt(u32, dhcp_packet[236..240], .big);
        if (magic != 0x63825363) return null;

        var server_id: ?[4]u8 = null;
        var gateway: ?[4]u8 = null;
        var subnet_mask: ?[4]u8 = null;
        var message_type: ?u8 = null;

        // Parse options
        var offset: usize = 240;
        while (offset < dhcp_packet.len) {
            const option = dhcp_packet[offset];
            if (option == 0xFF) break; // End option
            if (option == 0x00) { // Pad option
                offset += 1;
                continue;
            }

            if (offset + 1 >= dhcp_packet.len) break;
            const len = dhcp_packet[offset + 1];
            if (offset + 2 + len > dhcp_packet.len) break;

            const data = dhcp_packet[offset + 2 .. offset + 2 + len];

            switch (option) {
                53 => { // Message type
                    if (len >= 1) message_type = data[0];
                },
                1 => { // Subnet mask
                    if (len >= 4) {
                        var mask: [4]u8 = undefined;
                        @memcpy(&mask, data[0..4]);
                        subnet_mask = mask;
                    }
                },
                3 => { // Router (gateway)
                    if (len >= 4) {
                        var gw: [4]u8 = undefined;
                        @memcpy(&gw, data[0..4]);
                        gateway = gw;
                    }
                },
                54 => { // Server identifier
                    if (len >= 4) {
                        var sid: [4]u8 = undefined;
                        @memcpy(&sid, data[0..4]);
                        server_id = sid;
                    }
                },
                else => {},
            }

            offset += 2 + len;
        }

        // Only return info for DHCP Offer (2) or ACK (5)
        if (message_type) |mt| {
            if (mt == 2 or mt == 5) {
                if (server_id) |sid| {
                    return DhcpInfo{
                        .offered_ip = offered_ip,
                        .server_id = sid,
                        .gateway = gateway,
                        .subnet_mask = subnet_mask,
                        .dns_servers = null, // Not parsing DNS for now
                    };
                }
            }
        }

        _ = allocator; // Not used yet, but keep for future DNS parsing
        return null;
    }
};

// Tests
test "DhcpHandler.isDhcpPacket" {
    // Minimal DHCP packet structure
    var packet = [_]u8{
        0x45, 0x00, 0x00, 0x00, // IP header
        0x00, 0x00, 0x00, 0x00,
        0x00, 17, 0x00, 0x00, // Protocol = UDP (17)
        0x00, 0x00, 0x00, 0x00, // Source IP
        0x00, 0x00, 0x00, 0x00, // Dest IP
        // UDP header
        0x00, 0x43, // Src port = 67
        0x00, 0x44, // Dst port = 68
        0x00, 0x00,
        0x00, 0x00,
    };

    try std.testing.expect(DhcpHandler.isDhcpPacket(&packet));
}
