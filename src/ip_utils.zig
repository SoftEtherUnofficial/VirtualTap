//! IP Utilities
//!
//! Helper functions for IP address manipulation and validation.
//! Pure protocol implementation with no platform dependencies.

const std = @import("std");

/// Convert IP address string to u32 (network byte order)
pub fn ipToU32(ip_str: []const u8) !u32 {
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var num: u16 = 0;
    var has_digit = false;

    for (ip_str) |ch| {
        if (ch >= '0' and ch <= '9') {
            num = num * 10 + (ch - '0');
            if (num > 255) return error.InvalidIpAddress;
            has_digit = true;
        } else if (ch == '.') {
            if (!has_digit) return error.InvalidIpAddress;
            if (octet_idx >= 4) return error.InvalidIpAddress;
            octets[octet_idx] = @intCast(num);
            octet_idx += 1;
            num = 0;
            has_digit = false;
        } else {
            return error.InvalidIpAddress;
        }
    }

    // Last octet
    if (!has_digit) return error.InvalidIpAddress;
    if (octet_idx != 3) return error.InvalidIpAddress;
    octets[3] = @intCast(num);

    // Convert to network byte order (big endian)
    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);
}

/// Convert u32 (network byte order) to IP address string
pub fn u32ToIp(ip: u32, buf: []u8) ![]const u8 {
    if (buf.len < 15) return error.BufferTooSmall; // Max: "255.255.255.255"

    const octet1 = (ip >> 24) & 0xFF;
    const octet2 = (ip >> 16) & 0xFF;
    const octet3 = (ip >> 8) & 0xFF;
    const octet4 = ip & 0xFF;

    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ octet1, octet2, octet3, octet4 });
}

/// Check if packet is a valid IP packet
pub fn isValidIpPacket(packet: []const u8) bool {
    if (packet.len < 20) return false;
    const version = packet[0] >> 4;
    return version == 4 or version == 6;
}

/// Get IP version from packet
pub fn getIpVersion(packet: []const u8) u8 {
    if (packet.len == 0) return 0;
    return packet[0] >> 4;
}

/// Get IP header length (IPv4 only)
pub fn getIpHeaderLength(packet: []const u8) usize {
    if (packet.len == 0) return 0;
    const version = packet[0] >> 4;
    if (version != 4) return 0;
    const ihl = packet[0] & 0x0F;
    return @as(usize, ihl) * 4;
}

/// Extract source IP from IPv4 packet
pub fn getSourceIp(packet: []const u8) ?u32 {
    if (packet.len < 20) return null;
    if ((packet[0] & 0xF0) != 0x40) return null; // Not IPv4
    return std.mem.readInt(u32, packet[12..16], .big);
}

/// Extract destination IP from IPv4 packet
pub fn getDestIp(packet: []const u8) ?u32 {
    if (packet.len < 20) return null;
    if ((packet[0] & 0xF0) != 0x40) return null; // Not IPv4
    return std.mem.readInt(u32, packet[16..20], .big);
}

/// Get protocol from IPv4 packet
pub fn getProtocol(packet: []const u8) ?u8 {
    if (packet.len < 20) return null;
    if ((packet[0] & 0xF0) != 0x40) return null; // Not IPv4
    return packet[9];
}

/// Check if two MAC addresses are equal
pub fn macEqual(mac1: [6]u8, mac2: [6]u8) bool {
    return std.mem.eql(u8, &mac1, &mac2);
}

/// Check if MAC address is broadcast
pub fn isBroadcastMac(mac: [6]u8) bool {
    return std.mem.eql(u8, &mac, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
}

/// Check if MAC address is zero
pub fn isZeroMac(mac: [6]u8) bool {
    return std.mem.eql(u8, &mac, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
}

// Tests
test "ipToU32 and u32ToIp" {
    const ip_u32 = try ipToU32("192.168.1.100");
    try std.testing.expectEqual(@as(u32, 0xC0A80164), ip_u32);

    var buf: [16]u8 = undefined;
    const ip_str = try u32ToIp(0xC0A80164, &buf);
    try std.testing.expectEqualStrings("192.168.1.100", ip_str);
}

test "IP packet validation" {
    const ipv4_packet = [_]u8{
        0x45, 0x00, 0x00, 0x54, // Version 4, IHL 5
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x00, 0x00, // TTL, Protocol (ICMP)
        0xC0, 0xA8, 0x01, 0x64, // Source IP
        0xC0, 0xA8, 0x01, 0x01, // Dest IP
    };

    try std.testing.expect(isValidIpPacket(&ipv4_packet));
    try std.testing.expectEqual(@as(u8, 4), getIpVersion(&ipv4_packet));
    try std.testing.expectEqual(@as(usize, 20), getIpHeaderLength(&ipv4_packet));
    try std.testing.expectEqual(@as(u32, 0xC0A80164), getSourceIp(&ipv4_packet).?);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), getDestIp(&ipv4_packet).?);
    try std.testing.expectEqual(@as(u8, 1), getProtocol(&ipv4_packet).?); // ICMP
}

test "MAC address utilities" {
    const mac1 = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const mac2 = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const mac3 = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const mac4 = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    try std.testing.expect(macEqual(mac1, mac2));
    try std.testing.expect(!macEqual(mac1, mac3));
    try std.testing.expect(isBroadcastMac(mac3));
    try std.testing.expect(isZeroMac(mac4));
}
