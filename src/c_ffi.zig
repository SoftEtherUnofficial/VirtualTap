//! C FFI Layer for VirtualTap
//!
//! Provides C-compatible API for use in other languages (Go, Swift, Rust, etc.)

const std = @import("std");
const VirtualTap = @import("virtual_tap_integrated.zig").VirtualTap;
const Config = @import("virtual_tap_integrated.zig").Config;
const Stats = @import("virtual_tap_integrated.zig").Stats;
const MacAddr = @import("virtual_tap_integrated.zig").MacAddr;

// Global allocator for C API
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

/// C-compatible configuration structure
pub const CVirtualTapConfig = extern struct {
    our_mac: [6]u8,
    our_ip: u32, // Network byte order, 0 if unknown
    gateway_ip: u32, // Network byte order, 0 if unknown
    gateway_mac: [6]u8, // All zeros if unknown
    handle_arp: bool,
    learn_ip: bool,
    learn_gateway_mac: bool,
    verbose: bool,
};

/// C-compatible statistics structure
pub const CVirtualTapStats = extern struct {
    ip_to_eth_packets: u64,
    eth_to_ip_packets: u64,
    arp_requests_handled: u64,
    arp_replies_sent: u64,
    ipv4_packets: u64,
    arp_packets: u64,
    dhcp_packets: u64,
};

/// Check if MAC address is all zeros
fn isZeroMac(mac: [6]u8) bool {
    return std.mem.eql(u8, &mac, &[_]u8{ 0, 0, 0, 0, 0, 0 });
}

/// Create a new VirtualTap instance
export fn virtual_tap_create(c_config: [*c]const CVirtualTapConfig) ?*VirtualTap {
    if (c_config == null) return null;

    const config = Config{
        .our_mac = c_config.*.our_mac,
        .our_ip = if (c_config.*.our_ip != 0) c_config.*.our_ip else null,
        .gateway_ip = if (c_config.*.gateway_ip != 0) c_config.*.gateway_ip else null,
        .gateway_mac = if (!isZeroMac(c_config.*.gateway_mac)) c_config.*.gateway_mac else null,
        .handle_arp = c_config.*.handle_arp,
        .learn_ip = c_config.*.learn_ip,
        .learn_gateway_mac = c_config.*.learn_gateway_mac,
        .verbose = c_config.*.verbose,
    };

    return VirtualTap.init(allocator, config) catch null;
}

/// Destroy a VirtualTap instance
export fn virtual_tap_destroy(tap: ?*VirtualTap) void {
    if (tap) |t| {
        t.deinit();
    }
}

/// Convert IP packet to Ethernet frame
/// Returns length of Ethernet frame (>= 0), or negative error code:
///   -1: Invalid tap handle
///   -2: Conversion error
///   -3: Output buffer too small
export fn virtual_tap_ip_to_ethernet(
    tap: ?*VirtualTap,
    ip_packet: [*c]const u8,
    ip_len: u32,
    eth_frame_out: [*c]u8,
    out_capacity: u32,
) i32 {
    const t = tap orelse return -1;
    if (ip_packet == null or eth_frame_out == null) return -1;
    if (ip_len == 0) return -1;

    const ip_slice = ip_packet[0..ip_len];
    const eth_frame = t.ipToEthernet(ip_slice) catch |err| {
        std.debug.print("ipToEthernet failed: {}\n", .{err});
        return -2;
    };
    defer allocator.free(eth_frame);

    if (eth_frame.len > out_capacity) {
        return -3; // Buffer too small
    }

    @memcpy(eth_frame_out[0..eth_frame.len], eth_frame);
    return @intCast(eth_frame.len);
}

/// Convert Ethernet frame to IP packet
/// Returns:
///   > 0: Length of IP packet
///   = 0: Frame was handled internally (ARP, etc.)
///   < 0: Error code:
///     -1: Invalid tap handle
///     -2: Conversion error
///     -3: Output buffer too small
export fn virtual_tap_ethernet_to_ip(
    tap: ?*VirtualTap,
    eth_frame: [*c]const u8,
    eth_len: u32,
    ip_packet_out: [*c]u8,
    out_capacity: u32,
) i32 {
    const t = tap orelse return -1;
    if (eth_frame == null or ip_packet_out == null) return -1;
    if (eth_len < 14) return -2; // Invalid Ethernet frame

    const eth_slice = eth_frame[0..eth_len];
    const ip_packet_opt = t.ethernetToIp(eth_slice) catch |err| {
        std.debug.print("ethernetToIp failed: {}\n", .{err});
        return -2;
    };

    if (ip_packet_opt) |ip_packet| {
        defer allocator.free(ip_packet);

        if (ip_packet.len > out_capacity) {
            return -3; // Buffer too small
        }

        @memcpy(ip_packet_out[0..ip_packet.len], ip_packet);
        return @intCast(ip_packet.len);
    } else {
        // Frame handled internally (ARP, etc.)
        return 0;
    }
}

/// Get learned IP address
/// Returns IP in network byte order, or 0 if not learned yet
export fn virtual_tap_get_learned_ip(tap: ?*VirtualTap) u32 {
    const t = tap orelse return 0;
    return t.getLearnedIp() orelse 0;
}

/// Get learned gateway MAC address
/// Returns true if gateway MAC is known, false otherwise
/// If true, copies MAC to mac_out
export fn virtual_tap_get_gateway_mac(tap: ?*VirtualTap, mac_out: [*c]u8) bool {
    const t = tap orelse return false;
    if (mac_out == null) return false;

    if (t.getGatewayMac()) |mac| {
        @memcpy(mac_out[0..6], &mac);
        return true;
    }
    return false;
}

/// Get statistics
export fn virtual_tap_get_stats(tap: ?*VirtualTap, stats_out: [*c]CVirtualTapStats) void {
    if (tap == null or stats_out == null) return;

    const stats = tap.?.getStats();
    stats_out.*.ip_to_eth_packets = stats.ip_to_eth_packets;
    stats_out.*.eth_to_ip_packets = stats.eth_to_ip_packets;
    stats_out.*.arp_requests_handled = stats.arp_requests_handled;
    stats_out.*.arp_replies_sent = stats.arp_replies_sent;
    stats_out.*.ipv4_packets = stats.ipv4_packets;
    stats_out.*.arp_packets = stats.arp_packets;
    stats_out.*.dhcp_packets = stats.dhcp_packets;
}

/// Check if there are pending ARP replies to send back to server
export fn virtual_tap_has_pending_arp_reply(tap: ?*VirtualTap) bool {
    const t = tap orelse return false;
    return t.hasPendingArpReply();
}

/// Get next pending ARP reply
/// Returns length of ARP reply (> 0), or 0 if no pending replies
/// Negative values indicate errors:
///   -1: Invalid tap handle
///   -3: Output buffer too small
export fn virtual_tap_pop_arp_reply(
    tap: ?*VirtualTap,
    arp_reply_out: [*c]u8,
    out_capacity: u32,
) i32 {
    const t = tap orelse return -1;
    if (arp_reply_out == null) return -1;

    if (t.popArpReply()) |reply| {
        defer allocator.free(reply);

        if (reply.len > out_capacity) {
            return -3; // Buffer too small
        }

        @memcpy(arp_reply_out[0..reply.len], reply);
        return @intCast(reply.len);
    }

    return 0; // No pending replies
}

/// Manually set our IP address
export fn virtual_tap_set_our_ip(tap: ?*VirtualTap, ip: u32) void {
    if (tap) |t| {
        t.setOurIp(ip);
    }
}

/// Manually set gateway IP
export fn virtual_tap_set_gateway_ip(tap: ?*VirtualTap, ip: u32) void {
    if (tap) |t| {
        t.setGatewayIp(ip);
    }
}

/// Manually set gateway MAC
export fn virtual_tap_set_gateway_mac(tap: ?*VirtualTap, mac: [*c]const u8) void {
    if (tap == null or mac == null) return;
    var mac_array: [6]u8 = undefined;
    @memcpy(&mac_array, mac[0..6]);
    tap.?.setGatewayMac(mac_array);
}
