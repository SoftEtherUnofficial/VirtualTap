//! ARP (Address Resolution Protocol) Handler
//!
//! Handles ARP requests, replies, and maintains ARP table for L2↔L3 translation.
//! Pure protocol implementation with no platform dependencies.

const std = @import("std");

/// ARP table entry
pub const ArpEntry = struct {
    ip: u32, // Network byte order
    mac: [6]u8,
    timestamp: i64, // Unix timestamp in milliseconds
    is_static: bool, // Static entries don't age out
};

/// ARP packet information (parsed)
pub const ArpInfo = struct {
    operation: u16, // 1=Request, 2=Reply
    sender_mac: [6]u8,
    sender_ip: u32,
    target_mac: [6]u8,
    target_ip: u32,
};

/// ARP table for IP↔MAC mapping
pub const ArpTable = struct {
    entries: std.AutoHashMap(u32, ArpEntry),
    allocator: std.mem.Allocator,
    timeout_ms: i64, // Entry timeout in milliseconds

    pub fn init(allocator: std.mem.Allocator, timeout_ms: i64) ArpTable {
        return .{
            .entries = std.AutoHashMap(u32, ArpEntry).init(allocator),
            .allocator = allocator,
            .timeout_ms = timeout_ms,
        };
    }

    pub fn deinit(self: *ArpTable) void {
        self.entries.deinit();
    }

    /// Look up MAC address for IP
    pub fn lookup(self: *ArpTable, ip: u32) ?[6]u8 {
        if (self.entries.get(ip)) |entry| {
            // Check if entry is still valid
            const now = std.time.milliTimestamp();
            if (!entry.is_static and now - entry.timestamp > self.timeout_ms) {
                // Entry expired - remove it
                _ = self.entries.remove(ip);
                return null;
            }
            return entry.mac;
        }
        return null;
    }

    /// Insert or update ARP entry
    pub fn insert(self: *ArpTable, ip: u32, mac: [6]u8, is_static: bool) !void {
        try self.entries.put(ip, .{
            .ip = ip,
            .mac = mac,
            .timestamp = std.time.milliTimestamp(),
            .is_static = is_static,
        });
    }

    /// Remove ARP entry
    pub fn remove(self: *ArpTable, ip: u32) bool {
        return self.entries.remove(ip);
    }

    /// Clear all dynamic entries
    pub fn clearDynamic(self: *ArpTable) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.is_static) {
                _ = self.entries.remove(entry.key_ptr.*);
            }
        }
    }

    /// Get number of entries
    pub fn count(self: *ArpTable) usize {
        return self.entries.count();
    }
};

/// ARP protocol handler
pub const ArpHandler = struct {
    allocator: std.mem.Allocator,
    our_mac: [6]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, our_mac: [6]u8) !Self {
        return Self{
            .allocator = allocator,
            .our_mac = our_mac,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Parse ARP packet (expects Ethernet frame starting at ARP header)
    pub fn parseArpPacket(arp_packet: []const u8) !ArpInfo {
        if (arp_packet.len < 28) {
            return error.PacketTooShort;
        }

        const hw_type = std.mem.readInt(u16, arp_packet[0..2], .big);
        const proto_type = std.mem.readInt(u16, arp_packet[2..4], .big);

        if (hw_type != 0x0001) return error.InvalidHardwareType; // Not Ethernet
        if (proto_type != 0x0800) return error.InvalidProtocolType; // Not IPv4

        const operation = std.mem.readInt(u16, arp_packet[6..8], .big);

        var sender_mac: [6]u8 = undefined;
        @memcpy(&sender_mac, arp_packet[8..14]);

        const sender_ip = std.mem.readInt(u32, arp_packet[14..18], .big);

        var target_mac: [6]u8 = undefined;
        @memcpy(&target_mac, arp_packet[18..24]);

        const target_ip = std.mem.readInt(u32, arp_packet[24..28], .big);

        return ArpInfo{
            .operation = operation,
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
        };
    }

    /// Build ARP reply packet (full Ethernet frame)
    pub fn buildArpReply(
        self: *Self,
        our_ip: u32,
        target_mac: [6]u8,
        target_ip: u32,
    ) ![]const u8 {
        const packet = try self.allocator.alloc(u8, 42); // Ethernet + ARP
        errdefer self.allocator.free(packet);

        var pos: usize = 0;

        // Ethernet header (14 bytes)
        @memcpy(packet[pos..][0..6], &target_mac); // Dest MAC
        pos += 6;
        @memcpy(packet[pos..][0..6], &self.our_mac); // Src MAC
        pos += 6;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0806, .big); // EtherType: ARP
        pos += 2;

        // ARP packet (28 bytes)
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0001, .big); // Hardware type: Ethernet
        pos += 2;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0800, .big); // Protocol type: IPv4
        pos += 2;
        packet[pos] = 6; // Hardware size
        pos += 1;
        packet[pos] = 4; // Protocol size
        pos += 1;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0002, .big); // Opcode: Reply
        pos += 2;

        // Sender (us)
        @memcpy(packet[pos..][0..6], &self.our_mac); // Sender MAC
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], our_ip, .big); // Sender IP
        pos += 4;

        // Target
        @memcpy(packet[pos..][0..6], &target_mac); // Target MAC
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big); // Target IP
        pos += 4;

        return packet;
    }

    /// Build ARP request packet (full Ethernet frame)
    pub fn buildArpRequest(
        self: *Self,
        our_ip: u32,
        target_ip: u32,
    ) ![]const u8 {
        const packet = try self.allocator.alloc(u8, 42);
        errdefer self.allocator.free(packet);

        var pos: usize = 0;

        // Ethernet header - broadcast
        @memset(packet[pos..][0..6], 0xFF); // Broadcast MAC
        pos += 6;
        @memcpy(packet[pos..][0..6], &self.our_mac); // Src MAC
        pos += 6;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0806, .big); // EtherType: ARP
        pos += 2;

        // ARP packet
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0001, .big); // Hardware type
        pos += 2;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0800, .big); // Protocol type
        pos += 2;
        packet[pos] = 6; // Hardware size
        pos += 1;
        packet[pos] = 4; // Protocol size
        pos += 1;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0001, .big); // Opcode: Request
        pos += 2;

        // Sender (us)
        @memcpy(packet[pos..][0..6], &self.our_mac);
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], our_ip, .big);
        pos += 4;

        // Target (unknown MAC)
        @memset(packet[pos..][0..6], 0x00);
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big);
        pos += 4;

        return packet;
    }
};

// Tests
test "ArpTable basic operations" {
    const allocator = std.testing.allocator;

    var table = ArpTable.init(allocator, 300_000); // 5 minute timeout
    defer table.deinit();

    // Insert entry
    try table.insert(0x0A150001, [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, false);

    // Lookup
    const mac = table.lookup(0x0A150001);
    try std.testing.expect(mac != null);
    try std.testing.expectEqual(@as(u8, 0xAA), mac.?[0]);

    // Count
    try std.testing.expectEqual(@as(usize, 1), table.count());

    // Remove
    _ = table.remove(0x0A150001);
    try std.testing.expectEqual(@as(usize, 0), table.count());
}

test "ArpHandler build packets" {
    const allocator = std.testing.allocator;

    var handler = try ArpHandler.init(allocator, [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 });
    defer handler.deinit();

    const reply = try handler.buildArpReply(
        0x0A150001, // 10.21.0.1
        [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        0x0A150064, // 10.21.0.100
    );
    defer allocator.free(reply);

    try std.testing.expectEqual(@as(usize, 42), reply.len);
    try std.testing.expectEqual(@as(u16, 0x0806), std.mem.readInt(u16, reply[12..14], .big));
}
