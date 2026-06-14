const std = @import("std");

// Montenegro eID card ATRs.
//
// Montenegro eID cards are built on the NetSeT / IAS-ECC platform. Different
// production batches have slightly different ATRs (the interface byte and the
// resulting TCK checksum vary), so each distinct card ATR is listed explicitly
// here. New variants are added as they are reported, following the same
// convention as the upstream project.
//
// To add a new card: run `opensc-tool --atr`, then append the 22-byte ATR
// below and add it to the test cases.

// Card variant 1 (e.g. production ~2024).
const MNE_EID_ATR_1 = [_]u8{
    0x3B, 0xDC, 0x96, 0xFF, 0x81, 0x91, 0xFE, 0x1F,
    0xC3, 0x80, 0x73, 0xC8, 0x21, 0x13, 0x66, 0x05,
    0x03, 0x63, 0x51, 0x00, 0x02, 0xDE,
};

// Card variant 2 (e.g. production ~2022). Differs from variant 1 only in the
// interface byte (position 2) and the TCK checksum (final byte).
const MNE_EID_ATR_2 = [_]u8{
    0x3B, 0xDC, 0x18, 0xFF, 0x81, 0x91, 0xFE, 0x1F,
    0xC3, 0x80, 0x73, 0xC8, 0x21, 0x13, 0x66, 0x05,
    0x03, 0x63, 0x51, 0x00, 0x02, 0x50,
};

pub fn validATR(atr: []const u8) bool {
    const known_atrs = [_][]const u8{ &MNE_EID_ATR_1, &MNE_EID_ATR_2 };

    for (known_atrs) |known| {
        if (std.mem.eql(u8, known, atr))
            return true;
    }

    return false;
}

