// pace.zig — PACE (BSI TR-03110) for Montenegro eID
//
// Implements id-PACE-ECDH-GM-AES-CBC-CMAC-128 on brainpoolP256r1, seeded by
// the card's CAN. After establishPACE() succeeds, the card is unlocked and the
// existing plaintext PIN-verify and PSO:sign (IDENTITET) operations work.
//
// Crypto primitives come from OpenSSL (libcrypto). EC point arithmetic uses the
// low-level EC_POINT API because Generic Mapping needs G' = s*G + H.
//
// Validated against captured traffic before implementation:
//   - KDF = SHA1(input || counter_be32)[0:16]
//   - K_pi = KDF(CAN, 3); nonce = AES-128-CBC-dec(K_pi, IV=0, z)
//   - curve = brainpoolP256r1 (params confirmed on-curve from capture)
//   - points encoded as 0x04 || X(32) || Y(32)

const std = @import("std");
const apdu = @import("apdu.zig");
const pkcs_error = @import("pkcs_error.zig");
const smart_card = @import("smart-card.zig");
const PkcsError = pkcs_error.PkcsError;

const c = @cImport({
    @cDefine("OPENSSL_API_COMPAT", "0x10100000L");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/bn.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/cmac.h");
    @cInclude("openssl/sha.h");
});

const PACE_OID = [_]u8{ 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02 };

fn kdf(input: []const u8, counter: u32, out: *[16]u8) void {
    var ctx: c.SHA_CTX = undefined;
    _ = c.SHA1_Init(&ctx);
    _ = c.SHA1_Update(&ctx, input.ptr, input.len);
    const ctr = [_]u8{
        @intCast((counter >> 24) & 0xFF),
        @intCast((counter >> 16) & 0xFF),
        @intCast((counter >> 8) & 0xFF),
        @intCast(counter & 0xFF),
    };
    _ = c.SHA1_Update(&ctx, &ctr, 4);
    var digest: [20]u8 = undefined;
    _ = c.SHA1_Final(&digest, &ctx);
    @memcpy(out, digest[0..16]);
}

fn aesCbcDecryptNoPad(key: *const [16]u8, data: []const u8, out: []u8) void {
    const ctx = c.EVP_CIPHER_CTX_new();
    defer c.EVP_CIPHER_CTX_free(ctx);
    const iv = [_]u8{0} ** 16;
    _ = c.EVP_DecryptInit_ex(ctx, c.EVP_aes_128_cbc(), null, key, &iv);
    _ = c.EVP_CIPHER_CTX_set_padding(ctx, 0);
    var outl: c_int = 0;
    _ = c.EVP_DecryptUpdate(ctx, out.ptr, &outl, data.ptr, @intCast(data.len));
    var tmp: c_int = 0;
    _ = c.EVP_DecryptFinal_ex(ctx, out.ptr + @as(usize, @intCast(outl)), &tmp);
}

fn aesCmac(key: *const [16]u8, data: []const u8, out: *[16]u8) void {
    const ctx = c.CMAC_CTX_new();
    defer c.CMAC_CTX_free(ctx);
    _ = c.CMAC_Init(ctx, key, 16, c.EVP_aes_128_cbc(), null);
    _ = c.CMAC_Update(ctx, data.ptr, data.len);
    var outlen: usize = 0;
    _ = c.CMAC_Final(ctx, out, &outlen);
}

fn encodePubkeyForToken(allocator: std.mem.Allocator, point65: []const u8) ![]u8 {
    const inner_len = 2 + PACE_OID.len + 2 + 65;
    var buf = try allocator.alloc(u8, 3 + inner_len);
    var i: usize = 0;
    buf[i] = 0x7F;
    i += 1;
    buf[i] = 0x49;
    i += 1;
    buf[i] = @intCast(inner_len);
    i += 1;
    buf[i] = 0x06;
    i += 1;
    buf[i] = 0x0A;
    i += 1;
    @memcpy(buf[i .. i + PACE_OID.len], &PACE_OID);
    i += PACE_OID.len;
    buf[i] = 0x86;
    i += 1;
    buf[i] = 0x41;
    i += 1;
    @memcpy(buf[i .. i + 65], point65[0..65]);
    i += 65;
    return buf;
}

fn checkSW(rsp: []const u8) PkcsError!void {
    if (rsp.len < 2) return PkcsError.DeviceError;
    if (rsp[rsp.len - 2] != 0x90 or rsp[rsp.len - 1] != 0x00)
        return PkcsError.DeviceError;
}

fn generalAuthenticate(
    card: *const smart_card.Card,
    allocator: std.mem.Allocator,
    chained: bool,
    data: []const u8,
) PkcsError![]u8 {
    const cla: u8 = if (chained) 0x10 else 0x00;
    const unit = apdu.build(allocator, cla, 0x86, 0x00, 0x00, data, 0x100) catch
        return PkcsError.HostMemory;
    defer allocator.free(unit);
    const rsp = try card.transmitPublic(allocator, unit);
    errdefer allocator.free(rsp);
    try checkSW(rsp);
    const body = allocator.alloc(u8, rsp.len - 2) catch return PkcsError.HostMemory;
    @memcpy(body, rsp[0 .. rsp.len - 2]);
    allocator.free(rsp);
    return body;
}

fn tlvFind(buf: []const u8, tag: u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 2 <= buf.len) {
        const t = buf[i];
        const l = buf[i + 1];
        const start = i + 2;
        if (start + l > buf.len) return null;
        if (t == tag) return buf[start .. start + l];
        i = start + l;
    }
    return null;
}

fn innerOf7C(buf: []const u8) ?[]const u8 {
    if (buf.len < 2 or buf[0] != 0x7C) return null;
    const l = buf[1];
    if (2 + @as(usize, l) > buf.len) return null;
    return buf[2 .. 2 + l];
}

pub fn establishPACE(
    card: *const smart_card.Card,
    allocator: std.mem.Allocator,
    can: []const u8,
) PkcsError!void {
    std.debug.print("[PACE] starting handshake\n", .{});

    // PRE-STEP: select IasEccRoot application (required before PACE)
    {
        std.debug.print("[PACE] pre-step: select IasEccRoot\n", .{});
        const aid = [_]u8{ 0xF0, 0x49, 0x61, 0x73, 0x45, 0x63, 0x63, 0x52, 0x6F, 0x6F, 0x74 };
        const unit = apdu.build(allocator, 0x00, 0xA4, 0x04, 0x0C, &aid, 0x00) catch
            return PkcsError.HostMemory;
        defer allocator.free(unit);
        const rsp = try card.transmitPublic(allocator, unit);
        defer allocator.free(rsp);
        try checkSW(rsp);
    }

    // STEP 0: MSE:SET AT
    {
        std.debug.print("[PACE] step 0: MSE:SET AT\n", .{});
        const body = [_]u8{ 0x80, 0x0A } ++ PACE_OID ++ [_]u8{ 0x83, 0x01, 0x02, 0x84, 0x01, 0x0D };
        const unit = apdu.build(allocator, 0x00, 0x22, 0xC1, 0xA4, &body, 0x00) catch
            return PkcsError.HostMemory;
        defer allocator.free(unit);
        const rsp = try card.transmitPublic(allocator, unit);
        defer allocator.free(rsp);
        try checkSW(rsp);
    }

    // STEP 1: encrypted nonce
    var nonce_s: [16]u8 = undefined;
    {
        std.debug.print("[PACE] step 1: get nonce\n", .{});
        const req = [_]u8{ 0x7C, 0x00 };
        const body = try generalAuthenticate(card, allocator, true, &req);
        defer allocator.free(body);
        const inner = innerOf7C(body) orelse return PkcsError.DeviceError;
        const z = tlvFind(inner, 0x80) orelse return PkcsError.DeviceError;
        if (z.len != 16) return PkcsError.DeviceError;
        var k_pi: [16]u8 = undefined;
        kdf(can, 3, &k_pi);
        aesCbcDecryptNoPad(&k_pi, z, &nonce_s);
        std.crypto.secureZero(u8, &k_pi);
    }

    const group = c.EC_GROUP_new_by_curve_name(c.NID_brainpoolP256r1) orelse
        return PkcsError.GeneralError;
    defer c.EC_GROUP_free(group);
    const bnctx = c.BN_CTX_new() orelse return PkcsError.GeneralError;
    defer c.BN_CTX_free(bnctx);

    // STEP 2: Generic Mapping
    var mapped_gen: ?*c.EC_POINT = null;
    defer if (mapped_gen) |mg| c.EC_POINT_free(mg);
    {
        std.debug.print("[PACE] step 2: generic mapping\n", .{});
        const order = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(order);
        _ = c.EC_GROUP_get_order(group, order, bnctx);
        const t_priv = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(t_priv);
        _ = c.BN_rand_range(t_priv, order);

        const t_pub = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        defer c.EC_POINT_free(t_pub);
        _ = c.EC_POINT_mul(group, t_pub, t_priv, null, null, bnctx);
        var t_pub_oct: [65]u8 = undefined;
        _ = c.EC_POINT_point2oct(group, t_pub, c.POINT_CONVERSION_UNCOMPRESSED, &t_pub_oct, 65, bnctx);

        var sbuf: [69]u8 = undefined;
        sbuf[0] = 0x7C;
        sbuf[1] = 0x43;
        sbuf[2] = 0x81;
        sbuf[3] = 0x41;
        @memcpy(sbuf[4..69], &t_pub_oct);
        const body = try generalAuthenticate(card, allocator, true, &sbuf);
        defer allocator.free(body);
        const inner = innerOf7C(body) orelse return PkcsError.DeviceError;
        const c_map = tlvFind(inner, 0x82) orelse return PkcsError.DeviceError;
        if (c_map.len != 65) return PkcsError.DeviceError;

        const c_map_pt = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        defer c.EC_POINT_free(c_map_pt);
        _ = c.EC_POINT_oct2point(group, c_map_pt, c_map.ptr, 65, bnctx);
        const h = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        defer c.EC_POINT_free(h);
        _ = c.EC_POINT_mul(group, h, null, c_map_pt, t_priv, bnctx);

        const s_bn = c.BN_bin2bn(&nonce_s, 16, null) orelse return PkcsError.GeneralError;
        defer c.BN_free(s_bn);
        const one = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(one);
        _ = c.BN_one(one);
        mapped_gen = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        _ = c.EC_POINT_mul(group, mapped_gen, s_bn, h, one, bnctx);
    }

    // STEP 3: ephemeral ECDH on G'
    var k_mac: [16]u8 = undefined;
    var t_eph_oct: [65]u8 = undefined;
    var c_eph_oct: [65]u8 = undefined;
    {
        std.debug.print("[PACE] step 3: ephemeral ECDH\n", .{});
        const order = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(order);
        _ = c.EC_GROUP_get_order(group, order, bnctx);
        const e_priv = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(e_priv);
        _ = c.BN_rand_range(e_priv, order);

        const t_eph = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        defer c.EC_POINT_free(t_eph);
        _ = c.EC_POINT_mul(group, t_eph, null, mapped_gen, e_priv, bnctx);
        _ = c.EC_POINT_point2oct(group, t_eph, c.POINT_CONVERSION_UNCOMPRESSED, &t_eph_oct, 65, bnctx);

        var sbuf: [69]u8 = undefined;
        sbuf[0] = 0x7C;
        sbuf[1] = 0x43;
        sbuf[2] = 0x83;
        sbuf[3] = 0x41;
        @memcpy(sbuf[4..69], &t_eph_oct);
        const body = try generalAuthenticate(card, allocator, true, &sbuf);
        defer allocator.free(body);
        const inner = innerOf7C(body) orelse return PkcsError.DeviceError;
        const c_eph = tlvFind(inner, 0x84) orelse return PkcsError.DeviceError;
        if (c_eph.len != 65) return PkcsError.DeviceError;
        @memcpy(&c_eph_oct, c_eph[0..65]);

        const c_eph_pt = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        defer c.EC_POINT_free(c_eph_pt);
        _ = c.EC_POINT_oct2point(group, c_eph_pt, c_eph.ptr, 65, bnctx);
        const shared = c.EC_POINT_new(group) orelse return PkcsError.GeneralError;
        defer c.EC_POINT_free(shared);
        _ = c.EC_POINT_mul(group, shared, null, c_eph_pt, e_priv, bnctx);

        const x = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(x);
        const y = c.BN_new() orelse return PkcsError.GeneralError;
        defer c.BN_free(y);
        _ = c.EC_POINT_get_affine_coordinates(group, shared, x, y, bnctx);
        var k_buf: [32]u8 = undefined;
        @memset(&k_buf, 0);
        const xlen = c.BN_num_bytes(x);
        if (xlen > 0 and xlen <= 32)
            _ = c.BN_bn2bin(x, k_buf[@as(usize, @intCast(32 - xlen))..].ptr);

        var k_enc: [16]u8 = undefined;
        kdf(&k_buf, 1, &k_enc);
        kdf(&k_buf, 2, &k_mac);
        std.crypto.secureZero(u8, &k_buf);
        std.crypto.secureZero(u8, &k_enc);
    }

    // STEP 4: mutual auth tokens
    {
        std.debug.print("[PACE] step 4: auth tokens\n", .{});
        const enc_c = encodePubkeyForToken(allocator, &c_eph_oct) catch
            return PkcsError.HostMemory;
        defer allocator.free(enc_c);
        var tpcd_full: [16]u8 = undefined;
        aesCmac(&k_mac, enc_c, &tpcd_full);

        var sbuf: [12]u8 = undefined;
        sbuf[0] = 0x7C;
        sbuf[1] = 0x0A;
        sbuf[2] = 0x85;
        sbuf[3] = 0x08;
        @memcpy(sbuf[4..12], tpcd_full[0..8]);
        const body = try generalAuthenticate(card, allocator, false, &sbuf);
        defer allocator.free(body);
        const inner = innerOf7C(body) orelse return PkcsError.DeviceError;
        const tpicc = tlvFind(inner, 0x86) orelse return PkcsError.DeviceError;
        if (tpicc.len != 8) return PkcsError.DeviceError;

        const enc_t = encodePubkeyForToken(allocator, &t_eph_oct) catch
            return PkcsError.HostMemory;
        defer allocator.free(enc_t);
        var tpicc_full: [16]u8 = undefined;
        aesCmac(&k_mac, enc_t, &tpicc_full);
        if (!std.mem.eql(u8, tpicc, tpicc_full[0..8]))
            return PkcsError.DeviceError;
    }

    std.debug.print("[PACE] handshake SUCCESS\n", .{});
    std.crypto.secureZero(u8, &k_mac);
    std.crypto.secureZero(u8, &nonce_s);
}
