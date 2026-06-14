const std = @import("std");

const hasher = @import("hasher.zig");
const pkcs = @import("pkcs.zig").pkcs;

const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

// rfc8017 - Section 9.2
const md5_prefix: [18]u8 = [_]u8{ 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
const sha1_prefix: [15]u8 = [_]u8{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
const sha256_prefix: [19]u8 = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
const sha384_prefix: [19]u8 = [_]u8{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
const sha512_prefix: [19]u8 = [_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

pub const signature_size: usize = 256;
pub const encrypted_data_size: usize = 256;

pub const SignType = enum {
    RawRsa,
    Pkcs1Pad,
    DigestAndSign,
};

pub fn signTypeFromMechanism(mechanism: pkcs.CK_MECHANISM_TYPE) PkcsError!SignType {
    return switch (mechanism) {
        pkcs.CKM_RSA_X_509 => .RawRsa,
        pkcs.CKM_RSA_PKCS => .Pkcs1Pad,
        pkcs.CKM_MD5_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA1_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA256_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA384_RSA_PKCS => .DigestAndSign,
        pkcs.CKM_SHA512_RSA_PKCS => .DigestAndSign,
        else => return PkcsError.MechanismInvalid,
    };
}

pub const Type = enum {
    None,
    Digest,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Search,
};

pub const None = struct {};

pub const Digest = struct {
    hasher: hasher.Hasher,
    multipart_operation: bool,

    pub fn deinit(self: *Digest, allocator: std.mem.Allocator) void {
        self.hasher.destroy(allocator);
    }
};

pub const Sign = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    key_size: usize,
    sign_type: SignType,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn update(self: *Sign, allocator: std.mem.Allocator, data: []const u8) PkcsError!void {
        switch (self.sign_type) {
            .DigestAndSign => self.hasher.?.update(data),
            .RawRsa, .Pkcs1Pad => {
                self.msg_buffer.?.appendSlice(allocator, data) catch
                    return PkcsError.HostMemory;
            },
        }
    }

    pub fn createSignRequest(self: *Sign, allocator: std.mem.Allocator) PkcsError![]u8 {
        return switch (self.sign_type) {
            .RawRsa => createRawSignRequest(&self.msg_buffer, allocator, self.key_size),
            .Pkcs1Pad => createPkcs1PaddedSignRequest(&self.msg_buffer, allocator, self.key_size),
            .DigestAndSign => createHashedSignRequest(&self.hasher.?, allocator),
        };
    }

    pub fn deinit(self: *Sign, allocator: std.mem.Allocator) void {
        if (self.hasher != null)
            self.hasher.?.destroy(allocator);

        if (self.msg_buffer != null)
            self.msg_buffer.?.deinit(allocator);
    }
};

pub const Verify = struct {
    private_key: pkcs.CK_OBJECT_HANDLE,
    key_size: usize,
    sign_type: SignType,
    multipart_operation: bool,
    hasher: ?hasher.Hasher,
    msg_buffer: ?std.ArrayList(u8),

    pub fn update(self: *Verify, allocator: std.mem.Allocator, data: []const u8) PkcsError!void {
        switch (self.sign_type) {
            .DigestAndSign => self.hasher.?.update(data),
            .RawRsa, .Pkcs1Pad => {
                self.msg_buffer.?.appendSlice(allocator, data) catch
                    return PkcsError.HostMemory;
            },
        }
    }

    pub fn createSignRequest(self: *Verify, allocator: std.mem.Allocator) PkcsError![]u8 {
        return switch (self.sign_type) {
            .RawRsa => createRawSignRequest(&self.msg_buffer, allocator, self.key_size),
            .Pkcs1Pad => createPkcs1PaddedSignRequest(&self.msg_buffer, allocator, self.key_size),
            .DigestAndSign => createHashedSignRequest(&self.hasher.?, allocator),
        };
    }

    pub fn deinit(self: *Verify, allocator: std.mem.Allocator) void {
        if (self.hasher != null)
            self.hasher.?.destroy(allocator);

        if (self.msg_buffer != null)
            self.msg_buffer.?.deinit(allocator);
    }
};

pub const Encrypt = struct {
    multipart_operation: bool,
    public_key: pkcs.CK_OBJECT_HANDLE,
    modulus: []const u8,
    exponent: []const u8,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn update(self: *Encrypt, allocator: std.mem.Allocator, data: []const u8) PkcsError![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return PkcsError.HostMemory;

        return &[_]u8{};
    }

    fn pad(self: *Encrypt, allocator: std.mem.Allocator) PkcsError![256]u8 {
        var buf: [256]u8 = [1]u8{0x00} ** encrypted_data_size;

        if (self.raw) {
            if (self.msg_buffer.items.len != encrypted_data_size)
                return PkcsError.DataLenRange;
        } else {
            if (self.msg_buffer.items.len > encrypted_data_size - 11)
                return PkcsError.DataLenRange;
        }

        const msg = self.msg_buffer.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;
        defer allocator.free(msg);
        defer std.crypto.secureZero(u8, msg);

        if (!self.raw) {
            const rand = std.crypto.random;
            const difference: usize = encrypted_data_size - msg.len - 3;

            buf[1] = 0x02;

            for (2..2 + difference) |i| {
                buf[i] = rand.uintLessThan(u8, std.math.maxInt(u8)) + 1;
            }
        }

        @memcpy(buf[(encrypted_data_size - msg.len)..], msg);

        return buf;
    }

    pub fn encrypt(self: *Encrypt, allocator: std.mem.Allocator) PkcsError![256]u8 {
        const rsa_public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(self.exponent, self.modulus) catch
            return PkcsError.GeneralError;

        const max_modulus_bits = 4096;
        const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
        const Fe = Modulus.Fe;

        const buffer = try self.pad(allocator);

        const m = Fe.fromBytes(rsa_public_key.n, buffer[0..], .big) catch
            return PkcsError.GeneralError;

        const e = rsa_public_key.n.powPublic(m, rsa_public_key.e) catch
            return PkcsError.GeneralError;

        var result: [256]u8 = undefined;
        e.toBytes(&result, .big) catch
            return PkcsError.HostMemory;

        return result;
    }

    pub fn deinit(self: *Encrypt, allocator: std.mem.Allocator) void {
        self.msg_buffer.deinit(allocator);
    }
};

pub const Decrypt = struct {
    multipart_operation: bool,
    private_key: pkcs.CK_OBJECT_HANDLE,
    msg_buffer: std.ArrayList(u8),
    raw: bool,

    pub fn update(self: *Decrypt, allocator: std.mem.Allocator, data: []const u8) PkcsError![]u8 {
        self.msg_buffer.appendSlice(allocator, data) catch
            return PkcsError.HostMemory;

        return &[_]u8{};
    }

    pub fn createDecryptRequest(self: *Decrypt, allocator: std.mem.Allocator) PkcsError![]u8 {
        return self.msg_buffer.toOwnedSlice(allocator) catch
            return PkcsError.HostMemory;
    }

    pub fn stripPad(self: *const Decrypt, data: []const u8) PkcsError![]const u8 {
        if (self.raw)
            return data;

        var start_index: usize = 0;

        for (data, 0..) |b, i| {
            start_index += 1;

            if (b == 0 and i > 0)
                break;
        }

        if (start_index >= data.len)
            return PkcsError.GeneralError;

        return data[start_index..];
    }

    pub fn deinit(self: *Decrypt, allocator: std.mem.Allocator) void {
        self.msg_buffer.deinit(allocator);
    }
};

pub const Search = struct {
    index: usize,
    found_objects: []pkcs.CK_OBJECT_HANDLE,

    pub fn deinit(self: *Search, allocator: std.mem.Allocator) void {
        allocator.free(self.found_objects);
    }
};

pub const Operation = union(enum) {
    none: None,
    digest: Digest,
    sign: Sign,
    verify: Verify,
    encrypt: Encrypt,
    decrypt: Decrypt,
    search: Search,

    pub fn deinit(self: *Operation, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .none => {},
            .digest => self.digest.deinit(allocator),
            .sign => self.sign.deinit(allocator),
            .verify => self.verify.deinit(allocator),
            .encrypt => self.encrypt.deinit(allocator),
            .decrypt => self.decrypt.deinit(allocator),
            .search => self.search.deinit(allocator),
        }
    }
};

fn createRawSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator, key_size: usize) PkcsError![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;
    errdefer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len != key_size)
        return PkcsError.DataLenRange;

    return payload;
}

fn createPkcs1PaddedSignRequest(msg_buffer: *?std.ArrayList(u8), allocator: std.mem.Allocator, key_size: usize) PkcsError![]u8 {
    const payload = msg_buffer.*.?.toOwnedSlice(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(payload);

    msg_buffer.* = null;

    if (payload.len > key_size - 11)
        return PkcsError.DataLenRange;

    var request = allocator.alloc(u8, key_size) catch
        return PkcsError.HostMemory;

    for (request) |*b|
        b.* = 0xff;

    const data_start_index = key_size - payload.len;
    request[0] = 0x00;
    request[1] = 0x01;
    request[data_start_index - 1] = 0x00;
    @memcpy(request[data_start_index..key_size], payload);

    return request;
}

fn createHashedSignRequest(hash: *hasher.Hasher, allocator: std.mem.Allocator) PkcsError![]u8 {
    const prefix = getPrefixFromHasher(hash);

    const payload = hash.finalize(allocator) catch
        return PkcsError.HostMemory;
    defer allocator.free(payload);

    // Build the DigestInfo (prefix || hash)
    const di_len = prefix.len + payload.len;

    // PKCS#1 v1.5 type-1 pad the DigestInfo to the key size (256 bytes for RSA-2048):
    //   00 01 FF..FF 00 <DigestInfo>
    const key_size: usize = signature_size; // 256
    if (di_len + 11 > key_size)
        return PkcsError.DataLenRange;

    var request = allocator.alloc(u8, key_size) catch
        return PkcsError.HostMemory;

    for (request) |*b|
        b.* = 0xff;

    const data_start_index = key_size - di_len;
    request[0] = 0x00;
    request[1] = 0x01;
    request[data_start_index - 1] = 0x00;
    @memcpy(request[data_start_index .. data_start_index + prefix.len], prefix);
    @memcpy(request[data_start_index + prefix.len .. key_size], payload);

    return request;
}

fn getPrefixFromHasher(hash: *hasher.Hasher) []const u8 {
    return switch (hash.*.hasherType.?) {
        .md5 => md5_prefix[0..md5_prefix.len],
        .sha1 => sha1_prefix[0..sha1_prefix.len],
        .sha256 => sha256_prefix[0..sha256_prefix.len],
        .sha384 => sha384_prefix[0..sha384_prefix.len],
        .sha512 => sha512_prefix[0..sha512_prefix.len],
    };
}

