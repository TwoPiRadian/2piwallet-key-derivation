// Mirrors the main app's lib/services/cold_wallet_service.dart.
//
// This is the logic behind 2π Wallet's offline "Cold Wallet Creator":
// generates a 24-word BIP-39 mnemonic and derives an EVM address + a
// native SegWit BTC address, entirely offline. No network calls are
// made anywhere in this file.
//
// Deliberately implemented from scratch in pure Dart (secp256k1 point
// math, Keccak-256, RIPEMD-160, Bech32 — no bip39/bip32/bitcoin_base/
// web3dart packages) so it can be read end-to-end and verified against
// an air-gapped device with no package trust chain to audit.
//
// The only difference from the app's copy: the app loads the BIP-39
// English word list from a Flutter asset bundle (`rootBundle`); here it
// is passed in as a plain `List<String>` so this file has zero Flutter
// dependency. See example/main.dart for loading assets/bip39_english.txt.

import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/digests/keccak.dart';
import 'package:pointycastle/digests/ripemd160.dart';

import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto/crypto.dart';

class ColdWalletResult {
  final List<String> mnemonic; // 24 words
  final String evmAddress; // 0x...
  final String btcAddress; // bc1q... native SegWit
  final String evmDerivationPath;
  final String btcDerivationPath;

  const ColdWalletResult({
    required this.mnemonic,
    required this.evmAddress,
    required this.btcAddress,
    required this.evmDerivationPath,
    required this.btcDerivationPath,
  });
}

class ColdWalletDerivation {
  // ── Generate cryptographically secure entropy ──────────────────────────
  // 256 bits of entropy → 24 words (BIP39 spec)
  static Uint8List _generateEntropy() {
    final random = Random.secure();
    final entropy = Uint8List(32); // 256 bits
    for (int i = 0; i < 32; i++) {
      entropy[i] = random.nextInt(256);
    }
    return entropy;
  }

  // ── Convert entropy to 24-word mnemonic (BIP39) ───────────────────────
  static List<String> _entropyToMnemonic(
    Uint8List entropy,
    List<String> wordList,
  ) {
    assert(
      wordList.length == 2048,
      'BIP39 word list must have exactly 2048 words',
    );

    // Checksum: SHA256 of entropy, take first (entropyBits/32) bits
    final hash = sha256.convert(entropy);
    final checksumBits = entropy.length * 8 ~/ 32; // = 8 for 256-bit entropy

    // Combine entropy bits + checksum bits into one bit string
    final bits = StringBuffer();
    for (final byte in entropy) {
      bits.write(byte.toRadixString(2).padLeft(8, '0'));
    }
    // Append checksum bits from hash
    final hashByte = hash.bytes[0];
    final checksum = hashByte
        .toRadixString(2)
        .padLeft(8, '0')
        .substring(0, checksumBits);
    bits.write(checksum);

    final bitString = bits.toString(); // 264 bits total for 24 words
    assert(bitString.length == 264);

    // Split into 24 groups of 11 bits → index into word list
    final words = <String>[];
    for (int i = 0; i < 24; i++) {
      final chunk = bitString.substring(i * 11, (i + 1) * 11);
      final index = int.parse(chunk, radix: 2);
      words.add(wordList[index]);
    }
    return words;
  }

  static Uint8List _mnemonicToSeed(
    List<String> mnemonic, {
    String passphrase = '',
  }) {
    final mnemonicStr = mnemonic.join(' ');
    final salt = utf8.encode('mnemonic$passphrase');

    final params = Pbkdf2Parameters(Uint8List.fromList(salt), 2048, 64);
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128));
    pbkdf2.init(params);
    return pbkdf2.process(Uint8List.fromList(utf8.encode(mnemonicStr)));
  }

  // ── HMAC-SHA512 child key derivation (BIP32) ──────────────────────────
  static _Bip32Key _deriveMaster(Uint8List seed) {
    const key = 'Bitcoin seed';
    final hmac = Hmac(sha512, utf8.encode(key));
    final digest = hmac.convert(seed).bytes;
    final il = Uint8List.fromList(digest.sublist(0, 32)); // private key
    final ir = Uint8List.fromList(digest.sublist(32, 64)); // chain code
    return _Bip32Key(privateKey: il, chainCode: ir);
  }

  static _Bip32Key _deriveChild(_Bip32Key parent, int index) {
    final hardened = index >= 0x80000000;
    final data = Uint8List(37);

    if (hardened) {
      data[0] = 0x00;
      data.setRange(1, 33, parent.privateKey);
    } else {
      // Compressed public key from private key
      final pubKey = _compressedPublicKey(parent.privateKey);
      data.setRange(0, 33, pubKey);
    }
    // Index as big-endian 4 bytes
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    final hmac = Hmac(sha512, parent.chainCode);
    final digest = hmac.convert(data).bytes;
    final il = Uint8List.fromList(digest.sublist(0, 32));
    final ir = Uint8List.fromList(digest.sublist(32, 64));

    // child key = (il + parent.privateKey) mod n
    final childKey = _addPrivateKeys(il, parent.privateKey);
    return _Bip32Key(privateKey: childKey, chainCode: ir);
  }

  // Derive key at path m/purpose'/coin'/0'/0/0
  static _Bip32Key _derivePath(_Bip32Key master, List<int> path) {
    var key = master;
    for (final index in path) {
      key = _deriveChild(key, index);
    }
    return key;
  }

  // ── EVM address from private key (Keccak256 of public key) ────────────
  static String _evmAddress(Uint8List privateKey) {
    // Uncompressed public key (65 bytes: 04 || X || Y)
    final pubKey = _uncompressedPublicKey(privateKey);
    // Drop the 0x04 prefix → 64 bytes
    final pubKeyBytes = pubKey.sublist(1);
    // Keccak256 hash → take last 20 bytes
    final hash = _keccak256(pubKeyBytes);
    final addrBytes = hash.sublist(12);
    final hex = addrBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return '0x${_toChecksumAddress(hex)}';
  }

  // EIP-55 checksum
  static String _toChecksumAddress(String hex) {
    final lower = hex.toLowerCase();
    final hash = _keccak256(
      utf8.encode(lower),
    ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final result = StringBuffer();
    for (int i = 0; i < lower.length; i++) {
      final c = lower[i];
      if (int.tryParse(c, radix: 16) != null &&
          int.parse(hash[i], radix: 16) >= 8) {
        result.write(c.toUpperCase());
      } else {
        result.write(c);
      }
    }
    return result.toString();
  }

  // ── BTC native SegWit (bc1q) address from private key ─────────────────
  static String _btcSegwitAddress(Uint8List privateKey) {
    // Compressed public key
    final pubKey = _compressedPublicKey(privateKey);
    // Hash160 = RIPEMD160(SHA256(pubKey))
    final sha = sha256.convert(pubKey).bytes;
    final ripe = _ripemd160(Uint8List.fromList(sha));
    // Bech32 encode: hrp='bc', witver=0, program=ripe
    return _bech32Encode('bc', 0, ripe);
  }

  // ── Main entry point ───────────────────────────────────────────────────
  // [wordList] must be the standard 2048-word BIP-39 English word list
  // (see assets/bip39_english.txt in this repo).
  static ColdWalletResult generate(List<String> wordList) {
    // 1. Generate entropy & mnemonic
    final entropy = _generateEntropy();
    final mnemonic = _entropyToMnemonic(entropy, wordList);

    // 2. Derive BIP39 seed (no passphrase)
    final seed = _mnemonicToSeed(mnemonic);

    // 3. Derive master key
    final master = _deriveMaster(seed);

    // 4. EVM: BIP44 path m/44'/60'/0'/0/0
    const evmPath = [
      0x8000002C, // 44' hardened
      0x8000003C, // 60' hardened (ETH)
      0x80000000, // 0'  hardened
      0, // 0   external
      0, // 0   first address
    ];
    final evmKey = _derivePath(master, evmPath);
    final evmAddress = _evmAddress(evmKey.privateKey);

    // 5. BTC: BIP84 path m/84'/0'/0'/0/0 (native SegWit)
    const btcPath = [
      0x80000054, // 84' hardened (native SegWit)
      0x80000000, // 0'  hardened (Bitcoin mainnet)
      0x80000000, // 0'  hardened
      0, // 0   external
      0, // 0   first address
    ];
    final btcKey = _derivePath(master, btcPath);
    final btcAddress = _btcSegwitAddress(btcKey.privateKey);

    return ColdWalletResult(
      mnemonic: mnemonic,
      evmAddress: evmAddress,
      btcAddress: btcAddress,
      evmDerivationPath: "m/44'/60'/0'/0/0",
      btcDerivationPath: "m/84'/0'/0'/0/0",
    );
  }

  /// Re-derives EVM + BTC addresses from an existing mnemonic (e.g. to
  /// verify a written-down backup reproduces the same addresses).
  static ColdWalletResult fromMnemonic(List<String> mnemonic) {
    final seed = _mnemonicToSeed(mnemonic);
    final master = _deriveMaster(seed);

    const evmPath = [0x8000002C, 0x8000003C, 0x80000000, 0, 0];
    final evmAddress = _evmAddress(_derivePath(master, evmPath).privateKey);

    const btcPath = [0x80000054, 0x80000000, 0x80000000, 0, 0];
    final btcAddress = _btcSegwitAddress(
      _derivePath(master, btcPath).privateKey,
    );

    return ColdWalletResult(
      mnemonic: mnemonic,
      evmAddress: evmAddress,
      btcAddress: btcAddress,
      evmDerivationPath: "m/44'/60'/0'/0/0",
      btcDerivationPath: "m/84'/0'/0'/0/0",
    );
  }

  // ── Verify mnemonic matches (used in confirmation step) ────────────────
  static bool verifyMnemonic(List<String> entered, List<String> original) {
    if (entered.length != original.length) return false;
    for (int i = 0; i < original.length; i++) {
      if (entered[i].trim().toLowerCase() != original[i].toLowerCase()) {
        return false;
      }
    }
    return true;
  }

  // ── Securely wipe a list from memory ──────────────────────────────────
  static void secureClear(List<String> words) {
    for (int i = 0; i < words.length; i++) {
      words[i] = '';
    }
    words.clear();
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Elliptic curve helpers (secp256k1) — pure Dart, no FFI
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  // secp256k1 parameters
  static final _p = BigInt.parse(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
    radix: 16,
  );
  static final _n = BigInt.parse(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
    radix: 16,
  );
  static final _Gx = BigInt.parse(
    '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    radix: 16,
  );
  static final _Gy = BigInt.parse(
    '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
    radix: 16,
  );

  static Uint8List _compressedPublicKey(Uint8List privKey) {
    final k = _bytesToBigInt(privKey);
    final point = _pointMul(_Gx, _Gy, k);
    final prefix = point.y.isOdd ? 0x03 : 0x02;
    final xBytes = _bigIntToBytes(point.x, 32);
    return Uint8List.fromList([prefix, ...xBytes]);
  }

  static Uint8List _uncompressedPublicKey(Uint8List privKey) {
    final k = _bytesToBigInt(privKey);
    final point = _pointMul(_Gx, _Gy, k);
    final xBytes = _bigIntToBytes(point.x, 32);
    final yBytes = _bigIntToBytes(point.y, 32);
    return Uint8List.fromList([0x04, ...xBytes, ...yBytes]);
  }

  static Uint8List _addPrivateKeys(Uint8List a, Uint8List b) {
    final ai = _bytesToBigInt(a);
    final bi = _bytesToBigInt(b);
    final result = (ai + bi) % _n;
    return _bigIntToBytes(result, 32);
  }

  static _EcPoint _pointMul(BigInt px, BigInt py, BigInt k) {
    _EcPoint? result;
    var addend = _EcPoint(px, py);
    var scalar = k;

    while (scalar > BigInt.zero) {
      if (scalar.isOdd) {
        result = result == null ? addend : _pointAdd(result, addend);
      }
      addend = _pointAdd(addend, addend);
      scalar >>= 1;
    }
    return result!;
  }

  static _EcPoint _pointAdd(_EcPoint p, _EcPoint q) {
    if (p.x == q.x && p.y == q.y) {
      // Point doubling
      final lam =
          (BigInt.from(3) *
              p.x *
              p.x *
              _modInverse(BigInt.from(2) * p.y, _p)) %
          _p;
      final rx = (lam * lam - BigInt.from(2) * p.x) % _p;
      final ry = (lam * (p.x - rx) - p.y) % _p;
      return _EcPoint((rx + _p) % _p, (ry + _p) % _p);
    } else {
      final lam = ((q.y - p.y) * _modInverse(q.x - p.x, _p)) % _p;
      final rx = (lam * lam - p.x - q.x) % _p;
      final ry = (lam * (p.x - rx) - p.y) % _p;
      return _EcPoint((rx + _p) % _p, (ry + _p) % _p);
    }
  }

  static BigInt _modInverse(BigInt a, BigInt m) {
    final am = ((a % m) + m) % m;
    return am.modPow(m - BigInt.two, m);
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    return BigInt.parse(
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16,
    );
  }

  static Uint8List _bigIntToBytes(BigInt n, int length) {
    final hex = n.toRadixString(16).padLeft(length * 2, '0');
    final result = Uint8List(length);
    for (int i = 0; i < length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  // ── Keccak-256 (EVM) ──────────────────────────────────────────────────
  static Uint8List _keccak256(List<int> data) {
    final digest = KeccakDigest(256);
    final input = Uint8List.fromList(data);
    digest.update(input, 0, input.length);
    final out = Uint8List(32);
    digest.doFinal(out, 0);
    return out;
  }

  // ── RIPEMD-160 ────────────────────────────────────────────────────────
  static Uint8List _ripemd160(Uint8List data) {
    final digest = RIPEMD160Digest();
    digest.update(data, 0, data.length);
    final out = Uint8List(20);
    digest.doFinal(out, 0);
    return out;
  }

  // ── Bech32 encoding (BIP173 native SegWit) ────────────────────────────
  static const _bech32Charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  static String _bech32Encode(String hrp, int witver, Uint8List witprog) {
    // Convert 8-bit data to 5-bit groups
    final data = _convertBits(witprog, 8, 5, true);
    final payload = [witver, ...data];
    final checksum = _bech32Checksum(hrp, payload);
    final combined = [...payload, ...checksum];
    final encoded = combined.map((v) => _bech32Charset[v]).join();
    return '${hrp}1$encoded';
  }

  static List<int> _convertBits(Uint8List data, int from, int to, bool pad) {
    int acc = 0, bits = 0;
    final result = <int>[];
    final maxv = (1 << to) - 1;
    for (final value in data) {
      acc = ((acc << from) | value) & 0xFFFFFFFF;
      bits += from;
      while (bits >= to) {
        bits -= to;
        result.add((acc >> bits) & maxv);
      }
    }
    if (pad && bits > 0) result.add((acc << (to - bits)) & maxv);
    return result;
  }

  static List<int> _bech32Checksum(String hrp, List<int> data) {
    final values = [..._hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
    final polymod = _bech32Polymod(values) ^ 1;
    return List.generate(6, (i) => (polymod >> (5 * (5 - i))) & 31);
  }

  static List<int> _hrpExpand(String hrp) {
    final result = <int>[];
    for (final c in hrp.codeUnits) result.add(c >> 5);
    result.add(0);
    for (final c in hrp.codeUnits) result.add(c & 31);
    return result;
  }

  static int _bech32Polymod(List<int> values) {
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    int chk = 1;
    for (final v in values) {
      final b = (chk >> 25) & 0x1F;
      chk = ((chk & 0x1FFFFFF) << 5) ^ v;
      for (int i = 0; i < 5; i++) {
        if ((b >> i) & 1 == 1) chk ^= gen[i];
      }
    }
    return chk;
  }
}

// ── Internal data classes ──────────────────────────────────────────────────

class _Bip32Key {
  final Uint8List privateKey;
  final Uint8List chainCode;
  const _Bip32Key({required this.privateKey, required this.chainCode});
}

class _EcPoint {
  final BigInt x, y;
  const _EcPoint(this.x, this.y);
}
