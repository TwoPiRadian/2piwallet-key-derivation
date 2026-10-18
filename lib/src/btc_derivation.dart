// Mirrors the BTC derivation in the main app's
// lib/services/btc_wallet_service.dart (`_deriveFromMnemonic` /
// `_bech32Encode`).
//
// Used by 2π Wallet's regular ("hot") wallet to derive a native SegWit
// (bc1q…) Bitcoin address from the SAME mnemonic used for the EVM address
// (see evm_derivation.dart) — one seed, one path per asset.

import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:bitcoin_base/bitcoin_base.dart';

/// BIP-84 path for native SegWit Bitcoin: m/84'/0'/0'/0/0
/// Matches Trust Wallet, Ledger, and most modern wallets.
const String defaultBtcDerivationPath = "m/84'/0'/0'/0/0";

/// Derives the native SegWit (bc1q…) address and WIF private key for
/// [mnemonic] at [path]. No network calls, no storage — pure function.
(String address, String wif) deriveBtcFromMnemonic(
  String mnemonic, {
  String path = defaultBtcDerivationPath,
}) {
  final seed = bip39.mnemonicToSeed(mnemonic);
  final root = bip32.BIP32.fromSeed(seed);
  final child = root.derivePath(path);

  final privateKeyBytes = child.privateKey;
  if (privateKeyBytes == null) throw Exception('BTC key derivation failed');

  // Same library the app uses for signing, so address + WIF round-trip
  // correctly through bitcoin_base elsewhere in the codebase.
  final ecPriv = ECPrivate.fromBytes(privateKeyBytes);
  final ecPub = ecPriv.getPublic();

  final p2wpkh = ecPub.toSegwitAddress();
  final hex = p2wpkh.addressProgram;
  final hash160 = List<int>.generate(
    hex.length ~/ 2,
    (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
  );
  final address = bech32Encode('bc', 0, hash160);
  final wif = ecPriv.toWif();

  return (address, wif);
}

/// Pure-Dart Bech32 encoder for P2WPKH bc1q addresses (BIP-173).
String bech32Encode(String hrp, int witVer, List<int> witProg) {
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  final data = <int>[witVer];
  int acc = 0, bits = 0;
  for (final v in witProg) {
    acc = ((acc << 8) | v) & 0xFFFF;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data.add((acc >> bits) & 31);
    }
  }
  if (bits > 0) data.add((acc << (5 - bits)) & 31);

  List<int> expand(String s) => [
    ...s.runes.map((c) => c >> 5),
    0,
    ...s.runes.map((c) => c & 31),
  ];

  int polymod(List<int> v) {
    const g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    int chk = 1;
    for (final d in v) {
      final b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ d;
      for (int i = 0; i < 5; i++) {
        if ((b >> i) & 1 != 0) chk ^= g[i];
      }
    }
    return chk;
  }

  final cs = polymod([...expand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  final full = [
    ...data,
    ...List.generate(6, (i) => (cs >> (5 * (5 - i))) & 31),
  ];
  final encoded = full.map((d) => charset[d]).join();
  return '${hrp}1$encoded';
}
