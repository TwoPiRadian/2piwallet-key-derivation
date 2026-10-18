// Mirrors the EVM derivation in the main app's
// lib/services/evm_wallet_service.dart (`_deriveEthKeyFromMnemonic`).
//
// Used by 2π Wallet's regular ("hot") create/import wallet flow for
// Ethereum and all other EVM chains the app supports (BSC, Polygon,
// Avalanche, Fantom, Base, etc. — they all share one address since they
// are the same curve/derivation, just different networks).

import 'package:bip39/bip39.dart' as bip39;
import 'package:bip32/bip32.dart' as bip32;
import 'package:web3dart/crypto.dart';
import 'package:web3dart/web3dart.dart';

/// BIP-44 path for Ethereum / EVM chains: m/44'/60'/0'/0/0
const String defaultEvmDerivationPath = "m/44'/60'/0'/0/0";

/// Derives the EVM private key for [mnemonic] at [path] (BIP-39 seed →
/// BIP-32 HD derivation). No network calls, no storage — pure function.
///
/// This file only *derives* from an existing mnemonic — it never
/// generates one, so there's no randomness here to audit. The hot
/// wallet's mnemonic is created by `bip39.generateMnemonic()` (see
/// example/main.dart), which uses `Random.secure()` internally — the
/// same cryptographically-secure source the Cold Wallet Creator in
/// cold_wallet_derivation.dart calls directly and visibly.
EthPrivateKey deriveEvmKeyFromMnemonic(
  String mnemonic, {
  String path = defaultEvmDerivationPath,
}) {
  final seed = bip39.mnemonicToSeed(mnemonic);
  final root = bip32.BIP32.fromSeed(seed);
  final child = root.derivePath(path);

  final pkBytes = child.privateKey;
  if (pkBytes == null) throw Exception('Failed to derive private key');

  return EthPrivateKey.fromHex(bytesToHex(pkBytes, include0x: true));
}

/// Derives the checksummed (EIP-55) EVM address for [mnemonic] at [path].
Future<String> deriveEvmAddressFromMnemonic(
  String mnemonic, {
  String path = defaultEvmDerivationPath,
}) async {
  final key = deriveEvmKeyFromMnemonic(mnemonic, path: path);
  return (await key.extractAddress()).hexEip55;
}
