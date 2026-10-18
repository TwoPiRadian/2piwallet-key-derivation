// Demonstrates both derivation paths side by side:
//  1. "Hot" wallet: a normal 12-word mnemonic → EVM address + BTC address.
//  2. Cold Wallet Creator: a freshly generated 24-word mnemonic → EVM
//     address + BTC address, entirely offline.
//
// Run with: dart run example/main.dart
import 'dart:io';

import 'package:bip39/bip39.dart' as bip39;
import 'package:twopiwallet_key_derivation/twopiwallet_key_derivation.dart';

Future<void> main() async {
  print('── Hot wallet (12-word) ─────────────────────────────');

  // In the real app this mnemonic is generated once and stored in secure
  // storage; here we just generate one locally to demonstrate derivation.
  final hotMnemonic = bip39.generateMnemonic(strength: 128);
  print('Mnemonic: $hotMnemonic');

  final evmAddress = await deriveEvmAddressFromMnemonic(hotMnemonic);
  print('EVM address ($defaultEvmDerivationPath): $evmAddress');

  final (btcAddress, btcWif) = deriveBtcFromMnemonic(hotMnemonic);
  print('BTC address ($defaultBtcDerivationPath): $btcAddress');
  print('BTC WIF: $btcWif');

  print('\n── Cold Wallet Creator (24-word, offline) ───────────');

  final wordList = await File(
    'assets/bip39_english.txt',
  ).readAsLines().then((lines) => lines.where((w) => w.isNotEmpty).toList());

  final cold = ColdWalletDerivation.generate(wordList);
  print('Mnemonic: ${cold.mnemonic.join(' ')}');
  print('EVM address (${cold.evmDerivationPath}): ${cold.evmAddress}');
  print('BTC address (${cold.btcDerivationPath}): ${cold.btcAddress}');

  // Re-deriving from the same mnemonic must reproduce identical addresses —
  // this is exactly what the app's "confirm your backup" step relies on.
  final rederived = ColdWalletDerivation.fromMnemonic(cold.mnemonic);
  final matches =
      rederived.evmAddress == cold.evmAddress &&
      rederived.btcAddress == cold.btcAddress;
  print('Re-derivation matches original: $matches');
}
