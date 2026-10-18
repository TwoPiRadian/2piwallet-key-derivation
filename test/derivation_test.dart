// Verifies the extracted derivation code against well-known public test
// vectors, and checks the Cold Wallet Creator's generate/verify round-trip.
import 'dart:io';

import 'package:test/test.dart';
import 'package:twopiwallet_key_derivation/twopiwallet_key_derivation.dart';

// Standard BIP-39 test mnemonic used across the ecosystem (e.g. the
// "abandon...about" vector from the trezor/python-mnemonic test suite).
const testMnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon about';

void main() {
  group('EVM derivation', () {
    test('matches the well-known test-vector address', () async {
      // This address for the "abandon...about" mnemonic at m/44'/60'/0'/0/0
      // is a widely published reference value (e.g. MetaMask/ethers.js docs).
      final address = await deriveEvmAddressFromMnemonic(testMnemonic);
      expect(address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
    });
  });

  group('BTC derivation', () {
    test('produces a valid bc1q native SegWit address', () {
      final (address, wif) = deriveBtcFromMnemonic(testMnemonic);
      expect(address, startsWith('bc1q'));
      expect(wif, isNotEmpty);
    });
  });

  group('Cold Wallet Creator', () {
    late List<String> wordList;

    setUpAll(() async {
      wordList = await File(
        'assets/bip39_english.txt',
      ).readAsLines().then((l) => l.where((w) => w.isNotEmpty).toList());
    });

    test('word list has exactly 2048 entries', () {
      expect(wordList.length, 2048);
    });

    test('generates a valid 24-word mnemonic with addresses', () {
      final result = ColdWalletDerivation.generate(wordList);
      expect(result.mnemonic.length, 24);
      expect(result.evmAddress, startsWith('0x'));
      expect(result.btcAddress, startsWith('bc1q'));
    });

    test('re-deriving from the same mnemonic reproduces the same addresses', () {
      final first = ColdWalletDerivation.generate(wordList);
      final second = ColdWalletDerivation.fromMnemonic(first.mnemonic);
      expect(second.evmAddress, first.evmAddress);
      expect(second.btcAddress, first.btcAddress);
    });

    test('verifyMnemonic correctly accepts/rejects', () {
      final result = ColdWalletDerivation.generate(wordList);
      expect(ColdWalletDerivation.verifyMnemonic(result.mnemonic, result.mnemonic), isTrue);

      final wrong = [...result.mnemonic];
      wrong[0] = wrong[0] == 'abandon' ? 'zoo' : 'abandon';
      expect(ColdWalletDerivation.verifyMnemonic(wrong, result.mnemonic), isFalse);
    });
  });
}
