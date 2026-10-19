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
final testMnemonicWords = testMnemonic.split(' ');

// Known-correct outputs for [testMnemonic], from authoritative specs —
// not derived from this repo's own code, so they can actually catch a
// regression instead of just checking the code agrees with itself.
//
//  - EVM: widely published reference value for m/44'/60'/0'/0/0
//    (e.g. MetaMask/ethers.js docs).
//  - BTC: the official BIP-84 spec test vector for m/84'/0'/0'/0/0
//    (https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki).
const expectedEvmAddress = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
const expectedBtcAddress = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';

void main() {
  group('EVM derivation', () {
    test('matches the well-known test-vector address', () async {
      final address = await deriveEvmAddressFromMnemonic(testMnemonic);
      expect(address, expectedEvmAddress);
    });
  });

  group('BTC derivation', () {
    test('matches the official BIP-84 spec test-vector address', () {
      final (address, wif) = deriveBtcFromMnemonic(testMnemonic);
      expect(address, expectedBtcAddress);
      expect(wif, isNotEmpty);
    });
  });

  group('Cold Wallet Creator derivation, cross-checked against the hot wallet', () {
    // ColdWalletDerivation is a completely separate, from-scratch
    // implementation (raw secp256k1 point math, Keccak-256, RIPEMD-160,
    // Bech32 — no bip32/bip39/bitcoin_base/web3dart packages). Feeding it
    // the SAME test mnemonic as above and checking it lands on the SAME
    // known-correct addresses proves two independently-written code paths
    // agree with each other and with the public spec — not just that one
    // implementation agrees with itself. If a future refactor broke either
    // file's math, this would very likely catch it, where a format-only
    // check (e.g. "address starts with bc1q") would not.
    test('matches the same test-vector addresses as the hot wallet', () {
      final result = ColdWalletDerivation.fromMnemonic(testMnemonicWords);
      expect(result.evmAddress, expectedEvmAddress);
      expect(result.btcAddress, expectedBtcAddress);
    });
  });

  group('Cold Wallet Creator generation', () {
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
