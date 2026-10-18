/// Standalone key-derivation code extracted from 2π Wallet
/// (https://2piwallet.com), a self-custody crypto wallet app.
///
/// Exports the exact mnemonic-to-address logic used by:
///  - the regular ("hot") create/import wallet flow — [deriveEvmKeyFromMnemonic],
///    [deriveEvmAddressFromMnemonic], [deriveBtcFromMnemonic]
///  - the offline Cold Wallet Creator — [ColdWalletDerivation]
///
/// None of this code makes network calls, reads secure storage, or touches
/// the Flutter framework. See the package README for how it maps to the
/// real app source files.
library twopiwallet_key_derivation;

export 'src/evm_derivation.dart';
export 'src/btc_derivation.dart';
export 'src/cold_wallet_derivation.dart';
