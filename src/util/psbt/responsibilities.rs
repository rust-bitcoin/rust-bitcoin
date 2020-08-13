use hashes::core::fmt::Debug;
use secp256k1::{Message, Signature};
use util::bip32::{DerivationPath, ExtendedPrivKey, Fingerprint};
use util::psbt::PartiallySignedTransaction;
use {Address, Amount};
use {Script, TxOut};

/// This trait corresponds to the Creator and Updater responsibility described in
/// [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#creator). As noted
/// there the both functionalities are most often combined as the creator most likely has more meta
/// information about the transaction they are creating and is thus able to put it into the PSBT
/// (which otherwise would be a separate update step).
pub trait PsbtWallet {
    /// Wallet backend specific errors like database connection errors that aren't captured in
    /// `PsbtCreationError`.
    type Error: Debug;

    /// Create a transaction that pays a set of outputs.
    fn create_transaction(
        &mut self,
        outputs: &[TxOut],
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>>;

    /// Creates a transaction that pays a certain `amount` to a `script` and keeps the change
    fn pay_to_script(
        &mut self,
        script_pk: Script,
        amount: Amount,
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>> {
        self.create_transaction(&[TxOut {
            value: amount.as_sat(),
            script_pubkey: script_pk,
        }])
    }

    /// Creates a transaction that pays a certain `amount` to an `address` and keeps the change
    fn pay_to_address(
        &mut self,
        address: Address,
        amount: Amount,
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>> {
        self.pay_to_script(address.script_pubkey(), amount)
    }
}

/// Common errors when creating a transaction
#[derive(Debug)]
pub enum PsbtCreationError<E: Debug> {
    /// The wallet doens't control a sufficient amount of Bitcoins to fund the transaction
    InsufficientFunds,
    /// One of the outputs has a value below the dust limit
    OutputBelowDustLimit,
    /// Too many outputs were supplied
    TooManyOutputs,
    /// Wallet backend error
    WalletError(E),
}

/// A signer capable of signing PSBTs. This can either be a software signer (see the implementation
/// for `ExtendedSecretKey`) or a hardware device.
pub trait SignPsbt {
    /// Signing backend error type
    type Error: Debug;

    /// PSBT validation function that can be used by custom signers too
    fn validate(&self, psbt: &PartiallySignedTransaction) -> Result<(), PsbtValidationError> {
        // default validator impl
        unimplemented!()
    }

    /// Signs all inputs for which it controls the keys and adds the signatures to the PSBT
    fn sign_psbt(
        &mut self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, PsbtSignError<Self::Error>>;
}

/// Common errors in the signing stage
#[derive(Debug)]
pub enum PsbtSignError<E: Debug> {
    /// The PSBT is not valid for signig according to BIP-174
    ValidationError(PsbtValidationError),
    /// Error of the signing backend
    BackendError(E),
}

/// Errors that can happen when validating a PSBT before signing
#[derive(Debug)]
pub enum PsbtValidationError {}

impl<T, E> SignPsbt for T
where
    T: Fn(Message, Fingerprint, DerivationPath) -> Result<Option<Signature>, E>,
    E: Debug,
{
    type Error = E;

    fn sign_psbt(
        &mut self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, PsbtSignError<Self::Error>> {
        self.validate(&psbt)
            .map_err(PsbtSignError::ValidationError)?;

        // PSBT signing logic goes here
        unimplemented!()
    }
}

impl SignPsbt for ExtendedPrivKey {
    type Error = secp256k1::Error;

    fn sign_psbt(
        &mut self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, PsbtSignError<Self::Error>> {
        let mut sign_closure = |msg, fp, path| -> Result<Option<Signature>, Self::Error> {
            let ctx = secp256k1::Secp256k1::new();
            if self.fingerprint(&ctx) != fp {
                return Ok(None);
            }

            let key = match self.derive_priv(&ctx, &path) {
                Ok(key) => key,
                Err(crate::util::bip32::Error::Ecdsa(e)) => return Err(e),
                _ => unreachable!(),
            };

            Ok(Some(ctx.sign(&msg, &key.private_key.key)))
        };
        sign_closure.sign_psbt(psbt)
    }
}
