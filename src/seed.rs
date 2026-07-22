// SPDX-License-Identifier: Apache-2.0
//! BIP-39 / BIP-32 seed derivation — the OPT-IN secp256k1 self-custody path.

use bip32::{DerivationPath, Language, Mnemonic, XPrv};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::did::{Curve, KeyPair};
use crate::error::CryptoError;

/// The pinned BIP-44 derivation path for a Phi self-custody k1 identity: the standard Cosmos account path (coin type 118), first account, external chain, first address.
pub const K1_DERIVATION_PATH: &str = "m/44'/118'/0'/0/0";

/// Word count of a generated recovery phrase: 24 words = 256 bits of entropy.
pub const MNEMONIC_WORD_COUNT: usize = 24;

/// Generates a fresh 24-word BIP-39 recovery phrase from the OS CSPRNG.
pub fn generate_mnemonic() -> Zeroizing<String> {
    let mnemonic = Mnemonic::random(rand_core::OsRng, Language::English);
    Zeroizing::new(mnemonic.phrase().to_string())
}

/// Derives the Phi self-custody k1 key pair from a BIP-39 mnemonic at the pinned [`K1_DERIVATION_PATH`].
pub fn derive_k1_keypair(mnemonic: &str, passphrase: &str) -> Result<KeyPair, CryptoError> {
    derive_k1_keypair_at(mnemonic, passphrase, K1_DERIVATION_PATH)
}

/// Derivation at an explicit path.
fn derive_k1_keypair_at(
    mnemonic: &str,
    passphrase: &str,
    path: &str,
) -> Result<KeyPair, CryptoError> {
    let mnemonic = Mnemonic::new(mnemonic.trim(), Language::English)
        .map_err(|_| CryptoError::InvalidInput("mnemonic is not a valid BIP-39 phrase"))?;
    let path: DerivationPath = path
        .parse()
        .map_err(|_| CryptoError::InvalidInput("invalid BIP-32 derivation path"))?;

    let passphrase = Zeroizing::new(passphrase.nfkd().collect::<String>());
    let seed = mnemonic.to_seed(&passphrase);
    let xprv = XPrv::derive_from_path(&seed, &path)
        .map_err(|_| CryptoError::Backend("BIP-32 derivation failed"))?;

    let sk: &k256::ecdsa::SigningKey = xprv.private_key();
    let pk = k256::ecdsa::VerifyingKey::from(sk);
    // Wrap the transient scalar bytes so this stack copy is wiped on drop, not just the Vec.
    let sk_bytes = Zeroizing::new(sk.to_bytes());
    Ok(KeyPair {
        curve: Curve::Secp256k1,
        secret: Zeroizing::new(sk_bytes.to_vec()),
        public: pk.to_sec1_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did;

    /// The official BIP-39 test vector (Trezor): 32 bytes of zero entropy, passphrase "TREZOR".
    const KAT_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const KAT_SEED_TREZOR: &str = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8";

    #[test]
    fn bip39_seed_matches_the_official_vector() {
        let m = Mnemonic::new(KAT_MNEMONIC, Language::English).unwrap();
        let seed = m.to_seed("TREZOR");
        assert_eq!(hex::encode(seed.as_bytes()), KAT_SEED_TREZOR);
    }

    #[test]
    fn generated_mnemonic_is_24_words_and_re_derivable() {
        let phrase = generate_mnemonic();
        assert_eq!(phrase.split_whitespace().count(), MNEMONIC_WORD_COUNT);
        let a = derive_k1_keypair(&phrase, "").unwrap();
        let b = derive_k1_keypair(&phrase, "").unwrap();
        assert_eq!(a.secret.to_vec(), b.secret.to_vec());
    }

    /// THE RECOVERY PROPERTY, in one assertion: the same mnemonic always derives the same key, so a user who loses their device re-derives the identical identity — no chain interaction at all.
    #[test]
    fn derivation_is_deterministic() {
        let first = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        let after_device_loss = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        assert_eq!(first.secret.to_vec(), after_device_loss.secret.to_vec());
        assert_eq!(first.public, after_device_loss.public);
        assert_eq!(
            did::did_from_public(Curve::Secp256k1, &first.public).unwrap(),
            did::did_from_public(Curve::Secp256k1, &after_device_loss.public).unwrap(),
        );
    }

    /// The passphrase and the path each bind the key.
    #[test]
    fn passphrase_and_path_change_the_key() {
        let base = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        let with_passphrase = derive_k1_keypair(KAT_MNEMONIC, "TREZOR").unwrap();
        assert_ne!(base.secret.to_vec(), with_passphrase.secret.to_vec());

        let other_account = derive_k1_keypair_at(KAT_MNEMONIC, "", "m/44'/118'/1'/0/0").unwrap();
        let other_index = derive_k1_keypair_at(KAT_MNEMONIC, "", "m/44'/118'/0'/0/1").unwrap();
        assert_ne!(base.secret.to_vec(), other_account.secret.to_vec());
        assert_ne!(base.secret.to_vec(), other_index.secret.to_vec());
    }

    /// A seed-derived key is an ORDINARY k1 key: it signs and verifies through the normal did path, and yields the canonical dual-curve DID (tag 0x01 ‖ compressed SEC1) from Slice 0.
    #[test]
    fn derived_key_is_an_ordinary_k1_identity() {
        let kp = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        assert_eq!(kp.curve, Curve::Secp256k1);
        assert_eq!(kp.secret.len(), 32);
        assert_eq!(kp.public.len(), 33, "compressed SEC1, as k256 emits");

        let msg = b"phi seed-derived identity";
        let sig = did::sign(Curve::Secp256k1, &kp.secret, msg).unwrap();
        assert!(did::verify(Curve::Secp256k1, &kp.public, msg, &sig));

        let did = did::did_from_public(Curve::Secp256k1, &kp.public).unwrap();
        assert!(did.starts_with("did:phi:"));
        assert_eq!(did.len(), "did:phi:".len() + 64);
    }

    /// A wrong phrase is not a near miss — it is somebody else's identity (or nobody's).
    #[test]
    fn wrong_mnemonic_derives_a_different_identity() {
        let right = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        let wrong = generate_mnemonic();
        let wrong = derive_k1_keypair(&wrong, "").unwrap();
        assert_ne!(right.secret.to_vec(), wrong.secret.to_vec());
        assert_ne!(
            did::did_from_public(Curve::Secp256k1, &right.public).unwrap(),
            did::did_from_public(Curve::Secp256k1, &wrong.public).unwrap(),
        );
    }

    /// CROSS-LANGUAGE KNOWN-ANSWER VECTOR — the load-bearing one.
    #[test]
    fn cross_language_kat_matches_the_cosmos_sdk_derivation() {
        let kp = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        assert_eq!(
            hex::encode(&*kp.secret),
            "8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7",
            "secret scalar at m/44'/118'/0'/0/0"
        );
        assert_eq!(
            hex::encode(&kp.public),
            "02ba66a84cf7839af172a13e7fc9f5e7008cb8bca1585f8f3bafb3039eda3c1fdd",
            "compressed SEC1 public key"
        );
        assert_eq!(
            did::did_from_public(Curve::Secp256k1, &kp.public).unwrap(),
            "did:phi:17010867b1779053627535b78920d69733c4ef4725ad72c78948f1b14387472c",
            "canonical dual-curve k1 DID (tag 0x01 ‖ compressed SEC1), per Slice 0"
        );
    }

    /// A Persian passphrase, written two ways that a user cannot tell apart and platforms disagree about.
    const PASSPHRASE_NFC: &str = "رمز م\u{0624}سسه";
    const PASSPHRASE_NFD: &str = "رمز م\u{0648}\u{0654}سسه";

    #[test]
    fn persian_passphrase_nfc_and_nfd_derive_the_same_key() {
        assert_ne!(
            PASSPHRASE_NFC.as_bytes(),
            PASSPHRASE_NFD.as_bytes(),
            "the two forms must differ on the wire for this test to be meaningful"
        );

        let composed = derive_k1_keypair(KAT_MNEMONIC, PASSPHRASE_NFC).unwrap();
        let decomposed = derive_k1_keypair(KAT_MNEMONIC, PASSPHRASE_NFD).unwrap();

        assert_eq!(
            composed.secret.to_vec(),
            decomposed.secret.to_vec(),
            "NFC and NFD of the same passphrase must derive one key"
        );
        assert_eq!(composed.public, decomposed.public);
        assert_eq!(
            did::did_from_public(Curve::Secp256k1, &composed.public).unwrap(),
            did::did_from_public(Curve::Secp256k1, &decomposed.public).unwrap(),
            "…and therefore one identity",
        );
    }

    /// NFKD, not merely NFD: a compatibility character must fold too.
    #[test]
    fn passphrase_normalization_is_nfkd_not_nfd() {
        let presentation = derive_k1_keypair(KAT_MNEMONIC, "\u{FEFB}").unwrap();
        let canonical = derive_k1_keypair(KAT_MNEMONIC, "\u{0644}\u{0627}").unwrap();
        assert_eq!(
            presentation.secret.to_vec(),
            canonical.secret.to_vec(),
            "a compatibility form must normalize to its canonical spelling (NFKD, not NFD)"
        );
    }

    /// KNOWN-ANSWER VECTOR for the non-ASCII passphrase path — the bytes are pinned so a future change to the normalization step (dropping it, or moving to NFC/NFD) cannot pass silently.
    #[test]
    fn persian_passphrase_kat() {
        let kp = derive_k1_keypair(KAT_MNEMONIC, PASSPHRASE_NFC).unwrap();
        assert_eq!(
            hex::encode(&*kp.secret),
            "3cabcf9753c826c9a2a8907bfc5345cabc747a85cd1b2e66dab46948a62a702c",
            "secret scalar at m/44'/118'/0'/0/0 with the NFKD-normalized Persian passphrase"
        );
        assert_eq!(
            hex::encode(&kp.public),
            "03e6ab3671b981a2c0ebb55bc7e2d49faada34cf6d4cc6bd7c87d0c7daee7e1fbf",
            "compressed SEC1 public key"
        );
        assert_eq!(
            did::did_from_public(Curve::Secp256k1, &kp.public).unwrap(),
            "did:phi:9f07779bc5bfede9fcd9679db51fe0469f327262fb76e3fa62801200da6a9c74",
            "canonical dual-curve k1 DID"
        );
    }

    /// An ASCII passphrase is NFKD-invariant, so normalization must not have moved the existing vectors.
    #[test]
    fn ascii_passphrase_derivation_is_unchanged_by_normalization() {
        let kp = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        assert_eq!(
            hex::encode(&*kp.secret),
            "8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7",
            "the empty-passphrase vector must be byte-identical to before normalization"
        );
    }

    /// A typo'd or truncated phrase must FAIL, not silently derive a valid key to an identity the user does not own.
    #[test]
    fn invalid_mnemonic_is_rejected() {
        let bad_checksum = KAT_MNEMONIC.replace(" art", " zoo");
        assert!(derive_k1_keypair(&bad_checksum, "").is_err());
        assert!(derive_k1_keypair("phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi phi", "").is_err());
        assert!(derive_k1_keypair("abandon abandon about", "").is_err());
        assert!(derive_k1_keypair("", "").is_err());
    }

    /// Zeroization.
    #[test]
    fn secret_is_zeroized_on_drop() {
        use zeroize::Zeroize;

        let kp = derive_k1_keypair(KAT_MNEMONIC, "").unwrap();
        // (1) Compile-time: the secret is wrapped in Zeroizing, whose Drop wipes it.
        let _: &Zeroizing<Vec<u8>> = &kp.secret;

        // (2) Runtime: run the very wipe that Drop runs, on memory we still legally hold.
        let mut buf: Vec<u8> = kp.secret.to_vec();
        assert!(buf.iter().any(|&b| b != 0), "a live secret is not all-zero");
        buf.zeroize();
        assert!(buf.iter().all(|&b| b == 0), "zeroize clears the secret");
    }
}
