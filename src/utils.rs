use rand_core::{CryptoRng, RngCore};
use sha2::{Sha512, Digest};
use crate::arithmetic::*;
use crate::elgamal::*;
use crate::primitives::*;

type GlobalPublicKey = GroupElement;
type GlobalSecretKey = ScalarNonZero;
type GlobalEncryptedPseudonym = ElGamal;
type LocalEncryptedPseudonym = ElGamal;
type LocalPseudonym = GroupElement;
type LocalDecryptionKey = ScalarNonZero;

pub fn generate_global_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicKey, GlobalSecretKey) {
    // secret key of system
    let y = ScalarNonZero::random(rng);
    // public key of system
    let gy = y * G;
    (gy, y)
}

/// Generates a non-zero scalar.
fn make_factor(typ: &str, secret: &str, context: &str) -> ScalarNonZero {
    let mut hasher = Sha512::default();
    hasher.update(typ.as_bytes());
    hasher.update(b"|");
    hasher.update(secret.as_bytes());
    hasher.update(b"|");
    hasher.update(context.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    ScalarNonZero::from_hash(&bytes)
}

/// Generates a non-zero scalar.
pub fn make_pseudonymisation_factor(secret: &str, context: &str) -> ScalarNonZero {
    make_factor("pseudonym", secret, context)
}

/// Generates a non-zero scalar.
pub fn make_decryption_factor(secret: &str, context: &str) -> ScalarNonZero {
    make_factor("decryption", secret, context)
}

/// Generates a encrypted global pseudonym by encrypting a text with ElGamal using the global
/// public key `pkg`.
pub fn generate_pseudonym<R: RngCore + CryptoRng>(identity: &str, pk: &GlobalPublicKey, rng: &mut R) -> GlobalEncryptedPseudonym {
    let mut hasher = Sha512::default();
    hasher.update(identity.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let p = GroupElement::from_hash(&bytes);
    encrypt(&p, pk, rng)
}

/// Using a PEP `rks` operation, convert a global encrypted pseudonym to a local encrypted pseudonym,
/// which is:
/// - decryptable with the key `k` that is generated by [libpep::simple::make_local_decryption_key] using the same
///   `decryption_context`;
/// - decrypts to the pseudonym that is the global pseudonym multiplied by a factor specific to the
///   `pseudonimisation_context`.
pub fn convert_to_local_pseudonym(p: &GlobalEncryptedPseudonym, secret: &str, decryption_context: &str, pseudonimisation_context: &str) -> LocalEncryptedPseudonym {
    let u = make_pseudonymisation_factor(secret, pseudonimisation_context);
    let t = make_decryption_factor(secret, decryption_context);
    rsk(p, &u, &t)
}

pub fn convert_from_local_pseudonym(p: &LocalEncryptedPseudonym, secret: &str, decryption_context: &str, pseudonimisation_context: &str) -> GlobalEncryptedPseudonym {
    let u = make_pseudonymisation_factor(secret, pseudonimisation_context).invert();
    let t = make_decryption_factor(secret, decryption_context).invert();
    rsk(p, &u, &t)
}

pub fn make_local_decryption_key(k: &GlobalSecretKey, secret: &str, decryption_context: &str) -> LocalDecryptionKey {
    let t = make_decryption_factor(secret, decryption_context);
    t * k
}

pub fn decrypt_local_pseudonym(p: &LocalEncryptedPseudonym, k: &LocalDecryptionKey) -> LocalPseudonym {
    decrypt(p, k)
}

pub fn rerandomize_global<R: RngCore + CryptoRng>(p: &GlobalEncryptedPseudonym, rng: &mut R) -> GlobalEncryptedPseudonym {
    rerandomize(p, &ScalarNonZero::random(rng))
}

pub fn rerandomize_local<R: RngCore + CryptoRng>(p: &LocalEncryptedPseudonym, rng: &mut R) -> LocalEncryptedPseudonym {
    rerandomize(p, &ScalarNonZero::random(rng))
}
