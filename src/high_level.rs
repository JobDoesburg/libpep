use crate::arithmetic::{GroupElement, ScalarNonZero, G};
use crate::elgamal::{decrypt, encrypt, ElGamal};
use crate::primitives::*;
use crate::utils::{make_decryption_factor, make_pseudonymisation_factor};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub type Context = String;
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct PseudonymizationContext(pub Context);
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptionContext(pub Context);

#[derive(Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct Pseudonym {
    #[deref]
    pub value: GroupElement,
    pub context: PseudonymizationContext,
}
#[derive(Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct DataPoint {
    pub value: GroupElement,
}
#[derive(Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedPseudonym {
    #[deref]
    pub value: ElGamal,
    pub pseudo_context: PseudonymizationContext,
    pub enc_context: EncryptionContext,
}
#[derive(Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedDataPoint {
    #[deref]
    pub value: ElGamal,
    pub enc_context: EncryptionContext,
}

#[derive(Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionSecretKey {
    #[deref]
    pub value: ScalarNonZero,
    pub context: EncryptionContext
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct GlobalSecretKey(pub ScalarNonZero);
#[derive(Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionPublicKey{
    #[deref]
    pub value: GroupElement,
    pub context: EncryptionContext
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct GlobalPublicKey(pub GroupElement);

pub type Secret = String;
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From)]
pub struct PseudonymizationSecret(pub Secret);
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From)]
pub struct EncryptionSecret(pub Secret);
impl Pseudonym {
    pub fn new(value: GroupElement, context: &PseudonymizationContext) -> Self {
        Pseudonym { value, context: context.clone() }
    }
    pub fn random<R: RngCore + CryptoRng>(context: &PseudonymizationContext, rng: &mut R) -> Self {
        Pseudonym::new(GroupElement::random(rng), &context)
    }
    pub fn encode(&self) -> String {
        let prefix = self.context.0.to_owned();
        let value = self.value.encode_to_hex();
        format!("{prefix}#{value}")
    }
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<_> = s.split("#").collect();
        if parts.len() != 2 {
            return None;
        }
        let context = parts[0];
        let value = parts[1];
        Some(Pseudonym::new(GroupElement::decode_from_hex(value)?, &PseudonymizationContext::from(Context::from(context))))
    }
}
impl DataPoint {
    pub fn new(value: GroupElement) -> Self {
        DataPoint { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        DataPoint::new(GroupElement::random(rng))
    }
}
impl EncryptedPseudonym {
    pub fn new(value: ElGamal, pseudo_context: PseudonymizationContext, enc_context: EncryptionContext) -> Self {
        EncryptedPseudonym { value, pseudo_context, enc_context }
    }
    pub fn encode(&self) -> String {
        let prefix = self.pseudo_context.0.to_owned();
        let value = self.value.encode_to_base64();
        let postfix = self.enc_context.0.to_owned();
        format!("{prefix}#{value}#{postfix}")
    }
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<_> = s.split("#").collect();
        if parts.len() != 3 {
            return None;
        }
        let pseudo_context = parts[0];
        let value = parts[1];
        let enc_context = parts[2];
        Some(EncryptedPseudonym::new(ElGamal::decode_from_base64(value)?, PseudonymizationContext::from(Context::from(pseudo_context)), EncryptionContext::from(Context::from(enc_context))))
    }
}
impl EncryptedDataPoint {
    pub fn new(value: ElGamal, enc_context: EncryptionContext) -> Self {
        EncryptedDataPoint { value, enc_context }
    }
}

/// Generate a new global key pair
pub fn make_global_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicKey, GlobalSecretKey) {
    let sk = ScalarNonZero::random(rng);
    let pk = sk * G;
    (GlobalPublicKey(pk), GlobalSecretKey(sk))
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
pub fn make_session_keys(
    global: &GlobalSecretKey,
    context: &EncryptionContext,
    encryption_secret: &EncryptionSecret,
) -> (SessionPublicKey, SessionSecretKey) {
    let k = make_decryption_factor(encryption_secret, context);
    let sk = *k * global.deref();
    let pk = sk * G;
    (SessionPublicKey{ value: pk, context: context.clone() }, SessionSecretKey { value: sk, context: context.clone() })
}

/// Encrypt a pseudonym
pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
    p: &Pseudonym,
    pk: &SessionPublicKey,
    rng: &mut R,
) -> EncryptedPseudonym {
    EncryptedPseudonym::new(encrypt(p, pk, rng), p.context.clone(), pk.context.clone())
}

/// Decrypt an encrypted pseudonym
pub fn decrypt_pseudonym(p: &EncryptedPseudonym, sk: &SessionSecretKey) -> Pseudonym {
    Pseudonym::new(decrypt(p, sk), &p.pseudo_context)
}

/// Encrypt a data point
pub fn encrypt_data<R: RngCore + CryptoRng>(
    data: &DataPoint,
    pk: &SessionPublicKey,
    rng: &mut R,
) -> EncryptedDataPoint {
    EncryptedDataPoint::new(encrypt(data, pk, rng), pk.context.clone())
}

/// Decrypt an encrypted data point
pub fn decrypt_data(data: &EncryptedDataPoint, sk: &SessionSecretKey) -> DataPoint {
    DataPoint::new(decrypt(&data, &sk))
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct RerandomizeFactor(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct ReshuffleFactor(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct RekeyFactor(pub ScalarNonZero);
#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
    encrypted: &EncryptedPseudonym,
    rng: &mut R,
) -> EncryptedPseudonym {
    let r = ScalarNonZero::random(rng);
    EncryptedPseudonym::new(rerandomize(&encrypted.value, &r), encrypted.pseudo_context.clone(), encrypted.enc_context.clone())
}

#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted data point
pub fn rerandomize_encrypted<R: RngCore + CryptoRng>(
    encrypted: &EncryptedDataPoint,
    rng: &mut R,
) -> EncryptedDataPoint {
    let r = ScalarNonZero::random(rng);
    EncryptedDataPoint::new(rerandomize(&encrypted.value, &r), encrypted.enc_context.clone())
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Reshuffle2Factors {
    pub from: ReshuffleFactor,
    pub to: ReshuffleFactor,
}
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Rekey2Factors {
    pub from: RekeyFactor,
    pub to: RekeyFactor,
}
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct RSK2Factors {
    pub s: Reshuffle2Factors,
    pub k: Rekey2Factors,
}

impl Reshuffle2Factors {
    pub fn reverse(self) -> Self {
        Reshuffle2Factors {
            from: self.to,
            to: self.from,
        }
    }
}
impl Rekey2Factors {
    pub fn reverse(self) -> Self {
        Rekey2Factors {
            from: self.to,
            to: self.from,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Reshuffle2Contexts {
    pub from: PseudonymizationContext,
    pub to: PseudonymizationContext,
}
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Rekey2Contexts {
    pub from: EncryptionContext,
    pub to: EncryptionContext,
}
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct RSK2Contexts {
    pub pseudo: Reshuffle2Contexts,
    pub enc: Rekey2Contexts,
}

impl Reshuffle2Contexts {
    pub fn reverse(self) -> Self {
        Reshuffle2Contexts {
            from: self.to,
            to: self.from,
        }
    }
}
impl Rekey2Contexts {
    pub fn reverse(self) -> Self {
        Rekey2Contexts {
            from: self.to,
            to: self.from,
        }
    }
}


#[derive(Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct PseudonymizationInfo {
    #[deref]
    pub factors: RSK2Factors,
    pub contexts: RSK2Contexts,
}
#[derive(Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct RekeyInfo {
    #[deref]
    pub factors: Rekey2Factors,
    pub contexts: Rekey2Contexts,
}
impl PseudonymizationInfo {
    pub fn new(
        from_pseudo_context: &PseudonymizationContext,
        to_pseudo_context: &PseudonymizationContext,
        from_enc_context: &EncryptionContext,
        to_enc_context: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_pseudo_context);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_pseudo_context);
        let reshuffle_factors = Reshuffle2Factors {
            from: s_from,
            to: s_to,
        };
        let rekey_factors = RekeyInfo::new(from_enc_context, to_enc_context, encryption_secret);
        PseudonymizationInfo {
            factors: RSK2Factors {
                s: reshuffle_factors,
                k: rekey_factors.factors,
            },
            contexts: RSK2Contexts {
                pseudo: Reshuffle2Contexts {
                    from: from_pseudo_context.clone(),
                    to: to_pseudo_context.clone(),
                },
                enc: rekey_factors.contexts,
            },
        }
    }
    pub fn reverse(self) -> Self {
        PseudonymizationInfo {
            factors: RSK2Factors {
                s: self.s.reverse(),
                k: self.k.reverse(),
            },
            contexts: RSK2Contexts {
                pseudo: self.contexts.pseudo.reverse(),
                enc: self.contexts.enc.reverse(),
            },
        }
    }
}
impl RekeyInfo {
    pub fn new(
        from_session: &EncryptionContext,
        to_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_decryption_factor(&encryption_secret, &from_session);
        let k_to = make_decryption_factor(&encryption_secret, &to_session);
        RekeyInfo {
            factors: Rekey2Factors {
                from: k_from,
                to: k_to,
            },
            contexts: Rekey2Contexts {
                from: from_session.clone(),
                to: to_session.clone(),
            },
        }
    }
}
impl From<&PseudonymizationInfo> for RekeyInfo {
    fn from(x: &PseudonymizationInfo) -> Self {
        RekeyInfo {
            factors: x.factors.k,
            contexts: x.contexts.enc.clone(),
        }
    }
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
pub fn pseudonymize(
    p: &EncryptedPseudonym,
    info: &PseudonymizationInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::new(rsk2(
        &p.value,
        &info.s.from,
        &info.s.to,
        &info.k.from,
        &info.k.to,
    ), info.contexts.pseudo.to.clone(), info.contexts.enc.to.clone())
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::new(rekey2(&p.value, &info.from, &info.to), info.contexts.to.clone())
}
