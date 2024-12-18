//! High-level data types for pseudonyms and data points, and their encrypted versions,
//! Including several ways to encode and decode them.

use crate::internal::arithmetic::GroupElement;
use crate::low_level::elgamal::{ElGamal, ELGAMAL_LENGTH};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct Pseudonym {
    pub(crate) value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct DataPoint {
    pub(crate) value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedDataPoint {
    pub value: ElGamal,
}
impl Pseudonym {
    pub fn from_point(value: GroupElement) -> Self {
        Self { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_point(GroupElement::random(rng))
    }
    pub fn encode(&self) -> [u8; 32] {
        self.value.encode()
    }
    pub fn encode_as_hex(&self) -> String {
        self.value.encode_as_hex()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::decode(bytes).map(Self::from_point)
    }
    pub fn decode_from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::decode_from_slice(slice).map(Self::from_point)
    }
    pub fn decode_from_hex(hex: &str) -> Option<Self> {
        GroupElement::decode_from_hex(hex).map(Self::from_point)
    }
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    pub fn from_bytes(data: &[u8; 16]) -> Self {
        Self::from_point(GroupElement::decode_lizard(data))
    }
    pub fn as_bytes(&self) -> Option<[u8; 16]> {
        self.value.encode_lizard()
    }
}
impl DataPoint {
    pub fn from_point(value: GroupElement) -> Self {
        Self { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_point(GroupElement::random(rng))
    }
    pub fn encode(&self) -> [u8; 32] {
        self.value.encode()
    }
    pub fn encode_as_hex(&self) -> String {
        self.value.encode_as_hex()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::decode(bytes).map(Self::from_point)
    }
    pub fn decode_from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::decode_from_slice(slice).map(Self::from_point)
    }
    pub fn decode_from_hex(hex: &str) -> Option<Self> {
        GroupElement::decode_from_hex(hex).map(Self::from_point)
    }
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    pub fn from_bytes(data: &[u8; 16]) -> Self {
        Self::from_point(GroupElement::decode_lizard(data))
    }
    pub fn as_bytes(&self) -> Option<[u8; 16]> {
        self.value.encode_lizard()
    }
    pub fn bytes_into_multiple_messages(data: &[u8]) -> Vec<Self> {
        data.chunks(16)
            .map(|x| Self::from_bytes(x.try_into().unwrap()))
            .collect()
    }
}
pub trait Encrypted {
    type UnencryptedType: Encryptable;
    const IS_PSEUDONYM: bool = false;
    fn value(&self) -> &ElGamal;
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized;
    fn encode(&self) -> [u8; ELGAMAL_LENGTH] {
        self.value().encode()
    }
    fn decode(v: &[u8; ELGAMAL_LENGTH]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::decode(v).map(|x| Self::from_value(x))
    }

    fn decode_from_slice(v: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::decode_from_slice(v).map(|x| Self::from_value(x))
    }
    fn as_base64(&self) -> String {
        self.value().encode_as_base64()
    }
    fn from_base64(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::decode_from_base64(s).map(|x| Self::from_value(x))
    }
}
pub trait Encryptable {
    type EncryptedType: Encrypted;
    fn value(&self) -> &GroupElement;
    fn from_value(value: GroupElement) -> Self;
}
impl Encryptable for Pseudonym {
    type EncryptedType = EncryptedPseudonym;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self {
        Self::from_point(value)
    }
}
impl Encryptable for DataPoint {
    type EncryptedType = EncryptedDataPoint;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self {
        Self::from_point(value)
    }
}
impl Encrypted for EncryptedPseudonym {
    type UnencryptedType = Pseudonym;
    const IS_PSEUDONYM: bool = true;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self {
        Self { value }
    }
}
impl Encrypted for EncryptedDataPoint {
    type UnencryptedType = DataPoint;
    const IS_PSEUDONYM: bool = false;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self {
        Self { value }
    }
}
