//! ECDSA signing key

use super::{CurveAlg, PrimeCurve, Signature, VerifyingKey};
use crate::signature::{Error, Signature as _, Signer};
use ::ecdsa::{
    elliptic_curve::{sec1, FieldSize},
    SignatureSize,
};
use core::marker::PhantomData;
use generic_array::ArrayLength;
use ring::{
    self,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair},
};

/// ECDSA signing key. Generic over elliptic curves.
pub struct SigningKey<C>
where
    C: PrimeCurve + CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// *ring* ECDSA keypair
    keypair: EcdsaKeyPair,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,

    /// Elliptic curve type
    curve: PhantomData<C>,
}

impl<C> SigningKey<C>
where
    C: PrimeCurve + CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Initialize a [`SigningKey`] from a PKCS#8-encoded private key
    pub fn from_pkcs8(pkcs8_key: &[u8]) -> Result<Self, Error> {
        EcdsaKeyPair::from_pkcs8(C::signing_alg(), pkcs8_key)
            .map(|keypair| Self {
                keypair,
                csrng: SystemRandom::new(),
                curve: PhantomData,
            })
            .map_err(|_| Error::new())
    }

    /// Initialize a [`SigningKey`] from a raw keypair
    pub fn from_keypair_bytes(signing_key: &[u8], verify_key: &[u8]) -> Result<Self, Error> {
        EcdsaKeyPair::from_private_key_and_public_key(C::signing_alg(), signing_key, verify_key)
            .map(|keypair| Self {
                keypair,
                csrng: SystemRandom::new(),
                curve: PhantomData,
            })
            .map_err(|_| Error::new())
    }

    /// Get the [`VerifyingKey`] for this [`SigningKey`]
    pub fn verify_key(&self) -> VerifyingKey<C>
    where
        FieldSize<C>: sec1::ModulusSize,
    {
        VerifyingKey::new(self.keypair.public_key().as_ref()).unwrap()
    }
}

impl<C> Signer<Signature<C>> for SigningKey<C>
where
    C: PrimeCurve + CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, Error> {
        self.keypair
            .sign(&self.csrng, msg)
            .map_err(|_| Error::new())
            .and_then(|sig| Signature::from_bytes(sig.as_ref()))
    }
}
