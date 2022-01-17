//! Digest tests

use digest::{core_api::BlockSizeUser, Digest, OutputSizeUser};
use digest::{
    dev::{feed_rand_16mib, fixed_reset_test},
    generic_array::typenum::Unsigned,
    new_test,
};
use hex_literal::hex;
use ring_compat::digest::*;

new_test!(sha1_main, "sha1", Sha1, fixed_reset_test);
new_test!(sha256_main, "sha256", Sha256, fixed_reset_test);
new_test!(sha384_main, "sha384", Sha384, fixed_reset_test);
new_test!(sha512_main, "sha512", Sha512, fixed_reset_test);
new_test!(
    sha512_256_main,
    "sha512_256",
    Sha512Trunc256,
    fixed_reset_test,
);

#[test]
fn sha1_rand() {
    let mut h = Sha1::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("7e565a25a8b123e9881addbcedcd927b23377a78")[..]
    );
}

#[test]
fn sha256_rand() {
    let mut h = Sha256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("45f51fead87328fe837a86f4f1ac0eb15116ab1473adc0423ef86c62eb2320c7")[..]
    );
}

#[test]
fn sha512_rand() {
    let mut h = Sha512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("9084d75a7c0721541d737b6171eb465dc9ba08a119a182a8508484aa27a176cde7c2103b108393eb024493ced4aac56be6f57222cac41b801f11494886264997")[..]
    );
}

#[test]
fn test_block_len() {
    assert_eq!(
        ring::digest::SHA1_FOR_LEGACY_USE_ONLY.block_len,
        <Sha1 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA256.block_len,
        <Sha256 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA384.block_len,
        <Sha384 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512.block_len,
        <Sha512 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512_256.block_len,
        <Sha512Trunc256 as BlockSizeUser>::BlockSize::to_usize()
    );
}

#[test]
fn test_output_len() {
    assert_eq!(
        ring::digest::SHA1_FOR_LEGACY_USE_ONLY.output_len,
        <Sha1 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA256.output_len,
        <Sha256 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA384.output_len,
        <Sha384 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512.output_len,
        <Sha512 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512_256.output_len,
        <Sha512Trunc256 as OutputSizeUser>::OutputSize::to_usize()
    );
}
