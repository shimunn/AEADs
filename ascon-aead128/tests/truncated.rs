//! Tests for truncated tags (NIST SP 800-232 permits 32..=128 bits).

use ascon_aead128::{
    AsconAead128, AsconAead128Trunc, ValidTagSize,
    aead::{
        AeadInOut, KeyInit,
        consts::{U4, U5, U8, U12, U16},
    },
};

const KEY: [u8; 16] = *b"0123456789abcdef";
const NONCE: [u8; 16] = *b"fedcba9876543210";
const AAD: &[u8] = b"header";
const PT: [u8; 43] = *b"The quick brown fox jumps over the lazy dog";

fn full_reference() -> (Vec<u8>, [u8; 16]) {
    let c = AsconAead128::new(&KEY.into());
    let mut buf = PT.to_vec();
    let tag = c
        .encrypt_inout_detached(&NONCE.into(), AAD, buf.as_mut_slice().into())
        .unwrap();
    (buf, tag.into())
}

fn check<T: ValidTagSize>() {
    let (ref_ct, ref_tag) = full_reference();
    let c = AsconAead128Trunc::<T>::new(&KEY.into());
    let n = T::USIZE;

    // Ciphertext is identical; tag is a prefix of the full tag.
    let mut buf = PT.to_vec();
    let tag = c
        .encrypt_inout_detached(&NONCE.into(), AAD, buf.as_mut_slice().into())
        .unwrap();
    assert_eq!(buf, ref_ct);
    assert_eq!(tag.len(), n);
    assert_eq!(&tag[..], &ref_tag[..n]);

    // Round trip.
    let mut dec = buf.clone();
    c.decrypt_inout_detached(&NONCE.into(), AAD, dec.as_mut_slice().into(), &tag)
        .unwrap();
    assert_eq!(dec, PT);

    // Flipping any tag byte is rejected, and the output is wiped.
    for i in 0..n {
        let mut bad = tag.clone();
        bad[i] ^= 1;
        let mut dec = buf.clone();
        assert!(
            c.decrypt_inout_detached(&NONCE.into(), AAD, dec.as_mut_slice().into(), &bad)
                .is_err()
        );
        assert!(dec.iter().all(|&b| b == 0));
    }

    // Wrong AAD / tampered ciphertext rejected.
    let mut dec = buf.clone();
    assert!(
        c.decrypt_inout_detached(&NONCE.into(), b"other", dec.as_mut_slice().into(), &tag)
            .is_err()
    );
    let mut ct = buf.clone();
    ct[0] ^= 1;
    assert!(
        c.decrypt_inout_detached(&NONCE.into(), AAD, ct.as_mut_slice().into(), &tag)
            .is_err()
    );
}

#[test]
fn sizes() {
    check::<U4>();
    check::<U5>();
    check::<U8>();
    check::<U12>();
    check::<U16>();
}

#[test]
fn empty_message_and_aad() {
    let c = AsconAead128Trunc::<U4>::new(&KEY.into());
    let mut b: [u8; 0] = [];
    let t = c
        .encrypt_inout_detached(&NONCE.into(), b"", (&mut b[..]).into())
        .unwrap();
    c.decrypt_inout_detached(&NONCE.into(), b"", (&mut b[..]).into(), &t)
        .unwrap();
}

#[test]
fn not_truncated_is_identical() {
    let trunc_impl = AsconAead128Trunc::<U16>::new(&KEY.into());
    let standard_impl = AsconAead128::new(&KEY.into());
    let mut pt_t = PT;
    let mut pt_s = PT;
    let tag_t = trunc_impl
        .encrypt_inout_detached(&NONCE.into(), AAD, (&mut pt_t[..]).into())
        .unwrap();
    let tag_s = standard_impl
        .encrypt_inout_detached(&NONCE.into(), AAD, (&mut pt_s[..]).into())
        .unwrap();
    assert_eq!(pt_t, pt_s);
    assert_eq!(tag_t, tag_s);
    // decrypt payload which has been encrypted by the truncated impl with the standard impl
    standard_impl
        .decrypt_inout_detached(&NONCE.into(), AAD, (&mut pt_t[..]).into(), &tag_t)
        .unwrap();
    assert_eq!(pt_t, PT);
}
