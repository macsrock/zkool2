//! Wire mirrors of the two PCZT v2 dialects.
//!
//! Cake speaks the `lrz` fork of `pczt` 0.7; a Keystone running Cypherpunk
//! firmware speaks 0.8.0-rc.1. Both call their encoding "v2", but six fields
//! differ, so a PCZT written by one is misread by the other -- silently, since
//! nothing is malformed, only misaligned. Translating at the QR boundary keeps
//! Cake on its own dialect while handing the device one it can read.
//!
//! postcard is not self-describing: fields are positional and typed by the
//! compiled-in schema, so an `Option<T>` writes a tag byte that a bare `T`
//! does not. Cake's `pczt` (lrz 0.7) and Keystone's (0.8.0-rc.1) disagree on
//! exactly six fields, which is enough to shift every following byte. These
//! mirrors exist so the two layouts can be read and written independently of
//! either crate's private types.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::BTreeMap;

// ---- shared between both dialects -------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zip32Derivation {
    pub seed_fingerprint: [u8; 32],
    pub derivation_path: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Global {
    pub tx_version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub fallback_lock_time: Option<u32>,
    pub expiry_height: u32,
    pub coin_type: u32,
    pub tx_modifiable: u8,
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparentInput {
    pub prevout_txid: [u8; 32],
    pub prevout_index: u32,
    pub sequence: Option<u32>,
    pub required_time_lock_time: Option<u32>,
    pub required_height_lock_time: Option<u32>,
    pub script_sig: Option<Vec<u8>>,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub redeem_script: Option<Vec<u8>>,
    #[serde_as(as = "BTreeMap<[_; 33], _>")]
    pub partial_signatures: BTreeMap<[u8; 33], Vec<u8>>,
    pub sighash_type: u8,
    #[serde_as(as = "BTreeMap<[_; 33], _>")]
    pub bip32_derivation: BTreeMap<[u8; 33], Zip32Derivation>,
    pub ripemd160_preimages: BTreeMap<[u8; 20], Vec<u8>>,
    pub sha256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
    pub hash160_preimages: BTreeMap<[u8; 20], Vec<u8>>,
    pub hash256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparentOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub redeem_script: Option<Vec<u8>>,
    #[serde_as(as = "BTreeMap<[_; 33], _>")]
    pub bip32_derivation: BTreeMap<[u8; 33], Zip32Derivation>,
    pub user_address: Option<String>,
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparentBundle {
    pub inputs: Vec<TransparentInput>,
    pub outputs: Vec<TransparentOutput>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum NoteVersion {
    V2,
    V3,
}

// ---- source dialect: lrz 0.7 -----------------------------------------

pub mod src_ {
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct OrchardBundle {
        pub actions: Vec<Action>,
        pub flags: u8,
        pub value_sum: (u64, bool),
        pub anchor: [u8; 32],
        pub note_version: NoteVersion,
        pub zkproof: Option<Vec<u8>>,
        pub bsk: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Action {
        pub cv_net: [u8; 32],
        pub spend: Spend,
        pub output: Output,
        pub rcv: Option<[u8; 32]>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Spend {
        pub nullifier: [u8; 32],
        pub rk: [u8; 32],
        #[serde_as(as = "Option<[_; 64]>")]
        pub spend_auth_sig: Option<[u8; 64]>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub recipient: Option<[u8; 43]>,
        pub value: Option<u64>,
        pub rho: Option<[u8; 32]>,
        pub rseed: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 96]>")]
        pub fvk: Option<[u8; 96]>,
        pub witness: Option<(u32, [[u8; 32]; 32])>,
        pub alpha: Option<[u8; 32]>,
        pub zip32_derivation: Option<Zip32Derivation>,
        pub dummy_sk: Option<[u8; 32]>,
        pub proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Output {
        pub cmx: [u8; 32],
        pub ephemeral_key: [u8; 32],
        pub enc_ciphertext: Vec<u8>,
        pub out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub recipient: Option<[u8; 43]>,
        pub value: Option<u64>,
        pub rseed: Option<[u8; 32]>,
        pub ock: Option<[u8; 32]>,
        pub zip32_derivation: Option<Zip32Derivation>,
        pub user_address: Option<String>,
        pub proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SaplingBundle {
        pub spends: Vec<SaplingSpend>,
        pub outputs: Vec<SaplingOutput>,
        pub value_sum: i128,
        pub anchor: [u8; 32],
        pub bsk: Option<[u8; 32]>,
    }

    // Cake never builds Sapling bundles; these exist so a non-empty one is a
    // hard error rather than a silent misparse.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SaplingSpend {}
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SaplingOutput {}

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Pczt {
        pub global: Global,
        pub transparent: Option<TransparentBundle>,
        pub sapling: Option<SaplingBundle>,
        pub orchard: Option<OrchardBundle>,
        pub ironwood: Option<OrchardBundle>,
        #[serde(default)]
        pub issue: Option<IssueBundle>,
    }

    // The ZSA issuance bundle has no counterpart in 0.8.0-rc.1 and is dropped.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct IssueBundle {}
}

// ---- target dialect: 0.8.0-rc.1 (what Keystone reads) -----------------

pub mod dst {
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum EncCiphertext {
        Encrypted(Vec<u8>),
        MemoPlaintext(Vec<u8>),
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct OrchardBundle {
        pub actions: Vec<Action>,
        pub flags: u8,
        pub value_sum: (u64, bool),
        pub anchor: Option<[u8; 32]>,
        pub note_version: NoteVersion,
        pub zkproof: Option<Vec<u8>>,
        pub bsk: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Action {
        pub cv_net: Option<[u8; 32]>,
        pub spend: Spend,
        pub output: Output,
        pub rcv: Option<[u8; 32]>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Spend {
        #[serde_as(as = "Option<[_; 32]>")]
        pub nullifier: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 32]>")]
        pub rk: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 64]>")]
        pub spend_auth_sig: Option<[u8; 64]>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub recipient: Option<[u8; 43]>,
        pub value: Option<u64>,
        pub rho: Option<[u8; 32]>,
        pub rseed: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 96]>")]
        pub fvk: Option<[u8; 96]>,
        pub witness: Option<(u32, [[u8; 32]; 32])>,
        pub alpha: Option<[u8; 32]>,
        pub zip32_derivation: Option<Zip32Derivation>,
        pub dummy_sk: Option<[u8; 32]>,
        pub proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Output {
        #[serde_as(as = "Option<[_; 32]>")]
        pub cmx: Option<[u8; 32]>,
        pub ephemeral_key: [u8; 32],
        pub enc_ciphertext: EncCiphertext,
        pub out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub recipient: Option<[u8; 43]>,
        pub value: Option<u64>,
        pub rseed: Option<[u8; 32]>,
        pub ock: Option<[u8; 32]>,
        pub zip32_derivation: Option<Zip32Derivation>,
        pub user_address: Option<String>,
        pub proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SaplingBundle {
        pub spends: Vec<super::src_::SaplingSpend>,
        pub outputs: Vec<super::src_::SaplingOutput>,
        pub value_sum: i128,
        pub anchor: Option<[u8; 32]>,
        pub bsk: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Pczt {
        pub global: Global,
        pub transparent: Option<TransparentBundle>,
        pub sapling: Option<SaplingBundle>,
        pub orchard: Option<OrchardBundle>,
        pub ironwood: Option<OrchardBundle>,
    }
}


// ---- translation ------------------------------------------------------

const MAGIC: [u8; 4] = *b"PCZT";
const V2: u32 = 2;

fn to_dst_orchard(b: src_::OrchardBundle) -> dst::OrchardBundle {
    dst::OrchardBundle {
        actions: b
            .actions
            .into_iter()
            .map(|a| dst::Action {
                cv_net: Some(a.cv_net),
                spend: dst::Spend {
                    nullifier: Some(a.spend.nullifier),
                    rk: Some(a.spend.rk),
                    spend_auth_sig: a.spend.spend_auth_sig,
                    recipient: a.spend.recipient,
                    value: a.spend.value,
                    rho: a.spend.rho,
                    rseed: a.spend.rseed,
                    fvk: a.spend.fvk,
                    witness: a.spend.witness,
                    alpha: a.spend.alpha,
                    zip32_derivation: a.spend.zip32_derivation,
                    dummy_sk: a.spend.dummy_sk,
                    proprietary: a.spend.proprietary,
                },
                output: dst::Output {
                    cmx: Some(a.output.cmx),
                    ephemeral_key: a.output.ephemeral_key,
                    enc_ciphertext: dst::EncCiphertext::Encrypted(a.output.enc_ciphertext),
                    out_ciphertext: a.output.out_ciphertext,
                    recipient: a.output.recipient,
                    value: a.output.value,
                    rseed: a.output.rseed,
                    ock: a.output.ock,
                    zip32_derivation: a.output.zip32_derivation,
                    user_address: a.output.user_address,
                    proprietary: a.output.proprietary,
                },
                rcv: a.rcv,
            })
            .collect(),
        flags: b.flags,
        value_sum: b.value_sum,
        anchor: Some(b.anchor),
        note_version: b.note_version,
        zkproof: b.zkproof,
        bsk: b.bsk,
    }
}

fn to_src_orchard(b: dst::OrchardBundle) -> Result<src_::OrchardBundle, String> {
    // The signer only ever fills fields in, so anything absent here means the
    // returned PCZT is not one this side can carry back.
    fn need(v: Option<[u8; 32]>, what: &str) -> Result<[u8; 32], String> {
        v.ok_or_else(|| format!("signed PCZT is missing {what}"))
    }
    Ok(src_::OrchardBundle {
        actions: b
            .actions
            .into_iter()
            .map(|a| {
                Ok(src_::Action {
                    cv_net: need(a.cv_net, "action cv_net")?,
                    spend: src_::Spend {
                        nullifier: need(a.spend.nullifier, "spend nullifier")?,
                        rk: need(a.spend.rk, "spend rk")?,
                        spend_auth_sig: a.spend.spend_auth_sig,
                        recipient: a.spend.recipient,
                        value: a.spend.value,
                        rho: a.spend.rho,
                        rseed: a.spend.rseed,
                        fvk: a.spend.fvk,
                        witness: a.spend.witness,
                        alpha: a.spend.alpha,
                        zip32_derivation: a.spend.zip32_derivation,
                        dummy_sk: a.spend.dummy_sk,
                        proprietary: a.spend.proprietary,
                    },
                    output: src_::Output {
                        cmx: need(a.output.cmx, "output cmx")?,
                        ephemeral_key: a.output.ephemeral_key,
                        enc_ciphertext: match a.output.enc_ciphertext {
                            dst::EncCiphertext::Encrypted(c) => c,
                            dst::EncCiphertext::MemoPlaintext(_) => {
                                return Err("signed PCZT left a memo unresolved".into())
                            }
                        },
                        out_ciphertext: a.output.out_ciphertext,
                        recipient: a.output.recipient,
                        value: a.output.value,
                        rseed: a.output.rseed,
                        ock: a.output.ock,
                        zip32_derivation: a.output.zip32_derivation,
                        user_address: a.output.user_address,
                        proprietary: a.output.proprietary,
                    },
                    rcv: a.rcv,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        flags: b.flags,
        value_sum: b.value_sum,
        anchor: need(b.anchor, "bundle anchor")?,
        note_version: b.note_version,
        zkproof: b.zkproof,
        bsk: b.bsk,
    })
}

fn split_header(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.len() < 8 || bytes[..4] != MAGIC {
        return Err("not a PCZT".into());
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != V2 {
        return Err(format!("expected the v2 PCZT encoding, got v{version}"));
    }
    Ok(&bytes[8..])
}

fn with_header<T: serde::Serialize>(body: &T, hint: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(hint + 64);
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&V2.to_le_bytes());
    postcard::to_extend(body, buf).map_err(|e| format!("re-encode failed: {e:?}"))
}

/// Rewrites a PCZT from Cake's dialect into the one a Keystone reads.
pub fn to_keystone(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let src: src_::Pczt = postcard::from_bytes(split_header(bytes)?)
        .map_err(|e| format!("could not read this PCZT: {e:?}"))?;
    if src
        .sapling
        .as_ref()
        .is_some_and(|s| !s.spends.is_empty() || !s.outputs.is_empty())
    {
        return Err("Sapling bundles cannot be signed by this device".into());
    }
    let out = dst::Pczt {
        global: src.global,
        transparent: src.transparent,
        sapling: src.sapling.map(|s| dst::SaplingBundle {
            spends: s.spends,
            outputs: s.outputs,
            value_sum: s.value_sum,
            anchor: Some(s.anchor),
            bsk: s.bsk,
        }),
        orchard: src.orchard.map(to_dst_orchard),
        ironwood: src.ironwood.map(to_dst_orchard),
    };
    with_header(&out, bytes.len())
}

/// Rewrites a signed PCZT from the Keystone's dialect back into Cake's.
pub fn from_keystone(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let signed: dst::Pczt = postcard::from_bytes(split_header(bytes)?)
        .map_err(|e| format!("could not read the signed PCZT: {e:?}"))?;
    let out = src_::Pczt {
        global: signed.global,
        transparent: signed.transparent,
        sapling: signed
            .sapling
            .map(|s| {
                Ok::<_, String>(src_::SaplingBundle {
                    spends: s.spends,
                    outputs: s.outputs,
                    value_sum: s.value_sum,
                    anchor: s.anchor.ok_or("signed PCZT is missing sapling anchor")?,
                    bsk: s.bsk,
                })
            })
            .transpose()?,
        orchard: signed.orchard.map(to_src_orchard).transpose()?,
        ironwood: signed.ironwood.map(to_src_orchard).transpose()?,
        issue: None,
    };
    with_header(&out, bytes.len())
}

/// Applies a Keystone's signatures to the PCZT this wallet built.
///
/// A signer returns only what it needed to produce: it redacts prover-only
/// fields such as the full viewing key, so its reply cannot be proved on its
/// own. Rather than trusting the returned document, keep the original and take
/// just the signatures out of the reply.
pub fn apply_signatures(original: &[u8], signed: &[u8]) -> Result<Vec<u8>, String> {
    let mut orig: src_::Pczt = postcard::from_bytes(split_header(original)?)
        .map_err(|e| format!("could not read the original PCZT: {e:?}"))?;
    let from_device: src_::Pczt = postcard::from_bytes(split_header(signed)?)
        .map_err(|e| format!("could not read the signed PCZT: {e:?}"))?;

    fn merge_orchard(
        into: &mut Option<src_::OrchardBundle>,
        from: &Option<src_::OrchardBundle>,
        pool: &str,
    ) -> Result<usize, String> {
        match (into.as_mut(), from.as_ref()) {
            (Some(a), Some(b)) => {
                if a.actions.len() != b.actions.len() {
                    return Err(format!(
                        "the signed PCZT is not the {pool} transaction that was sent: \
                         {} actions returned, {} expected",
                        b.actions.len(),
                        a.actions.len()
                    ));
                }
                let mut applied = 0;
                for (x, y) in a.actions.iter_mut().zip(b.actions.iter()) {
                    // A spend already carrying its own signature keeps it; the
                    // IO Finalizer signs dummy spends before the device sees them.
                    if x.spend.spend_auth_sig.is_none() {
                        if let Some(sig) = y.spend.spend_auth_sig {
                            x.spend.spend_auth_sig = Some(sig);
                            applied += 1;
                        }
                    }
                }
                Ok(applied)
            }
            (None, Some(b)) if !b.actions.is_empty() => {
                Err(format!("the signed PCZT has {pool} actions the original does not"))
            }
            _ => Ok(0),
        }
    }

    let mut applied = merge_orchard(&mut orig.orchard, &from_device.orchard, "Orchard")?;
    applied += merge_orchard(&mut orig.ironwood, &from_device.ironwood, "Ironwood")?;

    // Transparent inputs are authorised with script signatures rather than a
    // spend auth signature.
    if let (Some(a), Some(b)) = (orig.transparent.as_mut(), from_device.transparent.as_ref()) {
        if a.inputs.len() != b.inputs.len() {
            return Err(format!(
                "the signed PCZT is not the transaction that was sent: {} transparent \
                 inputs returned, {} expected",
                b.inputs.len(),
                a.inputs.len()
            ));
        }
        for (x, y) in a.inputs.iter_mut().zip(b.inputs.iter()) {
            for (k, v) in &y.partial_signatures {
                if x.partial_signatures.insert(*k, v.clone()).is_none() {
                    applied += 1;
                }
            }
        }
    }

    if applied == 0 {
        return Err("the device returned no signatures".into());
    }
    with_header(&orig, original.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real Ironwood PCZT built by Cake, captured off the wire.
    const CAKE: &[u8] = include_bytes!("../tests/data/cake_ironwood.pczt");

    /// The same transaction in the Keystone's dialect.
    ///
    /// Checked in as a golden file rather than re-derived: `pczt` 0.8.0-rc.1
    /// cannot be built alongside the lrz stack this crate pins, so the
    /// device-side assertion cannot live here. These bytes were verified
    /// against the firmware's own parser, which reports two Ironwood actions
    /// and one signable spend; Cake's dialect yields zero of each, which is
    /// the bug this module exists to fix.
    const KEYSTONE: &[u8] = include_bytes!("../tests/data/cake_ironwood.keystone.pczt");

    #[test]
    fn matches_what_the_device_can_read() {
        assert_eq!(to_keystone(CAKE).expect("transcode"), KEYSTONE);
    }

    #[test]
    fn round_trip_is_lossless() {
        assert_eq!(from_keystone(KEYSTONE).expect("transcode back"), CAKE);
    }

    #[test]
    fn takes_signatures_and_keeps_prover_fields() {
        // Stand in for the device: strip the prover-only fields it redacts,
        // and attach a spend authorising signature.
        let mut device: src_::Pczt = postcard::from_bytes(&CAKE[8..]).unwrap();
        let iw = device.ironwood.as_mut().unwrap();
        for a in iw.actions.iter_mut() {
            a.spend.fvk = None;
            a.spend.witness = None;
            a.spend.spend_auth_sig = Some([7u8; 64]);
        }
        let device_bytes = with_header(&device, CAKE.len()).unwrap();

        let merged = apply_signatures(CAKE, &device_bytes).expect("apply");
        let out: src_::Pczt = postcard::from_bytes(&merged[8..]).unwrap();
        let actions = &out.ironwood.as_ref().unwrap().actions;

        let orig: src_::Pczt = postcard::from_bytes(&CAKE[8..]).unwrap();
        let orig_actions = &orig.ironwood.as_ref().unwrap().actions;

        // Every spend ends up authorised, and a spend the wallet had not
        // already signed takes the device's signature. Dummy spends keep the
        // one the IO Finalizer produced before the device ever saw them.
        assert!(actions.iter().all(|a| a.spend.spend_auth_sig.is_some()));
        let taken = actions
            .iter()
            .zip(orig_actions.iter())
            .filter(|(_, b)| b.spend.spend_auth_sig.is_none())
            .count();
        assert!(taken > 0, "the fixture must have a spend for the device to sign");
        for (a, b) in actions.iter().zip(orig_actions.iter()) {
            let expected = b.spend.spend_auth_sig.or(Some([7u8; 64]));
            assert_eq!(a.spend.spend_auth_sig, expected);
        }

        for (a, b) in actions.iter().zip(orig_actions.iter()) {
            assert_eq!(a.spend.fvk, b.spend.fvk);
            assert!(a.spend.fvk.is_some());
            assert_eq!(a.spend.witness.is_some(), b.spend.witness.is_some());
        }
    }

    #[test]
    fn rejects_a_reply_for_a_different_transaction() {
        let mut other: src_::Pczt = postcard::from_bytes(&CAKE[8..]).unwrap();
        other.ironwood.as_mut().unwrap().actions.truncate(1);
        let bytes = with_header(&other, CAKE.len()).unwrap();
        assert!(apply_signatures(CAKE, &bytes).is_err());
    }

    #[test]
    fn rejects_a_foreign_encoding() {
        assert!(to_keystone(b"not a pczt at all").is_err());
        let mut v1 = CAKE.to_vec();
        v1[4] = 1;
        assert!(to_keystone(&v1).is_err());
    }
}
