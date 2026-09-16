//! Wire mirrors of the PCZT v2 dialects Cake has to speak.
//!
//! Three encodings all call themselves "v2" and differ only in which fields
//! exist and which are optional:
//!
//! - [`cake`]: the `pczt` this crate pins, which every PCZT the wallet builds
//!   is written in;
//! - [`dst`]: `pczt` 0.8.0-rc.1, what a Keystone running Cypherpunk firmware
//!   reads;
//! - [`src_`]: the `lrz` fork of `pczt` 0.7, what the Cupcake signer reads
//!   (and what Cake itself wrote before its `pczt` upgrade).
//!
//! postcard is not self-describing: fields are positional and typed by the
//! compiled-in schema, so an `Option<T>` writes a tag byte that a bare `T`
//! does not, and one extra field shifts every byte after it. A PCZT written in
//! one dialect is misread by the others -- silently, since nothing is
//! malformed, only misaligned. These mirrors exist so each layout can be read
//! and written independently of any crate's private types, and the
//! translation happens at the QR boundary.

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

// ---- Cake's dialect: the `pczt` this crate pins ------------------------
//
// The encoding every PCZT this wallet builds is written in. It is the
// Keystone dialect plus the ZSA fields (a split-note seed and an asset on each
// spend and output, a ZSA note version, a trailing issuance bundle) that plain
// ZEC transactions leave empty.

pub mod cake {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum NoteVersion {
        V2,
        V3,
        V3Zsa,
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
        pub rseed_split_note: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 96]>")]
        pub fvk: Option<[u8; 96]>,
        pub witness: Option<(u32, [[u8; 32]; 32])>,
        pub alpha: Option<[u8; 32]>,
        pub zip32_derivation: Option<Zip32Derivation>,
        pub dummy_sk: Option<[u8; 32]>,
        pub proprietary: BTreeMap<String, Vec<u8>>,
        pub asset: Option<[u8; 32]>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Output {
        #[serde_as(as = "Option<[_; 32]>")]
        pub cmx: Option<[u8; 32]>,
        pub ephemeral_key: [u8; 32],
        pub enc_ciphertext: super::dst::EncCiphertext,
        pub out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub recipient: Option<[u8; 43]>,
        pub value: Option<u64>,
        pub rseed: Option<[u8; 32]>,
        pub ock: Option<[u8; 32]>,
        pub zip32_derivation: Option<Zip32Derivation>,
        pub user_address: Option<String>,
        pub proprietary: BTreeMap<String, Vec<u8>>,
        pub asset: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Pczt {
        pub global: Global,
        pub transparent: Option<TransparentBundle>,
        pub sapling: Option<super::dst::SaplingBundle>,
        pub orchard: Option<OrchardBundle>,
        pub ironwood: Option<OrchardBundle>,
        #[serde(default)]
        pub issue: Option<super::src_::IssueBundle>,
    }
}

// ---- Cupcake dialect: lrz 0.7 (Cake's own before its pczt upgrade) ----

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

// ---- Keystone dialect: 0.8.0-rc.1 -------------------------------------

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

/// The ZEC asset id, which the pinned `pczt` writes on every plain-ZEC spend
/// and output. The device dialects have no asset field.
fn zec_asset() -> [u8; 32] {
    orchard::note::AssetBase::zatoshi().to_bytes()
}

/// Accepts an asset only if it is ZEC (or absent), so dropping it on the way
/// to a device cannot hide a shielded asset transfer from its review.
fn require_zec(asset: Option<[u8; 32]>, what: &str) -> Result<(), String> {
    match asset {
        None => Ok(()),
        Some(a) if a == zec_asset() => Ok(()),
        Some(_) => Err(format!("{what} carries a shielded asset this device cannot sign")),
    }
}

fn need(v: Option<[u8; 32]>, what: &str) -> Result<[u8; 32], String> {
    v.ok_or_else(|| format!("the PCZT is missing {what}"))
}

fn cake_note_version(v: cake::NoteVersion) -> Result<NoteVersion, String> {
    match v {
        cake::NoteVersion::V2 => Ok(NoteVersion::V2),
        cake::NoteVersion::V3 => Ok(NoteVersion::V3),
        cake::NoteVersion::V3Zsa => Err("shielded asset notes cannot be signed by this device".into()),
    }
}

fn from_note_version(v: NoteVersion) -> cake::NoteVersion {
    match v {
        NoteVersion::V2 => cake::NoteVersion::V2,
        NoteVersion::V3 => cake::NoteVersion::V3,
    }
}

/// Checks the parts of a PCZT no device dialect can carry: split notes,
/// non-ZEC assets are checked per action; this covers the bundle level.
fn check_device_signable(p: &cake::Pczt) -> Result<(), String> {
    if p.issue.is_some() {
        return Err("asset issuance cannot be signed by this device".into());
    }
    if p
        .sapling
        .as_ref()
        .is_some_and(|s| !s.spends.is_empty() || !s.outputs.is_empty())
    {
        return Err("Sapling bundles cannot be signed by this device".into());
    }
    Ok(())
}

fn read_cake(bytes: &[u8], what: &str) -> Result<cake::Pczt, String> {
    postcard::from_bytes(split_header(bytes)?).map_err(|e| format!("could not read {what}: {e:?}"))
}

// ---- Cake <-> Keystone (dst) ------------------------------------------

fn cake_to_dst_orchard(b: cake::OrchardBundle) -> Result<dst::OrchardBundle, String> {
    Ok(dst::OrchardBundle {
        actions: b
            .actions
            .into_iter()
            .map(|a| {
                if a.spend.rseed_split_note.is_some() {
                    return Err("split notes cannot be signed by this device".to_string());
                }
                require_zec(a.spend.asset, "a spend")?;
                require_zec(a.output.asset, "an output")?;
                Ok(dst::Action {
                    cv_net: a.cv_net,
                    spend: dst::Spend {
                        nullifier: a.spend.nullifier,
                        rk: a.spend.rk,
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
                        cmx: a.output.cmx,
                        ephemeral_key: a.output.ephemeral_key,
                        enc_ciphertext: a.output.enc_ciphertext,
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
        anchor: b.anchor,
        note_version: cake_note_version(b.note_version)?,
        zkproof: b.zkproof,
        bsk: b.bsk,
    })
}

fn dst_to_cake_orchard(b: dst::OrchardBundle) -> cake::OrchardBundle {
    cake::OrchardBundle {
        actions: b
            .actions
            .into_iter()
            .map(|a| cake::Action {
                cv_net: a.cv_net,
                spend: cake::Spend {
                    nullifier: a.spend.nullifier,
                    rk: a.spend.rk,
                    spend_auth_sig: a.spend.spend_auth_sig,
                    recipient: a.spend.recipient,
                    value: a.spend.value,
                    rho: a.spend.rho,
                    rseed: a.spend.rseed,
                    rseed_split_note: None,
                    fvk: a.spend.fvk,
                    witness: a.spend.witness,
                    alpha: a.spend.alpha,
                    zip32_derivation: a.spend.zip32_derivation,
                    dummy_sk: a.spend.dummy_sk,
                    proprietary: a.spend.proprietary,
                    asset: Some(zec_asset()),
                },
                output: cake::Output {
                    cmx: a.output.cmx,
                    ephemeral_key: a.output.ephemeral_key,
                    enc_ciphertext: a.output.enc_ciphertext,
                    out_ciphertext: a.output.out_ciphertext,
                    recipient: a.output.recipient,
                    value: a.output.value,
                    rseed: a.output.rseed,
                    ock: a.output.ock,
                    zip32_derivation: a.output.zip32_derivation,
                    user_address: a.output.user_address,
                    proprietary: a.output.proprietary,
                    asset: Some(zec_asset()),
                },
                rcv: a.rcv,
            })
            .collect(),
        flags: b.flags,
        value_sum: b.value_sum,
        anchor: b.anchor,
        note_version: from_note_version(b.note_version),
        zkproof: b.zkproof,
        bsk: b.bsk,
    }
}

// ---- Cake <-> Cupcake (src_, lrz 0.7) ---------------------------------

fn cake_to_src_orchard(b: cake::OrchardBundle) -> Result<src_::OrchardBundle, String> {
    Ok(src_::OrchardBundle {
        actions: b
            .actions
            .into_iter()
            .map(|a| {
                if a.spend.rseed_split_note.is_some() {
                    return Err("split notes cannot be signed by this device".to_string());
                }
                require_zec(a.spend.asset, "a spend")?;
                require_zec(a.output.asset, "an output")?;
                Ok(src_::Action {
                    cv_net: need(a.cv_net, "an action's cv_net")?,
                    spend: src_::Spend {
                        nullifier: need(a.spend.nullifier, "a spend nullifier")?,
                        rk: need(a.spend.rk, "a spend rk")?,
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
                        cmx: need(a.output.cmx, "an output cmx")?,
                        ephemeral_key: a.output.ephemeral_key,
                        enc_ciphertext: match a.output.enc_ciphertext {
                            dst::EncCiphertext::Encrypted(c) => c,
                            dst::EncCiphertext::MemoPlaintext(_) => {
                                return Err("the PCZT left a memo unencrypted".into())
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
        anchor: need(b.anchor, "a bundle anchor")?,
        note_version: cake_note_version(b.note_version)?,
        zkproof: b.zkproof,
        bsk: b.bsk,
    })
}

fn src_to_cake_orchard(b: src_::OrchardBundle) -> cake::OrchardBundle {
    cake::OrchardBundle {
        actions: b
            .actions
            .into_iter()
            .map(|a| cake::Action {
                cv_net: Some(a.cv_net),
                spend: cake::Spend {
                    nullifier: Some(a.spend.nullifier),
                    rk: Some(a.spend.rk),
                    spend_auth_sig: a.spend.spend_auth_sig,
                    recipient: a.spend.recipient,
                    value: a.spend.value,
                    rho: a.spend.rho,
                    rseed: a.spend.rseed,
                    rseed_split_note: None,
                    fvk: a.spend.fvk,
                    witness: a.spend.witness,
                    alpha: a.spend.alpha,
                    zip32_derivation: a.spend.zip32_derivation,
                    dummy_sk: a.spend.dummy_sk,
                    proprietary: a.spend.proprietary,
                    asset: Some(zec_asset()),
                },
                output: cake::Output {
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
                    asset: Some(zec_asset()),
                },
                rcv: a.rcv,
            })
            .collect(),
        flags: b.flags,
        value_sum: b.value_sum,
        anchor: Some(b.anchor),
        note_version: from_note_version(b.note_version),
        zkproof: b.zkproof,
        bsk: b.bsk,
    }
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

/// Parses a PCZT in Cake's dialect and transcodes it to the one a Keystone
/// reads, without the framing header. The batch request carries these
/// headerless; [`to_keystone`] wraps a single one for the legacy path.
fn to_dst_pczt(bytes: &[u8]) -> Result<dst::Pczt, String> {
    let p = read_cake(bytes, "this PCZT")?;
    check_device_signable(&p)?;
    Ok(dst::Pczt {
        global: p.global,
        transparent: p.transparent,
        sapling: p.sapling,
        orchard: p.orchard.map(cake_to_dst_orchard).transpose()?,
        ironwood: p.ironwood.map(cake_to_dst_orchard).transpose()?,
    })
}

/// Global fields of a PCZT in Cake's dialect.
///
/// The pinned `pczt` exposes no getters for the fallback lock time, coin type
/// or modifiable flags, which a device header has to carry verbatim.
pub fn read_global(bytes: &[u8]) -> Result<Global, String> {
    Ok(read_cake(bytes, "this PCZT")?.global)
}

/// Rewrites a PCZT from Cake's dialect into the one a Keystone reads.
pub fn to_keystone(bytes: &[u8]) -> Result<Vec<u8>, String> {
    with_header(&to_dst_pczt(bytes)?, bytes.len())
}

/// Rewrites a signed PCZT from the Keystone's dialect back into Cake's.
pub fn from_keystone(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let signed: dst::Pczt = postcard::from_bytes(split_header(bytes)?)
        .map_err(|e| format!("could not read the signed PCZT: {e:?}"))?;
    let out = cake::Pczt {
        global: signed.global,
        transparent: signed.transparent,
        sapling: signed.sapling,
        orchard: signed.orchard.map(dst_to_cake_orchard),
        ironwood: signed.ironwood.map(dst_to_cake_orchard),
        issue: None,
    };
    with_header(&out, bytes.len())
}

/// Rewrites a PCZT from Cake's dialect into the one the Cupcake signer reads.
pub fn to_cupcake(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let p = read_cake(bytes, "this PCZT")?;
    check_device_signable(&p)?;
    let out = src_::Pczt {
        global: p.global,
        transparent: p.transparent,
        // The pinned `pczt` writes an empty Sapling bundle as present with no
        // anchor (and the IO Finalizer's zero binding key); the Cupcake
        // dialect writes it as absent. A bundle with no spends or outputs has
        // no binding signature and nothing a signature commits to, so the two
        // mean the same.
        sapling: p
            .sapling
            .filter(|s| {
                !(s.spends.is_empty()
                    && s.outputs.is_empty()
                    && s.value_sum == 0
                    && s.anchor.is_none())
            })
            .map(|s| {
                Ok::<_, String>(src_::SaplingBundle {
                    spends: s.spends,
                    outputs: s.outputs,
                    value_sum: s.value_sum,
                    anchor: need(s.anchor, "a Sapling anchor")?,
                    bsk: s.bsk,
                })
            })
            .transpose()?,
        orchard: p.orchard.map(cake_to_src_orchard).transpose()?,
        ironwood: p.ironwood.map(cake_to_src_orchard).transpose()?,
        issue: None,
    };
    with_header(&out, bytes.len())
}

/// Rewrites a PCZT from the Cupcake signer's dialect (Cake's own before its
/// `pczt` upgrade) into Cake's current one.
pub fn from_cupcake(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let p: src_::Pczt = postcard::from_bytes(split_header(bytes)?)
        .map_err(|e| format!("could not read the PCZT: {e:?}"))?;
    if p.issue.is_some() {
        return Err("asset issuance is not supported here".into());
    }
    let out = cake::Pczt {
        global: p.global,
        transparent: p.transparent,
        sapling: p.sapling.map(|s| dst::SaplingBundle {
            spends: s.spends,
            outputs: s.outputs,
            value_sum: s.value_sum,
            anchor: Some(s.anchor),
            bsk: s.bsk,
        }),
        orchard: p.orchard.map(src_to_cake_orchard),
        ironwood: p.ironwood.map(src_to_cake_orchard),
        issue: None,
    };
    with_header(&out, bytes.len())
}

/// Applies a Keystone's signatures to the PCZT this wallet built.
///
/// A signer returns only what it needed to produce: it redacts prover-only
/// fields such as the full viewing key, so its reply cannot be proved on its
/// own. Rather than trusting the returned document, keep the original and take
/// just the signatures out of the reply. Both arguments are in Cake's dialect
/// (translate a Keystone reply with [`from_keystone`] first).
pub fn apply_signatures(original: &[u8], signed: &[u8]) -> Result<Vec<u8>, String> {
    let mut orig = read_cake(original, "the original PCZT")?;
    let from_device = read_cake(signed, "the signed PCZT")?;

    fn merge_orchard(
        into: &mut Option<cake::OrchardBundle>,
        from: &Option<cake::OrchardBundle>,
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

// ---- batch signing (zcash-sign-batch / zcash-batch-sig-result) ---------
//
// The device's batch protocol shrinks the airgapped round trip. The request
// carries headerless v2 PCZTs under one shared version; the reply is only the
// Orchard/Ironwood spend-auth signatures, not a whole PCZT -- an order of
// magnitude fewer QR frames coming back. Firmware 3.0.2 (cypherpunk) speaks
// batch version 1; see keystone3-firmware docs/protocols/ur_registrys/zcash.md.
//
// Only shielded spends are signable this way: the device rejects a batch PCZT
// with transparent inputs or Sapling. The caller routes only shielded sends
// here and keeps the transparent shield on the single zcash-pczt path.

const BATCH_REQUEST_MAGIC: [u8; 4] = *b"PCZB";
const BATCH_RESPONSE_MAGIC: [u8; 4] = *b"PCZS";
const BATCH_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct BatchSignRequest {
    pczts: Vec<dst::Pczt>,
}

#[derive(Serialize, Deserialize)]
struct BatchSignResponse {
    signatures: Vec<Vec<SpendAuthSignature>>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum ValuePool {
    Orchard,
    Ironwood,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct SpendAuthSignature {
    value_pool: ValuePool,
    action_index: u32,
    #[serde_as(as = "[_; 64]")]
    signature: [u8; 64],
}

/// Builds a `zcash-sign-batch` request body from PCZTs in Cake's dialect.
///
/// Each is transcoded to the device's v2 dialect and carried headerless; the
/// shared PCZT version rides in the batch header. The bytes returned are the
/// opaque `data` the UR layer wraps.
pub fn to_batch_request(pczts: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if pczts.is_empty() {
        return Err("a batch request needs at least one transaction".into());
    }
    let mut dst_pczts: Vec<dst::Pczt> =
        pczts.iter().map(|b| to_dst_pczt(b)).collect::<Result<_, _>>()?;
    // The device rejects a batch request carrying ANY spend-authorization
    // signature -- including the ones the IO Finalizer puts on preauthorized
    // padding (dummy) spends before this wallet ever saw the transaction.
    // Strip them from the request; the wallet-owned base PCZT keeps them, and
    // apply_batch_sig_result layers the device's real-spend signatures on top.
    for p in dst_pczts.iter_mut() {
        clear_batch_spend_auth_sigs(p);
    }
    let body = BatchSignRequest { pczts: dst_pczts };
    let hint: usize = pczts.iter().map(|b| b.len()).sum();
    let mut buf = Vec::with_capacity(hint + 32);
    buf.extend_from_slice(&BATCH_REQUEST_MAGIC);
    buf.extend_from_slice(&BATCH_VERSION.to_le_bytes());
    buf.extend_from_slice(&V2.to_le_bytes()); // one shared PCZT version for the batch
    postcard::to_extend(&body, buf).map_err(|e| format!("batch request encode failed: {e:?}"))
}

/// Removes every Orchard and Ironwood spend-auth signature from a PCZT bound
/// for a batch request. The device refuses a request that carries any.
fn clear_batch_spend_auth_sigs(pczt: &mut dst::Pczt) {
    for bundle in [pczt.orchard.as_mut(), pczt.ironwood.as_mut()] {
        if let Some(b) = bundle {
            for a in b.actions.iter_mut() {
                a.spend.spend_auth_sig = None;
            }
        }
    }
}

/// Applies a `zcash-batch-sig-result` reply to the PCZT this wallet built.
///
/// The reply carries only spend-auth signatures, keyed by value pool and action
/// index; everything the prover needs stays in `original`, which must be the
/// single PCZT that was sent in the batch.
pub fn apply_batch_sig_result(original: &[u8], response: &[u8]) -> Result<Vec<u8>, String> {
    if response.len() < 8 || response[..4] != BATCH_RESPONSE_MAGIC {
        return Err("not a batch signature response".into());
    }
    let version = u32::from_le_bytes(response[4..8].try_into().unwrap());
    if version != BATCH_VERSION {
        return Err(format!("expected batch version {BATCH_VERSION}, got {version}"));
    }
    let (parsed, rest): (BatchSignResponse, _) = postcard::take_from_bytes(&response[8..])
        .map_err(|e| format!("could not read the batch response: {e:?}"))?;
    if !rest.is_empty() {
        return Err("trailing data after the batch response".into());
    }
    // One PCZT was sent, so its signatures are the first (and only) entry.
    let sigs = parsed
        .signatures
        .into_iter()
        .next()
        .ok_or("the device returned no signatures")?;

    let mut orig = read_cake(original, "the original PCZT")?;

    let mut applied = 0usize;
    for sig in sigs {
        let (bundle, pool) = match sig.value_pool {
            ValuePool::Orchard => (orig.orchard.as_mut(), "Orchard"),
            ValuePool::Ironwood => (orig.ironwood.as_mut(), "Ironwood"),
        };
        let bundle = bundle.ok_or_else(|| {
            format!("the response signs a {pool} action but the transaction has no {pool} bundle")
        })?;
        let action_count = bundle.actions.len();
        let action = bundle
            .actions
            .get_mut(sig.action_index as usize)
            .ok_or_else(|| {
                format!(
                    "the response signs {pool} action {} but the transaction has {action_count}",
                    sig.action_index
                )
            })?;
        // A spend the IO Finalizer already signed (a dummy) keeps its signature.
        if action.spend.spend_auth_sig.is_none() {
            action.spend.spend_auth_sig = Some(sig.signature);
            applied += 1;
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

    /// A shield-shaped PCZT built with the `pczt` this crate pins today: one
    /// transparent input sweeping into an Ironwood output, IO-finalized, so
    /// the padding actions carry dummy spends with their signatures. Every
    /// translation is tested against this rather than only against the
    /// recorded fixtures, which predate the current encoding.
    pub(crate) fn fresh_shield_pczt() -> Vec<u8> {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
        use rand_core::OsRng;
        use secp256k1::{PublicKey, Secp256k1, SecretKey};
        use zcash_primitives::transaction::{
            builder::{BuildConfig, Builder, BundlePadding},
            fees::zip317::FeeRule,
        };
        use zcash_protocol::{
            consensus::{NetworkUpgrade, Parameters},
            value::Zatoshis,
        };
        use zcash_transparent::{
            address::TransparentAddress,
            builder::{SpendInfo, TransparentInputInfo},
            bundle::{OutPoint, TxOut},
        };

        let network = crate::api::coin::Network::Main;
        let height = network.activation_height(NetworkUpgrade::Nu6_3).unwrap() + 10;
        let config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(&network, height, config);

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &sk);
        let addr = TransparentAddress::from_pubkey(&pubkey);
        let coin = TxOut::new(Zatoshis::from_u64(200_000).unwrap(), addr.script().into());
        builder.add_transparent_input(
            TransparentInputInfo::from_parts(
                OutPoint::new([3u8; 32], 1),
                coin,
                SpendInfo::P2pkh { pubkey },
            )
            .unwrap(),
        );

        let osk = SpendingKey::from_bytes([7u8; 32]).unwrap();
        let fvk = FullViewingKey::from(&osk);
        let to = fvk.address_at(0u32, Scope::External);
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(fvk.to_ovk(Scope::External)),
                to,
                Zatoshis::from_u64(185_000).unwrap(),
                zcash_protocol::memo::MemoBytes::empty(),
            )
            .unwrap();

        let r = builder
            .build_for_pczt(OsRng, &FeeRule::standard(), |_: &orchard::note::AssetBase| false)
            .unwrap();
        let pczt = Creator::build_from_parts(r.pczt_parts).unwrap();
        let (pczt, _) = IoFinalizer::new(pczt).finalize_io().unwrap();
        pczt.serialize().unwrap()
    }

    /// A real Ironwood PCZT built by Cake before its `pczt` upgrade, captured
    /// off the wire: the dialect the Cupcake signer still reads.
    const LEGACY: &[u8] = include_bytes!("../tests/data/cake_ironwood.pczt");

    /// The same transaction in the Keystone's dialect.
    ///
    /// Checked in as a golden file rather than re-derived: `pczt` 0.8.0-rc.1
    /// cannot be built alongside the stack this crate pins, so the device-side
    /// assertion cannot live here. These bytes were verified against the
    /// firmware's own parser, which reports two Ironwood actions and one
    /// signable spend.
    const KEYSTONE: &[u8] = include_bytes!("../tests/data/cake_ironwood.keystone.pczt");

    /// The recorded transaction in Cake's current dialect.
    fn cake_fixture() -> Vec<u8> {
        from_cupcake(LEGACY).expect("legacy fixture translates to Cake's dialect")
    }

    #[test]
    fn cake_mirror_matches_the_pinned_pczt() {
        let fresh = fresh_shield_pczt();
        let p = read_cake(&fresh, "fresh").expect("mirror decodes a freshly built PCZT");
        assert_eq!(with_header(&p, fresh.len()).unwrap(), fresh);
    }

    #[test]
    fn cupcake_translation_is_valid_for_the_pinned_pczt() {
        // What the Cupcake path hands back to the prover must be a PCZT the
        // real library accepts, not just one the mirror can round trip.
        pczt::Pczt::parse(&cake_fixture()).expect("pinned pczt parses the translated fixture");
    }

    #[test]
    fn matches_what_the_device_can_read() {
        assert_eq!(to_keystone(&cake_fixture()).expect("transcode"), KEYSTONE);
    }

    #[test]
    fn round_trips_are_lossless() {
        assert_eq!(from_keystone(KEYSTONE).expect("from keystone"), cake_fixture());
        assert_eq!(to_cupcake(&cake_fixture()).expect("to cupcake"), LEGACY);

        let fresh = fresh_shield_pczt();
        let via_keystone = from_keystone(&to_keystone(&fresh).unwrap()).unwrap();
        assert_eq!(via_keystone, fresh);
        // The Cupcake dialect has no "empty but present" Sapling bundle (see
        // to_cupcake), so compare everything else byte for byte, and check the
        // pinned library still accepts the result.
        let via_cupcake = from_cupcake(&to_cupcake(&fresh).unwrap()).unwrap();
        pczt::Pczt::parse(&via_cupcake).expect("pinned pczt parses the Cupcake round trip");
        let without_sapling = |b: &[u8]| {
            let mut p = read_cake(b, "round trip").unwrap();
            let s = p.sapling.take();
            assert!(s.map_or(true, |s| s.spends.is_empty() && s.outputs.is_empty()));
            with_header(&p, b.len()).unwrap()
        };
        assert_eq!(without_sapling(&via_cupcake), without_sapling(&fresh));
    }

    #[test]
    fn refuses_to_drop_a_shielded_asset() {
        let fresh = fresh_shield_pczt();
        let mut p = read_cake(&fresh, "fresh").unwrap();
        p.ironwood.as_mut().unwrap().actions[1].output.asset = Some([1u8; 32]);
        let tampered = with_header(&p, fresh.len()).unwrap();
        assert!(to_keystone(&tampered).is_err());
        assert!(to_cupcake(&tampered).is_err());
        assert!(to_batch_request(&[tampered]).is_err());
    }

    #[test]
    fn takes_signatures_and_keeps_prover_fields() {
        let original = cake_fixture();
        // Stand in for the device: strip the prover-only fields it redacts,
        // and attach a spend authorising signature.
        let mut device = read_cake(&original, "fixture").unwrap();
        let iw = device.ironwood.as_mut().unwrap();
        for a in iw.actions.iter_mut() {
            a.spend.fvk = None;
            a.spend.witness = None;
            a.spend.spend_auth_sig = Some([7u8; 64]);
        }
        let device_bytes = with_header(&device, original.len()).unwrap();

        let merged = apply_signatures(&original, &device_bytes).expect("apply");
        let out = read_cake(&merged, "merged").unwrap();
        let actions = &out.ironwood.as_ref().unwrap().actions;

        let orig = read_cake(&original, "fixture").unwrap();
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
        let original = cake_fixture();
        let mut other = read_cake(&original, "fixture").unwrap();
        other.ironwood.as_mut().unwrap().actions.truncate(1);
        let bytes = with_header(&other, original.len()).unwrap();
        assert!(apply_signatures(&original, &bytes).is_err());
    }

    #[test]
    fn rejects_a_foreign_encoding() {
        assert!(to_keystone(b"not a pczt at all").is_err());
        assert!(to_cupcake(b"not a pczt at all").is_err());
        let mut v1 = cake_fixture();
        v1[4] = 1;
        assert!(to_keystone(&v1).is_err());
        assert!(to_cupcake(&v1).is_err());
    }

    #[test]
    fn batch_request_strips_spend_auth_sigs() {
        let req = to_batch_request(&[cake_fixture()]).expect("batch request");
        // Header: "PCZB" || batch version 1 || pczt version 2, all little-endian.
        assert_eq!(&req[..4], b"PCZB");
        assert_eq!(u32::from_le_bytes(req[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(req[8..12].try_into().unwrap()), 2);

        let body: BatchSignRequest = postcard::from_bytes(&req[12..]).expect("decode body");
        assert_eq!(body.pczts.len(), 1);

        // The device refuses a batch request with any spend-auth signature.
        let inner = &body.pczts[0];
        for bundle in [inner.orchard.as_ref(), inner.ironwood.as_ref()] {
            if let Some(b) = bundle {
                assert!(
                    b.actions.iter().all(|a| a.spend.spend_auth_sig.is_none()),
                    "batch request must not carry any spend-auth signature"
                );
            }
        }

        // The device golden has an IO-Finalizer signature on its padding spend,
        // so stripping proves both that the fixture exercises the case and that
        // the batch inner is otherwise the device-dialect PCZT byte for byte.
        let mut golden: dst::Pczt = postcard::from_bytes(&KEYSTONE[8..]).unwrap();
        let had_sig = [golden.orchard.as_ref(), golden.ironwood.as_ref()]
            .iter()
            .flatten()
            .flat_map(|b| b.actions.iter())
            .any(|a| a.spend.spend_auth_sig.is_some());
        assert!(had_sig, "fixture must carry a spend-auth sig to strip");
        clear_batch_spend_auth_sigs(&mut golden);
        let golden_inner = postcard::to_extend(&golden, Vec::new()).unwrap();
        let inner_bytes = postcard::to_extend(inner, Vec::new()).unwrap();
        assert_eq!(inner_bytes, golden_inner);
    }

    #[test]
    fn batch_request_rejects_an_empty_batch() {
        assert!(to_batch_request(&[]).is_err());
    }

    #[test]
    fn applies_batch_signatures() {
        let original = cake_fixture();
        // The Ironwood actions the device would sign are those the IO Finalizer
        // left unsigned.
        let orig = read_cake(&original, "fixture").unwrap();
        let to_sign: Vec<u32> = orig
            .ironwood
            .as_ref()
            .unwrap()
            .actions
            .iter()
            .enumerate()
            .filter(|(_, a)| a.spend.spend_auth_sig.is_none())
            .map(|(i, _)| i as u32)
            .collect();
        assert!(!to_sign.is_empty(), "fixture must have a spend to sign");

        // Stand in for the device: a compact response signing just those.
        let body = BatchSignResponse {
            signatures: vec![to_sign
                .iter()
                .map(|&i| SpendAuthSignature {
                    value_pool: ValuePool::Ironwood,
                    action_index: i,
                    signature: [9u8; 64],
                })
                .collect()],
        };
        let mut resp = Vec::new();
        resp.extend_from_slice(b"PCZS");
        resp.extend_from_slice(&1u32.to_le_bytes());
        let resp = postcard::to_extend(&body, resp).unwrap();

        let merged = apply_batch_sig_result(&original, &resp).expect("apply");
        let out = read_cake(&merged, "merged").unwrap();
        let out_actions = &out.ironwood.as_ref().unwrap().actions;
        let orig_actions = &orig.ironwood.as_ref().unwrap().actions;

        // Every spend is now authorised; the ones the device signed took [9; 64],
        // and any the IO Finalizer had already signed kept theirs.
        assert!(out_actions.iter().all(|a| a.spend.spend_auth_sig.is_some()));
        for (a, b) in out_actions.iter().zip(orig_actions.iter()) {
            let expected = b.spend.spend_auth_sig.or(Some([9u8; 64]));
            assert_eq!(a.spend.spend_auth_sig, expected);
        }
        // The merged transaction is still one the pinned library accepts.
        pczt::Pczt::parse(&merged).expect("pinned pczt parses the merged PCZT");
    }

    #[test]
    fn rejects_a_malformed_batch_response() {
        let original = cake_fixture();
        // Wrong magic.
        assert!(apply_batch_sig_result(&original, b"nope____").is_err());
        // Right magic, unsupported version.
        let mut bad = Vec::new();
        bad.extend_from_slice(b"PCZS");
        bad.extend_from_slice(&2u32.to_le_bytes());
        assert!(apply_batch_sig_result(&original, &bad).is_err());
        // Valid header, no signatures.
        let empty = BatchSignResponse { signatures: vec![vec![]] };
        let mut resp = Vec::new();
        resp.extend_from_slice(b"PCZS");
        resp.extend_from_slice(&1u32.to_le_bytes());
        let resp = postcard::to_extend(&empty, resp).unwrap();
        assert!(apply_batch_sig_result(&original, &resp).is_err());
    }
}
