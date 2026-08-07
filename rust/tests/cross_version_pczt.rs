//! Wire-compatibility check between PCZT implementations.
//!
//! This crate pins `pczt 0.7` (MrCyjaneK fork); the Cupcake airgapped signer
//! uses crates.io `pczt 0.9`. Both must read each other's bytes or the
//! airgapped flow cannot work: the signer's output has to parse here for
//! proving and broadcast.
//!
//! The fixture is a real Ironwood (NU6.3, v6) PCZT produced by the signer.

use pczt::Pczt;

#[test]
fn parses_a_pczt_serialized_by_the_airgapped_signer() {
    let hex_text = include_str!("cupcake_ironwood_pczt.hex");
    let bytes = hex::decode(hex_text.trim()).expect("fixture is valid hex");

    assert_eq!(&bytes[..4], b"PCZT", "fixture carries the PCZT magic");
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    println!("fixture PCZT version: {version}");

    match Pczt::parse(&bytes) {
        Ok(pczt) => {
            println!(
                "parsed OK: expiry={} orchard_actions={} ironwood_actions={}",
                pczt.global().expiry_height(),
                pczt.orchard().actions().len(),
                pczt.ironwood().actions().len(),
            );
        }
        Err(e) => panic!("INCOMPATIBLE: pczt 0.7 cannot parse 0.9 output: {e:?}"),
    }
}
