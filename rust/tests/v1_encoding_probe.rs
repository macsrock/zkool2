//! Scratch probe: dump v1 and v2 PCZT encodings of an Orchard-anchored PCZT
//! produced by this crate's pinned `pczt` (lrz 0.7), so they can be fed to
//! another pczt version's parser.

use pczt::roles::creator::Creator;
use zcash_protocol::consensus::BranchId;

#[test]
fn dump_v1_and_v2_encodings() {
    let branch: u32 = BranchId::Nu6.into();
    let mut out = String::new();

    for (tag, orchard_anchor) in [("ANCHORED", [7u8; 32]), ("EMPTYPOOLS", [0u8; 32])] {
        let pczt = Creator::new(branch, 10_000_000, 133, [0u8; 32], orchard_anchor)
            .unwrap()
            .build();

        let v2 = pczt.clone().serialize().expect("v2 serialize");
        out.push_str(&format!("{tag}-V2 {}\n", hex::encode(&v2)));

        match pczt::v1::Pczt::try_from(pczt) {
            Ok(v1) => out.push_str(&format!("{tag}-V1 {}\n", hex::encode(v1.serialize()))),
            Err(e) => out.push_str(&format!("V1_ERR {tag} {:?}\n", e)),
        }
    }

    // A v6 (NU6.3 / Ironwood) PCZT: can it use the v1 escape hatch at all?
    let branch63: u32 = BranchId::Nu6_3.into();
    let p6 = Creator::new(branch63, 10_000_000, 133, [0u8; 32], [7u8; 32])
        .unwrap()
        .build();
    match pczt::v1::Pczt::try_from(p6) {
        Ok(v1) => out.push_str(&format!("V6-V1 {}\n", hex::encode(v1.serialize()))),
        Err(e) => out.push_str(&format!("V1_ERR V6 {:?}\n", e)),
    }

    let path = std::env::var("PROBE_OUT").unwrap_or_else(|_| "/tmp/pczt_probe.txt".into());
    std::fs::write(&path, &out).unwrap();
    println!("{out}");
}
