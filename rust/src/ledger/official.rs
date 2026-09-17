// Official Ledger App (LedgerHQ/app-zcash, CLA 0xE0)

#[cfg(feature = "ledger")]
use anyhow::Result;
use byteorder::{WriteBytesExt, BE};
#[cfg(feature = "ledger")]
use tonic::async_trait;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::NetworkConstants as _;

use crate::{
    api::coin::Network,
    ledger::{
        transport::{APDUCommand, Device},
        LedgerError, LedgerResult,
    },
};
#[cfg(feature = "ledger")]
use crate::ledger::{HwKind, LedgerApp};

/// The app reached over the desktop USB HID transport.
#[cfg(feature = "ledger")]
pub struct OfficialApp {}

const CLA: u8 = 0xE0;
const INS_GET_FIRMWARE_VERSION: u8 = 0xC4;
const INS_GET_VK: u8 = 0x50;
const INS_GET_SHIELD_ADDR: u8 = 0x51;
const P1_NO_DISPLAY: u8 = 0x00;
const P1_DISPLAY: u8 = 0x01;
const P2_UNIFIED_ADDRESS: u8 = 0x00;
const P1_FIRST: u8 = 0x00;
const P1_CONTINUE: u8 = 0x80;
const P2_UFVK: u8 = 0x00;
const SW_OK: u16 = 0x9000;
const SW_DENY: u16 = 0x6985;
const HARDENED: u32 = 0x8000_0000;
const MAX_RESPONSE_LEN: usize = 4096;

fn append_path(data: &mut Vec<u8>, purpose: u32, coin_type: u32, account: u32) -> LedgerResult<()> {
    data.write_u8(3)?;
    data.write_u32::<BE>(purpose | HARDENED)?;
    data.write_u32::<BE>(coin_type | HARDENED)?;
    data.write_u32::<BE>(account | HARDENED)?;
    Ok(())
}

/// m/44'/coin'/account'/0/0: the external address the device puts in its
/// unified address, as GET_SHIELD_ADDR wants it.
fn append_transparent_address_path(
    data: &mut Vec<u8>,
    coin_type: u32,
    account: u32,
) -> LedgerResult<()> {
    data.write_u8(5)?;
    data.write_u32::<BE>(44 | HARDENED)?;
    data.write_u32::<BE>(coin_type | HARDENED)?;
    data.write_u32::<BE>(account | HARDENED)?;
    data.write_u32::<BE>(0)?;
    data.write_u32::<BE>(0)?;
    Ok(())
}

/// The account's default unified address as the device derives it.
///
/// With `display`, the device shows the address on its own screen and waits
/// for the user to approve it; that screen is the only thing on the path a
/// tampered link cannot alter, so the host shows the address it derived from
/// the imported viewing key alongside, and the user compares the two. A
/// refusal on the device is reported as such.
pub async fn get_shield_address<D: Device>(
    ledger: &D,
    network: &Network,
    aindex: u32,
    display: bool,
) -> LedgerResult<String> {
    let coin_type = network.coin_type();
    let mut data = vec![];
    append_path(&mut data, 32, coin_type, aindex)?;
    append_transparent_address_path(&mut data, coin_type, aindex)?;

    let res = ledger
        .execute(APDUCommand {
            cla: CLA,
            ins: INS_GET_SHIELD_ADDR,
            p1: if display { P1_DISPLAY } else { P1_NO_DISPLAY },
            p2: P2_UNIFIED_ADDRESS,
            data,
        })
        .await?;
    if res.retcode == SW_DENY {
        return Err(LedgerError::Generic(
            SW_DENY,
            "user did not confirm the address on the device".into(),
        ));
    }
    if res.retcode != SW_OK {
        return Err(LedgerError::Execute(res.retcode, INS_GET_SHIELD_ADDR));
    }
    let payload = res.data;
    if payload.len() < 2 {
        return Err(LedgerError::Protocol("short address response".into()));
    }
    let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let body = &payload[2..];
    if body.len() < len {
        return Err(LedgerError::Protocol(
            "the device sent less of the address than it announced".into(),
        ));
    }
    let address = String::from_utf8(body[..len].to_vec())
        .map_err(|_| LedgerError::Protocol("invalid utf8 in address response".into()))?;
    let parsed = zcash_address::ZcashAddress::try_from_encoded(&address)
        .map_err(|_| LedgerError::Protocol("device returned an invalid address".into()))?;
    if !parsed.can_receive_as(zcash_protocol::PoolType::ORCHARD) {
        return Err(LedgerError::Protocol(
            "device address has no Orchard receiver".into(),
        ));
    }
    Ok(address)
}

/// Version of the Zcash app open on the device, as (major, minor, patch).
///
/// GET_FIRMWARE_VERSION is the Bitcoin-app style probe the Official app
/// answers even before any key is touched, so it doubles as the "is the right
/// app open" check: any other app answers with an error status word.
pub async fn get_app_version<D: Device>(ledger: &D) -> LedgerResult<(u8, u8, u8)> {
    let res = ledger
        .execute(APDUCommand {
            cla: CLA,
            ins: INS_GET_FIRMWARE_VERSION,
            p1: 0,
            p2: 0,
            data: vec![],
        })
        .await?;
    if res.retcode != SW_OK {
        return Err(LedgerError::Execute(res.retcode, INS_GET_FIRMWARE_VERSION));
    }
    // features, arch, major, minor, patch, ...
    if res.data.len() < 5 {
        return Err(LedgerError::Protocol("short version response".into()));
    }
    Ok((res.data[2], res.data[3], res.data[4]))
}

/// Ask the device for the account UFVK (Orchard + transparent receivers).
/// The user must approve the export on the device.
pub async fn get_ufvk<D: Device>(ledger: &D, network: &Network, aindex: u32) -> LedgerResult<String> {
    let coin_type = network.coin_type();
    let mut data = vec![];
    // m/32'/coin'/account' (Orchard, ZIP-32) then m/44'/coin'/account' (transparent)
    append_path(&mut data, 32, coin_type, aindex)?;
    append_path(&mut data, 44, coin_type, aindex)?;
    assert_eq!(data.len(), 26);

    let get_vk = APDUCommand {
        cla: CLA,
        ins: INS_GET_VK,
        p1: P1_FIRST,
        p2: P2_UFVK,
        data,
    };
    let res = ledger.execute(get_vk).await?;
    if res.retcode == SW_DENY {
        return Err(LedgerError::Generic(
            SW_DENY,
            "user refused to export the viewing key".into(),
        ));
    }
    if res.retcode != SW_OK {
        return Err(LedgerError::Execute(res.retcode, INS_GET_VK));
    }

    // response is len (u16 BE) || ufvk string, delivered in chunks
    let mut payload = res.data;
    if payload.len() < 2 {
        return Err(LedgerError::Protocol("short vk response".into()));
    }
    let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    payload.drain(..2);
    if len > payload.len() {
        if len > MAX_RESPONSE_LEN {
            return Err(LedgerError::Protocol("vk response too long".into()));
        }
        payload.reserve(len - payload.len());
    }
    while payload.len() < len {
        let next = APDUCommand {
            cla: CLA,
            ins: INS_GET_VK,
            p1: P1_CONTINUE,
            p2: P2_UFVK,
            data: vec![],
        };
        let res = ledger.execute(next).await?;
        if res.retcode != SW_OK {
            return Err(LedgerError::Execute(res.retcode, INS_GET_VK));
        }
        // A chunk that adds nothing would loop forever waiting for the rest.
        if res.data.is_empty() {
            return Err(LedgerError::Protocol(
                "the device stopped sending the viewing key before it was complete".into(),
            ));
        }
        payload.extend_from_slice(&res.data);
    }
    payload.truncate(len);

    let ufvk = String::from_utf8(payload).map_err(|_| LedgerError::Protocol("invalid utf8 in vk response".into()))?;
    let uvk = UnifiedFullViewingKey::decode(network, &ufvk)
        .map_err(|_| LedgerError::Protocol("device returned an invalid UFVK".into()))?;
    if uvk.orchard().is_none() || uvk.transparent().is_none() {
        return Err(LedgerError::Protocol(
            "device UFVK is missing the orchard or transparent receiver".into(),
        ));
    }
    Ok(ufvk)
}

#[cfg(feature = "ledger")]
#[async_trait]
impl LedgerApp for OfficialApp {
    fn kind(&self) -> HwKind {
        HwKind::Official
    }

    async fn get_ufvk(&self, network: &Network, aindex: u32) -> Result<String> {
        let ledger = crate::ledger::transport::connect_ledger().await?;
        Ok(get_ufvk(&ledger, network, aindex).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tonic::async_trait;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    use crate::ledger::transport::APDUAnswer;

    /// Replays scripted replies and records the commands it was sent.
    struct Scripted {
        replies: Mutex<Vec<Vec<u8>>>,
        sent: Mutex<Vec<APDUCommand>>,
    }

    impl Scripted {
        fn new(replies: Vec<Vec<u8>>) -> Self {
            Self {
                replies: Mutex::new(replies),
                sent: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl Device for Scripted {
        async fn execute(&self, command: APDUCommand) -> LedgerResult<APDUAnswer> {
            self.sent.lock().unwrap().push(command);
            let mut replies = self.replies.lock().unwrap();
            if replies.is_empty() {
                return Err(LedgerError::Protocol("script exhausted".into()));
            }
            APDUAnswer::from_bytes(&replies.remove(0))
        }
    }

    fn with_sw(mut data: Vec<u8>, sw: u16) -> Vec<u8> {
        data.extend_from_slice(&sw.to_be_bytes());
        data
    }

    #[tokio::test]
    async fn app_version_is_parsed_from_the_firmware_probe() {
        // What app-zcash 3.9.3 answers to GET_FIRMWARE_VERSION.
        let device = Scripted::new(vec![hex::decode("38300309030100039000").unwrap()]);
        let version = get_app_version(&device).await.unwrap();
        assert_eq!(version, (3, 9, 3));
        let sent = device.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!((sent[0].cla, sent[0].ins), (CLA, INS_GET_FIRMWARE_VERSION));
    }

    #[tokio::test]
    async fn wrong_app_fails_the_version_probe() {
        let device = Scripted::new(vec![vec![0x6e, 0x01]]);
        let err = get_app_version(&device).await.unwrap_err();
        assert!(matches!(err, LedgerError::Execute(0x6e01, INS_GET_FIRMWARE_VERSION)));
    }

    #[tokio::test]
    async fn ufvk_is_reassembled_across_continuation_chunks() {
        let network = Network::Main;
        let seed = [7u8; 32];
        let usk = UnifiedSpendingKey::from_seed(&network, &seed, AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key().encode(&network);
        let bytes = ufvk.as_bytes();

        // len (u16 BE) || first slice, then the rest in two more chunks.
        let mut first = (bytes.len() as u16).to_be_bytes().to_vec();
        first.extend_from_slice(&bytes[..100]);
        let device = Scripted::new(vec![
            with_sw(first, SW_OK),
            with_sw(bytes[100..180].to_vec(), SW_OK),
            with_sw(bytes[180..].to_vec(), SW_OK),
        ]);

        let got = get_ufvk(&device, &network, 0).await.unwrap();
        assert_eq!(got, ufvk);

        let sent = device.sent.lock().unwrap();
        assert_eq!(sent.len(), 3);
        // First command carries both derivation paths for account 0.
        assert_eq!(sent[0].p1, P1_FIRST);
        assert_eq!(sent[0].data.len(), 26);
        assert_eq!(&sent[0].data[0..5], &[3, 0x80, 0, 0, 32]);
        assert_eq!(&sent[0].data[13..18], &[3, 0x80, 0, 0, 44]);
        assert!(sent[1..].iter().all(|c| c.p1 == P1_CONTINUE && c.data.is_empty()));
    }

    #[tokio::test]
    async fn an_empty_continuation_chunk_is_an_error_not_a_hang() {
        let mut first = 300u16.to_be_bytes().to_vec();
        first.extend_from_slice(&[b'u'; 100]);
        let device = Scripted::new(vec![with_sw(first, SW_OK), vec![0x90, 0x00]]);
        let err = get_ufvk(&device, &Network::Main, 0).await.unwrap_err();
        assert!(matches!(err, LedgerError::Protocol(_)));
    }

    fn account_zero_address(network: &Network) -> String {
        let usk = UnifiedSpendingKey::from_seed(network, &[7u8; 32], AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let (ua, _) = ufvk
            .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
            .unwrap();
        ua.encode(network)
    }

    #[tokio::test]
    async fn the_device_address_is_requested_on_screen_for_the_external_path() {
        let network = Network::Main;
        let ua = account_zero_address(&network);
        let mut reply = (ua.len() as u16).to_be_bytes().to_vec();
        reply.extend_from_slice(ua.as_bytes());
        let device = Scripted::new(vec![with_sw(reply, SW_OK)]);

        let got = get_shield_address(&device, &network, 0, true).await.unwrap();
        assert_eq!(got, ua);

        let sent = device.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].ins, INS_GET_SHIELD_ADDR);
        assert_eq!(sent[0].p1, P1_DISPLAY);
        assert_eq!(sent[0].p2, P2_UNIFIED_ADDRESS);
        // Orchard account path, then the five-component transparent address path.
        assert_eq!(&sent[0].data[0..5], &[3, 0x80, 0, 0, 32]);
        assert_eq!(&sent[0].data[13..18], &[5, 0x80, 0, 0, 44]);
        assert_eq!(&sent[0].data[26..34], &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sent[0].data.len(), 13 + 21);
    }

    #[tokio::test]
    async fn a_truncated_or_foreign_address_reply_is_refused() {
        let network = Network::Main;
        let ua = account_zero_address(&network);
        let mut short = (ua.len() as u16).to_be_bytes().to_vec();
        short.extend_from_slice(&ua.as_bytes()[..20]);
        let device = Scripted::new(vec![with_sw(short, SW_OK)]);
        assert!(matches!(
            get_shield_address(&device, &network, 0, true).await.unwrap_err(),
            LedgerError::Protocol(_)
        ));

        let junk = b"not an address";
        let mut reply = (junk.len() as u16).to_be_bytes().to_vec();
        reply.extend_from_slice(junk);
        let device = Scripted::new(vec![with_sw(reply, SW_OK)]);
        assert!(matches!(
            get_shield_address(&device, &network, 0, true).await.unwrap_err(),
            LedgerError::Protocol(_)
        ));

        let device = Scripted::new(vec![vec![0x69, 0x85]]);
        assert!(matches!(
            get_shield_address(&device, &network, 0, true).await.unwrap_err(),
            LedgerError::Generic(SW_DENY, _)
        ));
    }

    #[tokio::test]
    async fn refusing_the_export_is_reported_as_such() {
        let device = Scripted::new(vec![vec![0x69, 0x85]]);
        let err = get_ufvk(&device, &Network::Main, 0).await.unwrap_err();
        assert!(matches!(err, LedgerError::Generic(SW_DENY, _)));
    }
}
