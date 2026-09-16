//! Ledger access from Flutter.
//!
//! The device connection lives on the Dart side (ledger_flutter_plus over
//! BLE, or USB on Android); Rust drives the Official Zcash app protocol and
//! hands every APDU to the `exchange` callback, which answers with the raw
//! response including the status word, or an empty vector if the transport
//! failed.

#[cfg(feature = "flutter")]
use anyhow::{anyhow, Result};
#[cfg(feature = "flutter")]
use flutter_rust_bridge::{frb, DartFnFuture};
#[cfg(feature = "flutter")]
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};

#[cfg(feature = "flutter")]
use crate::{
    api::{
        coin::Coin,
        pay::{PcztPackage, SigningEvent},
    },
    frb_generated::StreamSink,
    ledger::{dart_device::DartDevice, official, official_sign},
    Sink,
};

/// Version of the Zcash app open on the device, e.g. "3.9.3".
///
/// Fails with the device's status word when another app is open, which is
/// the cheapest way to tell the user to switch apps before asking for keys.
#[cfg(feature = "flutter")]
#[frb]
pub async fn ledger_app_version(
    exchange: impl Fn(Vec<u8>) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
) -> Result<String> {
    let device = DartDevice::new(exchange);
    let (major, minor, patch) = official::get_app_version(&device).await?;
    Ok(format!("{major}.{minor}.{patch}"))
}

/// Unified full viewing key of ZIP-32 account `aindex` on the device
/// (transparent + orchard receivers). The user approves the export on the
/// device screen, so this blocks until they do.
#[cfg(feature = "flutter")]
#[frb]
pub async fn ledger_get_ufvk(
    aindex: u32,
    c: &Coin,
    exchange: impl Fn(Vec<u8>) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
) -> Result<String> {
    let device = DartDevice::new(exchange);
    Ok(official::get_ufvk(&device, &c.network(), aindex).await?)
}

/// Default unified address of a viewing key, for showing which account a
/// device key belongs to before the account exists in the database.
#[cfg(feature = "flutter")]
#[frb(sync)]
pub fn ufvk_default_address(ufvk: String, c: &Coin) -> Result<String> {
    let network = c.network();
    let uvk = UnifiedFullViewingKey::decode(&network, &ufvk)
        .map_err(|e| anyhow!("invalid unified viewing key: {e}"))?;
    let (ua, _) = uvk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
    Ok(ua.encode(&network))
}

/// Signs a transaction plan on the Official Zcash app.
///
/// Streams `SigningEvent::Progress` while the device reviews and signs, then
/// `SigningEvent::Result` with the proven, finalized package ready for
/// `extract_transaction`. Errors, including a refusal on the device, close
/// the stream with the error.
#[cfg(feature = "flutter")]
#[frb]
pub async fn ledger_sign_transaction(
    sink: StreamSink<SigningEvent>,
    package: PcztPackage,
    c: &Coin,
    exchange: impl Fn(Vec<u8>) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
) -> Result<()> {
    let device = DartDevice::new(exchange);
    let c = c.clone();
    tokio::spawn(async move {
        let result = async {
            let mut connection = c.get_connection().await?;
            official_sign::sign_transaction(
                &c.network(),
                &mut connection,
                c.account,
                &package,
                Some(&sink),
                &device,
            )
            .await
        }
        .await;
        match result {
            Ok(pkg) => sink.send(SigningEvent::Result(pkg)).await,
            Err(e) => sink.send_error(e).await,
        }
    });
    Ok(())
}
