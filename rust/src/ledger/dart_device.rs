// A Ledger reached through the Flutter side.
//
// On mobile the wallet cannot open the device itself: the BLE (and Android
// USB) connection is owned by ledger_flutter_plus on the Dart side. Rust keeps
// driving the Zcash app protocol and hands every APDU to a Dart closure, which
// sends it over the live connection and answers with the raw response, status
// word included.

use std::sync::Arc;

use flutter_rust_bridge::DartFnFuture;
use tonic::async_trait;

use crate::ledger::{
    transport::{APDUAnswer, APDUCommand, Device},
    LedgerError, LedgerResult,
};

type Exchange = dyn Fn(Vec<u8>) -> DartFnFuture<Vec<u8>> + Send + Sync;

pub struct DartDevice {
    exchange: Arc<Exchange>,
}

impl DartDevice {
    pub fn new(
        exchange: impl Fn(Vec<u8>) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            exchange: Arc::new(exchange),
        }
    }
}

#[async_trait]
impl Device for DartDevice {
    async fn execute(&self, command: APDUCommand) -> LedgerResult<APDUAnswer> {
        let ins = command.ins;
        let request = command.to_bytes()?;
        tracing::debug!("ledger > ins {ins:#04x} ({} bytes)", request.len());
        let response = (self.exchange)(request).await;
        // The Dart side answers an empty vector when the transport itself
        // failed (disconnected device, cancelled operation); the reason is
        // kept on that side and surfaced with the error.
        if response.is_empty() {
            return Err(LedgerError::Protocol(
                "the Ledger connection was lost while talking to the device".into(),
            ));
        }
        let answer = APDUAnswer::from_bytes(&response)?;
        tracing::debug!("ledger < sw {:#06x} ({} bytes)", answer.retcode, answer.data.len());
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(reply: Vec<u8>) -> DartDevice {
        DartDevice::new(move |_request| {
            let reply = reply.clone();
            Box::pin(async move { reply })
        })
    }

    fn probe() -> APDUCommand {
        APDUCommand {
            cla: 0xE0,
            ins: 0xC4,
            p1: 0,
            p2: 0,
            data: vec![],
        }
    }

    #[tokio::test]
    async fn reply_is_split_into_data_and_status_word() {
        let answer = device(vec![1, 2, 3, 0x90, 0x00]).execute(probe()).await.unwrap();
        assert_eq!(answer.data, vec![1, 2, 3]);
        assert_eq!(answer.retcode, 0x9000);
    }

    #[tokio::test]
    async fn a_bare_status_word_is_a_valid_reply() {
        let answer = device(vec![0x69, 0x85]).execute(probe()).await.unwrap();
        assert!(answer.data.is_empty());
        assert_eq!(answer.retcode, 0x6985);
    }

    #[tokio::test]
    async fn an_empty_reply_means_the_transport_failed() {
        let err = device(vec![]).execute(probe()).await.unwrap_err();
        assert!(matches!(err, LedgerError::Protocol(_)));
    }

    #[tokio::test]
    async fn the_request_is_a_framed_apdu() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let seen2 = seen.clone();
        let d = DartDevice::new(move |request| {
            seen2.lock().unwrap().push(request);
            Box::pin(async { vec![0x90, 0x00] })
        });
        d.execute(APDUCommand {
            cla: 0xE0,
            ins: 0x50,
            p1: 0x80,
            p2: 0x01,
            data: vec![0xAA, 0xBB],
        })
        .await
        .unwrap();
        assert_eq!(seen.lock().unwrap()[0], vec![0xE0, 0x50, 0x80, 0x01, 2, 0xAA, 0xBB]);
    }
}
