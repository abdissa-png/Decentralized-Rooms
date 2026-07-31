//! Length-prefixed sync frames over libp2p request-response.
//!
//! Protocol id: [`SYNC_PROTOCOL_ID`] (`/derooms/sync/1.0.0`).
//! Frames are opaque bytes from transport's POV — Offer / Want / Have / Ack
//! encoding lives in `rooms-proto` / `rooms-sync`.
//!
//! Connections use libp2p **Noise** (TCP+Noise+Yamux). Circuit relay is a
//! Phase 1 residual (see `docs/gate-1-review.md`).

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{self, Codec, ProtocolSupport};
use libp2p::StreamProtocol;
use std::io;

/// libp2p protocol id for Gate 1 sync (Offer/Want/Have/Ack).
pub const SYNC_PROTOCOL_ID: &str = "/derooms/sync/1.0.0";

/// Max sync payload (16 MiB) — text + small sealed objects for Phase 1.
const MAX_SYNC_MESSAGE: usize = 16 * 1024 * 1024;

/// Opaque sync frame bytes (already versioned by rooms-proto).
pub type SyncPayload = Vec<u8>;

/// Length-prefixed (u32 LE) request/response codec for sync frames.
#[derive(Clone, Default, Debug)]
pub struct SyncCodec;

async fn read_lp<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_SYNC_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sync payload too large",
        ));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        io.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn write_lp<T>(io: &mut T, data: Vec<u8>) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if data.len() > MAX_SYNC_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync payload too large",
        ));
    }
    let len = (data.len() as u32).to_le_bytes();
    io.write_all(&len).await?;
    io.write_all(&data).await?;
    io.close().await?;
    Ok(())
}

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncPayload;
    type Response = SyncPayload;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_lp(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_lp(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp(io, req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp(io, res).await
    }
}

/// Build the request-response behaviour for `/derooms/sync/1.0.0`.
pub fn sync_behaviour() -> request_response::Behaviour<SyncCodec> {
    request_response::Behaviour::new(
        [(StreamProtocol::new(SYNC_PROTOCOL_ID), ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn length_prefix_roundtrip_via_codec_helpers() {
        let payload = b"rooms-sync-offer-frame".to_vec();
        let mut buf = Vec::new();
        {
            let mut cursor = futures::io::Cursor::new(&mut buf);
            write_lp(&mut cursor, payload.clone()).await.unwrap();
        }
        // Cursor after write_lp closes — re-read from bytes (skip close effect on Vec).
        // write_lp appends len+data then close (no-op on Cursor<&mut Vec>).
        let mut reader = futures::io::Cursor::new(&buf[..]);
        let got = read_lp(&mut reader).await.unwrap();
        assert_eq!(got, payload);
    }
}
