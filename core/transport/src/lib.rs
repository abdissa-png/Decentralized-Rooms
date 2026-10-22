//! Transport abstraction for Decentralized Encrypted Rooms.
//!
//! Owns streams, NAT traversal, and mesh adapters (QUIC via libp2p, relay,
//! BLE / Wi‑Fi Direct later). Does **not** own room ACL (architecture §11.2).
//!
//! Sessions are Noise-encrypted via **libp2p Noise** on TCP/QUIC streams
//! (SRS `FR-TX-002`). Additional [`noise_session`] helpers use `snow` Noise XX
//! for unit demos of transport AEAD (not application 1:1 crypto — that is
//! Signal Protocol / `rooms-signal`).
//!
//! Sync frames multiplex on [`SYNC_PROTOCOL_ID`] (`/derooms/sync/1.0.0`) via
//! libp2p request-response (length-prefixed Offer / Want / Have / Ack bytes).
//!
//! # Status
//! Phase 1: [`Transport`] trait + libp2p Swarm (QUIC listen + TCP+Noise dial) +
//! sync stream protocol + snow XX. TCP circuit relay helper for NAT labs
//! ([`tcp_relay`]); full libp2p relay v2 still residual.
//!
//! # Dependency pins
//! - `libp2p` **0.54** (workspace) — compatible with `blake3 = "=1.5.5"`.
//! - `snow` **0.10** — Noise XX helpers only; production streams use libp2p Noise.

mod noise_session;
mod sync_protocol;
mod tcp_relay;

pub use noise_session::{
    noise_xx_handshake, noise_xx_roundtrip, NoiseSessionError, NoiseXxPair, NOISE_PATTERN,
};
pub use sync_protocol::{sync_behaviour, SyncCodec, SyncPayload, SYNC_PROTOCOL_ID};
pub use tcp_relay::{
    decode_register, dial_via_relay, dial_via_relay_with_retry, encode_register,
    normalize_relay_host_port, relay_dial_hint, RelayError, TcpRelayServer, DIAL_ACK_TIMEOUT,
    MAX_ACTIVE_SPLICES, MAX_PENDING_SESSIONS, PENDING_TTL, RELAY_MAGIC, RELAY_VERSION,
};

use futures::StreamExt;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, noise, ping, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use std::collections::HashMap;
use std::time::Duration;

/// Bandwidth / latency class used to select sync policy (architecture principle 3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportClass {
    /// QUIC / good internet — full sync.
    OnlineHigh,
    /// Constrained IP path.
    OnlineLow,
    /// Local mesh (BLE / Wi‑Fi Direct).
    LocalMesh,
    /// Ultra-low / radio (deferred).
    UltraLow,
}

/// Opaque peer dial target (multiaddr string).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAddr(pub String);

/// Transport errors.
#[derive(Clone, Debug)]
pub enum TransportError {
    Build(String),
    Listen(String),
    Dial(String),
    Sync(String),
    Disconnected(String),
    Timeout,
}

/// Architecture §11.2 transport trait stub (single impl OK in Phase 1).
pub trait Transport {
    fn local_peer_id(&self) -> String;
    fn preferred_class(&self) -> TransportClass;
}

/// Placeholder handle kept for facade compatibility.
#[derive(Clone, Debug, Default)]
pub struct TransportHandle {
    pub preferred: Option<TransportClass>,
}

impl TransportHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_preferred(class: TransportClass) -> Self {
        Self {
            preferred: Some(class),
        }
    }
}

/// Combined ping + identify + sync behaviour for the Phase 1 host.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct RoomsBehaviour {
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub sync: request_response::Behaviour<SyncCodec>,
}

impl RoomsBehaviour {
    pub fn new(local_public_key: libp2p::identity::PublicKey) -> Self {
        let identify = identify::Behaviour::new(identify::Config::new(
            "/rooms/0.1.0".into(),
            local_public_key,
        ));
        Self {
            ping: ping::Behaviour::default(),
            identify,
            sync: sync_behaviour(),
        }
    }
}

/// Inbound sync request waiting for an application response.
pub struct InboundSyncRequest {
    pub peer: PeerId,
    pub payload: SyncPayload,
    pub channel: ResponseChannel<SyncPayload>,
}

/// libp2p host (QUIC + TCP+Noise+Yamux + sync protocol) implementing [`Transport`].
pub struct Libp2pHost {
    swarm: Swarm<RoomsBehaviour>,
    preferred: TransportClass,
    /// Pending outbound sync responses keyed by request id.
    pending_sync: HashMap<OutboundRequestId, Option<Result<SyncPayload, TransportError>>>,
    /// Inbound sync requests that arrived while polling other waits.
    pending_inbound: std::collections::VecDeque<InboundSyncRequest>,
}

impl Libp2pHost {
    /// Build a Swarm with TCP+Noise+Yamux and QUIC; sync on [`SYNC_PROTOCOL_ID`].
    pub fn new() -> Result<Self, TransportError> {
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| TransportError::Build(e.to_string()))?
            .with_quic()
            .with_behaviour(|key| Ok(RoomsBehaviour::new(key.public())))
            .map_err(|e| TransportError::Build(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        Ok(Self {
            swarm,
            preferred: TransportClass::OnlineHigh,
            pending_sync: HashMap::new(),
            pending_inbound: std::collections::VecDeque::new(),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn listen_on(&mut self, addr: &str) -> Result<(), TransportError> {
        let multiaddr: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| TransportError::Listen(e.to_string()))?;
        self.swarm
            .listen_on(multiaddr)
            .map_err(|e| TransportError::Listen(e.to_string()))?;
        Ok(())
    }

    /// Dial a peer multiaddr (localhost CI). libp2p performs Noise on TCP paths.
    pub fn dial(&mut self, addr: &str) -> Result<(), TransportError> {
        let multiaddr: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| TransportError::Dial(e.to_string()))?;
        self.swarm
            .dial(multiaddr)
            .map_err(|e| TransportError::Dial(e.to_string()))?;
        Ok(())
    }

    /// Send a sync request (one frame) to `peer`; returns outbound id.
    pub fn send_sync_request(&mut self, peer: PeerId, payload: SyncPayload) -> OutboundRequestId {
        let id = self.swarm.behaviour_mut().sync.send_request(&peer, payload);
        self.pending_sync.insert(id, None);
        id
    }

    /// Respond to an inbound sync request.
    pub fn send_sync_response(
        &mut self,
        channel: ResponseChannel<SyncPayload>,
        payload: SyncPayload,
    ) -> Result<(), TransportError> {
        self.swarm
            .behaviour_mut()
            .sync
            .send_response(channel, payload)
            .map_err(|_| TransportError::Sync("response channel closed".into()))?;
        Ok(())
    }

    /// Poll until the first listen address is reported (localhost tests).
    pub async fn wait_listening(&mut self, timeout: Duration) -> Result<PeerAddr, TransportError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            match tokio::time::timeout(remaining, self.swarm.select_next_some()).await {
                Ok(SwarmEvent::NewListenAddr { address, .. }) => {
                    return Ok(PeerAddr(address.to_string()));
                }
                Ok(other) => {
                    self.note_swarm_side_effect(other);
                    continue;
                }
                Err(_) => return Err(TransportError::Timeout),
            }
        }
    }

    /// Poll until a connection is established (inbound or outbound).
    pub async fn wait_connected(&mut self, timeout: Duration) -> Result<PeerId, TransportError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            match tokio::time::timeout(remaining, self.swarm.select_next_some()).await {
                Ok(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                    return Ok(peer_id);
                }
                Ok(SwarmEvent::OutgoingConnectionError { error, .. }) => {
                    return Err(TransportError::Dial(error.to_string()));
                }
                Ok(other) => {
                    self.note_swarm_side_effect(other);
                    continue;
                }
                Err(_) => return Err(TransportError::Timeout),
            }
        }
    }

    /// Wait for an inbound sync request (Offer or Have from the peer).
    ///
    /// Prefer [`sync_rpc`] when both peers run in one process — both swarms
    /// must be polled for request-response to make progress.
    pub async fn wait_inbound_sync(
        &mut self,
        timeout: Duration,
    ) -> Result<InboundSyncRequest, TransportError> {
        if let Some(queued) = self.pending_inbound.pop_front() {
            return Ok(queued);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(queued) = self.pending_inbound.pop_front() {
                return Ok(queued);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            match tokio::time::timeout(remaining, self.swarm.select_next_some()).await {
                Ok(SwarmEvent::Behaviour(RoomsBehaviourEvent::Sync(
                    request_response::Event::Message { peer, message, .. },
                ))) => {
                    if let request_response::Message::Request {
                        request, channel, ..
                    } = message
                    {
                        return Ok(InboundSyncRequest {
                            peer,
                            payload: request,
                            channel,
                        });
                    }
                }
                Ok(SwarmEvent::ConnectionClosed { peer_id, cause, .. }) => {
                    return Err(TransportError::Disconnected(format!(
                        "peer {peer_id} closed: {cause:?}"
                    )));
                }
                Ok(other) => {
                    self.note_swarm_side_effect(other);
                    continue;
                }
                Err(_) => return Err(TransportError::Timeout),
            }
        }
    }

    /// Wait for the response to a previously sent sync request.
    pub async fn wait_sync_response(
        &mut self,
        request_id: OutboundRequestId,
        timeout: Duration,
    ) -> Result<SyncPayload, TransportError> {
        if let Some(Some(ready)) = self.pending_sync.remove(&request_id) {
            return ready;
        }
        self.pending_sync.insert(request_id, None);

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(Some(ready)) = self.pending_sync.remove(&request_id) {
                return ready;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.pending_sync.remove(&request_id);
                return Err(TransportError::Timeout);
            }
            match tokio::time::timeout(remaining, self.swarm.select_next_some()).await {
                Ok(ev) => self.note_swarm_side_effect(ev),
                Err(_) => {
                    self.pending_sync.remove(&request_id);
                    return Err(TransportError::Timeout);
                }
            }
        }
    }

    fn take_ready_sync_response(
        &mut self,
        request_id: OutboundRequestId,
    ) -> Option<Result<SyncPayload, TransportError>> {
        match self.pending_sync.get(&request_id) {
            Some(Some(_)) => self.pending_sync.remove(&request_id).flatten(),
            _ => None,
        }
    }

    fn handle_responder_event(
        &mut self,
        event: SwarmEvent<RoomsBehaviourEvent>,
        pending_channel: &mut Option<(SyncPayload, ResponseChannel<SyncPayload>)>,
    ) {
        match event {
            SwarmEvent::Behaviour(RoomsBehaviourEvent::Sync(
                request_response::Event::Message { message, .. },
            )) => {
                if let request_response::Message::Request {
                    request, channel, ..
                } = message
                {
                    *pending_channel = Some((request, channel));
                }
            }
            other => self.note_swarm_side_effect(other),
        }
    }

    fn note_swarm_side_effect(&mut self, event: SwarmEvent<RoomsBehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(RoomsBehaviourEvent::Sync(ev)) => match ev {
                request_response::Event::Message { peer, message, .. } => match message {
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        if self.pending_sync.contains_key(&request_id) {
                            self.pending_sync.insert(request_id, Some(Ok(response)));
                        }
                    }
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        self.pending_inbound.push_back(InboundSyncRequest {
                            peer,
                            payload: request,
                            channel,
                        });
                    }
                },
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                } => {
                    if self.pending_sync.contains_key(&request_id) {
                        self.pending_sync.insert(
                            request_id,
                            Some(Err(TransportError::Sync(error.to_string()))),
                        );
                    }
                }
                request_response::Event::InboundFailure { error, .. } => {
                    let _ = error;
                }
                request_response::Event::ResponseSent { .. } => {}
            },
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                let _ = error;
            }
            _ => {}
        }
    }
}

/// One request/response on `/derooms/sync/1.0.0`, driving both swarms (localhost CI).
///
/// `responder_handler` maps inbound request bytes → response bytes.
pub async fn sync_rpc(
    requester: &mut Libp2pHost,
    responder: &mut Libp2pHost,
    remote_peer: PeerId,
    request: SyncPayload,
    mut responder_handler: impl FnMut(SyncPayload) -> Result<SyncPayload, TransportError>,
    timeout: Duration,
) -> Result<SyncPayload, TransportError> {
    let request_id = requester.send_sync_request(remote_peer, request);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut pending_inbound: Option<(SyncPayload, ResponseChannel<SyncPayload>)> = None;
    let mut responded = false;

    loop {
        if let Some(ready) = requester.take_ready_sync_response(request_id) {
            return ready;
        }
        if let Some((payload, channel)) = pending_inbound.take() {
            let response = responder_handler(payload)?;
            responder.send_sync_response(channel, response)?;
            responded = true;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            requester.pending_sync.remove(&request_id);
            return Err(TransportError::Timeout);
        }

        tokio::select! {
            ev = requester.swarm.select_next_some() => {
                requester.note_swarm_side_effect(ev);
            }
            ev = responder.swarm.select_next_some() => {
                responder.handle_responder_event(ev, &mut pending_inbound);
            }
            _ = tokio::time::sleep(remaining) => {
                requester.pending_sync.remove(&request_id);
                return Err(TransportError::Timeout);
            }
        }

        let _ = responded;
    }
}

impl Transport for Libp2pHost {
    fn local_peer_id(&self) -> String {
        self.peer_id().to_string()
    }

    fn preferred_class(&self) -> TransportClass {
        self.preferred
    }
}

/// Exchange opaque bytes through a completed Noise XX transport pair.
///
/// Demonstrates transport AEAD (`snow`). Application 1:1 payloads still use
/// Signal Protocol once libsignal-client is wired on Android.
pub fn encrypt_bytes_noise_xx(plaintext: &[u8]) -> Result<Vec<u8>, NoiseSessionError> {
    let mut pair = noise_xx_handshake()?;
    noise_xx_roundtrip(&mut pair, plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rooms_proto::ContentType;
    use rooms_storage::{KvStore, MemoryKvStore, Namespace};
    use rooms_sync::{
        ack_bytes_from_have, create_signed_message_event, have_bytes_from_want,
        verify_message_event, want_bytes_from_offer, EventStore, Outbox, SyncReplica,
    };

    #[test]
    fn preferred_class_round_trips() {
        let t = TransportHandle::with_preferred(TransportClass::OnlineHigh);
        assert_eq!(t.preferred, Some(TransportClass::OnlineHigh));
    }

    #[test]
    fn snow_noise_xx_encrypts_sync_shaped_bytes() {
        let payload = b"rooms-sync-offer-frame";
        let recovered = encrypt_bytes_noise_xx(payload).expect("noise xx");
        assert_eq!(recovered, payload);
    }

    #[tokio::test]
    async fn libp2p_quic_listens_localhost() {
        let mut host = Libp2pHost::new().expect("host");
        host.listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("listen quic");
        let addr = host
            .wait_listening(Duration::from_secs(5))
            .await
            .expect("new listen addr");
        assert!(
            addr.0.contains("quic"),
            "unexpected listen addr: {}",
            addr.0
        );
    }

    #[tokio::test]
    async fn two_hosts_dial_localhost_tcp_noise() {
        let mut listener = Libp2pHost::new().expect("listener");
        let mut dialer = Libp2pHost::new().expect("dialer");
        assert_ne!(listener.peer_id(), dialer.peer_id());

        listener
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("listen tcp");
        let listen_addr = listener
            .wait_listening(Duration::from_secs(5))
            .await
            .expect("listen addr");

        let dial_addr = format!("{}/p2p/{}", listen_addr.0, listener.peer_id());
        dialer.dial(&dial_addr).expect("dial");

        let (a, b) = tokio::join!(
            listener.wait_connected(Duration::from_secs(10)),
            dialer.wait_connected(Duration::from_secs(10)),
        );
        let peer_on_listener = a.expect("listener connected");
        let peer_on_dialer = b.expect("dialer connected");
        assert_eq!(peer_on_listener, dialer.peer_id());
        assert_eq!(peer_on_dialer, listener.peer_id());
    }

    #[tokio::test]
    async fn dial_failure_is_clear_error() {
        let mut dialer = Libp2pHost::new().expect("dialer");
        let dead_peer = Libp2pHost::new().expect("unused").peer_id();
        dialer
            .dial(&format!("/ip4/127.0.0.1/tcp/1/p2p/{dead_peer}"))
            .expect("dial accepted into swarm");
        let err = dialer
            .wait_connected(Duration::from_secs(5))
            .await
            .expect_err("must fail");
        match err {
            TransportError::Dial(_) | TransportError::Timeout => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// IT-P2P: two localhost nodes sync a signed MessageEvent over `/derooms/sync/1.0.0`
    /// on a Noise-secured TCP connection (Gate 1 must-ship).
    #[tokio::test]
    async fn two_node_sync_over_libp2p_streams() {
        assert_eq!(SYNC_PROTOCOL_ID, "/derooms/sync/1.0.0");

        let mut rng = StdRng::seed_from_u64(20260805);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let room = rooms_proto::Cid([0xD1; 32]);
        let device_id = [0xD2; 32];
        let identity_id = [0xD3; 32];
        let event = create_signed_message_event(
            room,
            device_id,
            identity_id,
            vec![],
            0,
            ContentType::Text,
            b"opaque-signal-ct-libp2p".to_vec(),
            &sk,
        );
        verify_message_event(&event, &vk).unwrap();

        let mut store_a = MemoryKvStore::new();
        let mut store_b = MemoryKvStore::new();
        EventStore::new(&mut store_a).put_event(&event).unwrap();
        Outbox::new(&mut store_a).enqueue(&event).unwrap();

        let mut replica_a = SyncReplica::new(room);
        replica_a.tips.push(event.id);
        replica_a.vv.counters.push((device_id, 1));
        let mut replica_b = SyncReplica::new(room);

        let mut provider = Libp2pHost::new().expect("provider");
        let mut consumer = Libp2pHost::new().expect("consumer");

        consumer.listen_on("/ip4/127.0.0.1/tcp/0").expect("listen");
        let listen_addr = consumer
            .wait_listening(Duration::from_secs(5))
            .await
            .expect("addr");
        let dial_addr = format!("{}/p2p/{}", listen_addr.0, consumer.peer_id());
        provider.dial(&dial_addr).expect("dial");

        let (peer_on_consumer, peer_on_provider) = tokio::join!(
            consumer.wait_connected(Duration::from_secs(10)),
            provider.wait_connected(Duration::from_secs(10)),
        );
        assert_eq!(peer_on_consumer.unwrap(), provider.peer_id());
        let consumer_peer = peer_on_provider.unwrap();
        assert_eq!(consumer_peer, consumer.peer_id());

        let offer = replica_a.build_offer().encode_v1().unwrap();
        let want_bytes = sync_rpc(
            &mut provider,
            &mut consumer,
            consumer_peer,
            offer,
            |offer_bytes| {
                want_bytes_from_offer(&replica_b, &offer_bytes)
                    .map_err(|e| TransportError::Sync(format!("{e:?}")))
            },
            Duration::from_secs(15),
        )
        .await
        .expect("want");

        let have = have_bytes_from_want(&store_a, &want_bytes).unwrap();
        let ack_bytes = sync_rpc(
            &mut provider,
            &mut consumer,
            consumer_peer,
            have,
            |have_bytes| {
                let (_n, ack) = ack_bytes_from_have(&mut store_b, &mut replica_b, &have_bytes, &vk)
                    .map_err(|e| TransportError::Sync(format!("{e:?}")))?;
                Ok(ack)
            },
            Duration::from_secs(15),
        )
        .await
        .expect("ack");

        let ack_decoded = rooms_proto::decode_sync_ack_v1(&ack_bytes).unwrap();
        assert_eq!(ack_decoded.applied_tips, vec![event.id]);

        let removed = Outbox::new(&mut store_a).apply_ack(&ack_decoded).unwrap();
        assert_eq!(removed, 1);

        let loaded = store_b
            .get(Namespace::Events, &event.id.0)
            .unwrap()
            .expect("event on B");
        let decoded = rooms_proto::decode_message_event_wire_v1(&loaded).unwrap();
        verify_message_event(&decoded, &vk).unwrap();
        assert_eq!(decoded.ciphertext, b"opaque-signal-ct-libp2p");
        assert!(replica_b.tips.contains(&event.id));
    }

    /// Host-side Gate 1 E2E companion: real identity keygen → opaque
    /// (libsignal-shaped) ciphertext → signed MessageEvent → libp2p sync → verify.
    /// Android 2-device lab remains the product E2E; this proves the core path.
    #[tokio::test]
    async fn two_node_identity_sign_sync_e2e() {
        assert_eq!(SYNC_PROTOCOL_ID, "/derooms/sync/1.0.0");

        let alice = rooms_identity::create_identity_osrng();
        let room = rooms_proto::Cid([0xE2; 32]);
        let sealed = b"\x02libsignal-framed-opaque-ct".to_vec();
        let event = create_signed_message_event(
            room,
            alice.device_id().0,
            alice.identity_id().0,
            vec![],
            0,
            ContentType::Text,
            sealed.clone(),
            &alice.device,
        );
        verify_message_event(&event, &alice.device.verifying_key()).unwrap();

        let mut store_a = MemoryKvStore::new();
        let mut store_b = MemoryKvStore::new();
        EventStore::new(&mut store_a).put_event(&event).unwrap();
        Outbox::new(&mut store_a).enqueue(&event).unwrap();

        let mut replica_a = SyncReplica::new(room);
        replica_a.tips.push(event.id);
        replica_a.vv.counters.push((alice.device_id().0, 1));
        let mut replica_b = SyncReplica::new(room);

        let mut provider = Libp2pHost::new().expect("provider");
        let mut consumer = Libp2pHost::new().expect("consumer");
        consumer.listen_on("/ip4/127.0.0.1/tcp/0").expect("listen");
        let listen_addr = consumer
            .wait_listening(Duration::from_secs(5))
            .await
            .expect("addr");
        let dial_addr = format!("{}/p2p/{}", listen_addr.0, consumer.peer_id());
        provider.dial(&dial_addr).expect("dial");
        let (_peer_on_consumer, peer_on_provider) = tokio::join!(
            consumer.wait_connected(Duration::from_secs(10)),
            provider.wait_connected(Duration::from_secs(10)),
        );
        let consumer_peer = peer_on_provider.unwrap();

        let offer = replica_a.build_offer().encode_v1().unwrap();
        let want_bytes = sync_rpc(
            &mut provider,
            &mut consumer,
            consumer_peer,
            offer,
            |offer_bytes| {
                want_bytes_from_offer(&replica_b, &offer_bytes)
                    .map_err(|e| TransportError::Sync(format!("{e:?}")))
            },
            Duration::from_secs(15),
        )
        .await
        .expect("want");

        let have = have_bytes_from_want(&store_a, &want_bytes).unwrap();
        let ack_bytes = sync_rpc(
            &mut provider,
            &mut consumer,
            consumer_peer,
            have,
            |have_bytes| {
                let (_n, ack) = ack_bytes_from_have(
                    &mut store_b,
                    &mut replica_b,
                    &have_bytes,
                    &alice.device.verifying_key(),
                )
                .map_err(|e| TransportError::Sync(format!("{e:?}")))?;
                Ok(ack)
            },
            Duration::from_secs(15),
        )
        .await
        .expect("ack");

        let ack_decoded = rooms_proto::decode_sync_ack_v1(&ack_bytes).unwrap();
        assert_eq!(ack_decoded.applied_tips, vec![event.id]);
        assert_eq!(
            Outbox::new(&mut store_a).apply_ack(&ack_decoded).unwrap(),
            1
        );

        let loaded = store_b
            .get(Namespace::Events, &event.id.0)
            .unwrap()
            .expect("event on B");
        let decoded = rooms_proto::decode_message_event_wire_v1(&loaded).unwrap();
        verify_message_event(&decoded, &alice.device.verifying_key()).unwrap();
        assert_eq!(decoded.ciphertext, sealed);
        assert_eq!(decoded.author_identity_id, alice.identity_id().0);
    }
}
