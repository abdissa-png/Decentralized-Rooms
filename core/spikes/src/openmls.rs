//! Spike 2.6 — OpenMLS hello-group (2–3 members, membership change, epoch).
//!
//! Uses the OpenMLS crate + `openmls_rust_crypto` provider. No custom MLS.
//! Production wrapper will live in a future `mls-glue` crate.

use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use thiserror::Error;

pub const SPIKE_NAME: &str = "openmls";
pub const WBS: &str = "2.6";

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[derive(Debug, Error)]
pub enum MlsSpikeError {
    #[error("openmls: {0}")]
    OpenMls(String),
}

fn map_err<E: std::fmt::Debug>(e: E) -> MlsSpikeError {
    MlsSpikeError::OpenMls(format!("{e:?}"))
}

/// Delivery-service stand-in: serialize outbound MLS messages to inbound form.
fn deliver(out: MlsMessageOut) -> Result<MlsMessageIn, MlsSpikeError> {
    let bytes = out.to_bytes().map_err(map_err)?;
    MlsMessageIn::tls_deserialize_exact(bytes.as_slice()).map_err(map_err)
}

fn extract_welcome(out: MlsMessageOut) -> Result<Welcome, MlsSpikeError> {
    match deliver(out)?.extract() {
        MlsMessageBodyIn::Welcome(w) => Ok(w),
        other => Err(MlsSpikeError::OpenMls(format!(
            "expected Welcome, got {other:?}"
        ))),
    }
}

struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
}

fn new_member(name: &str) -> Result<Member, MlsSpikeError> {
    let provider = OpenMlsRustCrypto::default();
    let credential = BasicCredential::new(name.as_bytes().to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(map_err)?;
    signer.store(provider.storage()).map_err(map_err)?;
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    Ok(Member {
        provider,
        signer,
        credential_with_key,
    })
}

fn generate_key_package(member: &Member) -> Result<KeyPackage, MlsSpikeError> {
    Ok(KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &member.provider,
            &member.signer,
            member.credential_with_key.clone(),
        )
        .map_err(map_err)?
        .key_package()
        .clone())
}

/// Outcome of the hello-group spike: epochs observed and a decrypted app message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HelloGroupResult {
    pub epoch_after_create: u64,
    pub epoch_after_add_bob: u64,
    pub epoch_after_add_charlie: u64,
    pub epoch_after_remove_bob: u64,
    pub decrypted_message: Vec<u8>,
    pub member_count_final: usize,
}

/// Create a 3-member MLS group, exchange an application message, remove a member,
/// and observe epoch advances.
pub fn hello_group() -> Result<HelloGroupResult, MlsSpikeError> {
    let alice = new_member("alice")?;
    let bob = new_member("bob")?;
    let charlie = new_member("charlie")?;

    let bob_kp = generate_key_package(&bob)?;
    let charlie_kp = generate_key_package(&charlie)?;

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new(
        &alice.provider,
        &alice.signer,
        &create_config,
        alice.credential_with_key.clone(),
    )
    .map_err(map_err)?;

    let epoch_after_create = alice_group.epoch().as_u64();

    // Alice adds Bob.
    let (_commit, welcome, _gi) = alice_group
        .add_members(&alice.provider, &alice.signer, &[bob_kp])
        .map_err(map_err)?;
    alice_group
        .merge_pending_commit(&alice.provider)
        .map_err(map_err)?;
    let epoch_after_add_bob = alice_group.epoch().as_u64();

    let welcome = extract_welcome(welcome)?;
    let mut bob_group =
        StagedWelcome::new_from_welcome(&bob.provider, create_config.join_config(), welcome, None)
            .map_err(map_err)?
            .into_group(&bob.provider)
            .map_err(map_err)?;

    assert_eq!(alice_group.epoch().as_u64(), bob_group.epoch().as_u64());

    // Alice adds Charlie (Bob processes the commit).
    let (commit, welcome, _gi) = alice_group
        .add_members(&alice.provider, &alice.signer, &[charlie_kp])
        .map_err(map_err)?;
    alice_group
        .merge_pending_commit(&alice.provider)
        .map_err(map_err)?;
    let epoch_after_add_charlie = alice_group.epoch().as_u64();

    let processed = bob_group
        .process_message(
            &bob.provider,
            deliver(commit)?
                .try_into_protocol_message()
                .map_err(map_err)?,
        )
        .map_err(map_err)?;
    if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
        bob_group
            .merge_staged_commit(&bob.provider, *staged)
            .map_err(map_err)?;
    } else {
        return Err(MlsSpikeError::OpenMls(
            "expected staged commit for Bob".into(),
        ));
    }

    let welcome = extract_welcome(welcome)?;
    let mut charlie_group = StagedWelcome::new_from_welcome(
        &charlie.provider,
        create_config.join_config(),
        welcome,
        None,
    )
    .map_err(map_err)?
    .into_group(&charlie.provider)
    .map_err(map_err)?;

    // Application message Alice → Charlie.
    let plaintext = b"hello mls room";
    let msg = alice_group
        .create_message(&alice.provider, &alice.signer, plaintext)
        .map_err(map_err)?;
    let processed = charlie_group
        .process_message(
            &charlie.provider,
            deliver(msg)?.try_into_protocol_message().map_err(map_err)?,
        )
        .map_err(map_err)?;
    let decrypted = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
        other => {
            return Err(MlsSpikeError::OpenMls(format!(
                "expected application message, got {other:?}"
            )));
        }
    };

    // Remove Bob; Charlie processes commit; epoch advances again.
    let bob_index = alice_group
        .members()
        .find(|m| m.credential.serialized_content() == b"bob")
        .map(|m| m.index)
        .ok_or_else(|| MlsSpikeError::OpenMls("bob leaf not found".into()))?;

    let (commit, _welcome, _gi) = alice_group
        .remove_members(&alice.provider, &alice.signer, &[bob_index])
        .map_err(map_err)?;
    alice_group
        .merge_pending_commit(&alice.provider)
        .map_err(map_err)?;
    let epoch_after_remove_bob = alice_group.epoch().as_u64();

    let processed = charlie_group
        .process_message(
            &charlie.provider,
            deliver(commit)?
                .try_into_protocol_message()
                .map_err(map_err)?,
        )
        .map_err(map_err)?;
    if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
        charlie_group
            .merge_staged_commit(&charlie.provider, *staged)
            .map_err(map_err)?;
    } else {
        return Err(MlsSpikeError::OpenMls(
            "expected staged commit for Charlie".into(),
        ));
    }

    Ok(HelloGroupResult {
        epoch_after_create,
        epoch_after_add_bob,
        epoch_after_add_charlie,
        epoch_after_remove_bob,
        decrypted_message: decrypted,
        member_count_final: alice_group.members().count(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openmls_hello_group_epochs_and_message() {
        let result = hello_group().expect("hello_group");
        assert_eq!(result.decrypted_message, b"hello mls room");
        assert!(result.epoch_after_add_bob > result.epoch_after_create);
        assert!(result.epoch_after_add_charlie > result.epoch_after_add_bob);
        assert!(result.epoch_after_remove_bob > result.epoch_after_add_charlie);
        assert_eq!(result.member_count_final, 2); // alice + charlie
    }
}
