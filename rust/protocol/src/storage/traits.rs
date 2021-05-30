//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use uuid::Uuid;

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{
    IdentityKey, IdentityKeyPair, PreKeyRecord, ProtocolAddress, Result, SenderKeyRecord,
    SessionRecord, SignedPreKeyRecord,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Context {
    ptr: *mut std::ffi::c_void,
}

impl Context {
    pub fn new(ptr: *mut std::ffi::c_void) -> Self {
        Self { ptr }
    }
}

// Raw pointers are marked as thread unsafe as a lint and not as a hard rule.
// As any read of a pointer is already unsafe, this Send implementation
// technically doesn't introduce any new vectors of triggering undefined behavior.
#[allow(unsafe_code)]
unsafe impl Send for Context {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    Sending,
    Receiving,
}

#[async_trait]
pub trait IdentityKeyStore {
    async fn get_identity_key_pair(&self, ctx: Option<Context>) -> Result<IdentityKeyPair>;

    async fn get_local_registration_id(&self, ctx: Option<Context>) -> Result<u32>;

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Option<Context>,
    ) -> Result<bool>;

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        ctx: Option<Context>,
    ) -> Result<bool>;

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Option<Context>,
    ) -> Result<Option<IdentityKey>>;
}

#[async_trait]
pub trait PreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId, ctx: Option<Context>) -> Result<PreKeyRecord>;

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        ctx: Option<Context>,
    ) -> Result<()>;

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId, ctx: Option<Context>) -> Result<()>;
}

#[async_trait]
pub trait SignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
        ctx: Option<Context>,
    ) -> Result<SignedPreKeyRecord>;

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        ctx: Option<Context>,
    ) -> Result<()>;
}

#[async_trait]
pub trait SessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Option<Context>,
    ) -> Result<Option<SessionRecord>>;

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        ctx: Option<Context>,
    ) -> Result<()>;
}

#[async_trait]
pub trait SenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        ctx: Option<Context>,
    ) -> Result<()>;

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        ctx: Option<Context>,
    ) -> Result<Option<SenderKeyRecord>>;
}

pub trait ProtocolStore: SessionStore + PreKeyStore + SignedPreKeyStore + IdentityKeyStore {}
