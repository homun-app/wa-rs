//! Shared types for the usync (user sync) protocol.
//!
//! The wire format build/parse logic lives in [`crate::iq::usync`]
//! (`DeviceListSpec`); the free functions that used to live here were
//! near-duplicates of it with no callers and have been removed.

use wa_rs_binary::jid::Jid;

/// A LID mapping learned from usync response
#[derive(Debug, Clone)]
pub struct UsyncLidMapping {
    /// The phone number user part (e.g., "559980000001")
    pub phone_number: String,
    /// The LID user part (e.g., "100000012345678")
    pub lid: String,
}

/// Device list with optional phash from usync response
#[derive(Debug, Clone)]
pub struct UserDeviceList {
    /// The user JID (without device suffix)
    pub user: Jid,
    /// List of device JIDs for this user
    pub devices: Vec<Jid>,
    /// Participant hash from device-list node (used for cache validation)
    pub phash: Option<String>,
}
