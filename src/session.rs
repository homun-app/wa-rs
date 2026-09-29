//! Session-related constants.
//!
//! The previous `SessionManager` (deduplicated concurrent prekey fetches) was
//! never wired into production: `Client::ensure_e2e_sessions` implements the
//! batching directly. Only the batch size constant is used.

/// Maximum number of JIDs to include in a single prekey fetch request.
/// Matches WhatsApp Web's SESSION_CHECK_BATCH constant.
pub const SESSION_CHECK_BATCH_SIZE: usize = 50;
