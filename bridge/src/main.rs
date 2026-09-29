//! Local HTTP sidecar bridging wa-rs to the Homun engine channel gateway.
//!
//! The Homun engine (or any local consumer) talks to this process over
//! 127.0.0.1 HTTP; the sidecar owns the WhatsApp Web session and pushes
//! inbound messages to a callback URL.
//!
//! Environment:
//!   WA_BRIDGE_PORT            HTTP port (default 8902, binds 127.0.0.1 only)
//!   WA_BRIDGE_DB              SQLite session path (default wa-bridge.db)
//!   WA_BRIDGE_PHONE           Optional phone number for pair-code linking
//!   WA_BRIDGE_PAIR_CODE       Optional custom 8-char pair code
//!   WA_BRIDGE_CALLBACK_URL    Engine inbound URL for received messages
//!   WA_BRIDGE_CALLBACK_TOKEN  Bearer token sent with the callback
//!
//! Pairing starts automatically at boot when no session exists: the QR
//! payload (and, with WA_BRIDGE_PHONE, the pair code) surfaces via
//! GET /status and POST /pair/start until the phone completes linking.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use wa_rs::bot::{Bot, MessageContext};
use wa_rs::client::Client;
use wa_rs::pair_code::PairCodeOptions;
use wa_rs_core::proto_helpers::MessageExt;
use wa_rs_core::types::events::Event;
use wa_rs_proto::whatsapp as wa;
use wa_rs_tokio_transport::TokioWebSocketTransportFactory;
use wa_rs_ureq_http::UreqHttpClient;

use wa_rs::store::SqliteStore;

#[derive(Clone)]
struct Callback {
    url: String,
    token: String,
}

struct AppState {
    client: RwLock<Option<Arc<Client>>>,
    qr: RwLock<Option<(String, DateTime<Utc>)>>,
    pair_code: RwLock<Option<(String, DateTime<Utc>)>>,
    jid: RwLock<Option<String>>,
    lid: RwLock<Option<String>>,
    self_chat_peer: RwLock<Option<String>>,
    pending_own: RwLock<std::collections::HashMap<String, (String, std::time::Instant)>>,
    recent_self: RwLock<Vec<(String, std::time::Instant)>>,
    connected: RwLock<bool>,
    logged_out: RwLock<bool>,
    last_error: RwLock<Option<String>>,
    last_pair_error: RwLock<Option<String>>,
    started_at: DateTime<Utc>,
    db_path: String,
    callback: Callback,
}

impl AppState {
    fn new(callback: Callback, db_path: String) -> Arc<Self> {
        Arc::new(Self {
            client: RwLock::new(None),
            qr: RwLock::new(None),
            pair_code: RwLock::new(None),
            jid: RwLock::new(None),
            lid: RwLock::new(None),
            self_chat_peer: RwLock::new(None),
            pending_own: RwLock::new(std::collections::HashMap::new()),
            recent_self: RwLock::new(Vec::new()),
            connected: RwLock::new(false),
            logged_out: RwLock::new(false),
            last_error: RwLock::new(None),
            last_pair_error: RwLock::new(None),
            started_at: Utc::now(),
            db_path,
            callback,
        })
    }

    async fn status_payload(self: &Arc<Self>) -> Value {
        let jid = self.jid.read().await.clone();
        let lid = self.lid.read().await.clone();
        let connected = *self.connected.read().await;
        let logged_out = *self.logged_out.read().await;
        let qr = self.qr.read().await.clone();
        let pair_code = self.pair_code.read().await.clone();
        let last_error = self.last_error.read().await.clone();
        let last_pair_error = self.last_pair_error.read().await.clone();
        let paired = connected && !logged_out;
        json!({
            "ok": true,
            "service": "wa-rs-bridge",
            "version": env!("CARGO_PKG_VERSION"),
            "paired": paired,
            "jid": jid,
            "lid": lid,
            "connected": connected,
            "logged_out": logged_out,
            "started_at": self.started_at.to_rfc3339(),
            "last_error": last_error,
            "last_pair_error": last_pair_error,
            "qr": qr.as_ref().map(|(payload, expires)| json!({
                "payload": payload,
                "expires_at": expires.to_rfc3339(),
            })),
            "pair_code": pair_code.as_ref().map(|(code, expires)| json!({
                "code": code,
                "expires_at": expires.to_rfc3339(),
            })),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| default.to_string())
}

/// Persist the paired identities next to the session db, and restore them at
/// boot: PairSuccess only fires on first linking, never on session resume.
fn identity_path(db_path: &str) -> std::path::PathBuf {
    std::path::Path::new(db_path).with_extension("identity.json")
}

fn persist_identity(db_path: &str, jid: &str, lid: &str, self_chat_peer: Option<&str>) {
    let doc = json!({"jid": jid, "lid": lid, "self_chat_peer": self_chat_peer});
    if let Err(e) = std::fs::write(identity_path(db_path), doc.to_string()) {
        log::warn!("failed to persist bridge identity: {e}");
    }
}

async fn restore_identity(state: &Arc<AppState>, db_path: &str) {
    let Ok(raw) = std::fs::read_to_string(identity_path(db_path)) else {
        return;
    };
    let Ok(doc) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    if let Some(jid) = doc.get("jid").and_then(Value::as_str) {
        *state.jid.write().await = Some(jid.to_string());
    }
    if let Some(lid) = doc.get("lid").and_then(Value::as_str) {
        *state.lid.write().await = Some(lid.to_string());
    }
    if let Some(peer) = doc.get("self_chat_peer").and_then(Value::as_str) {
        *state.self_chat_peer.write().await = Some(peer.to_string());
    }
    log::info!("restored paired identity from session store");
}

fn expires_in(timeout: Duration) -> DateTime<Utc> {
    Utc::now() + chrono::TimeDelta::from_std(timeout).unwrap_or(chrono::TimeDelta::seconds(60))
}

/// Deliver an inbound message to the engine callback. Blocking ureq call on
/// the tokio blocking pool; failures are logged, never fatal for the session.
async fn push_callback(callback: &Callback, body: Value) {
    if callback.url.is_empty() {
        return;
    }
    let url = callback.url.clone();
    let token = callback.token.clone();
    let payload = body.to_string();
    tokio::task::spawn_blocking(move || {
        // Same policy as the workspace ureq client: bounded connect and
        // global timeouts so a stuck engine can't pile up callback threads.
        let mut req = ureq::post(&url)
            .config()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            .build();
        req = req.header("Content-Type", "application/json");
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Err(e) = req.send(payload.as_bytes()) {
            log::warn!("callback to {url} failed: {e}");
        }
    })
    .await
    .ok();
}

async fn health() -> Json<Value> {
    Json(json!({"ok": true, "service": "wa-rs-bridge", "version": env!("CARGO_PKG_VERSION")}))
}

async fn status(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.status_payload().await)
}

async fn pair_start(State(state): State<Arc<AppState>>) -> Json<Value> {
    // Pairing begins at boot; this endpoint reports the live QR/pair code.
    Json(state.status_payload().await)
}

async fn send(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    let client = state.client.read().await.clone();
    let Some(client) = client else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": "bridge_not_ready"})),
        );
    };
    let to = body.get("to").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let text = body.get("text").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if to.is_empty() || text.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "missing_to_or_text"})),
        );
    }
    // Accept bare phone numbers as well as full JIDs.
    let mut jid_str = if to.contains('@') { to } else { format!("{to}@s.whatsapp.net") };
    // Self-chat routing: the self-chat only renders notes sent to the
    // account's phone-number JID. The companion JID and the account's LID
    // form are accepted by the server but land in invisible chats, so every
    // self-directed destination is rewritten to the bare PN form.
    {
        let bare = |s: &str| s.split('@').next().unwrap_or("").split(':').next().unwrap_or("").to_string();
        let own_jid = state.jid.read().await.clone();
        let own_lid = state.lid.read().await.clone();
        let peer = state.self_chat_peer.read().await.clone();
        let own_pn = own_jid.as_deref().map(bare).unwrap_or_default();
        let own_lid_user = own_lid.as_deref().map(bare).unwrap_or_default();
        let peer_user = peer.as_deref().map(bare).unwrap_or_default();
        let to_user = bare(&jid_str);
        let is_self_destination = !own_pn.is_empty()
            && (to_user == own_pn || (!own_lid_user.is_empty() && to_user == own_lid_user)
                || (!peer_user.is_empty() && to_user == peer_user));
        if is_self_destination {
            jid_str = format!("{own_pn}@s.whatsapp.net");
        }
    }
    let Ok(jid) = jid_str.parse() else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_jid"})),
        );
    };
    let message = wa::Message {
        extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
            text: Some(text),
            ..Default::default()
        })),
        ..Default::default()
    };
    match client.send_message(jid, message).await {
        Ok(id) => (axum::http::StatusCode::OK, Json(json!({"ok": true, "id": id}))),
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port: u16 = env_or("WA_BRIDGE_PORT", "8902").parse().unwrap_or(8902);
    let db_path = env_or("WA_BRIDGE_DB", "wa-bridge.db");
    let phone = std::env::var("WA_BRIDGE_PHONE").ok().filter(|v| !v.trim().is_empty());
    let custom_code = std::env::var("WA_BRIDGE_PAIR_CODE").ok().filter(|v| !v.trim().is_empty());
    let callback = Callback {
        url: env_or("WA_BRIDGE_CALLBACK_URL", ""),
        token: env_or("WA_BRIDGE_CALLBACK_TOKEN", ""),
    };

    let state = AppState::new(callback, db_path.clone());
    restore_identity(&state, &db_path).await;

    let backend = match SqliteStore::new(&db_path).await {
        Ok(store) => Arc::new(store),
        Err(e) => {
            log::error!("failed to open session db {db_path}: {e}");
            std::process::exit(1);
        }
    };

    let mut builder = Bot::builder()
        .with_backend(backend)
        .with_transport_factory(TokioWebSocketTransportFactory::new())
        .with_http_client(UreqHttpClient::new());
    if let Some(phone) = phone {
        log::info!("pair-code linking enabled for phone {phone}");
        builder = builder.with_pair_code(PairCodeOptions {
            phone_number: phone,
            custom_code,
            ..Default::default()
        });
    }

    let event_state = state.clone();
    let events_db_path = db_path.clone();
    let mut bot = builder
        .on_event(move |event, client| {
            let state = event_state.clone();
            let db_path = events_db_path.clone();
            async move {
                // Publish the client for /send as soon as it exists.
                {
                    let mut guard = state.client.write().await;
                    if guard.is_none() {
                        *guard = Some(client.clone());
                    }
                }
                match event {
                    Event::PairingQrCode { code, timeout } => {
                        log::info!("pairing QR available (valid {}s)", timeout.as_secs());
                        *state.qr.write().await = Some((code, expires_in(timeout)));
                    }
                    Event::PairingCode { code, timeout } => {
                        log::info!("pair code available: {code}");
                        *state.pair_code.write().await = Some((code, expires_in(timeout)));
                    }
                    Event::PairSuccess(success) => {
                        log::info!("paired as {} (lid {})", success.id, success.lid);
                        // A WhatsApp account has two wire identities: the phone
                        // Jid and an opaque LID. Keep both: incoming traffic is
                        // addressed with either, depending on the sender device.
                        // They survive restarts via a sidecar file: PairSuccess
                        // only fires on first linking, not on session resume.
                        *state.jid.write().await = Some(success.id.to_string());
                        *state.lid.write().await = Some(success.lid.to_string());
                        *state.logged_out.write().await = false;
                        *state.last_pair_error.write().await = None;
                        persist_identity(&db_path, &success.id.to_string(), &success.lid.to_string(), None);
                    }
                    Event::PairError(err) => {
                        // The phone showed an error: keep the server-provided
                        // reason for /status so the app can display it.
                        log::error!("pairing rejected: {} (platform {})", err.error, err.platform);
                        *state.last_pair_error.write().await =
                            Some(format!("{} (platform {})", err.error, err.platform));
                    }
                    Event::QrScannedWithoutMultidevice(_) => {
                        log::error!("QR scanned but the account has no multidevice support");
                        *state.last_pair_error.write().await = Some(
                            "QR scansionato ma l'account non supporta i dispositivi collegati (multidevice)".to_string(),
                        );
                    }
                    Event::Connected(_) => {
                        log::info!("WhatsApp session connected");
                        *state.connected.write().await = true;
                    }
                    Event::Disconnected(_) => {
                        log::warn!("WhatsApp session disconnected");
                        *state.connected.write().await = false;
                    }
                    Event::LoggedOut(logout) => {
                        log::error!("WhatsApp session logged out: {:?}", logout.reason);
                        *state.logged_out.write().await = true;
                        *state.connected.write().await = false;
                        *state.jid.write().await = None;
                    }
                    Event::Message(msg, info) => {
                        let ctx = MessageContext { message: msg, info, client };
                        handle_message(&state, ctx).await;
                    }
                    _ => {}
                }
            }
        })
        .build()
        .await
        .expect("failed to build bot");

    // The client exists right after build; publish it for /send.
    {
        let client = bot.client();
        *state.client.write().await = Some(client);
    }

    let run_state = state.clone();
    let handle = match bot.run().await {
        Ok(handle) => handle,
        Err(e) => {
            log::error!("bot failed to start: {e}");
            *run_state.last_error.write().await = Some(e.to_string());
            std::process::exit(1);
        }
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/pair/start", post(pair_start))
        .route("/send", post(send))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    log::info!("wa-rs-bridge listening on http://{addr}");

    let server = async move { axum::serve(listener, app).await };
    tokio::pin!(server);
    tokio::select! {
        _ = &mut server => {}
        result = handle => {
            log::error!("bot task terminated: {:?}", result);
        }
    }
}

async fn handle_message(state: &Arc<AppState>, ctx: MessageContext) {
    let info = &ctx.info;
    let Some(text) = ctx.message.text_content() else {
        log::info!("dropped message without text content");
        return; // v1 bridges text messages only.
    };
    if text.trim().is_empty() {
        log::info!("dropped empty message");
        return;
    }
    let chat = info.source.chat.to_string();
    let sender = info.source.sender.to_string();
    let jid = state.jid.read().await.clone();
    let lid = state.lid.read().await.clone();
    let bare = |s: &str| s.split('@').next().unwrap_or("").split(':').next().unwrap_or("").to_string();
    let own_users: Vec<String> = [jid.clone(), lid.clone()]
        .into_iter()
        .flatten()
        .map(|full| bare(&full))
        .filter(|u| !u.is_empty())
        .collect();
    let chat_bare = bare(&chat);

    // Self-notes reach linked devices in two shapes: delivered directly to
    // the account's own chat (is_from_me), or echoed by the self-chat
    // companion as ordinary inbound traffic. Both must produce exactly one
    // engine turn.
    let mut self_note = false;
    if info.source.is_from_me {
        if own_users.contains(&chat_bare) {
            self_note = true;
        } else {
            // Own message to someone else: remember it only as the seed for
            // companion-echo discovery, never as engine input.
            state
                .pending_own
                .write()
                .await
                .insert(chat.clone(), (text.to_string(), std::time::Instant::now()));
            log::info!("dropped own message outside the self-chat");
            return;
        }
    } else {
        let peer = state.self_chat_peer.read().await.clone();
        let from_peer = peer.as_deref().map(|p| bare(p) == bare(&sender)).unwrap_or(false);
        if from_peer {
            self_note = true;
        } else {
            let mut pending = state.pending_own.write().await;
            let matched = pending
                .get(&chat)
                .map(|(t, at)| t == &text && at.elapsed() < std::time::Duration::from_secs(30))
                .unwrap_or(false);
            if matched {
                pending.remove(&chat);
                drop(pending);
                *state.self_chat_peer.write().await = Some(sender.clone());
                persist_identity(
                    &state.db_path,
                    jid.as_deref().unwrap_or(""),
                    lid.as_deref().unwrap_or(""),
                    Some(&sender),
                );
                log::info!("learned self-chat companion {sender}");
                self_note = true;
            }
        }
    }

    if self_note {
        // The direct copy and the companion echo can both arrive: forward the
        // first, drop its duplicate.
        let mut recent = state.recent_self.write().await;
        if recent.iter().any(|(t, at)| t == &text && at.elapsed() < std::time::Duration::from_secs(25)) {
            log::info!("dropped duplicate self-note copy");
            return;
        }
        recent.push((text.to_string(), std::time::Instant::now()));
        recent.retain(|(_, at)| at.elapsed() < std::time::Duration::from_secs(60));
    }

    let mut body = json!({
        "source": "wa-rs-bridge",
        "message": {
            "id": info.id.clone(),
            "chat": chat,
            "sender": sender,
            "push_name": info.push_name.clone(),
            "is_group": info.source.is_group,
            "text": text,
            "timestamp": info.timestamp.to_rfc3339(),
        }
    });
    if self_note {
        // Attribute self-notes to the account owner so the engine's
        // authorization gate and conversation identity see the human.
        if let Some(obj) = body.get_mut("message").and_then(Value::as_object_mut) {
            obj.insert("self_echo".into(), json!(true));
            obj.insert("owner".into(), json!({"jid": jid, "lid": lid}));
        }
    }
    log::info!("forwarding message to engine callback (self_note={self_note})");
    push_callback(&state.callback, body).await;
}


