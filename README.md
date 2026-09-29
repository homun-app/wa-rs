# wa-rs

A high-performance, async Rust client for the WhatsApp Web API.

Fork of [whatsapp-rust](https://github.com/jlucaso1/whatsapp-rust) by João Lucas de Oliveira Lopes, with stable Rust support (no nightly features required) and bug fixes.

> **Note on upstream**: the original project has moved and is actively developed as [oxidezap/whatsapp-rust](https://github.com/oxidezap/whatsapp-rust). This fork tracks it selectively (pairing/ADV-HMAC, device props, Noise IK + XXfallback handshake); check the upstream before filing protocol-level issues here.

Inspired by [whatsmeow](https://github.com/tulir/whatsmeow) (Go) and [Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript).

## Features

### Authentication

- QR code pairing
- Pair code (phone number) linking
- Persistent sessions with automatic reconnection

### Messaging

- End-to-end encrypted messages (Signal Protocol)
- One-on-one and group chats
- Message editing and reactions
- Quoting/replying to messages
- Delivery, read, and played receipts

### Media

- Upload and download images, videos, documents, GIFs, and audio
- Automatic encryption and decryption

### Contacts & Groups

- Check if phone numbers are on WhatsApp
- Fetch profile pictures and user info
- Query group metadata and participants
- List all groups you're participating in

### Presence & Chat State

- Set online/offline presence
- Typing indicators (composing, recording, paused)
- Block and unblock contacts

### Architecture

- **Modular design** - Pluggable storage, transport, and HTTP clients
- **Runtime agnostic** - Works with Tokio, async-std, or WASM
- **SQLite included** - Default storage backend, easily swappable

## Quick Start

```rust
use std::sync::Arc;
use wa_rs::bot::Bot;
use wa_rs_sqlite_storage::SqliteStore;
use wa_rs_tokio_transport::TokioWebSocketTransportFactory;
use wa_rs_ureq_http::UreqHttpClient;
use wa_rs_core::types::events::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);

    let mut bot = Bot::builder()
        .with_backend(backend)
        .with_transport_factory(TokioWebSocketTransportFactory::new())
        .with_http_client(UreqHttpClient::new())
        .on_event(|event, client| async move {
            match event {
                Event::PairingQrCode { code, .. } => println!("QR:\n{}", code),
                Event::Message(msg, info) => {
                    println!("Message from {}: {:?}", info.source.sender, msg);
                }
                _ => {}
            }
        })
        .build()
        .await?;

    bot.run().await?.await?;
    Ok(())
}
```

Run the included demo bot:

```bash
cargo run                          # QR code only
cargo run -- -p 15551234567        # Pair code + QR code
cargo run -- -p 15551234567 -c 12345678 # Custom pair code
```

## Project Structure

```
wa-rs/
├── src/                    # Main client library (wa-rs)
├── wacore/                 # Platform-agnostic core (wa-rs-core, no_std compatible)
│   ├── binary/             # WhatsApp binary protocol (wa-rs-binary)
│   ├── derive/             # Derive macros (wa-rs-derive)
│   ├── libsignal/          # Signal Protocol implementation (wa-rs-libsignal)
│   ├── noise/              # Noise Protocol (wa-rs-noise)
│   └── appstate/           # App state management (wa-rs-appstate)
├── waproto/                # Protocol Buffers definitions (wa-rs-proto)
├── storages/sqlite-storage # SQLite backend (wa-rs-sqlite-storage)
├── transports/tokio-transport  # WebSocket transport (wa-rs-tokio-transport)
└── http_clients/ureq-client    # HTTP client (wa-rs-ureq-http)
```

## Crate Mapping

| Crate | Description |
|---|---|
| `wa-rs` | Main client library |
| `wa-rs-core` | Platform-agnostic core types and traits |
| `wa-rs-binary` | WhatsApp binary protocol encoder/decoder |
| `wa-rs-derive` | Derive macros |
| `wa-rs-libsignal` | Signal Protocol (E2E encryption) |
| `wa-rs-noise` | Noise Protocol (transport encryption) |
| `wa-rs-appstate` | App state synchronization |
| `wa-rs-proto` | Protocol Buffers definitions |
| `wa-rs-sqlite-storage` | SQLite storage backend |
| `wa-rs-tokio-transport` | Tokio WebSocket transport |
| `wa-rs-ureq-http` | ureq HTTP client |

## Custom Backends

Implement your own storage, transport, or HTTP client by implementing the respective traits. See the default implementations for reference.

## Changes from Upstream

This fork includes the following changes from the original [whatsapp-rust](https://github.com/jlucaso1/whatsapp-rust):

1. **Stable Rust support** - Removed `#![feature(portable_simd)]` and replaced SIMD optimizations with scalar implementations, enabling compilation on stable Rust (no nightly toolchain required).

2. **PairError event dispatch** - When pairing fails (socket timeout or error), the library now dispatches `Event::PairError` instead of silently returning, allowing applications to handle pairing failures gracefully.

## Disclaimer

This is an unofficial, open-source reimplementation. Using custom WhatsApp clients may violate Meta's Terms of Service and could result in account suspension. Use at your own risk.

## License

MIT - See [LICENSE](LICENSE) for details.

Original copyright (c) 2025 João Lucas de Oliveira Lopes.

## Acknowledgements

- [whatsapp-rust](https://github.com/jlucaso1/whatsapp-rust) by João Lucas de Oliveira Lopes (original project)
- [whatsmeow](https://github.com/tulir/whatsmeow) (Go)
- [Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript)
