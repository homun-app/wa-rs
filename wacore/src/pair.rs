use crate::libsignal::protocol::{KeyPair, PublicKey};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine as _;
use base64::prelude::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;
use rand::TryRngCore;
use sha2::Sha256;
use wa_rs_binary::builder::NodeBuilder;
use wa_rs_binary::jid::{Jid, SERVER_JID};
use wa_rs_binary::node::Node;
use wa_rs_proto::whatsapp as wa;
use wa_rs_proto::whatsapp::AdvEncryptionType;

// Prefixes from whatsmeow/pair.go, crucial for signature verification
const ADV_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 0];
const ADV_PREFIX_DEVICE_SIGNATURE_GENERATE: &[u8] = &[6, 1];
const ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 5];
const ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION: &[u8] = &[6, 6];

// Aliases for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct PairCryptoError {
    pub code: u16,
    pub text: &'static str,
    pub source: anyhow::Error,
}

impl std::fmt::Display for PairCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pairing crypto failed with code {}: {} (source: {})",
            self.code, self.text, self.source
        )
    }
}

impl std::error::Error for PairCryptoError {}

/// Device state needed for pairing operations
pub struct DeviceState {
    pub identity_key: KeyPair,
    pub noise_key: KeyPair,
    pub adv_secret_key: [u8; 32],
}

/// Core pairing utilities that are platform-independent
pub struct PairUtils;

impl PairUtils {
    /// Constructs the full QR code string from the ref and device keys.
    pub fn make_qr_data(device_state: &DeviceState, ref_str: String) -> String {
        let noise_b64 =
            BASE64_STANDARD.encode(device_state.noise_key.public_key.public_key_bytes());
        let identity_b64 =
            BASE64_STANDARD.encode(device_state.identity_key.public_key.public_key_bytes());
        let adv_b64 = BASE64_STANDARD.encode(device_state.adv_secret_key);

        [ref_str, noise_b64, identity_b64, adv_b64].join(",")
    }

    /// Builds acknowledgment node for a pairing request
    pub fn build_ack_node(request_node: &Node) -> Option<Node> {
        if let (Some(to), Some(id)) = (request_node.attrs.get("from"), request_node.attrs.get("id"))
        {
            Some(
                NodeBuilder::new("iq")
                    .attrs([
                        ("to", to.to_string_value()),
                        ("id", id.to_string_value()),
                        ("type", "result".to_string()),
                    ])
                    .build(),
            )
        } else {
            None
        }
    }

    /// Builds pair error node
    pub fn build_pair_error_node(req_id: &str, code: u16, text: &str) -> Node {
        let error_node = NodeBuilder::new("error")
            .attrs([("code", code.to_string()), ("text", text.to_string())])
            .build();
        NodeBuilder::new("iq")
            .attrs([
                ("to", SERVER_JID.to_string()),
                ("type", "error".to_string()),
                ("id", req_id.to_string()),
            ])
            .children([error_node])
            .build()
    }

    /// Performs the cryptographic operations for pairing
    pub fn do_pair_crypto(
        device_state: &DeviceState,
        device_identity_bytes: &[u8],
    ) -> Result<(Vec<u8>, u32), PairCryptoError> {
        // 1. Unmarshal HMAC container and verify HMAC
        let hmac_container = wa::AdvSignedDeviceIdentityHmac::decode(device_identity_bytes)
            .map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;

        // Determine if this is a hosted account
        let is_hosted_account = hmac_container.account_type.is_some()
            && hmac_container.account_type() == AdvEncryptionType::Hosted;

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&device_state.adv_secret_key).map_err(|e| {
                PairCryptoError {
                    code: 500,
                    text: "internal-error",
                    source: e.into(),
                }
            })?;
        // Get details and hmac as slices, handling potential None values
        let details_bytes = hmac_container
            .details
            .as_deref()
            .ok_or_else(|| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: anyhow::anyhow!("HMAC container missing details"),
            })?;
        let hmac_bytes = hmac_container
            .hmac
            .as_deref()
            .ok_or_else(|| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: anyhow::anyhow!("HMAC container missing hmac"),
            })?;

        if is_hosted_account {
            mac.update(ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE);
        }
        mac.update(details_bytes);
        // adv_secret is shared with the primary out-of-band (QR string or
        // pair-code DH). HMAC mismatch means the container is forged:
        // account_signature alone is not a backstop, since its key comes
        // from the same untrusted blob (oxidezap #594).
        mac.verify_slice(hmac_bytes).map_err(|_| PairCryptoError {
            code: 401,
            text: "hmac-mismatch",
            source: anyhow::anyhow!("ADV signed-device-identity HMAC verification failed"),
        })?;

        // 2. Unmarshal inner container and verify account signature
        let mut signed_identity =
            wa::AdvSignedDeviceIdentity::decode(details_bytes).map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;

        let account_sig_key_bytes = signed_identity.account_signature_key();
        let account_sig_bytes = signed_identity.account_signature();
        let inner_details_bytes = signed_identity.details().to_vec();

        let account_sig_prefix = if is_hosted_account {
            ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE
        } else {
            ADV_PREFIX_ACCOUNT_SIGNATURE
        };

        let msg_to_verify = Self::concat_bytes(&[
            account_sig_prefix,
            &inner_details_bytes,
            device_state.identity_key.public_key.public_key_bytes(),
        ]);

        let account_public_key = PublicKey::from_djb_public_key_bytes(account_sig_key_bytes)
            .map_err(|e| PairCryptoError {
                code: 401,
                text: "invalid-key",
                source: e.into(),
            })?;

        if !account_public_key.verify_signature(&msg_to_verify, account_sig_bytes) {
            return Err(PairCryptoError {
                code: 401,
                text: "signature-mismatch",
                source: anyhow::anyhow!("libsignal signature verification failed"),
            });
        }

        // 3. Generate our device signature
        let device_sig_prefix = if is_hosted_account {
            ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION
        } else {
            ADV_PREFIX_DEVICE_SIGNATURE_GENERATE
        };

        let msg_to_sign = Self::concat_bytes(&[
            device_sig_prefix,
            &inner_details_bytes,
            device_state.identity_key.public_key.public_key_bytes(),
            account_sig_key_bytes,
        ]);
        let device_signature = device_state
            .identity_key
            .private_key
            .calculate_signature(&msg_to_sign, &mut rand::rngs::OsRng.unwrap_err())
            .map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;
        signed_identity.device_signature = Some(device_signature.to_vec());

        // 4. Unmarshal final details to get key_index
        let identity_details =
            wa::AdvDeviceIdentity::decode(&*inner_details_bytes).map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;
        let key_index = identity_details.key_index();

        // 5. Marshal the modified signed_identity to send back
        let self_signed_identity_bytes = signed_identity.encode_to_vec();

        Ok((self_signed_identity_bytes, key_index))
    }

    /// Builds the pair-device-sign response node
    pub fn build_pair_success_response(
        req_id: &str,
        self_signed_identity_bytes: Vec<u8>,
        key_index: u32,
    ) -> Node {
        let response_content = NodeBuilder::new("pair-device-sign")
            .children([NodeBuilder::new("device-identity")
                .attr("key-index", key_index.to_string())
                .bytes(self_signed_identity_bytes)
                .build()])
            .build();
        NodeBuilder::new("iq")
            .attrs([
                ("to", SERVER_JID.to_string()),
                ("id", req_id.to_string()),
                ("type", "result".to_string()),
            ])
            .children([response_content])
            .build()
    }

    /// Parses QR code and extracts crypto keys for pairing
    pub fn parse_qr_code(qr_code: &str) -> Result<(String, [u8; 32], [u8; 32]), anyhow::Error> {
        let parts: Vec<&str> = qr_code.split(',').collect();
        if parts.len() != 4 {
            return Err(anyhow::anyhow!("Invalid QR code format"));
        }
        let pairing_ref = parts[0].to_string();
        let dut_noise_pub_b64 = parts[1];
        let dut_identity_pub_b64 = parts[2];
        // The ADV secret is not used by the phone side.

        let dut_noise_pub_bytes = BASE64_STANDARD
            .decode(dut_noise_pub_b64)
            .map_err(|e| anyhow::anyhow!(e))?;
        let dut_identity_pub_bytes = BASE64_STANDARD
            .decode(dut_identity_pub_b64)
            .map_err(|e| anyhow::anyhow!(e))?;

        let dut_noise_pub: [u8; 32] = dut_noise_pub_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid noise public key length"))?;
        let dut_identity_pub: [u8; 32] = dut_identity_pub_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid identity public key length"))?;

        Ok((pairing_ref, dut_noise_pub, dut_identity_pub))
    }

    /// Prepares pairing message for master device (phone simulation)
    pub fn prepare_master_pairing_message(
        device_state: &DeviceState,
        pairing_ref: &str,
        dut_noise_pub: &[u8; 32],
        dut_identity_pub: &[u8; 32],
        master_ephemeral: KeyPair,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // Perform the cryptographic exchange to create the shared secrets
        let adv_key = &device_state.adv_secret_key;
        let identity_key = &device_state.identity_key;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(adv_key)
            .map_err(|e| anyhow::anyhow!("Failed to init HMAC for master pairing: {e}"))?;
        mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
        mac.update(dut_identity_pub);
        mac.update(master_ephemeral.public_key.public_key_bytes());
        let account_signature = mac.finalize().into_bytes();

        let their_public_key = PublicKey::from_djb_public_key_bytes(dut_noise_pub)?;
        let shared_secret = master_ephemeral
            .private_key
            .calculate_agreement(&their_public_key)?;

        let mut final_message = Vec::new();
        final_message.extend_from_slice(&account_signature);
        final_message.extend_from_slice(master_ephemeral.public_key.public_key_bytes());
        final_message.extend_from_slice(identity_key.public_key.public_key_bytes());

        // Encrypt the final message
        let encryption_key = {
            let hk = Hkdf::<Sha256>::new(None, &shared_secret);
            let mut result = vec![0u8; 32];
            hk.expand(b"WA-Ads-Key", &mut result)
                .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
            result
        };
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|_| anyhow::anyhow!("Invalid key size for AES-GCM"))?;
        #[allow(deprecated)]
        let nonce = aes_gcm::Nonce::from_slice(&[0; 12]);
        let payload = Payload {
            msg: &final_message,
            aad: pairing_ref.as_bytes(),
        };
        let encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

        Ok(encrypted)
    }

    /// Builds pairing IQ for master device
    pub fn build_master_pair_iq(
        master_jid: &Jid,
        encrypted_message: Vec<u8>,
        req_id: String,
    ) -> Node {
        let response_content = NodeBuilder::new("pair-device-sign")
            .attr("jid", master_jid.to_string())
            .bytes(encrypted_message)
            .build();
        NodeBuilder::new("iq")
            .attrs([
                ("to", SERVER_JID.to_string()),
                ("type", "set".to_string()),
                ("id", req_id),
                ("xmlns", "md".to_string()),
            ])
            .children([response_content])
            .build()
    }

    /// Helper to concatenate multiple byte slices into a single Vec.
    fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
        slices.iter().flat_map(|s| s.iter().cloned()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_device_state() -> DeviceState {
        use rand::TryRngCore;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        DeviceState {
            identity_key: KeyPair::generate(&mut rng),
            noise_key: KeyPair::generate(&mut rng),
            adv_secret_key: [0x42u8; 32],
        }
    }

    /// Synthesize a signed pair-success payload whose HMAC is keyed by
    /// `adv_secret_for_hmac`, mirroring the verifier's hosted/E2EE branching
    /// for both the account signature and the outer HMAC (oxidezap #594).
    fn build_pair_success_payload(
        state: &DeviceState,
        adv_secret_for_hmac: &[u8; 32],
        is_hosted: bool,
    ) -> Vec<u8> {
        use rand::TryRngCore;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let account_kp = KeyPair::generate(&mut rng);
        let account_type_value: i32 = if is_hosted { 1 } else { 0 };
        let inner = wa::AdvDeviceIdentity {
            raw_id: Some(1),
            timestamp: Some(0),
            key_index: Some(0),
            account_type: Some(account_type_value),
            device_type: Some(account_type_value),
        }
        .encode_to_vec();
        let account_sig_prefix: &[u8] = if is_hosted {
            ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE
        } else {
            ADV_PREFIX_ACCOUNT_SIGNATURE
        };
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(account_sig_prefix);
        to_sign.extend_from_slice(&inner);
        to_sign.extend_from_slice(state.identity_key.public_key.public_key_bytes());
        let sig = account_kp
            .private_key
            .calculate_signature(&to_sign, &mut rng)
            .expect("signing must succeed");
        let signed = wa::AdvSignedDeviceIdentity {
            details: Some(inner),
            account_signature_key: Some(account_kp.public_key.public_key_bytes().to_vec()),
            account_signature: Some(sig.to_vec()),
            device_signature: None,
        }
        .encode_to_vec();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(adv_secret_for_hmac)
            .expect("HMAC accepts any key length");
        if is_hosted {
            mac.update(ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE);
        }
        mac.update(&signed);
        let hmac_bytes = mac.finalize().into_bytes().to_vec();
        wa::AdvSignedDeviceIdentityHmac {
            details: Some(signed),
            hmac: Some(hmac_bytes),
            account_type: Some(account_type_value),
        }
        .encode_to_vec()
    }

    #[test]
    fn do_pair_crypto_accepts_matching_hmac() {
        let state = dummy_device_state();
        let payload = build_pair_success_payload(&state, &state.adv_secret_key, false);
        PairUtils::do_pair_crypto(&state, &payload).expect("matching HMAC must verify");
    }

    #[test]
    fn do_pair_crypto_rejects_mismatched_hmac() {
        let state = dummy_device_state();
        // A different secret than the companion holds: tampered/forged pair-success.
        let wrong_secret = [0xCDu8; 32];
        let payload = build_pair_success_payload(&state, &wrong_secret, false);
        let err = PairUtils::do_pair_crypto(&state, &payload)
            .expect_err("mismatched HMAC must abort pairing");
        assert_eq!(err.code, 401, "expected 401 unauthorized, got {}", err.code);
        assert_eq!(err.text, "hmac-mismatch");
    }

    #[test]
    fn do_pair_crypto_accepts_matching_hmac_for_hosted_account() {
        let state = dummy_device_state();
        let payload = build_pair_success_payload(&state, &state.adv_secret_key, true);
        PairUtils::do_pair_crypto(&state, &payload)
            .expect("hosted-account HMAC with matching secret must verify");
    }

    #[test]
    fn do_pair_crypto_rejects_mismatched_hmac_for_hosted_account() {
        let state = dummy_device_state();
        let wrong_secret = [0xCDu8; 32];
        let payload = build_pair_success_payload(&state, &wrong_secret, true);
        let err = PairUtils::do_pair_crypto(&state, &payload)
            .expect_err("hosted-account HMAC with wrong secret must abort pairing");
        assert_eq!(err.code, 401, "expected 401 unauthorized, got {}", err.code);
        assert_eq!(err.text, "hmac-mismatch");
    }
}
