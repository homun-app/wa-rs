use crate::store::Device;
use wa_rs_binary::jid::Jid;
use wa_rs_proto::whatsapp as wa;

#[derive(Debug, Clone)]
pub enum DeviceCommand {
    SetId(Option<Jid>),
    SetLid(Option<Jid>),
    SetPushName(String),
    SetAccount(Option<wa::AdvSignedDeviceIdentity>),
    SetAppVersion((u32, u32, u32)),
    SetDeviceProps(crate::store::device::DevicePropsOverride),
    SetPropsHash(Option<String>),
    /// Rotate the ADV secret. Pairing embeds this secret out-of-band (QR string
    /// or pair-code DH) and the primary keys the pair-success HMAC with it.
    SetAdvSecretKey([u8; 32]),
    /// Cache the server cert chain extracted from a successful XX (or
    /// XX-fallback) handshake. Enables Noise IK on the next connect.
    SetServerCertChain(crate::store::device::CachedServerCertChain),
    /// Drop the cached server cert chain (e.g. after IK fails with a
    /// crypto-fatal error, signalling that the cached `leaf.key` is stale).
    /// Forces XX on the next connect.
    ClearServerCertChain,
}

pub fn apply_command_to_device(device: &mut Device, command: DeviceCommand) {
    match command {
        DeviceCommand::SetId(id) => {
            device.pn = id;
        }
        DeviceCommand::SetLid(lid) => {
            device.lid = lid;
        }
        DeviceCommand::SetPushName(name) => {
            device.push_name = name;
        }
        DeviceCommand::SetAccount(account) => {
            device.account = account;
        }
        DeviceCommand::SetAppVersion((p, s, t)) => {
            device.app_version_primary = p;
            device.app_version_secondary = s;
            device.app_version_tertiary = t;
            device.app_version_last_fetched_ms = chrono::Utc::now().timestamp_millis();
        }
        DeviceCommand::SetDeviceProps(override_) => {
            device.set_device_props(override_);
        }
        DeviceCommand::SetPropsHash(hash) => {
            device.props_hash = hash;
        }
        DeviceCommand::SetAdvSecretKey(key) => {
            device.adv_secret_key = key;
        }
        DeviceCommand::SetServerCertChain(chain) => {
            device.server_cert_chain = Some(chain);
        }
        DeviceCommand::ClearServerCertChain => {
            device.server_cert_chain = None;
        }
    }
}
