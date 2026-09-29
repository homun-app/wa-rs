use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatPresence {
    Composing,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChatPresenceMedia {
    #[serde(rename = "")]
    #[default]
    Text,
    #[serde(rename = "audio")]
    Audio,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String")]
pub enum ReceiptType {
    Delivered,
    Sender,
    Retry,
    Read,
    ReadSelf,
    Played,
    PlayedSelf,
    ServerError,
    Inactive,
    PeerMsg,
    HistorySync,
    Other(String),
}

impl From<String> for ReceiptType {
    fn from(s: String) -> Self {
        match s.as_str() {
            // Empty type is the legacy spelling of "delivered" (older clients);
            // "delivery" is what WhatsApp Web sends and what we write ourselves.
            "" | "delivery" => Self::Delivered,
            "sender" => Self::Sender,
            "retry" => Self::Retry,
            "read" => Self::Read,
            "read-self" => Self::ReadSelf,
            "played" => Self::Played,
            "played-self" => Self::PlayedSelf,
            "server-error" => Self::ServerError,
            "inactive" => Self::Inactive,
            "peer_msg" => Self::PeerMsg,
            "hist_sync" => Self::HistorySync,
            _ => Self::Other(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReceiptType;

    #[test]
    fn receipt_type_parses_both_delivered_spellings() {
        // Legacy: receipts from older clients carry no type at all, and the
        // incoming handler defaults the string to "delivery" (receipt.rs).
        // Both spellings must map to Delivered, not Other(...).
        assert_eq!(ReceiptType::from(String::new()), ReceiptType::Delivered);
        assert_eq!(
            ReceiptType::from("delivery".to_string()),
            ReceiptType::Delivered
        );
    }

    #[test]
    fn receipt_type_parses_known_variants() {
        assert_eq!(
            ReceiptType::from("read-self".to_string()),
            ReceiptType::ReadSelf
        );
        assert_eq!(
            ReceiptType::from("hist_sync".to_string()),
            ReceiptType::HistorySync
        );
    }

    #[test]
    fn receipt_type_unknown_falls_back_to_other() {
        assert_eq!(
            ReceiptType::from("future-type".to_string()),
            ReceiptType::Other("future-type".to_string())
        );
    }
}
