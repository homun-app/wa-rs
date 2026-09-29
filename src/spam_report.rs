//! Spam reporting feature.
//!
//! Types and IQ specification are defined in `wa_rs_core::iq::spam_report`.

use crate::client::Client;
use crate::request::IqError;
use wa_rs_core::iq::spam_report::SpamReportSpec;

// Re-export types from wa_rs_core
pub use wa_rs_core::types::{SpamFlow, SpamReportRequest, SpamReportResult, build_spam_list_node};

impl Client {
    /// Send a spam report to WhatsApp.
    ///
    /// This sends a `spam_list` IQ stanza to report one or more messages as spam.
    ///
    /// # Arguments
    /// * `request` - The spam report request containing message details
    ///
    /// # Returns
    /// * `Ok(SpamReportResult)` - If the report was successfully submitted
    /// * `Err` - If there was an error sending or processing the report
    ///
    /// # Example
    /// ```rust,ignore
    /// let result = client.send_spam_report(SpamReportRequest {
    ///     message_id: "MSG_ID".to_string(),
    ///     message_timestamp: 1234567890,
    ///     from_jid: Some(sender_jid),
    ///     spam_flow: SpamFlow::MessageMenu,
    ///     ..Default::default()
    /// }).await?;
    /// ```
    pub async fn send_spam_report(
        &self,
        request: SpamReportRequest,
    ) -> Result<SpamReportResult, IqError> {
        let spec = SpamReportSpec::new(request);
        self.execute(spec).await
    }
}
