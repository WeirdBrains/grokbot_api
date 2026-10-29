//! Desktop activity and per-chat client presence on the Cursor backend's
//! `aiserver.v1.GrokBotService`.
//!
//! [`Client::report_desktop_activity`] is what the Grok Bot desktop app sends every few
//! seconds while it is in use. While a report with `active: true` holds its lease, the
//! backend can hold push notifications to the user's other devices (desktop feature gate
//! `grok_bot_hold_push_until_desktop_inactive`). The server decides; this crate only
//! reports. Both calls need a Cursor access token.
use std::time::Duration;

use serde_json::{Value, json};

use crate::client::{Client, grokbot_service_call};
use crate::error::Result;

/// What the user is doing in a chat (`GrokBotBoxIntent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BoxIntent {
    /// The app came to the foreground.
    AppForeground,
    /// The app went to the background.
    AppBackground,
    /// A chat was opened.
    ChatOpen,
    /// The composer got focus.
    ComposerFocus,
    /// The user is typing.
    Typing,
    /// An upload started.
    UploadStart,
    /// A file was opened.
    FileOpen,
    /// The computer view was opened.
    ComputerOpen,
}

impl BoxIntent {
    /// The full proto enum name.
    pub fn proto_name(self) -> &'static str {
        match self {
            Self::AppForeground => "GROK_BOT_BOX_INTENT_APP_FOREGROUND",
            Self::AppBackground => "GROK_BOT_BOX_INTENT_APP_BACKGROUND",
            Self::ChatOpen => "GROK_BOT_BOX_INTENT_CHAT_OPEN",
            Self::ComposerFocus => "GROK_BOT_BOX_INTENT_COMPOSER_FOCUS",
            Self::Typing => "GROK_BOT_BOX_INTENT_TYPING",
            Self::UploadStart => "GROK_BOT_BOX_INTENT_UPLOAD_START",
            Self::FileOpen => "GROK_BOT_BOX_INTENT_FILE_OPEN",
            Self::ComputerOpen => "GROK_BOT_BOX_INTENT_COMPUTER_OPEN",
        }
    }
}

fn ms(v: Option<&Value>) -> Duration {
    let n = match v {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    Duration::from_millis(n.unwrap_or(0))
}

impl Client {
    /// `ReportGrokBotDesktopActivity {installId, active}` → the lease the server holds
    /// the report for. Re-send while active at least every half lease; send
    /// `active: false` on blur, idle, logout and quit.
    pub async fn report_desktop_activity(
        &self,
        install_id: &str,
        active: bool,
    ) -> Result<Duration> {
        let tok = self.cursor_token_opt().ok_or(crate::Error::Attachment(
            crate::UploadFailure::NoCursorSession,
        ))?;
        let v = grokbot_service_call(
            &tok,
            "ReportGrokBotDesktopActivity",
            &json!({"installId": install_id, "active": active}),
            self.options(),
        )
        .await?;
        Ok(ms(v.get("leaseMs")))
    }

    /// `ReportGrokBotClientPresence {agentId, viewing, surface: "desktop", trigger?, intent?}`
    /// → the presence TTL. `typing` sets `trigger: TYPING`.
    pub async fn report_client_presence(
        &self,
        agent_id: &str,
        viewing: bool,
        typing: bool,
        intent: Option<BoxIntent>,
    ) -> Result<Duration> {
        let tok = self.cursor_token_opt().ok_or(crate::Error::Attachment(
            crate::UploadFailure::NoCursorSession,
        ))?;
        let mut body = json!({"agentId": agent_id, "viewing": viewing, "surface": "desktop"});
        if typing {
            body["trigger"] = json!(1); // GROK_BOT_CLIENT_PRESENCE_TRIGGER_TYPING
        }
        if let Some(i) = intent {
            body["intent"] = json!(i as u8 + 1);
        }
        let v = grokbot_service_call(&tok, "ReportGrokBotClientPresence", &body, self.options())
            .await?;
        Ok(ms(v.get("presenceTtlMs")))
    }
}
