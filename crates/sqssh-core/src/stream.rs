use quinn::{Connection, RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::protocol::{
    read_channel_msg, read_control_msg, write_channel_msg, write_control_msg, ChannelMsg,
    ChannelType, ControlMsg,
};

/// A control channel on stream 0 (first bidi stream).
pub struct ControlChannel {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl ControlChannel {
    /// Open the control channel (client side).
    pub async fn open(conn: &Connection) -> Result<Self> {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Connection(format!("failed to open control stream: {e}")))?;
        Ok(Self { send, recv })
    }

    /// Accept the control channel (server side).
    pub async fn accept(conn: &Connection) -> Result<Self> {
        let (send, recv) = conn
            .accept_bi()
            .await
            .map_err(|e| Error::Connection(format!("failed to accept control stream: {e}")))?;
        Ok(Self { send, recv })
    }

    pub async fn send(&mut self, msg: &ControlMsg) -> Result<()> {
        write_control_msg(&mut self.send, msg).await
    }

    pub async fn recv(&mut self) -> Result<ControlMsg> {
        read_control_msg(&mut self.recv).await
    }

    /// Split into send and receive halves.
    pub fn into_parts(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}

/// A session/data channel on a bidi stream.
pub struct Channel {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl Channel {
    /// Open a new channel (client side) and send ChannelOpen.
    pub async fn open(conn: &Connection, channel_type: ChannelType) -> Result<Self> {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Connection(format!("failed to open channel stream: {e}")))?;

        write_channel_msg(
            &mut send,
            &ChannelMsg::ChannelOpen { channel_type },
        )
        .await?;

        Ok(Self { send, recv })
    }

    /// Accept a new channel (server side) — reads the ChannelOpen message.
    pub async fn accept(conn: &Connection) -> Result<(Self, ChannelType)> {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| Error::Connection(format!("failed to accept channel stream: {e}")))?;

        let msg = read_channel_msg(&mut recv).await?;
        match msg {
            ChannelMsg::ChannelOpen { channel_type } => {
                Ok((Self { send, recv }, channel_type))
            }
            other => Err(Error::Protocol(format!(
                "expected ChannelOpen, got {other:?}"
            ))),
        }
    }

    pub async fn send(&mut self, msg: &ChannelMsg) -> Result<()> {
        write_channel_msg(&mut self.send, msg).await
    }

    pub async fn recv(&mut self) -> Result<ChannelMsg> {
        read_channel_msg(&mut self.recv).await
    }

    /// Confirm channel open (server side).
    pub async fn confirm(&mut self) -> Result<()> {
        self.send(&ChannelMsg::ChannelOpenConfirm).await
    }

    /// Reject channel open (server side).
    pub async fn reject(&mut self, reason: u32, description: &str) -> Result<()> {
        self.send(&ChannelMsg::ChannelOpenFailure {
            reason,
            description: description.to_string(),
        })
        .await
    }

    /// Get a mutable reference to the raw receive stream.
    pub fn recv_stream(&mut self) -> &mut RecvStream {
        &mut self.recv
    }
}
