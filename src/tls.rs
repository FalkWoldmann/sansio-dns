//! DNS over TLS (RFC 7858) sessions, driven with in-memory buffers.

use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

/// Why [`Config::with_tls`](crate::Config::with_tls) or
/// [`Config::with_tls_names`](crate::Config::with_tls_names) refused the
/// settings.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum TlsConfigError {
    /// A server's port is 53, which DNS over TLS must not use (RFC 7858
    /// §3.1). The usual port is 853.
    #[error("DNS over TLS must not use port 53: {0}")]
    Port53(SocketAddr),
    /// A server was given no authentication name.
    #[error("no authentication name for {0}")]
    NoName(SocketAddr),
    /// An authentication name was given for an address that isn't one of
    /// the servers.
    #[error("{0} is not one of the servers")]
    UnknownServer(SocketAddr),
    /// rustls can't start a session with the `ClientConfig` and a name.
    #[error("rustls can't start a session: {0}")]
    Rustls(#[from] rustls::Error),
}

/// The rustls configuration, and the name each server's certificate must
/// match.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    client: Arc<rustls::ClientConfig>,
    /// Each server's authentication domain name (RFC 8310 §7.1).
    names: Vec<(SocketAddr, ServerName<'static>)>,
}

impl Settings {
    /// Settings for `servers`, with `names` giving each its authentication
    /// name. Fails if a server uses port 53, has no name or isn't in
    /// `servers`, or if rustls can't start a session for a name.
    pub(crate) fn new(
        client: Arc<rustls::ClientConfig>,
        servers: &[SocketAddr],
        names: impl IntoIterator<Item = (SocketAddr, ServerName<'static>)>,
    ) -> Result<Self, TlsConfigError> {
        if let Some(server) = servers.iter().find(|s| s.port() == 53) {
            return Err(TlsConfigError::Port53(*server));
        }
        let names: Vec<_> = names.into_iter().collect();
        if let Some((server, _)) = names.iter().find(|(s, _)| !servers.contains(s)) {
            return Err(TlsConfigError::UnknownServer(*server));
        }
        if let Some(server) = servers
            .iter()
            .find(|s| !names.iter().any(|(named, _)| named == *s))
        {
            return Err(TlsConfigError::NoName(*server));
        }
        for (_, name) in &names {
            ClientConnection::new(Arc::clone(&client), name.clone())?;
        }
        Ok(Self { client, names })
    }

    /// A new session with `server`, and its first bytes (the ClientHello).
    pub(crate) fn connect(&self, server: SocketAddr) -> Result<(Session, Vec<u8>), String> {
        // The last name given for an address counts.
        let name = self
            .names
            .iter()
            .rfind(|(named, _)| *named == server)
            .map(|(_, name)| name.clone())
            .ok_or_else(|| format!("no authentication name for {server}"))?;
        let mut connection =
            ClientConnection::new(Arc::clone(&self.client), name).map_err(|e| e.to_string())?;
        let mut hello = Vec::new();
        flush(&mut connection, &mut hello)?;
        let session = Session {
            connection,
            early: Vec::new(),
        };
        Ok((session, hello))
    }
}

/// A TLS session, and the messages that wait for its handshake.
#[derive(Debug)]
pub(crate) struct Session {
    connection: ClientConnection,
    /// Framed messages written before the handshake finished, sent as soon
    /// as it has. rustls itself would hold only 64 KiB of them and then
    /// take part of a message, breaking the framing (RFC 7858 §3.3).
    early: Vec<u8>,
}

/// What [`Session::receive`] got from the bytes fed to it.
#[derive(Debug)]
pub(crate) struct Received {
    /// The bytes to send back, and any messages that waited for the
    /// handshake.
    pub(crate) reply: Vec<u8>,
    /// The decrypted bytes.
    pub(crate) plaintext: Vec<u8>,
    /// Whether the server sent close_notify: it sends nothing more (RFC
    /// 8446 §6.1).
    pub(crate) closed: bool,
}

impl Session {
    /// Write `message` and return the bytes to send now. Before the
    /// handshake is done, the message waits, and goes out with a later
    /// [`Session::receive`]. On an error, part of the message may have been
    /// taken, so the connection can't be used any more.
    pub(crate) fn send(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        if self.connection.is_handshaking() {
            self.early.extend_from_slice(message);
        } else {
            write(&mut self.connection, message, &mut out)?;
        }
        Ok(out)
    }

    /// Feed bytes read from the connection, or fail with the TLS error (a
    /// bad certificate, say). After an error, [`Session::close`] returns
    /// the alert that tells the server, if rustls queued one, and otherwise
    /// close_notify.
    pub(crate) fn receive(&mut self, mut data: &[u8]) -> Result<Received, String> {
        let mut plaintext = Vec::new();
        let mut closed = false;
        while !data.is_empty() && !closed {
            let read = self
                .connection
                .read_tls(&mut data)
                .map_err(|e| e.to_string())?;
            let state = self
                .connection
                .process_new_packets()
                .map_err(|e| e.to_string())?;
            // rustls holds at most 16 KiB of plaintext: take it out before
            // reading more.
            match self.connection.reader().read_to_end(&mut plaintext) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
            // After the server's close_notify, what follows is ignored (RFC
            // 8446 §6.1).
            closed = state.peer_has_closed();
            if read == 0 {
                break;
            }
        }
        let mut reply = Vec::new();
        flush(&mut self.connection, &mut reply)?;
        if !self.connection.is_handshaking() && !self.early.is_empty() {
            let early = std::mem::take(&mut self.early);
            write(&mut self.connection, &early, &mut reply)?;
        }
        Ok(Received {
            reply,
            plaintext,
            closed,
        })
    }

    /// The last bytes to send before closing the connection: the alert
    /// rustls queued for a TLS error, which already ends the session (RFC
    /// 8446 §6.2), or, if it queued none, the close_notify alert (§6.1).
    /// Empty if rustls can't produce them.
    pub(crate) fn close(&mut self) -> Vec<u8> {
        self.connection.send_close_notify();
        let mut out = Vec::new();
        // Nothing to send if rustls can't produce it.
        flush(&mut self.connection, &mut out).ok();
        out
    }
}

/// Encrypt all of `data` into `out`, a record at a time, so rustls never
/// holds more than one.
fn write(session: &mut ClientConnection, mut data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
    while !data.is_empty() {
        let written = session.writer().write(data).map_err(|e| e.to_string())?;
        if written == 0 {
            return Err("the TLS session takes no more data".to_owned());
        }
        data = data.get(written..).unwrap_or_default();
        flush(session, out)?;
    }
    Ok(())
}

/// Move the bytes rustls has ready to send into `out`.
fn flush(session: &mut ClientConnection, out: &mut Vec<u8>) -> Result<(), String> {
    while session.wants_write() {
        session.write_tls(out).map_err(|e| e.to_string())?;
    }
    Ok(())
}
