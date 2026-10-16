//! DNS over TLS (RFC 7858) sessions, driven with in-memory buffers.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

/// The rustls configuration and the name server certificates must match.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub(crate) client: Arc<rustls::ClientConfig>,
    pub(crate) server_name: ServerName<'static>,
}

impl Settings {
    /// A new session with `message` queued for sending once the handshake is
    /// done, and the first bytes to send (the ClientHello).
    pub(crate) fn connect(&self, message: &[u8]) -> Result<(ClientConnection, Vec<u8>), String> {
        let mut session = ClientConnection::new(Arc::clone(&self.client), self.server_name.clone())
            .map_err(|e| e.to_string())?;
        let out = send(&mut session, message)?;
        Ok((session, out))
    }
}

/// Queue `message` on the session and return the bytes to send now. Before
/// the handshake is done, the message waits inside the session and goes out
/// with a later [`receive`].
pub(crate) fn send(session: &mut ClientConnection, message: &[u8]) -> Result<Vec<u8>, String> {
    session
        .writer()
        .write_all(message)
        .map_err(|e| e.to_string())?;
    pending_output(session)
}

/// Feed bytes read from the connection. Returns the bytes to send back and
/// the decrypted bytes, or the TLS error (a bad certificate, say).
pub(crate) fn receive(
    session: &mut ClientConnection,
    mut data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    while !data.is_empty() {
        let read = session.read_tls(&mut data).map_err(|e| e.to_string())?;
        let state = session.process_new_packets().map_err(|e| e.to_string())?;
        // After the server's close_notify, rustls reads nothing more; what
        // follows is ignored (RFC 8446 §6.1).
        if read == 0 || state.peer_has_closed() {
            break;
        }
    }
    let mut plaintext = Vec::new();
    match session.reader().read_to_end(&mut plaintext) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok((pending_output(session)?, plaintext))
}

fn pending_output(session: &mut ClientConnection) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while session.wants_write() {
        session.write_tls(&mut out).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
