//! DNS over TLS (RFC 7858) sessions, driven with in-memory buffers.

use std::fmt;
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
#[derive(Clone)]
pub(crate) struct Settings {
    client: Arc<rustls::ClientConfig>,
    /// Each server's authentication domain name (RFC 8310 §7.1), once per
    /// server, in the order of the servers.
    names: Vec<(SocketAddr, ServerName<'static>)>,
}

/// Shows each server's authentication name and the ALPN protocols offered,
/// not the rustls configuration, which is long and mostly internal.
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alpn: Vec<_> = self
            .client
            .alpn_protocols
            .iter()
            .map(|protocol| String::from_utf8_lossy(protocol))
            .collect();
        f.debug_struct("Settings")
            .field("names", &Names(&self.names))
            .field("alpn", &alpn)
            .finish_non_exhaustive()
    }
}

/// Shows the authentication names as a map from server to name.
struct Names<'a>(&'a [(SocketAddr, ServerName<'static>)]);

impl fmt::Debug for Names<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.0.iter().map(|(server, name)| (server, name.to_str()));
        f.debug_map().entries(names).finish()
    }
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
        // The last name given for an address counts.
        let mut named: Vec<(SocketAddr, ServerName<'static>)> = Vec::new();
        for server in servers {
            if named.iter().any(|(s, _)| s == server) {
                continue;
            }
            let (_, name) = names
                .iter()
                .rfind(|(s, _)| s == server)
                .ok_or(TlsConfigError::NoName(*server))?;
            named.push((*server, name.clone()));
        }
        for (_, name) in &names {
            ClientConnection::new(Arc::clone(&client), name.clone())?;
        }
        Ok(Self {
            client,
            names: named,
        })
    }

    /// A new session with `server`, and its first bytes (the ClientHello).
    pub(crate) fn connect(&self, server: SocketAddr) -> Result<(Session, Vec<u8>), String> {
        let name = self
            .names
            .iter()
            .find(|(named, _)| *named == server)
            .map(|(_, name)| name.clone())
            .ok_or_else(|| format!("no authentication name for {server}"))?;
        let mut connection =
            ClientConnection::new(Arc::clone(&self.client), name).map_err(|e| e.to_string())?;
        let mut hello = Vec::new();
        flush(&mut connection, &mut hello)?;
        let session = Session {
            connection,
            early: Vec::new(),
            alerted: false,
        };
        Ok((session, hello))
    }
}

/// A TLS session, and the messages that wait for its handshake.
///
/// | Input \[guard\] | Next | Bytes to send |
/// |---|---|---|
/// | `Settings::connect` | handshaking | the ClientHello |
/// | [`Session::send`] [while handshaking] | handshaking | none: the message waits in `early` |
/// | `send` [once established, TLS refuses the message] | ended (`Err`) | none |
/// | `send` [once established] | established | what rustls has to send: the message's records |
/// | [`Session::receive`] [no ending] | handshaking, or established once rustls finds the handshake done | what rustls has to send (the rest of the handshake), then, once established, the records of the messages in `early` |
/// | `receive` [the server's close_notify, no TLS error] | ended ([`Ending::CloseNotify`]) | the same |
/// | `receive` [a TLS error] | ended ([`Ending::Failed`]), with `alerted` set if rustls reports the server's alert as the error | none |
/// | [`Session::close`] [in any phase] | closed | the alert rustls queued for a TLS error, or else close_notify, after anything else rustls has left to send; nothing if `alerted` or if rustls can't produce them |
///
/// Between inputs it is handshaking or established: the resolver acts on
/// an ending in the input that brought it. After `receive`, it first
/// handles the plaintext decrypted before the ending. Then it shuts the
/// connection (`Resolver::shut`, which sends what `close` returns) and
/// drops it with the session. A connection the resolver shuts for another
/// reason closes its session the same way, and one the driver reports gone
/// drops it.
#[derive(Debug)]
pub(crate) struct Session {
    connection: ClientConnection,
    /// Framed messages written before the handshake finished, sent as soon
    /// as it has. rustls itself would hold only 64 KiB of them and then
    /// take part of a message, breaking the framing (RFC 7858 §3.3).
    early: Vec<u8>,
    /// Whether the error that ended the session is the server's alert, as
    /// rustls reports it (`Error::AlertReceived`): rustls has no flag for
    /// it that `close` could read. Such an alert is taken for an error
    /// alert, after which nothing more may be sent (RFC 8446 §6), not even
    /// the alert rustls queued in reply, so `close` returns nothing.
    ///
    /// rustls (`CommonState::process_alert`) reports an alert this way if
    /// its level is unknown, and otherwise, unless it is a close_notify
    /// once the handshake is done, if its level is fatal or, once the
    /// server has chosen TLS 1.3, if it is a warning other than
    /// user_canceled and one of the session's first four warnings. For the
    /// unknown level and the warning it queues its own illegal_parameter or
    /// decode_error alert.
    alerted: bool,
}

/// What [`Session::receive`] got from the bytes fed to it.
#[derive(Debug)]
pub(crate) struct Received {
    /// The bytes to send back, and any messages that waited for the
    /// handshake. Empty if the session failed ([`Ending::Failed`]).
    pub(crate) reply: Vec<u8>,
    /// The decrypted bytes, also those decrypted before the session ended.
    pub(crate) plaintext: Vec<u8>,
    /// How the bytes ended the session, if they did.
    pub(crate) ending: Option<Ending>,
}

/// How the bytes fed to [`Session::receive`] ended the session.
#[derive(Debug)]
pub(crate) enum Ending {
    /// rustls reported the server's close_notify: the server sends nothing
    /// more, and what follows it in the bytes is ignored (RFC 8446 §6.1).
    CloseNotify,
    /// A TLS error: the first one from reading records in, processing them
    /// (a bad certificate, a record that doesn't decrypt, an alert rustls
    /// reports as an error), taking their plaintext out, or producing
    /// [`Received::reply`]. It wins over a close_notify in the same bytes.
    /// The plaintext decrypted before it is kept.
    Failed(String),
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

    /// Feed bytes read from the connection. The server's close_notify or a
    /// TLS error (a bad certificate, say) ends the session
    /// ([`Received::ending`]), and nothing after it is taken in (RFC 8446
    /// §6). The plaintext decrypted before the end still comes back, so an
    /// answer that arrived intact counts. [`Session::close`] then gives the
    /// last bytes to send.
    pub(crate) fn receive(&mut self, data: &[u8]) -> Received {
        let mut plaintext = Vec::new();
        let ending = self.decrypt(data, &mut plaintext);
        let (reply, ending) = match ending {
            Some(Ending::Failed(_)) => (Vec::new(), ending),
            None | Some(Ending::CloseNotify) => match self.reply() {
                Ok(reply) => (reply, ending),
                Err(e) => (Vec::new(), Some(Ending::Failed(e))),
            },
        };
        Received {
            reply,
            plaintext,
            ending,
        }
    }

    /// Feed `data` to rustls a batch at a time, appending what each batch
    /// decrypts to `plaintext`, until the session ends, the data runs out
    /// or rustls takes none of a batch. Per batch, it checks for an ending
    /// in this order and returns the first: an error reading the batch in,
    /// before it is processed; then, once the batch's plaintext is taken
    /// out, an error processing it, an error taking the plaintext out, and
    /// the server's close_notify.
    fn decrypt(&mut self, mut data: &[u8], plaintext: &mut Vec<u8>) -> Option<Ending> {
        while !data.is_empty() {
            let read = match self.connection.read_tls(&mut data) {
                Ok(read) => read,
                Err(e) => return Some(Ending::Failed(e.to_string())),
            };
            let processed = self.connection.process_new_packets();
            // rustls holds at most 16 KiB of plaintext: take it out before
            // reading more, and after an error, which leaves what the
            // records before it decrypted.
            let taken = self.connection.reader().read_to_end(plaintext);
            let state = match processed {
                Ok(state) => state,
                Err(e) => {
                    self.alerted = matches!(e, rustls::Error::AlertReceived(_));
                    return Some(Ending::Failed(e.to_string()));
                }
            };
            match taken {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Some(Ending::Failed(e.to_string())),
            }
            // After the server's close_notify, what follows is ignored
            // (RFC 8446 §6.1).
            if state.peer_has_closed() {
                return Some(Ending::CloseNotify);
            }
            if read == 0 {
                break;
            }
        }
        None
    }

    /// What rustls has to send, and the messages that waited for the
    /// handshake once it is done.
    fn reply(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        flush(&mut self.connection, &mut out)?;
        if !self.connection.is_handshaking() && !self.early.is_empty() {
            let early = std::mem::take(&mut self.early);
            write(&mut self.connection, &early, &mut out)?;
        }
        Ok(out)
    }

    /// The last bytes to send before closing the connection: what rustls
    /// still has to send, ending with the alert it queued for a TLS error,
    /// which already ends the session (RFC 8446 §6.2), or, if it queued
    /// none, with the close_notify alert (§6.1). Nothing if rustls reported
    /// the server's alert as the error (`alerted`), as after an error alert
    /// (§6), and nothing if rustls can't produce them.
    pub(crate) fn close(&mut self) -> Vec<u8> {
        if self.alerted {
            return Vec::new();
        }
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
