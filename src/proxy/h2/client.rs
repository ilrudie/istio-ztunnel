// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::baggage::{Baggage, parse_baggage_header};
use crate::config;
use crate::identity::Identity;
use crate::proxy::{BAGGAGE_HEADER, Error};
use crate::tls::revocation::{self, RevocationHandle};
use bytes::{Buf, Bytes};
use h2::SendStream;
use h2::client::{Connection, SendRequest};
use http::Request;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio::sync::watch::{self, Receiver};
use tracing::{Instrument, debug, error, trace, warn};

#[derive(Debug, Clone)]
// H2ConnectClient is a wrapper abstracting h2
pub struct H2ConnectClient {
    sender: SendRequest<Bytes>,
    pub max_allowed_streams: u16,
    stream_count: Arc<AtomicU16>,
    wl_key: WorkloadKey,
    /// Tunnel revocation signal, surfaced to downstream connections via [`Self::revoked_receiver`]
    /// so they can attribute a revoked teardown as `CERT_REVOKED`.
    /// `None` when CRL enforcement is disabled.
    revoked_rx: Option<watch::Receiver<bool>>,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct WorkloadKey {
    pub src_id: Identity,
    pub dst_id: Vec<Identity>,
    // In theory we can just use src,dst,node. However, the dst has a check that
    // the L3 destination IP matches the HBONE IP. This could be loosened to just assert they are the same identity maybe.
    pub dst: SocketAddr,
    // Because we spoof the source IP, we need to key on this as well. Note: for in-pod its already per-pod
    // pools anyways.
    pub src: IpAddr,
}

impl Display for WorkloadKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})->{}[", self.src, self.src_id, self.dst,)?;
        for i in &self.dst_id {
            write!(f, "{i}")?;
        }
        write!(f, "]")
    }
}

impl H2ConnectClient {
    pub fn is_for_workload(&self, wl_key: &WorkloadKey) -> Result<(), crate::proxy::Error> {
        if !(self.wl_key == *wl_key) {
            Err(crate::proxy::Error::Generic(
                "connection does not match workload key!".into(),
            ))
        } else {
            Ok(())
        }
    }

    // will_be_at_max_streamcount checks if a stream will be maxed out if we send one more request on it
    pub fn will_be_at_max_streamcount(&self) -> bool {
        let future_count = self.stream_count.load(Ordering::Relaxed) + 1;
        trace!(
            "checking streamcount: {future_count} >= {}",
            self.max_allowed_streams
        );
        future_count >= self.max_allowed_streams
    }

    pub fn ready_to_use(&mut self) -> bool {
        let cx = &mut Context::from_waker(futures::task::noop_waker_ref());
        match self.sender.poll_ready(cx) {
            Poll::Ready(Ok(_)) => true,
            // We may have gotten GoAway, etc
            Poll::Ready(Err(_)) => false,
            Poll::Pending => {
                // Given our current usage, I am not sure this can ever be the case.
                // If it is, though, err on the safe side and do not use the connection
                warn!("checked out connection is Pending, skipping");
                false
            }
        }
    }

    pub async fn send_request(
        &mut self,
        req: http::Request<()>,
    ) -> Result<(crate::proxy::h2::H2Stream, Option<Baggage>), Error> {
        let cur = self.stream_count.fetch_add(1, Ordering::SeqCst);
        trace!(current_streams = cur, "sending request");
        let (send, recv, baggage) = match self.internal_send(req).await {
            Ok(r) => r,
            Err(e) => {
                // Request failed, so drop the stream now
                self.stream_count.fetch_sub(1, Ordering::SeqCst);
                return Err(e);
            }
        };

        let (dropped1, dropped2) = crate::proxy::h2::DropCounter::new(self.stream_count.clone());
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: dropped1,
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: dropped2,
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok((h2, baggage))
    }

    // helper to allow us to handle errors once
    async fn internal_send(
        &mut self,
        req: Request<()>,
    ) -> Result<(SendStream<Bytes>, h2::RecvStream, Option<Baggage>), Error> {
        // "This function must return `Ready` before `send_request` is called"
        // We should always be ready though, because we make sure we don't go over the max stream limit out of band.
        futures::future::poll_fn(|cx| self.sender.poll_ready(cx)).await?;
        let (response, stream) = self.sender.send_request(req, false)?;
        let response = response.await?;
        if response.status() != 200 {
            return Err(Error::HttpStatus(response.status()));
        }
        let baggage = parse_baggage_header(response.headers().get_all(BAGGAGE_HEADER)).ok();
        Ok((stream, response.into_body(), baggage))
    }

    /// A receiver for this tunnel's CRL revocation signal, or `None` when CRL enforcement is disabled
    pub fn revoked_receiver(&self) -> Option<watch::Receiver<bool>> {
        self.revoked_rx.clone()
    }
}

pub async fn spawn_connection(
    cfg: Arc<config::Config>,
    s: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    driver_drain: Receiver<bool>,
    wl_key: WorkloadKey,
    revocation: Option<RevocationHandle>,
) -> Result<H2ConnectClient, Error> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        .initial_max_send_streams(cfg.pool_max_streams_per_conn as usize)
        .max_header_list_size(1024 * 16)
        // 4mb. Aligned with window_size such that we can fill up the buffer, then flush it all in one go, without buffering up too much.
        .max_send_buffer_size(cfg.window_size as usize)
        .enable_push(false);

    let (send_req, connection) = builder
        .handshake::<_, Bytes>(s)
        .await
        .map_err(Error::Http2Handshake)?;

    // We store max as u16, so if they report above that max size we just cap at u16::MAX
    let max_allowed_streams = std::cmp::min(
        cfg.pool_max_streams_per_conn,
        connection
            .max_concurrent_send_streams()
            .try_into()
            .unwrap_or(u16::MAX),
    );
    // Subscribe to the tunnel's revocation signal (if CRL enforcement is on) before the revocation
    // state is moved into the driver task, so each stream this connection produces can attribute a
    // revoked teardown.
    let revoked_rx = revocation.as_ref().map(|r| r.subscribe_revoked());
    // spawn a task to poll the connection and drive the HTTP state
    // if we got a drain for that connection, respect it in a race
    // it is important to have a drain here, or this connection will never terminate
    tokio::spawn(
        async move {
            drive_connection(connection, driver_drain, revocation).await;
        }
        .in_current_span(),
    );

    let c = H2ConnectClient {
        sender: send_req,
        stream_count: Arc::new(AtomicU16::new(0)),
        max_allowed_streams,
        wl_key,
        revoked_rx,
    };
    Ok(c)
}

async fn drive_connection<S, B>(
    mut conn: Connection<S, B>,
    mut driver_drain: Receiver<bool>,
    mut revocation: Option<RevocationHandle>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    B: Buf,
{
    let ping_pong = conn
        .ping_pong()
        .expect("ping_pong should only be called once");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(
        super::do_ping_pong(ping_pong, ping_drop_tx, dropped.clone()).in_current_span(),
    );

    tokio::select! {
        _ = driver_drain.changed() => {
            debug!("draining outer HBONE connection");
        }
        _ = ping_drop_rx => {
            warn!("HBONE ping timeout/error");
        }
        // CRL update revoked a cert in this connection's upstream chain. Revocation is a security
        // event, so we tear the tunnel down abruptly (let `conn` drop below) so any in-flight
        // streams multiplexed over it are reset. `revoked()` fires this tunnel's revocation signal
        // before returning (and thus before the drop), so each downstream connection attributes
        // `CERT_REVOKED` rather than a generic reset.
        _ = revocation::wait_for_revocation(revocation.as_mut()) => {
            if let Some(rev) = revocation.as_ref() {
                debug!(
                    peer = %rev.peer(),
                    "terminating outbound connection: upstream certificate revoked by CRL update"
                );
            }
        }
        res = conn => {
            match res {
                Err(e) => {
                    error!("Error in HBONE connection handshake: {:?}", e);
                }
                Ok(_) => {
                    debug!("done with HBONE connection handshake: {:?}", res);
                }
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
}

/// Wraps the I/O of an outbound HBONE connection and calls `on_goaway` once, as soon as the peer
/// sends a GOAWAY frame.
///
/// The h2 client only reports a GOAWAY through `SendRequest::poll_ready`, and holding a
/// `SendRequest` just to poll it would keep the connection open forever. So this follows the frame
/// headers in the bytes the peer sends instead: the server side of an HTTP/2 connection starts
/// directly with a frame (its preface is a SETTINGS frame), and every frame starts with a 9-byte
/// header carrying its payload length and type.
pub struct GoAwayWatcher<S> {
    inner: S,
    on_goaway: Option<Box<dyn FnOnce() + Send>>,
    /// Bytes of the current frame header read so far.
    header: [u8; FRAME_HEADER_LEN],
    header_len: usize,
    /// Payload bytes of the current frame still to skip.
    payload_left: usize,
}

const FRAME_HEADER_LEN: usize = 9;
const FRAME_TYPE_GOAWAY: u8 = 0x7;

impl<S> GoAwayWatcher<S> {
    pub fn new(inner: S, on_goaway: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner,
            on_goaway: Some(Box::new(on_goaway)),
            header: [0; FRAME_HEADER_LEN],
            header_len: 0,
            payload_left: 0,
        }
    }

    fn observe(&mut self, mut data: &[u8]) {
        while !data.is_empty() && self.on_goaway.is_some() {
            if self.payload_left > 0 {
                let skip = self.payload_left.min(data.len());
                self.payload_left -= skip;
                data = &data[skip..];
                continue;
            }
            let take = (FRAME_HEADER_LEN - self.header_len).min(data.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&data[..take]);
            self.header_len += take;
            data = &data[take..];
            if self.header_len < FRAME_HEADER_LEN {
                return;
            }
            self.header_len = 0;
            self.payload_left =
                u32::from_be_bytes([0, self.header[0], self.header[1], self.header[2]]) as usize;
            if self.header[3] == FRAME_TYPE_GOAWAY
                && let Some(on_goaway) = self.on_goaway.take()
            {
                on_goaway();
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GoAwayWatcher<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if this.on_goaway.is_some() {
            let filled = buf.filled();
            // Copied out only because `observe` needs `&mut self`; this is cheap next to the read.
            let new = filled[before..].to_vec();
            this.observe(&new);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GoAwayWatcher<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() as u32).to_be_bytes();
        let mut f = vec![len[1], len[2], len[3], kind, 0, 0, 0, 0, 0];
        f.extend_from_slice(payload);
        f
    }

    fn watcher(fired: &Arc<AtomicUsize>) -> GoAwayWatcher<tokio::io::Empty> {
        let fired = fired.clone();
        GoAwayWatcher::new(tokio::io::empty(), move || {
            fired.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[test]
    fn goaway_watcher_finds_goaway_across_any_read_boundary() {
        // A GOAWAY type byte inside a DATA payload must not count: only frame headers do.
        let mut bytes = frame(0x4, &[0; 6]); // SETTINGS
        bytes.extend(frame(0x0, &[FRAME_TYPE_GOAWAY; 20])); // DATA
        let before_goaway = bytes.len();
        bytes.extend(frame(FRAME_TYPE_GOAWAY, &[0; 8]));
        bytes.extend(frame(FRAME_TYPE_GOAWAY, &[0; 8]));

        for chunk in 1..=bytes.len() {
            let fired = Arc::new(AtomicUsize::new(0));
            let mut w = watcher(&fired);
            let mut seen = 0;
            for piece in bytes.chunks(chunk) {
                w.observe(piece);
                seen += piece.len();
                let expected = usize::from(seen >= before_goaway + FRAME_HEADER_LEN);
                assert_eq!(
                    fired.load(Ordering::SeqCst),
                    expected,
                    "chunk size {chunk}, at {seen}"
                );
            }
        }
    }

    #[tokio::test]
    async fn goaway_watcher_sees_a_graceful_shutdown() {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let fired = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            conn.graceful_shutdown();
            while conn.accept().await.is_some() {}
        });
        let client_io = GoAwayWatcher::new(client_io, {
            let fired = fired.clone();
            move || {
                fired.fetch_add(1, Ordering::SeqCst);
            }
        });
        let noticed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (_send, conn) = h2::client::handshake(client_io).await.unwrap();
            let client = tokio::spawn(conn);
            while fired.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            client.abort();
        })
        .await;
        server.abort();
        assert!(noticed.is_ok(), "GOAWAY should be noticed");
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }
}
