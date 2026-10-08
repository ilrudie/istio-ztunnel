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

use crate::config;
use crate::drain::DrainWatcher;
use crate::proxy::Error;
use crate::tls::revocation::{self, RevocationHandle};
use bytes::Bytes;
use futures_util::FutureExt;
use http::Response;
use http::request::Parts;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, watch};
use tracing::{Instrument, debug};

pub struct H2Request {
    request: Parts,
    recv: h2::RecvStream,
    send: h2::server::SendResponse<Bytes>,
}

impl Debug for H2Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Request")
            .field("request", &self.request)
            .finish()
    }
}

impl H2Request {
    pub fn send_error(mut self, resp: Response<()>) -> Result<(), Error> {
        let _ = self.send.send_response(resp, true)?;
        Ok(())
    }

    pub async fn send_response(
        self,
        resp: Response<()>,
    ) -> Result<crate::proxy::h2::H2Stream, Error> {
        let H2Request { recv, mut send, .. } = self;
        let send = send.send_response(resp, false)?;
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: None, // We do not need to track on the server
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: None, // We do not need to track on the server
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok(h2)
    }

    pub fn get_request(&self) -> &Parts {
        &self.request
    }

    pub fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        self.request.headers()
    }
}

pub trait RequestParts {
    fn uri(&self) -> &http::Uri;
    fn method(&self) -> &http::Method;
    fn headers(&self) -> &http::HeaderMap<http::HeaderValue>;
}

impl RequestParts for Parts {
    fn uri(&self) -> &http::Uri {
        &self.uri
    }

    fn method(&self) -> &http::Method {
        &self.method
    }

    fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        &self.headers
    }
}

/// Serves one HBONE connection until it closes, or is drained or shut down.
///
/// `connection_drain` drains this connection, at once if the workload was already drained when it
/// was accepted (see [`crate::drain::ConnectionDrain`]). The connection then sends a graceful
/// GOAWAY and keeps serving the streams it already has, for as long as they run. A stream the peer
/// opens after that is reset with REFUSED_STREAM, which tells the peer it was never processed and
/// is safe to retry against another endpoint, but only if the peer said it can retry it (see
/// [`crate::proxy::X_ISTIO_DRAIN_HEADER`]). Any other new stream is served as usual.
pub async fn serve_connection<S, F, Fut>(
    cfg: Arc<config::Config>,
    s: S,
    drain: DrainWatcher,
    mut force_shutdown: watch::Receiver<()>,
    mut revocation: Option<RevocationHandle>,
    mut connection_drain: Option<watch::Receiver<()>>,
    handler: F,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(H2Request) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    let mut conn = builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        // 64KB max; default is 16MB driven from Golang's defaults
        // Since we know we are going to receive a bounded set of headers, more is overkill.
        .max_header_list_size(65536)
        // 400kb, default from hyper
        .max_send_buffer_size(1024 * 400)
        // default from hyper
        .max_concurrent_streams(200)
        .handshake(s)
        .await?;

    let ping_pong = conn
        .ping_pong()
        .expect("new connection should have ping_pong");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, mut ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(crate::proxy::h2::do_ping_pong(
        ping_pong,
        ping_drop_tx,
        dropped.clone(),
    ));

    let handler = |req| handler(req).map(|_| ());
    // Set once `connection_drain` fires and the GOAWAY has gone out.
    let mut goaway_sent = false;
    loop {
        let drain = drain.clone();
        tokio::select! {
            request = conn.accept() => {
                let Some(request) = request else {
                    // done!
                    // Signal to the ping_pong it should also stop.
                    dropped.store(true, Ordering::Relaxed);
                    return Ok(());
                };
                let (request, mut send) = request?;
                // `select!` picks among ready branches at random, so a drain that is already
                // pending (always the case for a connection accepted after the drain, whose first
                // stream arrives with the handshake) may not have been seen yet. Check it here
                // before serving anything.
                if !goaway_sent
                    && connection_drain
                        .as_ref()
                        .is_some_and(|d| d.has_changed().unwrap_or(false))
                {
                    debug!("connection drain requested, sending GOAWAY");
                    conn.graceful_shutdown();
                    goaway_sent = true;
                }
                if goaway_sent && drain_refusable(&request) {
                    // The peer opened this before it saw our GOAWAY, and can retry it elsewhere.
                    // Refuse it rather than serve it, so it lands on an endpoint that is staying.
                    debug!("refusing new stream on a draining connection");
                    send.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                }
                if goaway_sent {
                    debug!("serving new stream on a draining connection, the peer cannot retry it");
                }
                let (request, recv) = request.into_parts();
                let req = H2Request {
                    request,
                    recv,
                    send,
                };
                let handle = handler(req);
                // Serve the stream in a new task
                tokio::task::spawn(handle.in_current_span());
            }
            _ = &mut ping_drop_rx => {
                // Ideally this would be a warning/error message. However, due to an issue during shutdown,
                // by the time pods with in-pod know to shut down, the network namespace is destroyed.
                // This blocks the ability to send a GOAWAY and gracefully shutdown.
                // See https://github.com/istio/ztunnel/issues/1191.
                debug!("HBONE ping timeout/error, peer may have shutdown");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break
            }
            _ = crate::drain::wait_for_connection_drain(connection_drain.as_mut()), if !goaway_sent => {
                // Keep looping: the existing streams keep running, and new ones must be refused.
                debug!("connection drain requested, sending GOAWAY");
                conn.graceful_shutdown();
                goaway_sent = true;
            }
            _shutdown = drain.wait_for_drain() => {
                debug!("starting graceful drain...");
                // A no-op if a connection drain already sent the GOAWAY.
                conn.graceful_shutdown();
                break;
            }
            // CRL update: revocation is a security event, abruptly terminate (GOAWAY) rather than gracefully drain
            _ = revocation::wait_for_revocation(revocation.as_mut()) => {
                if let Some(rev) = revocation.as_ref() {
                    debug!(
                        peer = %rev.peer(),
                        "terminating inbound connection: peer certificate revoked by CRL update"
                    );
                    conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                    break;
                }
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
    let poll_closed = futures_util::future::poll_fn(move |cx| conn.poll_closed(cx));
    tokio::select! {
        _ = force_shutdown.changed() => {
            return Err(Error::DrainTimeOut)
        }
        _ = poll_closed => {}
    }
    // Mark we are done with the connection
    drop(drain);
    Ok(())
}

/// Whether the peer marked this CONNECT as safe to refuse while draining.
fn drain_refusable<B>(request: &http::Request<B>) -> bool {
    request
        .headers()
        .get(crate::proxy::X_ISTIO_DRAIN_HEADER)
        .is_some_and(|v| v == crate::proxy::DRAIN_REFUSABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain::ConnectionDrain;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use tokio::io::{DuplexStream, ReadBuf};

    /// Holds back reads on the client side, so the client does not see a GOAWAY until let through.
    #[derive(Clone, Default)]
    struct ReadGate(Arc<std::sync::Mutex<(bool, Option<Waker>)>>);

    impl ReadGate {
        fn close(&self) {
            self.0.lock().unwrap().0 = true;
        }

        fn open(&self) {
            let mut gate = self.0.lock().unwrap();
            gate.0 = false;
            if let Some(waker) = gate.1.take() {
                waker.wake();
            }
        }
    }

    struct GatedIo {
        io: DuplexStream,
        gate: ReadGate,
    }

    impl AsyncRead for GatedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            {
                let mut gate = self.gate.0.lock().unwrap();
                if gate.0 {
                    gate.1 = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    /// Accepts the stream and echoes back whatever the client sends, until it ends the stream.
    async fn echo(mut req: H2Request) {
        let mut send = req.send.send_response(Response::new(()), false).unwrap();
        while let Some(Ok(data)) = req.recv.data().await {
            let _ = req.recv.flow_control().release_capacity(data.len());
            send.send_data(data, false).unwrap();
        }
        let _ = send.send_data(Bytes::new(), true);
    }

    /// A CONNECT from a client that can retry it elsewhere, so a draining server may refuse it.
    fn connect_req() -> http::Request<()> {
        let mut req = connect_req_not_refusable();
        req.headers_mut().insert(
            crate::proxy::X_ISTIO_DRAIN_HEADER,
            http::HeaderValue::from_static(crate::proxy::DRAIN_REFUSABLE),
        );
        req
    }

    /// A CONNECT from a client that cannot retry it, such as an older ztunnel.
    fn connect_req_not_refusable() -> http::Request<()> {
        http::Request::builder()
            .uri("127.0.0.1:8080")
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap()
    }

    struct Conn {
        client: h2::client::SendRequest<Bytes>,
        gate: ReadGate,
        server: tokio::task::JoinHandle<Result<(), Error>>,
    }

    /// Serves one connection subscribed to `connection_drain`, and returns a client for it.
    async fn connect(connection_drain: &ConnectionDrain, drain: DrainWatcher) -> Conn {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let (force_tx, force_shutdown) = watch::channel(());
        let server = tokio::spawn(serve_connection(
            Arc::new(crate::test_helpers::test_config()),
            server_io,
            drain,
            force_shutdown,
            None,
            Some(connection_drain.subscribe()),
            echo,
        ));
        // Keep force shutdown from firing just because the sender went away.
        std::mem::forget(force_tx);
        let gate = ReadGate::default();
        let (client, conn) = h2::client::handshake(GatedIo {
            io: client_io,
            gate: gate.clone(),
        })
        .await
        .unwrap();
        tokio::spawn(conn);
        Conn {
            client,
            gate,
            server,
        }
    }

    /// Opens a stream and waits for the server to accept it.
    async fn open_stream(
        client: &mut h2::client::SendRequest<Bytes>,
    ) -> (h2::SendStream<Bytes>, h2::RecvStream) {
        let (resp, send) = client
            .clone()
            .ready()
            .await
            .unwrap()
            .send_request(connect_req(), false)
            .unwrap();
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        (send, resp.into_body())
    }

    async fn assert_echoes(
        send: &mut h2::SendStream<Bytes>,
        recv: &mut h2::RecvStream,
        msg: &'static str,
    ) {
        send.send_data(Bytes::from_static(msg.as_bytes()), false)
            .unwrap();
        let data = recv.data().await.unwrap().unwrap();
        let _ = recv.flow_control().release_capacity(data.len());
        assert_eq!(data, msg.as_bytes());
    }

    /// Lets every task run until all are idle. With the clock paused, the sleep only completes
    /// once nothing else can make progress.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn connection_drain_sends_goaway_and_refuses_new_streams() {
        let connection_drain = ConnectionDrain::default();
        let (_drain_trigger, drain) = crate::drain::new();
        let mut conn = connect(&connection_drain, drain).await;
        let (mut send, mut recv) = open_stream(&mut conn.client).await;
        assert_echoes(&mut send, &mut recv, "before").await;

        // Drain while the client cannot read, so it opens a stream before it sees the GOAWAY.
        conn.gate.close();
        connection_drain.drain();
        settle().await;
        let (raced, _raced_send) = conn
            .client
            .clone()
            .ready()
            .await
            .unwrap()
            .send_request(connect_req(), false)
            .unwrap();
        settle().await;
        conn.gate.open();

        let err = raced.await.unwrap_err();
        assert_eq!(err.reason(), Some(h2::Reason::REFUSED_STREAM), "{err:?}");
        // The client now knows the connection is going away, and opens no more streams on it.
        assert!(conn.client.clone().ready().await.is_err());

        // The stream that was already open keeps running, with no deadline.
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_echoes(&mut send, &mut recv, "after").await;
        assert!(!conn.server.is_finished());

        // Once it ends, the drained connection closes.
        send.send_data(Bytes::new(), true).unwrap();
        while recv.data().await.is_some() {}
        conn.server.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn connection_drain_reaches_connections_opened_after_it() {
        let connection_drain = ConnectionDrain::default();
        let (_drain_trigger, drain) = crate::drain::new();
        connection_drain.drain();

        // The connection is accepted, so the peer gets a GOAWAY rather than a TCP refusal...
        let conn = connect(&connection_drain, drain).await;
        // ...but a stream opened on it, even before the GOAWAY arrives, is refused.
        conn.gate.close();
        let (raced, _raced_send) = conn
            .client
            .clone()
            .ready()
            .await
            .unwrap()
            .send_request(connect_req(), false)
            .unwrap();
        settle().await;
        conn.gate.open();
        let err = raced.await.unwrap_err();
        assert_eq!(err.reason(), Some(h2::Reason::REFUSED_STREAM), "{err:?}");
        assert!(conn.client.clone().ready().await.is_err());
        // With no streams left, the connection closes. The client may hang up first, so the
        // server can see a broken pipe rather than a clean close.
        conn.server.await.unwrap().ok();
    }

    /// A connection accepted after the drain normally has its first stream waiting by the time it
    /// is first polled (it arrives right behind the handshake), so the stream and the drain are
    /// ready together. The stream must still be refused, whichever `select!` happens to pick.
    #[tokio::test(start_paused = true)]
    async fn connection_drain_refuses_a_stream_ready_with_the_handshake() {
        for _ in 0..20 {
            let connection_drain = ConnectionDrain::default();
            let (_drain_trigger, drain) = crate::drain::new();
            connection_drain.drain();

            let (client_io, server_io) = tokio::io::duplex(1 << 16);
            let (client, client_conn) = h2::client::handshake(client_io).await.unwrap();
            let client_conn = tokio::spawn(client_conn);
            let (response, _send) = client
                .ready()
                .await
                .unwrap()
                .send_request(connect_req(), false)
                .unwrap();
            // Let the client write the preface and the CONNECT before the server ever runs.
            settle().await;

            let (force_tx, force_shutdown) = watch::channel(());
            let server = tokio::spawn(serve_connection(
                Arc::new(crate::test_helpers::test_config()),
                server_io,
                drain,
                force_shutdown,
                None,
                Some(connection_drain.subscribe()),
                echo,
            ));
            let err = response.await.unwrap_err();
            assert_eq!(err.reason(), Some(h2::Reason::REFUSED_STREAM), "{err:?}");
            drop(force_tx);
            server.abort();
            client_conn.abort();
        }
    }

    /// A client that did not opt in to refusals is served on a draining connection, as it would be
    /// without the drain: refusing it could fail a connection that has nowhere else to go.
    #[tokio::test(start_paused = true)]
    async fn connection_drain_serves_streams_that_did_not_opt_in() {
        let connection_drain = ConnectionDrain::default();
        let (_drain_trigger, drain) = crate::drain::new();
        connection_drain.drain();
        let conn = connect(&connection_drain, drain).await;

        // Opened before the client sees the GOAWAY, as with the refused stream above.
        conn.gate.close();
        let (response, mut send) = conn
            .client
            .clone()
            .ready()
            .await
            .unwrap()
            .send_request(connect_req_not_refusable(), false)
            .unwrap();
        settle().await;
        conn.gate.open();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut recv = response.into_body();
        assert_echoes(&mut send, &mut recv, "served").await;
        // The GOAWAY still went out, so the client opens nothing more here.
        assert!(conn.client.clone().ready().await.is_err());

        send.send_data(Bytes::new(), true).unwrap();
        while recv.data().await.is_some() {}
        conn.server.await.unwrap().ok();
    }

    #[tokio::test(start_paused = true)]
    async fn global_drain_after_connection_drain_completes() {
        let connection_drain = ConnectionDrain::default();
        let (drain_trigger, drain) = crate::drain::new();
        let mut conn = connect(&connection_drain, drain).await;
        let (mut send, mut recv) = open_stream(&mut conn.client).await;
        connection_drain.drain();
        settle().await;

        // The GOAWAY is already out; the global drain just waits for the connection to close.
        let drained =
            tokio::spawn(drain_trigger.start_drain_and_wait(crate::drain::DrainMode::Graceful));
        settle().await;
        assert!(!drained.is_finished());
        send.send_data(Bytes::new(), true).unwrap();
        while recv.data().await.is_some() {}
        conn.server.await.unwrap().unwrap();
        drained.await.unwrap();
    }
}
