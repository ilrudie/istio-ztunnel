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

use std::net::SocketAddr;

use drain::Watch;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, trace, warn, Instrument};

use crate::config::ProxyMode;
use crate::proxy::connection_manager::ConnectionManager;
use crate::proxy::metrics::Reporter;
use crate::proxy::Error;
use crate::proxy::{metrics, util, ProxyInputs};
use crate::rbac;
use crate::state::workload::NetworkAddress;
use crate::{proxy, socket};

pub(super) struct InboundPassthrough {
    listener: TcpListener,
    pi: ProxyInputs,
    drain: Watch,
}

impl InboundPassthrough {
    pub(super) async fn new(
        mut pi: ProxyInputs,
        drain: Watch,
    ) -> Result<InboundPassthrough, Error> {
        let listener: TcpListener = pi
            .socket_factory
            .tcp_bind(pi.cfg.inbound_plaintext_addr)
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;

        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);

        info!(
            address=%listener.local_addr().expect("local_addr available"),
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough {
            listener,
            pi,
            drain,
        })
    }

    pub(super) async fn run(self) {
        let accept = async move {
        loop {
            // Asynchronously wait for an inbound socket.
            let socket = self.listener.accept().await;
            let pi = self.pi.clone();

            let connection_manager = self.pi.connection_manager.clone();
            match socket {
                Ok((stream, remote)) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_inbound_plaintext(
                            pi, // pi cloned above; OK to move
                            socket::to_canonical(remote),
                            stream,
                            connection_manager,
                        )
                        .await
                        {
                            warn!(source=%socket::to_canonical(remote), component="inbound plaintext", "proxying failed: {}", e)
                        }
                    }.in_current_span());
                }
                Err(e) => {
                    if util::is_runtime_shutdown(&e) {
                        return;
                    }
                    error!("Failed TCP handshake {}", e);
                }
            }
        }
      }.in_current_span();
        // Stop accepting once we drain.
        // Note: we are *not* waiting for all connections to be closed. In the future, we may consider
        // this, but will need some timeout period, as we have no back-pressure mechanism on connections.
        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                info!("inbound passthrough drained");
            }
        }
    }

    async fn proxy_inbound_plaintext(
        pi: ProxyInputs,
        source: SocketAddr,
        mut inbound: TcpStream,
        connection_manager: ConnectionManager,
    ) -> Result<(), Error> {
        let orig = socket::orig_dst_addr_or_default(&inbound);
        // Check if it is a recursive call when proxy mode is Node.
        if pi.cfg.proxy_mode == ProxyMode::Shared && Some(orig.ip()) == pi.cfg.local_ip {
            return Err(Error::SelfCall);
        }
        info!(%source, destination=%orig, component="inbound plaintext", "accepted connection");
        let network_addr = NetworkAddress {
            network: pi.cfg.network.clone(), // inbound request must be on our network
            address: orig.ip(),
        };
        let Some((upstream, upstream_service)) =
            pi.state.fetch_workload_services(&network_addr).await
        else {
            return Err(Error::UnknownDestination(orig.ip()));
        };

        let conn = rbac::Connection {
            src_identity: None,
            src: source,
            // inbound request must be on our network since this is passthrough
            // rather than HBONE, which can be tunneled across networks through gateways.
            // by definition, without the gateway our source must be on our network.
            dst_network: pi.cfg.network.clone(),
            dst: orig,
        };

        let rbac_ctx = crate::state::ProxyRbacContext {
            conn,
            dest_workload_info: pi.proxy_workload_info.clone(),
        };

        //register before assert_rbac to ensure the connection is tracked during it's entire valid span
        connection_manager.register(&rbac_ctx);
        if !pi.state.assert_rbac(&rbac_ctx).await {
            info!(%rbac_ctx.conn, "RBAC rejected");
            connection_manager.release(&rbac_ctx);
            return Ok(());
        }
        let close = match connection_manager.track(&rbac_ctx) {
            Some(c) => c,
            None => {
                // this seems unlikely but could occur if policy changes while track awaits lock
                error!(%rbac_ctx.conn, "RBAC rejected");
                return Ok(());
            }
        };
        let source_ip = super::get_original_src_from_stream(&inbound);
        let orig_src = pi
            .cfg
            .enable_original_source
            .unwrap_or_default()
            .then_some(source_ip)
            .flatten();
        trace!(%source, destination=%orig, component="inbound plaintext", "connect to {orig:?} from {orig_src:?}");

        let mut outbound =
            super::freebind_connect(orig_src, orig, pi.socket_factory.as_ref()).await?;

        trace!(%source, destination=%orig, component="inbound plaintext", "connected");

        // Find source info. We can lookup by XDS or from connection attributes
        let source_workload = if let Some(source_ip) = source_ip {
            let network_addr_srcip = NetworkAddress {
                // inbound request must be on our network since this is passthrough
                // rather than HBONE, which can be tunneled across networks through gateways.
                // by definition, without the gateway our source must be on our network.
                network: pi.cfg.network.clone(),
                address: source_ip,
            };
            pi.state.fetch_workload(&network_addr_srcip).await
        } else {
            None
        };
        let derived_source = metrics::DerivedWorkload {
            identity: rbac_ctx.conn.src_identity.clone(),
            ..Default::default()
        };
        let ds = proxy::guess_inbound_service(&rbac_ctx.conn, upstream_service, &upstream);
        let connection_metrics = metrics::ConnectionOpen {
            reporter: Reporter::destination,
            source: source_workload,
            derived_source: Some(derived_source),
            destination: Some(upstream),
            connection_security_policy: metrics::SecurityPolicy::unknown,
            destination_service: ds,
        };
        let _connection_close = pi
            .metrics
            .increment_defer::<_, metrics::ConnectionClose>(&connection_metrics);
        let transferred_bytes = metrics::BytesTransferred::from(&connection_metrics);
        tokio::select! {
            err =  proxy::relay(&mut outbound, &mut inbound, &pi.metrics, transferred_bytes) => {
                connection_manager.release(&rbac_ctx);
                err?;
            }
            _signaled = close.signaled() => {}
        }
        info!(%source, destination=%orig, component="inbound plaintext", "connection complete");
        Ok(())
    }
}
