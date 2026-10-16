//! Resolving reqwest's host names.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::Resolver;

impl Resolve for Resolver {
    /// Port 0 tells reqwest to use the URL's port, or the scheme's default.
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let addresses = resolver.lookup_ip(name.as_str()).await?;
            Ok(Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0))) as Addrs)
        })
    }
}
