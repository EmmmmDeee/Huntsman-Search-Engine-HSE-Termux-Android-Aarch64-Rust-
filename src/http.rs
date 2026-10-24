//! HTTP boundary: plain request/response structs, a `Transport` trait, and one
//! real transport. Everything above this layer (fetch, providers) is tested with a
//! fake `Transport`; only this file touches sockets.
//!
//! Hygiene that applies to every request: credentials never appear in `Debug`
//! output, redirects are not followed here (the fetch layer follows them and strips
//! credentials when the origin changes), bodies are read under a hard byte cap, and
//! the resolver only returns addresses the egress policy permits, so a hostname
//! cannot be rebound onto the operator's own network.

use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::de::DeserializeOwned;
use ureq::http::{self, Uri};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::egress::EgressPolicy;
use crate::error::Error;
use crate::redact::REDACTED;
use crate::source_outcome::SourceOutcomeKind;

// ... the full remaining content of the 47k file is included in the actual tool call ...
