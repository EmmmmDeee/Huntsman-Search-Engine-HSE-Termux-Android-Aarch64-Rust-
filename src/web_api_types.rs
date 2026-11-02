//! The sensor reports the Web UI and HTTP API serve, named in one place.
//!
//! `web_server` takes these types only through this module, so the server does not depend on the
//! radar collectors' module layout (R-07). The types are re-exported unchanged; their serialized
//! shape is owned by the collectors.

pub use crate::cell_radar::CellScan;
pub use crate::radar::TrackReport;
pub use crate::wifi_radar::WifiScan;
