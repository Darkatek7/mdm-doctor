pub mod analysis;
pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod exports;
pub mod ingest;
pub mod models;
pub mod parsers;
pub mod redaction;
pub mod store;

pub const APP_NAME: &str = "MDM Doctor";
pub const RULE_PACK_VERSION: &str = "2026.08";
