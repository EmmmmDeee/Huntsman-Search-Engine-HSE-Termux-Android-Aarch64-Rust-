//! Utilities: HTTP client, DNS resolver, key loading, UID generation, Termux helpers.

pub mod abn;
pub mod address_au;
pub mod atomic_file;
pub mod breach_sector;
pub mod bsb;
pub mod budget;
pub mod cell_db;
pub mod circuit_breaker;
pub mod city_coords;
pub mod ckan;
pub mod curl;
pub mod curl_client;
pub mod diagnostics;
pub mod dmarc;
pub mod dns;
pub mod domains;
pub mod endpoint_override;
pub mod extract;
pub mod found_keys;
pub mod freq;
pub mod geo;
pub mod geohash;
pub mod geometry;
pub mod hashcat;
pub mod html;
pub mod http;
pub mod json;
pub mod key_pool;
pub mod key_roi;
pub mod key_vault;
pub mod keys;
pub mod log_capture;
pub mod netrotate;
pub mod oathnet;
pub mod oathnet_batch;
pub mod osint_providers;
pub mod oui;
pub mod phone;
pub mod postcode_au;
pub mod preflight;
pub mod proxy;
pub mod raw_archive;
pub mod response_cache;
pub mod scan;
pub mod see_know;

// Exhaustive multi-API orchestration (12+ paid APIs, intelligent chaining, unified workflows)
pub mod multi_api_config;
pub mod multi_api_orchestrator;
pub mod multi_api_workflows;
pub mod multi_api_integration_tests;
pub mod autonomous_validation;

// Autonomous recursion enhancement (fixes data loss in multi-depth scans)
pub mod recursive_enhancement;
pub mod recursive_validation;

// Autonomous multi-API execution (intelligent orchestration of all 12 APIs)
pub mod multi_api_autonomous_execution;

// Exhaustive API expansion (50+ APIs with meta-orchestration)
pub mod exhaustive_api_expansion;
pub mod adaptive_workflow_engine;
pub mod exhaustive_autonomous_integration;

// API Key Management (secure configuration for 50+ APIs)
pub mod api_key_manager;
pub mod api_configuration_helper;
pub mod api_key_retriever;
pub mod api_key_startup;
pub mod api_key_health;
pub mod api_key_orchestrator;
pub mod api_key_integration_tests;
pub mod api_key_config_validator;
pub mod api_key_deployment;
pub mod multi_service_key_pool;

// Phase 7 comprehensive orchestration
pub mod phase7_orchestration;

// HSE OSINT optimization
pub mod hse_osint_apis;
pub mod hse_geolocation_apis;
pub mod hse_scan_orchestrator;
pub mod hse_phase1_guarantee;
pub mod hse_phase1_integration_tests;
pub mod hse_scan_optimizer;
pub mod hse_cross_correlation_engine;
pub mod hse_api_key_comprehensive;
pub mod hse_autonomous_batch_queries;

pub mod service_defs;
pub mod settings;
pub mod sim_anonymity;
pub mod spf;
pub mod str_util;
pub mod surnames;
pub mod target_match;
pub mod termux;
pub mod termux_integration;
pub mod termux_web_service;
pub mod threat;
pub mod timefmt;
pub mod uid;
pub mod url_util;
pub mod wigle;
