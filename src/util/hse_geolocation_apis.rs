/// HSE Geolocation APIs
///
/// Location intelligence APIs optimized for OSINT:
/// - IP geolocation with accuracy ranking
/// - Reverse geocoding (coordinates to address)
/// - Address verification and validation
/// - Cell tower/WiFi triangulation
/// - Mobile carrier detection
/// - Proximity searches

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Geolocation data type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GeolocationType {
    IpGeolocation,           // IP to coordinates
    ReverseGeocoding,        // Coordinates to address
    AddressGeocoding,        // Address to coordinates
    CellTowerTriangulation,  // Cell tower to location
    WiFiTriangulation,       // WiFi SSID to location
    CarrierDetection,        // Carrier and region
    ProximitySearch,         // Nearby entities
}

/// Accuracy tier
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccuracyTier {
    Continent,      // 5000+ km error
    Country,        // 500+ km error
    Region,         // 50+ km error
    City,           // 10+ km error
    Neighborhood,   // 1+ km error
    Street,         // 100+ m error
    Precise,        // <100 m error
}

/// Geolocation API definition
#[derive(Debug, Clone)]
pub struct GeolocationApiDef {
    pub name: String,
    pub api_type: GeolocationType,
    pub accuracy: AccuracyTier,
    pub coverage_percent: f32,         // Geographic coverage
    pub real_time: bool,                // Real-time vs historical
    pub rate_limit_per_minute: u32,
    pub requires_auth: bool,
    pub batch_capable: bool,
    pub cost_per_1k_requests: f32,
    pub data_freshness_hours: u32,
}

/// Location result
#[derive(Debug, Clone)]
pub struct LocationResult {
    pub latitude: f32,
    pub longitude: f32,
    pub latitude_accuracy_m: u32,
    pub longitude_accuracy_m: u32,
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub postal_code: String,
    pub timezone: String,
    pub isp: Option<String>,
    pub organization: Option<String>,
    pub confidence: f32,
}

/// Geolocation query
#[derive(Debug, Clone)]
pub struct GeolocationQuery {
    pub query_type: GeolocationType,
    pub input_data: String,
    pub min_accuracy: AccuracyTier,
    pub required_fields: Vec<String>,
    pub prefer_real_time: bool,
}

/// HSE Geolocation API manager
pub struct HseGeolocationApiManager {
    pub apis: Vec<GeolocationApiDef>,
    pub tier_rankings: HashMap<AccuracyTier, Vec<String>>,
    pub primary_apis: Vec<String>,
    pub backup_apis: Vec<String>,
}

impl HseGeolocationApiManager {
    /// Create new geolocation manager
    pub fn new() -> Self {
        let mut apis = Vec::new();

        // ============ CRITICAL IP GEOLOCATION (PRIMARY) ============
        apis.push(GeolocationApiDef {
            name: "MaxMind GeoIP2".to_string(),
            api_type: GeolocationType::IpGeolocation,
            accuracy: AccuracyTier::City,
            coverage_percent: 99.9,
            real_time: true,
            rate_limit_per_minute: 10000,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.50,
            data_freshness_hours: 6,
        });

        apis.push(GeolocationApiDef {
            name: "IPStack".to_string(),
            api_type: GeolocationType::IpGeolocation,
            accuracy: AccuracyTier::City,
            coverage_percent: 99.5,
            real_time: true,
            rate_limit_per_minute: 10000,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.40,
            data_freshness_hours: 1,
        });

        apis.push(GeolocationApiDef {
            name: "IP2Location".to_string(),
            api_type: GeolocationType::IpGeolocation,
            accuracy: AccuracyTier::City,
            coverage_percent: 98.5,
            real_time: true,
            rate_limit_per_minute: 5000,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.30,
            data_freshness_hours: 12,
        });

        apis.push(GeolocationApiDef {
            name: "GeoIP2 Precision".to_string(),
            api_type: GeolocationType::IpGeolocation,
            accuracy: AccuracyTier::Neighborhood,
            coverage_percent: 95.0,
            real_time: true,
            rate_limit_per_minute: 10000,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 2.50,
            data_freshness_hours: 3,
        });

        // ============ REVERSE GEOCODING (ADDRESS LOOKUP) ============
        apis.push(GeolocationApiDef {
            name: "Google Maps Geocoding".to_string(),
            api_type: GeolocationType::ReverseGeocoding,
            accuracy: AccuracyTier::Street,
            coverage_percent: 99.0,
            real_time: true,
            rate_limit_per_minute: 1000,
            requires_auth: true,
            batch_capable: false,
            cost_per_1k_requests: 0.50,
            data_freshness_hours: 1,
        });

        apis.push(GeolocationApiDef {
            name: "Nominatim (OSM)".to_string(),
            api_type: GeolocationType::ReverseGeocoding,
            accuracy: AccuracyTier::Street,
            coverage_percent: 98.0,
            real_time: true,
            rate_limit_per_minute: 1,
            requires_auth: false,
            batch_capable: false,
            cost_per_1k_requests: 0.0,
            data_freshness_hours: 6,
        });

        apis.push(GeolocationApiDef {
            name: "HERE Reverse Geocoding".to_string(),
            api_type: GeolocationType::ReverseGeocoding,
            accuracy: AccuracyTier::Street,
            coverage_percent: 97.0,
            real_time: true,
            rate_limit_per_minute: 500,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.35,
            data_freshness_hours: 2,
        });

        // ============ ADDRESS VERIFICATION ============
        apis.push(GeolocationApiDef {
            name: "SmartyStreets".to_string(),
            api_type: GeolocationType::AddressGeocoding,
            accuracy: AccuracyTier::Precise,
            coverage_percent: 98.0,
            real_time: true,
            rate_limit_per_minute: 5000,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.05,
            data_freshness_hours: 1,
        });

        apis.push(GeolocationApiDef {
            name: "USPS Address Verification".to_string(),
            api_type: GeolocationType::AddressGeocoding,
            accuracy: AccuracyTier::Precise,
            coverage_percent: 99.5,
            real_time: true,
            rate_limit_per_minute: 1000,
            requires_auth: true,
            batch_capable: false,
            cost_per_1k_requests: 0.0,
            data_freshness_hours: 1,
        });

        // ============ MOBILE GEOLOCATION (CELL/WiFi) ============
        apis.push(GeolocationApiDef {
            name: "Google Geolocation API".to_string(),
            api_type: GeolocationType::CellTowerTriangulation,
            accuracy: AccuracyTier::Neighborhood,
            coverage_percent: 95.0,
            real_time: true,
            rate_limit_per_minute: 1000,
            requires_auth: true,
            batch_capable: false,
            cost_per_1k_requests: 0.50,
            data_freshness_hours: 1,
        });

        apis.push(GeolocationApiDef {
            name: "OpenCellID".to_string(),
            api_type: GeolocationType::CellTowerTriangulation,
            accuracy: AccuracyTier::City,
            coverage_percent: 90.0,
            real_time: true,
            rate_limit_per_minute: 2000,
            requires_auth: false,
            batch_capable: true,
            cost_per_1k_requests: 0.0,
            data_freshness_hours: 6,
        });

        apis.push(GeolocationApiDef {
            name: "Skyhook Precision".to_string(),
            api_type: GeolocationType::WiFiTriangulation,
            accuracy: AccuracyTier::Precise,
            coverage_percent: 92.0,
            real_time: true,
            rate_limit_per_minute: 10000,
            requires_auth: true,
            batch_capable: false,
            cost_per_1k_requests: 0.10,
            data_freshness_hours: 1,
        });

        // ============ CARRIER DETECTION ============
        apis.push(GeolocationApiDef {
            name: "TrueCaller Carrier".to_string(),
            api_type: GeolocationType::CarrierDetection,
            accuracy: AccuracyTier::Region,
            coverage_percent: 98.0,
            real_time: true,
            rate_limit_per_minute: 1000,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.20,
            data_freshness_hours: 1,
        });

        apis.push(GeolocationApiDef {
            name: "NumVerify Carrier".to_string(),
            api_type: GeolocationType::CarrierDetection,
            accuracy: AccuracyTier::Region,
            coverage_percent: 97.0,
            real_time: true,
            rate_limit_per_minute: 500,
            requires_auth: true,
            batch_capable: true,
            cost_per_1k_requests: 0.15,
            data_freshness_hours: 1,
        });

        // Build tier rankings
        let mut tier_rankings = HashMap::new();
        for api in &apis {
            tier_rankings
                .entry(api.accuracy.clone())
                .or_insert_with(Vec::new)
                .push(api.name.clone());
        }

        // Identify primary and backup APIs
        let primary_apis = apis
            .iter()
            .filter(|a| {
                a.accuracy >= AccuracyTier::City
                    && a.coverage_percent > 98.0
                    && a.real_time
            })
            .map(|a| a.name.clone())
            .collect();

        let backup_apis = apis
            .iter()
            .filter(|a| {
                a.coverage_percent > 90.0 && (a.requires_auth == false || a.cost_per_1k_requests < 1.0)
            })
            .map(|a| a.name.clone())
            .collect();

        Self {
            apis,
            tier_rankings,
            primary_apis,
            backup_apis,
        }
    }

    /// Get best APIs for accuracy requirement
    pub fn get_apis_for_accuracy(&self, required: AccuracyTier) -> Vec<GeolocationApiDef> {
        self.apis
            .iter()
            .filter(|a| a.accuracy >= required)
            .cloned()
            .collect()
    }

    /// Get optimal API for query type
    pub fn get_optimal_api(&self, query_type: &GeolocationType) -> Option<GeolocationApiDef> {
        self.apis
            .iter()
            .filter(|a| a.api_type == *query_type && a.real_time)
            .max_by(|a, b| {
                let a_score = (a.coverage_percent * 0.5 + (100.0 - a.cost_per_1k_requests as f32 * 10.0) * 0.5) as u32;
                let b_score = (b.coverage_percent * 0.5 + (100.0 - b.cost_per_1k_requests as f32 * 10.0) * 0.5) as u32;
                a_score.cmp(&b_score)
            })
            .cloned()
    }

    /// Get failover chain for location type
    pub fn get_failover_chain(&self, query_type: &GeolocationType) -> Vec<GeolocationApiDef> {
        let mut chain: Vec<_> = self
            .apis
            .iter()
            .filter(|a| a.api_type == *query_type)
            .cloned()
            .collect();

        chain.sort_by(|a, b| {
            let a_priority = if a.real_time { 100 } else { 50 }
                - (a.data_freshness_hours as i32)
                + (a.coverage_percent as i32);
            let b_priority = if b.real_time { 100 } else { 50 }
                - (b.data_freshness_hours as i32)
                + (b.coverage_percent as i32);
            b_priority.cmp(&a_priority)
        });

        chain
    }

    /// Get geolocation coverage analysis
    pub fn get_coverage_analysis(&self) -> String {
        let ip_geo_apis: Vec<_> = self
            .apis
            .iter()
            .filter(|a| a.api_type == GeolocationType::IpGeolocation)
            .collect();

        let reverse_geo_apis: Vec<_> = self
            .apis
            .iter()
            .filter(|a| a.api_type == GeolocationType::ReverseGeocoding)
            .collect();

        let avg_ip_coverage: f32 =
            ip_geo_apis.iter().map(|a| a.coverage_percent).sum::<f32>() / ip_geo_apis.len().max(1) as f32;

        let avg_reverse_coverage: f32 = reverse_geo_apis
            .iter()
            .map(|a| a.coverage_percent)
            .sum::<f32>()
            / reverse_geo_apis.len().max(1) as f32;

        format!(
            "HSE Geolocation Coverage Analysis\n\
             =================================\n\
             Total Geolocation APIs: {}\n\
             Primary APIs: {}\n\
             Backup APIs: {}\n\n\
             Coverage by Type:\n\
             - IP Geolocation: {:.1}% ({}  APIs)\n\
             - Reverse Geocoding: {:.1}% ({} APIs)\n\
             - Mobile Triangulation: {} APIs\n\
             - Carrier Detection: {} APIs\n\n\
             Accuracy Distribution:\n{}\n",
            self.apis.len(),
            self.primary_apis.len(),
            self.backup_apis.len(),
            avg_ip_coverage,
            ip_geo_apis.len(),
            avg_reverse_coverage,
            reverse_geo_apis.len(),
            self.apis
                .iter()
                .filter(|a| {
                    a.api_type == GeolocationType::CellTowerTriangulation
                        || a.api_type == GeolocationType::WiFiTriangulation
                })
                .count(),
            self.apis
                .iter()
                .filter(|a| a.api_type == GeolocationType::CarrierDetection)
                .count(),
            self.format_accuracy_distribution()
        )
    }

    fn format_accuracy_distribution(&self) -> String {
        let mut distribution = HashMap::new();
        for api in &self.apis {
            *distribution.entry(api.accuracy.clone()).or_insert(0) += 1;
        }

        let mut result = String::new();
        let mut tiers: Vec<_> = distribution.into_iter().collect();
        tiers.sort_by_key(|a| std::cmp::Reverse(a.0.clone()));

        for (tier, count) in tiers {
            result.push_str(&format!("  {:?}: {} APIs\n", tier, count));
        }

        result
    }

    /// Calculate cost for geolocation query
    pub fn estimate_query_cost(&self, query_type: &GeolocationType, num_requests: u32) -> f32 {
        if let Some(api) = self.get_optimal_api(query_type) {
            (api.cost_per_1k_requests * (num_requests as f32 / 1000.0)).max(0.01)
        } else {
            0.0
        }
    }
}

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geolocation_api_manager_creation() {
        let manager = HseGeolocationApiManager::new();
        assert!(manager.apis.len() > 0);
        assert!(!manager.primary_apis.is_empty());
    }

    #[test]
    fn test_accuracy_tier_filtering() {
        let manager = HseGeolocationApiManager::new();
        let precise_apis = manager.get_apis_for_accuracy(AccuracyTier::Precise);

        assert!(precise_apis.len() >= 2);
        assert!(precise_apis.iter().all(|a| a.accuracy >= AccuracyTier::Precise));
    }

    #[test]
    fn test_optimal_api_selection() {
        let manager = HseGeolocationApiManager::new();
        let optimal = manager.get_optimal_api(&GeolocationType::IpGeolocation);

        assert!(optimal.is_some());
        let api = optimal.unwrap();
        assert_eq!(api.api_type, GeolocationType::IpGeolocation);
    }

    #[test]
    fn test_failover_chain_ordering() {
        let manager = HseGeolocationApiManager::new();
        let chain = manager.get_failover_chain(&GeolocationType::IpGeolocation);

        assert!(chain.len() > 1);
        assert_eq!(chain[0].api_type, GeolocationType::IpGeolocation);
    }

    #[test]
    fn test_primary_apis_high_quality() {
        let manager = HseGeolocationApiManager::new();

        for api_name in &manager.primary_apis {
            let api = manager.apis.iter().find(|a| a.name == *api_name).unwrap();
            assert!(api.coverage_percent > 98.0);
            assert!(api.real_time);
        }
    }

    #[test]
    fn test_backup_apis_accessible() {
        let manager = HseGeolocationApiManager::new();

        for api_name in &manager.backup_apis {
            let api = manager.apis.iter().find(|a| a.name == *api_name).unwrap();
            assert!(api.coverage_percent > 90.0);
        }
    }

    #[test]
    fn test_coverage_analysis_report() {
        let manager = HseGeolocationApiManager::new();
        let report = manager.get_coverage_analysis();

        assert!(report.contains("HSE Geolocation Coverage"));
        assert!(report.contains("IP Geolocation"));
    }

    #[test]
    fn test_query_cost_estimation() {
        let manager = HseGeolocationApiManager::new();
        let cost = manager.estimate_query_cost(&GeolocationType::IpGeolocation, 1000);

        assert!(cost > 0.0);
        assert!(cost < 10.0);
    }

    #[test]
    fn test_tier_distribution() {
        let manager = HseGeolocationApiManager::new();
        assert!(!manager.tier_rankings.is_empty());
    }

    #[test]
    fn test_reverse_geocoding_apis() {
        let manager = HseGeolocationApiManager::new();
        let reverse_geo = manager
            .apis
            .iter()
            .filter(|a| a.api_type == GeolocationType::ReverseGeocoding)
            .collect::<Vec<_>>();

        assert!(reverse_geo.len() >= 3);
    }

    #[test]
    fn test_mobile_triangulation_coverage() {
        let manager = HseGeolocationApiManager::new();
        let mobile = manager
            .apis
            .iter()
            .filter(|a| {
                a.api_type == GeolocationType::CellTowerTriangulation
                    || a.api_type == GeolocationType::WiFiTriangulation
            })
            .collect::<Vec<_>>();

        assert!(mobile.len() >= 2);
    }
}
