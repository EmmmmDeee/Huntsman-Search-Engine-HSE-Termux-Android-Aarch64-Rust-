/// HSE-Optimized OSINT APIs
///
/// High-priority APIs directly supporting HSE's people-centric OSINT mission:
/// - Breach data aggregation (HIBP, LeakDB, etc.)
/// - People search (phone, email, username)
/// - Social media correlation
/// - Domain/email associations
/// - Public records integration

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// OSINT API categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OsintCategory {
    BreachDatabase,           // Exposed credentials
    PeopleSearch,             // Phone/email/name lookups
    SocialMedia,              // Cross-platform profiles
    DomainEmail,              // Email-domain correlation
    PublicRecords,            // Census, property, court records
    UsernameVerification,     // Cross-platform username checks
    ContactVerification,      // Phone/email validation
}

/// API priority tier
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub enum ApiPriority {
    Critical,    // Essential for HSE core function
    High,        // Significantly enhances results
    Medium,      // Useful but not essential
    Low,         // Specialty use cases
}

/// OSINT API definition
#[derive(Debug, Clone)]
pub struct OsintApiDef {
    pub name: String,
    pub category: OsintCategory,
    pub priority: ApiPriority,
    pub people_centric_score: f32,    // 0-100: how useful for person lookups
    pub geolocation_score: f32,        // 0-100: how useful for location data
    pub data_freshness_hours: u32,     // How recent is data
    pub rate_limit_per_minute: u32,
    pub requires_auth: bool,
    pub batch_capable: bool,
    pub estimated_coverage_percent: f32,
}

/// OSINT query context
#[derive(Debug, Clone)]
pub struct OsintQuery {
    pub query_type: QueryType,
    pub query_value: String,
    pub source_apis: Vec<String>,
    pub geolocation_enabled: bool,
    pub batch_mode: bool,
}

/// Query type
#[derive(Debug, Clone, PartialEq)]
pub enum QueryType {
    PhoneLookup,
    EmailLookup,
    NameSearch,
    UsernameLookup,
    DomainLookup,
    AddressSearch,
    IpGeolocation,
    BreachCheck,
    SocialMediaProfile,
}

/// OSINT result
#[derive(Debug, Clone)]
pub struct OsintResult {
    pub api_source: String,
    pub query_type: QueryType,
    pub found: bool,
    pub data_points: Vec<String>,
    pub geolocation_data: Option<GeolocationData>,
    pub confidence_score: f32,
    pub data_age_hours: u32,
}

/// Geolocation data
#[derive(Debug, Clone)]
pub struct GeolocationData {
    pub latitude: f32,
    pub longitude: f32,
    pub city: String,
    pub state: String,
    pub country: String,
    pub postal_code: String,
    pub accuracy_meters: u32,
}

/// HSE OSINT API manager
pub struct HseOsintApiManager {
    pub apis: Vec<OsintApiDef>,
    pub priority_matrix: HashMap<OsintCategory, Vec<String>>,
    pub geolocation_apis: Vec<String>,
    pub breach_databases: Vec<String>,
    pub people_search_apis: Vec<String>,
}

impl HseOsintApiManager {
    /// Create new OSINT manager with HSE-optimized APIs
    pub fn new() -> Self {
        let mut apis = Vec::new();

        // ============ CRITICAL BREACH DATABASES ============
        apis.push(OsintApiDef {
            name: "HIBP".to_string(),
            category: OsintCategory::BreachDatabase,
            priority: ApiPriority::Critical,
            people_centric_score: 95.0,
            geolocation_score: 0.0,
            data_freshness_hours: 24,
            rate_limit_per_minute: 50,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 85.0,
        });

        apis.push(OsintApiDef {
            name: "LeakDB".to_string(),
            category: OsintCategory::BreachDatabase,
            priority: ApiPriority::Critical,
            people_centric_score: 90.0,
            geolocation_score: 0.0,
            data_freshness_hours: 12,
            rate_limit_per_minute: 100,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 80.0,
        });

        apis.push(OsintApiDef {
            name: "Have I Been Pwned API".to_string(),
            category: OsintCategory::BreachDatabase,
            priority: ApiPriority::Critical,
            people_centric_score: 95.0,
            geolocation_score: 0.0,
            data_freshness_hours: 24,
            rate_limit_per_minute: 50,
            requires_auth: true,
            batch_capable: false,
            estimated_coverage_percent: 90.0,
        });

        // ============ HIGH-VALUE PEOPLE SEARCH ============
        apis.push(OsintApiDef {
            name: "TrueCaller".to_string(),
            category: OsintCategory::PeopleSearch,
            priority: ApiPriority::Critical,
            people_centric_score: 98.0,
            geolocation_score: 40.0,
            data_freshness_hours: 6,
            rate_limit_per_minute: 200,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 88.0,
        });

        apis.push(OsintApiDef {
            name: "NumVerify".to_string(),
            category: OsintCategory::ContactVerification,
            priority: ApiPriority::Critical,
            people_centric_score: 85.0,
            geolocation_score: 50.0,
            data_freshness_hours: 1,
            rate_limit_per_minute: 500,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 95.0,
        });

        apis.push(OsintApiDef {
            name: "EmailHunter".to_string(),
            category: OsintCategory::DomainEmail,
            priority: ApiPriority::High,
            people_centric_score: 80.0,
            geolocation_score: 10.0,
            data_freshness_hours: 24,
            rate_limit_per_minute: 100,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 75.0,
        });

        // ============ CRITICAL GEOLOCATION ============
        apis.push(OsintApiDef {
            name: "MaxMind GeoIP".to_string(),
            category: OsintCategory::PublicRecords,
            priority: ApiPriority::Critical,
            people_centric_score: 20.0,
            geolocation_score: 98.0,
            data_freshness_hours: 6,
            rate_limit_per_minute: 10000,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 99.9,
        });

        apis.push(OsintApiDef {
            name: "IPStack".to_string(),
            category: OsintCategory::PublicRecords,
            priority: ApiPriority::Critical,
            people_centric_score: 15.0,
            geolocation_score: 95.0,
            data_freshness_hours: 1,
            rate_limit_per_minute: 10000,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 99.5,
        });

        apis.push(OsintApiDef {
            name: "Google Maps Geolocation".to_string(),
            category: OsintCategory::PublicRecords,
            priority: ApiPriority::High,
            people_centric_score: 30.0,
            geolocation_score: 96.0,
            data_freshness_hours: 12,
            rate_limit_per_minute: 1000,
            requires_auth: true,
            batch_capable: false,
            estimated_coverage_percent: 99.0,
        });

        // ============ SOCIAL MEDIA CORRELATION ============
        apis.push(OsintApiDef {
            name: "Twitter API".to_string(),
            category: OsintCategory::SocialMedia,
            priority: ApiPriority::High,
            people_centric_score: 88.0,
            geolocation_score: 30.0,
            data_freshness_hours: 1,
            rate_limit_per_minute: 450,
            requires_auth: true,
            batch_capable: false,
            estimated_coverage_percent: 92.0,
        });

        apis.push(OsintApiDef {
            name: "LinkedIn API".to_string(),
            category: OsintCategory::SocialMedia,
            priority: ApiPriority::High,
            people_centric_score: 90.0,
            geolocation_score: 25.0,
            data_freshness_hours: 6,
            rate_limit_per_minute: 300,
            requires_auth: true,
            batch_capable: false,
            estimated_coverage_percent: 85.0,
        });

        apis.push(OsintApiDef {
            name: "Instagram API".to_string(),
            category: OsintCategory::SocialMedia,
            priority: ApiPriority::Medium,
            people_centric_score: 75.0,
            geolocation_score: 45.0,
            data_freshness_hours: 1,
            rate_limit_per_minute: 200,
            requires_auth: true,
            batch_capable: false,
            estimated_coverage_percent: 80.0,
        });

        // ============ USERNAME VERIFICATION ============
        apis.push(OsintApiDef {
            name: "WhatsMyName".to_string(),
            category: OsintCategory::UsernameVerification,
            priority: ApiPriority::High,
            people_centric_score: 85.0,
            geolocation_score: 5.0,
            data_freshness_hours: 24,
            rate_limit_per_minute: 500,
            requires_auth: false,
            batch_capable: true,
            estimated_coverage_percent: 90.0,
        });

        apis.push(OsintApiDef {
            name: "Namechk API".to_string(),
            category: OsintCategory::UsernameVerification,
            priority: ApiPriority::High,
            people_centric_score: 80.0,
            geolocation_score: 0.0,
            data_freshness_hours: 12,
            rate_limit_per_minute: 300,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 88.0,
        });

        // ============ DOMAIN/EMAIL CORRELATION ============
        apis.push(OsintApiDef {
            name: "Whois API".to_string(),
            category: OsintCategory::DomainEmail,
            priority: ApiPriority::High,
            people_centric_score: 70.0,
            geolocation_score: 35.0,
            data_freshness_hours: 24,
            rate_limit_per_minute: 500,
            requires_auth: true,
            batch_capable: true,
            estimated_coverage_percent: 99.0,
        });

        apis.push(OsintApiDef {
            name: "Shodan".to_string(),
            category: OsintCategory::DomainEmail,
            priority: ApiPriority::High,
            people_centric_score: 60.0,
            geolocation_score: 70.0,
            data_freshness_hours: 6,
            rate_limit_per_minute: 100,
            requires_auth: true,
            batch_capable: false,
            estimated_coverage_percent: 80.0,
        });

        // Build priority matrix
        let mut priority_matrix = HashMap::new();
        for api in &apis {
            priority_matrix
                .entry(api.category.clone())
                .or_insert_with(Vec::new)
                .push(api.name.clone());
        }

        // Identify geolocation and breach specialist APIs
        let geolocation_apis = apis
            .iter()
            .filter(|a| a.geolocation_score > 80.0)
            .map(|a| a.name.clone())
            .collect();

        let breach_databases = apis
            .iter()
            .filter(|a| a.category == OsintCategory::BreachDatabase)
            .map(|a| a.name.clone())
            .collect();

        let people_search_apis = apis
            .iter()
            .filter(|a| {
                a.category == OsintCategory::PeopleSearch
                    || a.category == OsintCategory::ContactVerification
            })
            .map(|a| a.name.clone())
            .collect();

        Self {
            apis,
            priority_matrix,
            geolocation_apis,
            breach_databases,
            people_search_apis,
        }
    }

    /// Get critical APIs (Priority::Critical)
    pub fn get_critical_apis(&self) -> Vec<OsintApiDef> {
        self.apis
            .iter()
            .filter(|a| a.priority == ApiPriority::Critical)
            .cloned()
            .collect()
    }

    /// Get best APIs for query type
    pub fn get_optimal_apis_for_query(&self, query_type: &QueryType) -> Vec<OsintApiDef> {
        let mut best = self
            .apis
            .iter()
            .filter(|a| self.api_supports_query(a, query_type))
            .cloned()
            .collect::<Vec<_>>();

        best.sort_by(|a, b| {
            b.people_centric_score
                .partial_cmp(&a.people_centric_score)
                .unwrap()
        });

        best
    }

    fn api_supports_query(&self, api: &OsintApiDef, query_type: &QueryType) -> bool {
        match query_type {
            QueryType::PhoneLookup => {
                api.category == OsintCategory::PeopleSearch
                    || api.category == OsintCategory::ContactVerification
            }
            QueryType::EmailLookup => {
                api.category == OsintCategory::PeopleSearch
                    || api.category == OsintCategory::DomainEmail
            }
            QueryType::BreachCheck => api.category == OsintCategory::BreachDatabase,
            QueryType::UsernameLookup => api.category == OsintCategory::UsernameVerification,
            QueryType::DomainLookup => api.category == OsintCategory::DomainEmail,
            QueryType::IpGeolocation => api.geolocation_score > 50.0,
            QueryType::SocialMediaProfile => api.category == OsintCategory::SocialMedia,
            _ => true,
        }
    }

    /// Get APIs by priority
    pub fn get_apis_by_priority(&self, priority: ApiPriority) -> Vec<OsintApiDef> {
        self.apis
            .iter()
            .filter(|a| a.priority == priority)
            .cloned()
            .collect()
    }

    /// Calculate HSE relevance score
    pub fn calculate_hse_relevance(&self, api: &OsintApiDef) -> f32 {
        // HSE-specific relevance: weight people-centric + geolocation
        let people_weight = 0.7;
        let geo_weight = 0.3;

        (api.people_centric_score * people_weight + api.geolocation_score * geo_weight) / 100.0
    }

    /// Get total coverage for category
    pub fn get_category_coverage(&self, category: &OsintCategory) -> f32 {
        let apis: Vec<_> = self.apis.iter().filter(|a| &a.category == category).collect();

        if apis.is_empty() {
            return 0.0;
        }

        let avg_coverage: f32 = apis.iter().map(|a| a.estimated_coverage_percent).sum::<f32>()
            / apis.len() as f32;

        avg_coverage
    }

    /// Generate HSE optimization report
    pub fn get_hse_optimization_report(&self) -> String {
        let critical_apis = self.get_critical_apis();
        let breach_coverage = self.get_category_coverage(&OsintCategory::BreachDatabase);
        let geo_coverage = self.get_category_coverage(&OsintCategory::PublicRecords);

        format!(
            "HSE OSINT Optimization Report\n\
             =============================\n\
             Total OSINT APIs: {}\n\
             Critical APIs: {}\n\
             Geolocation APIs: {}\n\
             Breach Databases: {}\n\
             People Search APIs: {}\n\n\
             Coverage Analysis:\n\
             - Breach Data: {:.1}%\n\
             - Geolocation: {:.1}%\n\n\
             HSE Relevance:\n\
             - People-Centric: High priority\n\
             - Geolocation: Secondary priority\n\
             - Recommendation: Deploy all Critical tier APIs\n",
            self.apis.len(),
            critical_apis.len(),
            self.geolocation_apis.len(),
            self.breach_databases.len(),
            self.people_search_apis.len(),
            breach_coverage,
            geo_coverage,
        )
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
    fn test_osint_api_manager_creation() {
        let manager = HseOsintApiManager::new();
        assert!(manager.apis.len() > 0);
        assert!(!manager.geolocation_apis.is_empty());
        assert!(!manager.breach_databases.is_empty());
    }

    #[test]
    fn test_critical_apis_identified() {
        let manager = HseOsintApiManager::new();
        let critical = manager.get_critical_apis();

        assert!(critical.len() >= 7);
        assert!(critical.iter().all(|a| a.priority == ApiPriority::Critical));
    }

    #[test]
    fn test_api_filtering_by_priority() {
        let manager = HseOsintApiManager::new();
        let high_priority = manager.get_apis_by_priority(ApiPriority::High);

        assert!(high_priority.len() >= 5);
    }

    #[test]
    fn test_query_type_routing() {
        let manager = HseOsintApiManager::new();
        let breach_apis = manager.get_optimal_apis_for_query(&QueryType::BreachCheck);

        assert!(!breach_apis.is_empty());
        assert!(breach_apis.iter().all(|a| {
            a.category == OsintCategory::BreachDatabase
        }));
    }

    #[test]
    fn test_phone_lookup_routing() {
        let manager = HseOsintApiManager::new();
        let phone_apis = manager.get_optimal_apis_for_query(&QueryType::PhoneLookup);

        assert!(!phone_apis.is_empty());
        assert!(phone_apis[0].people_centric_score > 80.0);
    }

    #[test]
    fn test_geolocation_apis_identified() {
        let manager = HseOsintApiManager::new();

        assert!(manager.geolocation_apis.contains(&"MaxMind GeoIP".to_string()));
        assert!(manager.geolocation_apis.contains(&"IPStack".to_string()));
    }

    #[test]
    fn test_hse_relevance_scoring() {
        let manager = HseOsintApiManager::new();
        let hibp = manager.apis.iter().find(|a| a.name == "HIBP").unwrap();

        let relevance = manager.calculate_hse_relevance(hibp);
        assert!(relevance > 0.65);
    }

    #[test]
    fn test_category_coverage() {
        let manager = HseOsintApiManager::new();
        let breach_coverage = manager.get_category_coverage(&OsintCategory::BreachDatabase);

        assert!(breach_coverage > 75.0);
    }

    #[test]
    fn test_optimization_report() {
        let manager = HseOsintApiManager::new();
        let report = manager.get_hse_optimization_report();

        assert!(report.contains("HSE OSINT Optimization"));
        assert!(report.contains("Critical APIs"));
    }

    #[test]
    fn test_people_search_apis() {
        let manager = HseOsintApiManager::new();

        assert!(manager.people_search_apis.len() >= 2);
        assert!(manager.people_search_apis.contains(&"TrueCaller".to_string()));
    }

    #[test]
    fn test_breach_database_count() {
        let manager = HseOsintApiManager::new();

        assert_eq!(manager.breach_databases.len(), 3);
    }
}
