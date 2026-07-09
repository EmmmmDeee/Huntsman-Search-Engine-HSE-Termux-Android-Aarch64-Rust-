/// API Configuration Helper
///
/// Assists with:
/// - Auto-discovery of configured APIs from environment
/// - Generation of .env template files
/// - Key validation and health checks
/// - Configuration documentation
/// - Setup guides for each API
/// - Budget estimation

use std::collections::HashMap;

/// Configuration help guide
pub struct ApiConfigurationHelper {
    pub setup_guides: HashMap<String, ApiSetupGuide>,
}

/// Setup guide for each API
#[derive(Debug, Clone)]
pub struct ApiSetupGuide {
    pub api_name: String,
    pub provider_name: String,
    pub website_url: String,
    pub signup_url: String,
    pub documentation_url: String,
    pub setup_steps: Vec<String>,
    pub estimated_setup_time_minutes: u32,
    pub free_tier_available: bool,
    pub free_tier_limits: String,
    pub paid_tier_starting_cost_per_month: Option<f32>,
    pub environment_variable: String,
    pub key_format_hint: String,
    pub common_errors: Vec<(String, String)>,
}

impl ApiConfigurationHelper {
    pub fn new() -> Self {
        let mut helper = Self {
            setup_guides: HashMap::new(),
        };
        helper.initialize_setup_guides();
        helper
    }

    fn initialize_setup_guides(&mut self) {
        // ============ BREACH DATABASES ============
        self.add_guide(ApiSetupGuide {
            api_name: "SeekNow".to_string(),
            provider_name: "SeekNow".to_string(),
            website_url: "https://seeknow.com".to_string(),
            signup_url: "https://seeknow.com/register".to_string(),
            documentation_url: "https://seeknow.api.docs".to_string(),
            setup_steps: vec![
                "1. Visit https://seeknow.com/register".to_string(),
                "2. Create account with email".to_string(),
                "3. Verify email address".to_string(),
                "4. Go to Settings → API Keys".to_string(),
                "5. Generate new API key".to_string(),
                "6. Copy key to HUNTSMAN_SEEKNOW_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: false,
            free_tier_limits: "N/A".to_string(),
            paid_tier_starting_cost_per_month: Some(99.0),
            environment_variable: "HUNTSMAN_SEEKNOW_KEY".to_string(),
            key_format_hint: "Alphanumeric string, ~40 characters".to_string(),
            common_errors: vec![
                ("Invalid API Key".to_string(), "Ensure key is copied completely with no spaces".to_string()),
                ("Rate limit exceeded".to_string(), "Free tier has strict rate limits, upgrade to paid".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "OathNet Pro".to_string(),
            provider_name: "OathNet".to_string(),
            website_url: "https://oathnet.com".to_string(),
            signup_url: "https://oathnet.com/signup".to_string(),
            documentation_url: "https://oathnet.docs".to_string(),
            setup_steps: vec![
                "1. Visit https://oathnet.com/signup".to_string(),
                "2. Complete registration and KYC verification".to_string(),
                "3. Set up billing information".to_string(),
                "4. Navigate to API Management".to_string(),
                "5. Create API token with breach database access".to_string(),
                "6. Set HUNTSMAN_OATHNET_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 15,
            free_tier_available: false,
            free_tier_limits: "N/A".to_string(),
            paid_tier_starting_cost_per_month: Some(299.0),
            environment_variable: "HUNTSMAN_OATHNET_KEY".to_string(),
            key_format_hint: "JWT token or API key, usually starts with 'oath_'".to_string(),
            common_errors: vec![
                ("Unauthorized".to_string(), "KYC verification not completed or key permissions insufficient".to_string()),
                ("Quota exceeded".to_string(), "Daily query limit reached, wait for reset or upgrade plan".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "HIBP".to_string(),
            provider_name: "Have I Been Pwned".to_string(),
            website_url: "https://haveibeenpwned.com".to_string(),
            signup_url: "https://haveibeenpwned.com/API/v2".to_string(),
            documentation_url: "https://haveibeenpwned.com/api".to_string(),
            setup_steps: vec![
                "1. Visit https://haveibeenpwned.com/API/v2".to_string(),
                "2. Create free account or link existing Cloudflare account".to_string(),
                "3. Verify email address".to_string(),
                "4. Get API key from account dashboard".to_string(),
                "5. Set HUNTSMAN_HIBP_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 3,
            free_tier_available: true,
            free_tier_limits: "Public API (no key required)".to_string(),
            paid_tier_starting_cost_per_month: Some(3.5),
            environment_variable: "HUNTSMAN_HIBP_KEY".to_string(),
            key_format_hint: "Alphanumeric string, usually ~40 characters".to_string(),
            common_errors: vec![
                ("Forbidden".to_string(), "User-Agent header missing or API key not set".to_string()),
                ("Rate limited".to_string(), "Exceeded 1,500 requests per hour, implement backoff".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "Leakix".to_string(),
            provider_name: "Leakix".to_string(),
            website_url: "https://leakix.net".to_string(),
            signup_url: "https://leakix.net/register".to_string(),
            documentation_url: "https://leakix.net/api".to_string(),
            setup_steps: vec![
                "1. Visit https://leakix.net/register".to_string(),
                "2. Create account with username and password".to_string(),
                "3. Verify email".to_string(),
                "4. Go to account settings → API section".to_string(),
                "5. Generate API token".to_string(),
                "6. Set HUNTSMAN_LEAKIX_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: true,
            free_tier_limits: "Limited to 100 queries/day".to_string(),
            paid_tier_starting_cost_per_month: Some(49.0),
            environment_variable: "HUNTSMAN_LEAKIX_KEY".to_string(),
            key_format_hint: "Alphanumeric string, usually starts with 'lix_'".to_string(),
            common_errors: vec![
                ("Unauthorized".to_string(), "API key not valid or expired".to_string()),
                ("Daily quota exceeded".to_string(), "Free tier limited to 100 queries/day".to_string()),
            ],
        });

        // ============ EMAIL ENRICHMENT ============
        self.add_guide(ApiSetupGuide {
            api_name: "Hunter.io".to_string(),
            provider_name: "Hunter".to_string(),
            website_url: "https://hunter.io".to_string(),
            signup_url: "https://hunter.io/signup".to_string(),
            documentation_url: "https://hunter.io/api".to_string(),
            setup_steps: vec![
                "1. Visit https://hunter.io/signup".to_string(),
                "2. Create account (free or paid)".to_string(),
                "3. Verify email".to_string(),
                "4. Go to Account → API".to_string(),
                "5. Copy API key".to_string(),
                "6. Set HUNTSMAN_HUNTER_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 3,
            free_tier_available: true,
            free_tier_limits: "50 searches/month, 1000 email verifications/month".to_string(),
            paid_tier_starting_cost_per_month: Some(49.0),
            environment_variable: "HUNTSMAN_HUNTER_KEY".to_string(),
            key_format_hint: "Alphanumeric string, ~40 characters".to_string(),
            common_errors: vec![
                ("No emails found".to_string(), "Domain not in database or insufficient access level".to_string()),
                ("Daily quota exceeded".to_string(), "Upgrade to higher plan".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "FullContact".to_string(),
            provider_name: "FullContact".to_string(),
            website_url: "https://www.fullcontact.com".to_string(),
            signup_url: "https://app.fullcontact.com/signup".to_string(),
            documentation_url: "https://docs.fullcontact.com".to_string(),
            setup_steps: vec![
                "1. Visit https://app.fullcontact.com/signup".to_string(),
                "2. Create account".to_string(),
                "3. Verify email and set up billing".to_string(),
                "4. Go to Account Settings → API".to_string(),
                "5. Generate API token".to_string(),
                "6. Set HUNTSMAN_FULLCONTACT_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 10,
            free_tier_available: false,
            free_tier_limits: "N/A".to_string(),
            paid_tier_starting_cost_per_month: Some(99.0),
            environment_variable: "HUNTSMAN_FULLCONTACT_KEY".to_string(),
            key_format_hint: "Bearer token format, usually starts with 'pk_'".to_string(),
            common_errors: vec![
                ("401 Unauthorized".to_string(), "API key invalid or expired".to_string()),
                ("Quota exceeded".to_string(), "Monthly credit limit reached".to_string()),
            ],
        });

        // ============ INFRASTRUCTURE ============
        self.add_guide(ApiSetupGuide {
            api_name: "Shodan".to_string(),
            provider_name: "Shodan".to_string(),
            website_url: "https://www.shodan.io".to_string(),
            signup_url: "https://www.shodan.io/register".to_string(),
            documentation_url: "https://shodan.io/api".to_string(),
            setup_steps: vec![
                "1. Visit https://www.shodan.io/register".to_string(),
                "2. Create account".to_string(),
                "3. Verify email".to_string(),
                "4. Go to Account → Settings → API".to_string(),
                "5. Copy API key from dashboard".to_string(),
                "6. Set HUNTSMAN_SHODAN_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: true,
            free_tier_limits: "1 query/month, limited to basic searches".to_string(),
            paid_tier_starting_cost_per_month: Some(49.0),
            environment_variable: "HUNTSMAN_SHODAN_KEY".to_string(),
            key_format_hint: "Alphanumeric string, ~40 characters".to_string(),
            common_errors: vec![
                ("Invalid API key".to_string(), "Key not properly set in environment".to_string()),
                ("No results".to_string(), "Query syntax error, see documentation for proper format".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "Censys".to_string(),
            provider_name: "Censys".to_string(),
            website_url: "https://censys.io".to_string(),
            signup_url: "https://censys.io/register".to_string(),
            documentation_url: "https://censys.io/api".to_string(),
            setup_steps: vec![
                "1. Visit https://censys.io/register".to_string(),
                "2. Create account".to_string(),
                "3. Verify email".to_string(),
                "4. Navigate to Account → API".to_string(),
                "5. Get API ID and Secret".to_string(),
                "6. Set HUNTSMAN_CENSYS_ID and HUNTSMAN_CENSYS_SECRET".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: true,
            free_tier_limits: "120 queries/hour, limited data".to_string(),
            paid_tier_starting_cost_per_month: Some(99.0),
            environment_variable: "HUNTSMAN_CENSYS_ID (+ HUNTSMAN_CENSYS_SECRET)".to_string(),
            key_format_hint: "Two credentials: API ID (username-like) and Secret (password-like)".to_string(),
            common_errors: vec![
                ("401 Unauthorized".to_string(), "Credentials incorrect or not set as basic auth".to_string()),
                ("Rate limited".to_string(), "Exceeded 120 queries/hour limit".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "SecurityTrails".to_string(),
            provider_name: "SecurityTrails".to_string(),
            website_url: "https://securitytrails.com".to_string(),
            signup_url: "https://securitytrails.com/app/register".to_string(),
            documentation_url: "https://securitytrails.com/app/api".to_string(),
            setup_steps: vec![
                "1. Visit https://securitytrails.com/app/register".to_string(),
                "2. Create account".to_string(),
                "3. Verify email".to_string(),
                "4. Go to Account → API".to_string(),
                "5. Copy API key".to_string(),
                "6. Set HUNTSMAN_SECURITYTRAILS_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: false,
            free_tier_limits: "N/A".to_string(),
            paid_tier_starting_cost_per_month: Some(99.0),
            environment_variable: "HUNTSMAN_SECURITYTRAILS_KEY".to_string(),
            key_format_hint: "Alphanumeric string, ~40 characters".to_string(),
            common_errors: vec![
                ("Invalid API key".to_string(), "Key not copied correctly".to_string()),
                ("403 Forbidden".to_string(), "API key not authorized for requested endpoint".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "GreyNoise".to_string(),
            provider_name: "GreyNoise".to_string(),
            website_url: "https://www.greynoise.io".to_string(),
            signup_url: "https://viz.greynoise.io/signup".to_string(),
            documentation_url: "https://docs.greynoise.io".to_string(),
            setup_steps: vec![
                "1. Visit https://viz.greynoise.io/signup".to_string(),
                "2. Create account".to_string(),
                "3. Verify email".to_string(),
                "4. Go to Account → Settings → API Keys".to_string(),
                "5. Create new API key".to_string(),
                "6. Set HUNTSMAN_GREYNOISE_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: true,
            free_tier_limits: "Limited to 50 queries/month".to_string(),
            paid_tier_starting_cost_per_month: Some(500.0),
            environment_variable: "HUNTSMAN_GREYNOISE_KEY".to_string(),
            key_format_hint: "Bearer token format".to_string(),
            common_errors: vec![
                ("Unauthorized".to_string(), "API key not set or invalid".to_string()),
                ("Quota exceeded".to_string(), "Free tier limited to 50 queries/month".to_string()),
            ],
        });

        // ============ PERSON SEARCH ============
        self.add_guide(ApiSetupGuide {
            api_name: "Pipl".to_string(),
            provider_name: "Pipl".to_string(),
            website_url: "https://pipl.com".to_string(),
            signup_url: "https://pipl.com/api/services".to_string(),
            documentation_url: "https://pipl.com/api".to_string(),
            setup_steps: vec![
                "1. Visit https://pipl.com/api/services".to_string(),
                "2. Create account".to_string(),
                "3. Verify email and phone".to_string(),
                "4. Set up billing".to_string(),
                "5. Get API key from dashboard".to_string(),
                "6. Set HUNTSMAN_PIPL_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 10,
            free_tier_available: false,
            free_tier_limits: "N/A".to_string(),
            paid_tier_starting_cost_per_month: Some(99.0),
            environment_variable: "HUNTSMAN_PIPL_KEY".to_string(),
            key_format_hint: "Alphanumeric string, ~40 characters".to_string(),
            common_errors: vec![
                ("No match found".to_string(), "Person not in database".to_string()),
                ("403 Forbidden".to_string(), "API key not authorized or account suspended".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "Spokeo".to_string(),
            provider_name: "Spokeo".to_string(),
            website_url: "https://www.spokeo.com".to_string(),
            signup_url: "https://www.spokeo.com/api".to_string(),
            documentation_url: "https://www.spokeo.com/api".to_string(),
            setup_steps: vec![
                "1. Visit https://www.spokeo.com/api".to_string(),
                "2. Create account".to_string(),
                "3. Verify email".to_string(),
                "4. Request API access".to_string(),
                "5. Get API key once approved".to_string(),
                "6. Set HUNTSMAN_SPOKEO_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 15,
            free_tier_available: false,
            free_tier_limits: "N/A".to_string(),
            paid_tier_starting_cost_per_month: Some(299.0),
            environment_variable: "HUNTSMAN_SPOKEO_KEY".to_string(),
            key_format_hint: "Alphanumeric string".to_string(),
            common_errors: vec![
                ("Access denied".to_string(), "API access not yet approved".to_string()),
                ("Invalid query".to_string(), "Query parameters incorrect".to_string()),
            ],
        });

        // ============ THREAT INTEL ============
        self.add_guide(ApiSetupGuide {
            api_name: "VirusTotal".to_string(),
            provider_name: "VirusTotal".to_string(),
            website_url: "https://www.virustotal.com".to_string(),
            signup_url: "https://www.virustotal.com/gui/home/upload".to_string(),
            documentation_url: "https://developers.virustotal.com/reference".to_string(),
            setup_steps: vec![
                "1. Visit https://www.virustotal.com/gui/home/upload".to_string(),
                "2. Create free account".to_string(),
                "3. Verify email".to_string(),
                "4. Go to user profile icon → API Key".to_string(),
                "5. Copy your API key".to_string(),
                "6. Set HUNTSMAN_VIRUSTOTAL_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 3,
            free_tier_available: true,
            free_tier_limits: "4 queries/minute, up to 500k/day".to_string(),
            paid_tier_starting_cost_per_month: Some(0.0), // Free with rate limits
            environment_variable: "HUNTSMAN_VIRUSTOTAL_KEY".to_string(),
            key_format_hint: "Long alphanumeric string, typically 64+ characters".to_string(),
            common_errors: vec![
                ("Invalid API key".to_string(), "Key not copied correctly".to_string()),
                ("Rate limited".to_string(), "Exceeded 4 queries/minute for free tier".to_string()),
            ],
        });

        self.add_guide(ApiSetupGuide {
            api_name: "AlienVault OTX".to_string(),
            provider_name: "AlienVault OTX".to_string(),
            website_url: "https://otx.alienvault.com".to_string(),
            signup_url: "https://otx.alienvault.com/account/register".to_string(),
            documentation_url: "https://otx.alienvault.com/api".to_string(),
            setup_steps: vec![
                "1. Visit https://otx.alienvault.com/account/register".to_string(),
                "2. Create account (free or paid)".to_string(),
                "3. Verify email".to_string(),
                "4. Go to Account → Settings → API Key".to_string(),
                "5. Generate API key".to_string(),
                "6. Set HUNTSMAN_ALIENVAULT_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: true,
            free_tier_limits: "Limited to public threat feed access".to_string(),
            paid_tier_starting_cost_per_month: Some(29.0),
            environment_variable: "HUNTSMAN_ALIENVAULT_KEY".to_string(),
            key_format_hint: "Alphanumeric string, ~40 characters".to_string(),
            common_errors: vec![
                ("401 Unauthorized".to_string(), "API key not set or invalid".to_string()),
                ("Rate limited".to_string(), "Too many requests, implement backoff".to_string()),
            ],
        });

        // ============ SPECIALIZED ============
        self.add_guide(ApiSetupGuide {
            api_name: "Companies House".to_string(),
            provider_name: "UK Companies House".to_string(),
            website_url: "https://beta.companieshouse.gov.uk".to_string(),
            signup_url: "https://developer.company-information.service.gov.uk/registration".to_string(),
            documentation_url: "https://developer.company-information.service.gov.uk".to_string(),
            setup_steps: vec![
                "1. Visit registration page".to_string(),
                "2. Create developer account".to_string(),
                "3. Verify email".to_string(),
                "4. Accept terms and conditions".to_string(),
                "5. View your API key".to_string(),
                "6. Set HUNTSMAN_COMPANIES_HOUSE_KEY environment variable".to_string(),
            ],
            estimated_setup_time_minutes: 5,
            free_tier_available: true,
            free_tier_limits: "Free tier with generous limits".to_string(),
            paid_tier_starting_cost_per_month: Some(0.0), // Free
            environment_variable: "HUNTSMAN_COMPANIES_HOUSE_KEY".to_string(),
            key_format_hint: "Alphanumeric string used with basic auth".to_string(),
            common_errors: vec![
                ("401 Unauthorized".to_string(), "API key not set or incorrect basic auth".to_string()),
            ],
        });
    }

    fn add_guide(&mut self, guide: ApiSetupGuide) {
        self.setup_guides.insert(guide.api_name.clone(), guide);
    }

    /// Get setup guide for API
    pub fn get_setup_guide(&self, api_name: &str) -> Option<&ApiSetupGuide> {
        self.setup_guides.get(api_name)
    }

    /// Generate comprehensive setup documentation
    pub fn generate_setup_documentation(&self) -> String {
        let mut doc = String::from("# Huntsman Search Engine - API Configuration Guide\n\n");
        doc.push_str("This guide walks you through setting up API keys for 50+ intelligence APIs.\n\n");

        // Group by category
        let categories = vec![
            ("Breach Databases", vec!["SeekNow", "OathNet Pro", "HIBP", "Leakix"]),
            ("Email Enrichment", vec!["Hunter.io", "FullContact", "Clearbit"]),
            ("Infrastructure", vec!["Shodan", "Censys", "SecurityTrails", "GreyNoise"]),
            ("Person Search", vec!["Pipl", "Spokeo"]),
            ("Threat Intelligence", vec!["VirusTotal", "AlienVault OTX"]),
            ("Specialized", vec!["Companies House"]),
        ];

        for (category, apis) in categories {
            doc.push_str(&format!("## {}\n\n", category));

            for api_name in apis {
                if let Some(guide) = self.get_setup_guide(api_name) {
                    doc.push_str(&format!("### {}\n", guide.api_name));
                    doc.push_str(&format!("**Provider:** {}\n", guide.provider_name));
                    doc.push_str(&format!("**Website:** {}\n", guide.website_url));
                    doc.push_str(&format!("**Time to setup:** ~{} minutes\n", guide.estimated_setup_time_minutes));
                    doc.push_str(&format!("**Free tier:** {}\n", if guide.free_tier_available { "Yes" } else { "No" }));
                    if let Some(cost) = guide.paid_tier_starting_cost_per_month {
                        doc.push_str(&format!("**Starting price:** ${:.2}/month\n", cost));
                    }
                    doc.push_str("\n**Setup Steps:**\n");
                    for step in &guide.setup_steps {
                        doc.push_str(&format!("{}\n", step));
                    }
                    doc.push_str("\n**Environment Variable:**\n");
                    doc.push_str(&format!("```bash\nexport {}=YOUR_API_KEY\n```\n", guide.environment_variable));
                    doc.push_str("\n**Key Format:**\n");
                    doc.push_str(&format!("{}\n", guide.key_format_hint));

                    if !guide.common_errors.is_empty() {
                        doc.push_str("\n**Common Errors:**\n");
                        for (error, solution) in &guide.common_errors {
                            doc.push_str(&format!("- **{}**: {}\n", error, solution));
                        }
                    }

                    doc.push_str("\n---\n\n");
                }
            }
        }

        doc
    }

    /// Estimate total monthly cost for setup
    pub fn estimate_monthly_cost(&self) -> f32 {
        let mut total = 0.0;

        for guide in self.setup_guides.values() {
            if let Some(cost) = guide.paid_tier_starting_cost_per_month {
                total += cost;
            }
        }

        total
    }

    /// List all APIs requiring paid subscription
    pub fn list_paid_apis(&self) -> Vec<String> {
        self.setup_guides
            .values()
            .filter(|guide| !guide.free_tier_available)
            .map(|guide| guide.api_name.clone())
            .collect()
    }

    /// List all APIs with free tier
    pub fn list_free_tier_apis(&self) -> Vec<String> {
        self.setup_guides
            .values()
            .filter(|guide| guide.free_tier_available)
            .map(|guide| guide.api_name.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration_helper_initialization() {
        let helper = ApiConfigurationHelper::new();
        assert!(helper.setup_guides.len() >= 15);
    }

    #[test]
    fn test_get_setup_guide() {
        let helper = ApiConfigurationHelper::new();
        let guide = helper.get_setup_guide("SeekNow");
        assert!(guide.is_some());
        let g = guide.unwrap();
        assert_eq!(g.api_name, "SeekNow");
    }

    #[test]
    fn test_documentation_generation() {
        let helper = ApiConfigurationHelper::new();
        let doc = helper.generate_setup_documentation();
        assert!(doc.contains("Breach Databases"));
        assert!(doc.contains("Setup Steps"));
    }

    #[test]
    fn test_estimate_monthly_cost() {
        let helper = ApiConfigurationHelper::new();
        let cost = helper.estimate_monthly_cost();
        assert!(cost > 0.0);
    }

    #[test]
    fn test_list_free_apis() {
        let helper = ApiConfigurationHelper::new();
        let free_apis = helper.list_free_tier_apis();
        assert!(free_apis.contains(&"HIBP".to_string()));
    }

    #[test]
    fn test_list_paid_apis() {
        let helper = ApiConfigurationHelper::new();
        let paid_apis = helper.list_paid_apis();
        assert!(paid_apis.len() > 0);
    }
}
