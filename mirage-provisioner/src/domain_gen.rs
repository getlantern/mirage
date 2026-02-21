//! Domain name generation with legitimate-looking patterns.
//!
//! Generates domain names that blend in with real web infrastructure:
//! CDN subdomains, static asset hostnames, SaaS platforms, etc.

use rand::seq::SliceRandom;
use rand::Rng;

/// Patterns for generating plausible domain names.
const PREFIXES: &[&str] = &[
    "assets", "static", "cdn", "media", "img", "images", "files", "dl",
    "content", "res", "resources", "cache", "edge", "global", "api",
    "data", "app", "web", "cloud", "storage", "dist", "delivery",
];

const INFIXES: &[&str] = &[
    "prod", "live", "main", "core", "hub", "net", "sys", "fast",
    "next", "nova", "arc", "flux", "base", "link", "point", "zone",
];

const TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "dev", "app", "cloud",
    "tech", "site", "online", "info",
];

/// Generate a batch of plausible CDN-like domain names.
pub fn generate_candidates(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut results = Vec::with_capacity(count);

    for _ in 0..count {
        let pattern = rng.gen_range(0..5);
        let domain = match pattern {
            // Pattern 1: prefix-infix.tld  (e.g., cdn-prod.net)
            0 => {
                let prefix = PREFIXES.choose(&mut rng).unwrap();
                let infix = INFIXES.choose(&mut rng).unwrap();
                let tld = TLDS.choose(&mut rng).unwrap();
                format!("{}-{}.{}", prefix, infix, tld)
            }
            // Pattern 2: prefix.brand-suffix.tld  (e.g., assets.acmetech.com)
            1 => {
                let prefix = PREFIXES.choose(&mut rng).unwrap();
                let brand = generate_brand(&mut rng);
                let tld = TLDS.choose(&mut rng).unwrap();
                format!("{}.{}.{}", prefix, brand, tld)
            }
            // Pattern 3: prefix123.tld  (e.g., cdn42.net)
            2 => {
                let prefix = PREFIXES.choose(&mut rng).unwrap();
                let num: u32 = rng.gen_range(1..999);
                let tld = TLDS.choose(&mut rng).unwrap();
                format!("{}{}.{}", prefix, num, tld)
            }
            // Pattern 4: brand-prefix.tld  (e.g., acme-cdn.com)
            3 => {
                let brand = generate_brand(&mut rng);
                let prefix = PREFIXES.choose(&mut rng).unwrap();
                let tld = TLDS.choose(&mut rng).unwrap();
                format!("{}-{}.{}", brand, prefix, tld)
            }
            // Pattern 5: infix-prefix-region.tld  (e.g., fast-cdn-us.net)
            _ => {
                let infix = INFIXES.choose(&mut rng).unwrap();
                let prefix = PREFIXES.choose(&mut rng).unwrap();
                let region = ["us", "eu", "ap", "na", "sa"].choose(&mut rng).unwrap();
                let tld = TLDS.choose(&mut rng).unwrap();
                format!("{}-{}-{}.{}", infix, prefix, region, tld)
            }
        };

        results.push(domain);
    }

    results
}

/// Generate a plausible brand/company name fragment.
fn generate_brand(rng: &mut impl Rng) -> String {
    const SYLLABLES: &[&str] = &[
        "ace", "arc", "bit", "byte", "core", "data", "edge", "flux",
        "gate", "hub", "ion", "jet", "key", "link", "max", "net",
        "orb", "peak", "quest", "ray", "sync", "tech", "ultra", "vex",
        "wave", "xen", "zen",
    ];

    let n = rng.gen_range(2..=3);
    let mut name = String::new();
    for _ in 0..n {
        name.push_str(SYLLABLES.choose(rng).unwrap());
    }
    name
}
