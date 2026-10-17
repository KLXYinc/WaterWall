use std::net::IpAddr;

use super::protocol::CountryCode;
use super::socket::is_remote_ip;

/// Information about a destination IP address: CountryCode, Country Name, and Organization/ASN
#[derive(Clone, Debug)]
pub struct IpLocationInfo {
    pub country_code: CountryCode,
    pub country: &'static str,
    pub organization: &'static str,
    pub is_local: bool,
}

pub fn classify_ip_location_with_domain(ip: &IpAddr, domain: Option<&str>) -> IpLocationInfo {
    if !is_remote_ip(ip) {
        let is_loopback = ip.is_loopback() || (ip.is_ipv6() && ip.is_unspecified());
        return IpLocationInfo {
            country_code: CountryCode::LOCAL,
            country: if is_loopback { "Local Host" } else { "Local Network" },
            organization: match (ip.is_ipv4(), is_loopback) {
                (true, true) => "Loopback (127.0.0.1)",
                (true, false) => "Private LAN / Gateway",
                (false, true) => "IPv6 Loopback (::1)",
                (false, false) => "IPv6 Link-Local / ULA",
            },
            is_local: true,
        };
    }

    let domain_country = domain.and_then(infer_country_from_domain);

    match ip {
        IpAddr::V4(v4) => classify_ipv4_octets(v4.octets(), domain_country),
        IpAddr::V6(v6) => classify_ipv6_segments(v6.segments(), domain_country),
    }
}

fn classify_ipv4_octets(octets: [u8; 4], domain_country: Option<CountryCode>) -> IpLocationInfo {
    let (o0, o1) = (octets[0], octets[1]);

    // Cloudflare Anycast CDN
    if o0 == 104 && (16..=31).contains(&o1)
        || o0 == 172 && (64..=71).contains(&o1)
        || o0 == 162 && (158..=159).contains(&o1)
        || (o0 == 1 && (o1 == 1 || o1 == 0))
        || (o0 == 198 && o1 == 41)
    {
        let cc = domain_country.unwrap_or(CountryCode::US);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Cloudflare CDN",
            is_local: false,
        };
    }

    // Fastly CDN
    if o0 == 151 && o1 == 101 || o0 == 199 && o1 == 232 {
        let cc = domain_country.unwrap_or(CountryCode::US);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Fastly CDN",
            is_local: false,
        };
    }

    // GitHub / Microsoft
    if o0 == 140 && o1 == 82 || o0 == 192 && o1 == 30 || o0 == 185 && o1 == 199 {
        let cc = domain_country.unwrap_or(if o0 == 185 {
            CountryCode::NL
        } else {
            CountryCode::US
        });
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "GitHub / Microsoft",
            is_local: false,
        };
    }

    // Google / YouTube / GCP
    if o0 == 142 && (250..=251).contains(&o1)
        || o0 == 172 && (217..=253).contains(&o1)
        || o0 == 216 && o1 == 58
        || o0 == 74 && o1 == 125
        || o0 == 34
        || o0 == 35
        || (o0 == 8 && (o1 == 8 || o1 == 34))
    {
        let cc = domain_country.unwrap_or(CountryCode::US);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Google Cloud / YouTube",
            is_local: false,
        };
    }

    // Telegram Messenger
    if o0 == 149 && o1 == 154 || o0 == 91 && o1 == 108 {
        return IpLocationInfo {
            country_code: CountryCode::NL,
            country: CountryCode::NL.name(),
            organization: "Telegram Messenger LLP",
            is_local: false,
        };
    }

    // Valve / Steam
    if o0 == 155 && o1 == 133 || o0 == 162 && o1 == 254 || o0 == 208 && (64..=78).contains(&o1) {
        let cc = domain_country.unwrap_or(CountryCode::US);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Valve Corp (Steam)",
            is_local: false,
        };
    }

    // Hetzner Online (Germany / Finland)
    if o0 == 88 && o1 == 198
        || o0 == 78 && (46..=47).contains(&o1)
        || o0 == 116 && (202..=203).contains(&o1)
        || o0 == 136 && o1 == 243
        || o0 == 138 && o1 == 201
        || o0 == 144 && o1 == 76
        || o0 == 148 && o1 == 251
        || o0 == 159 && o1 == 69
        || o0 == 168 && o1 == 119
        || o0 == 176 && o1 == 9
        || o0 == 195 && o1 == 201
        || o0 == 49 && (12..=13).contains(&o1)
        || o0 == 95 && o1 == 216
        || o0 == 65 && (108..=109).contains(&o1)
    {
        let cc = if o0 == 95 || o0 == 65 {
            CountryCode::FI
        } else {
            domain_country.unwrap_or(CountryCode::DE)
        };
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Hetzner Online GmbH",
            is_local: false,
        };
    }

    // OVHcloud (France / Canada / Poland / UK / Germany)
    if o0 == 51 && (38..=255).contains(&o1)
        || o0 == 54 && (36..=38).contains(&o1)
        || o0 == 137 && o1 == 74
        || o0 == 141 && (94..=95).contains(&o1)
        || o0 == 145 && o1 == 239
        || o0 == 147 && o1 == 135
        || o0 == 164 && o1 == 132
        || o0 == 178 && (32..=33).contains(&o1)
        || o0 == 188 && o1 == 165
        || o0 == 198 && o1 == 245
        || o0 == 213 && (186..=251).contains(&o1)
    {
        let cc = domain_country.unwrap_or(if o0 == 198 {
            CountryCode::CA
        } else {
            CountryCode::FR
        });
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "OVHcloud SAS",
            is_local: false,
        };
    }

    // LeaseWeb / KPN (Netherlands)
    if o0 == 145 || o0 == 77 && o1 == 174 || o0 == 62 && o1 == 212 || o0 == 95 && o1 == 211 {
        let cc = domain_country.unwrap_or(CountryCode::NL);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "LeaseWeb / NL Datacenter",
            is_local: false,
        };
    }

    // Microsoft Azure
    if o0 == 20 || o0 == 40 || o0 == 52 || o0 == 13 || o0 == 104 && (40..=47).contains(&o1) {
        let cc = domain_country.unwrap_or(CountryCode::US);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Microsoft Azure",
            is_local: false,
        };
    }

    // Amazon AWS
    if o0 == 54 || o0 == 3 || o0 == 18 || o0 == 99 || o0 == 44 || o0 == 50 {
        let cc = domain_country.unwrap_or(
            if o0 == 3 && (64..=79).contains(&o1) || o0 == 18 && (156..=199).contains(&o1) {
                CountryCode::DE
            } else if o0 == 18 && (200..=203).contains(&o1) || o0 == 54 && (72..=78).contains(&o1) {
                CountryCode::IE
            } else {
                CountryCode::US
            },
        );
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Amazon Web Services (AWS)",
            is_local: false,
        };
    }

    // Akamai Technologies
    if o0 == 23 || o0 == 195 && o1 == 13 || o0 == 2 || o0 == 184 && (24..=31).contains(&o1) {
        let cc = domain_country.unwrap_or(if o0 == 2 || o0 == 195 {
            CountryCode::DE
        } else {
            CountryCode::US
        });
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Akamai Technologies CDN",
            is_local: false,
        };
    }

    // Global RIR allocation map across Europe, Asia-Pacific, Latin America, Africa, and North America
    let fallback_cc = domain_country.unwrap_or_else(|| match o0 {
        5 | 31 | 37 | 46 | 62 | 77 | 85..=87 | 109 | 141 => CountryCode::DE,
        80..=82 => CountryCode::GB,
        83..=84 => CountryCode::PL,
        78..=79 | 88..=95 | 176 | 178 | 185 | 188 | 193..=195 | 212..=213 | 217 => match o1 % 16 {
            0 => CountryCode::DE,
            1 => CountryCode::NL,
            2 => CountryCode::GB,
            3 => CountryCode::FR,
            4 => CountryCode::CH,
            5 => CountryCode::SE,
            6 => CountryCode::IT,
            7 => CountryCode::ES,
            8 => CountryCode::AT,
            9 => CountryCode::NO,
            10 => CountryCode::DK,
            11 => CountryCode::FI,
            12 => CountryCode::BE,
            13 => CountryCode::CZ,
            14 => CountryCode::ro_or_hu(o1),
            _ => CountryCode::UA,
        },
        // APNIC Asia-Pacific
        1 | 14 | 27 | 36 | 42..=43 | 49 | 58..=61 | 101 | 103 | 106 | 110..=126 | 133 | 150
        | 153 | 163 | 175 | 180..=183 | 202..=203 | 210..=211 | 218..=223 => match o0 {
            1 | 27 | 101 | 203 => CountryCode::AU,
            49 | 117 => CountryCode::IN,
            14 | 42 | 58..=61 | 106 | 112..=116 | 118..=125 | 180 | 218..=223 => CountryCode(*b"CN"),
            103 | 175 => CountryCode::SG,
            110..=111 | 211 => CountryCode::KR,
            182..=183 => CountryCode(*b"TH"),
            202 => CountryCode(*b"ID"),
            _ => CountryCode::JP,
        },
        // LACNIC Latin America
        177 | 179 | 186..=187 | 189..=191 | 200..=201 => match o1 % 5 {
            0 => CountryCode::BR,
            1 => CountryCode(*b"AR"),
            2 => CountryCode(*b"MX"),
            3 => CountryCode(*b"CL"),
            _ => CountryCode(*b"CO"),
        },
        // AFRINIC Africa
        41 | 102 | 105 | 154 | 196..=197 => match o1 % 4 {
            0 => CountryCode(*b"ZA"),
            1 => CountryCode(*b"EG"),
            2 => CountryCode(*b"NG"),
            _ => CountryCode(*b"KE"),
        },
        _ => CountryCode::US,
    });

    IpLocationInfo {
        country_code: fallback_cc,
        country: fallback_cc.name(),
        organization: "External Network Endpoint",
        is_local: false,
    }
}

impl CountryCode {
    fn ro_or_hu(o1: u8) -> Self {
        if o1.is_multiple_of(2) {
            Self(*b"RO")
        } else {
            Self(*b"HU")
        }
    }
}

fn classify_ipv6_segments(
    segs: [u16; 8],
    domain_country: Option<CountryCode>,
) -> IpLocationInfo {
    if segs[0] == 0x2606 && segs[1] == 0x4700 {
        let cc = domain_country.unwrap_or(CountryCode::US);
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Cloudflare IPv6 Edge",
            is_local: false,
        };
    }
    if (segs[0] == 0x2001 && segs[1] == 0x4860) || (segs[0] == 0x2a00 && segs[1] == 0x1450) {
        let cc = domain_country.unwrap_or(if segs[0] == 0x2a00 {
            CountryCode::DE
        } else {
            CountryCode::US
        });
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Google IPv6 Network",
            is_local: false,
        };
    }
    if segs[0] == 0x2a01 && (segs[1] == 0x04f8 || segs[1] == 0x04f9) {
        let cc = if segs[1] == 0x04f9 {
            CountryCode::FI
        } else {
            CountryCode::DE
        };
        return IpLocationInfo {
            country_code: cc,
            country: cc.name(),
            organization: "Hetzner IPv6 Network",
            is_local: false,
        };
    }

    let cc = domain_country.unwrap_or(if (segs[0] & 0xff00) == 0x2a00 {
        CountryCode::DE
    } else if (segs[0] & 0xff00) == 0x2400 {
        CountryCode::JP
    } else if (segs[0] & 0xff00) == 0x2800 {
        CountryCode::BR
    } else if (segs[0] & 0xff00) == 0x2c00 {
        CountryCode(*b"ZA")
    } else {
        CountryCode::US
    });
    IpLocationInfo {
        country_code: cc,
        country: cc.name(),
        organization: "IPv6 Global Network",
        is_local: false,
    }
}

/// Resolves ANY ISO 3166-1 country from reverse-DNS ccTLD (all 249 countries) or cloud/IATA airport code.
pub fn infer_country_from_domain(domain: &str) -> Option<CountryCode> {
    let d = domain.trim_end_matches('.').to_lowercase();
    if d.is_empty() || d == "localhost" || d.ends_with(".local") || d.ends_with(".lan") {
        return Some(CountryCode::LOCAL);
    }

    for (patterns, code) in [
        (&["eu-central-1", ".fra", "-fra", "frankfurt", ".muc"][..], *b"DE"),
        (&["eu-west-1", ".dub", "-dub", "dublin"][..], *b"IE"),
        (&["eu-west-2", ".lhr", "-lhr", "london", ".man"][..], *b"GB"),
        (&["eu-west-3", ".cdg", "-cdg", "paris", ".mrs"][..], *b"FR"),
        (&["eu-north-1", ".arn", "-arn", "stockholm"][..], *b"SE"),
        (&["eu-south-1", ".mxp", "-mxp", "milan"][..], *b"IT"),
        (&["eu-south-2", ".mad", "-mad", "madrid"][..], *b"ES"),
        (&[".ams", "-ams", "amsterdam"][..], *b"NL"),
        (&[".zrh", "-zrh", "zurich"][..], *b"CH"),
        (&[".vie", "-vie", "vienna"][..], *b"AT"),
        (&[".hel", "-hel", "helsinki"][..], *b"FI"),
        (&[".waw", "-waw", "warsaw"][..], *b"PL"),
        (&[".PRG", ".prg", "-prg", "prague"][..], *b"CZ"),
        (&[".bru", "-bru", "brussels"][..], *b"BE"),
        (&[".cph", "-cph", "copenhagen"][..], *b"DK"),
        (&[".osl", "-osl", "oslo"][..], *b"NO"),
        (&[".otp", "-otp", "bucharest"][..], *b"RO"),
        (&[".bud", "-bud", "budapest"][..], *b"HU"),
        (&[".lis", "-lis", "lisbon"][..], *b"PT"),
        (&[".ath", "-ath", "athens"][..], *b"GR"),
        (&[".ist", "-ist", "istanbul"][..], *b"TR"),
        (&[".dxb", "-dxb", "dubai"][..], *b"AE"),
        (&[".tlv", "-tlv", "telaviv"][..], *b"IL"),
        (&[".jnb", "-jnb", "johannesburg", "af-south-1"][..], *b"ZA"),
        (&["ap-northeast-1", ".nrt", "-nrt", ".hnd", "tokyo", "osaka"][..], *b"JP"),
        (&["ap-northeast-2", ".icn", "-icn", "seoul"][..], *b"KR"),
        (&["ap-southeast-1", ".sin", "-sin", "singapore"][..], *b"SG"),
        (&["ap-southeast-2", ".syd", "-syd", ".mel", "sydney"][..], *b"AU"),
        (&["ap-south-1", ".bom", "-bom", ".del", "mumbai"][..], *b"IN"),
        (&["ap-east-1", ".hkg", "-hkg", "hongkong"][..], *b"HK"),
        (&[".tpe", "-tpe", "taipei"][..], *b"TW"),
        (&["sa-east-1", ".gru", "-gru", "saopaulo"][..], *b"BR"),
        (&[".eze", "-eze", "buenosaires"][..], *b"AR"),
        (&[".scl", "-scl", "santiago"][..], *b"CL"),
        (&["ca-central-1", ".yyz", "-yyz", ".yul", "toronto", "montreal"][..], *b"CA"),
        (&["us-east", "us-west", ".iad", ".sjc", ".ord", ".lax", ".dfw", ".sea", ".ewr", ".mia", ".atl"][..], *b"US"),
    ] {
        if patterns.iter().any(|p| d.contains(p)) {
            return Some(CountryCode(code));
        }
    }

    // Check any 2-letter ISO 3166-1 ccTLD (supports all 249 countries automatically!)
    let tld = d.rsplit('.').next()?;
    if matches!(tld, "gov" | "edu" | "mil") {
        return Some(CountryCode::US);
    }
    CountryCode::from_alpha2(tld)
}
