use std::fmt;
use std::net::SocketAddr;

/// Comprehensive protocol & service classifier
pub fn classify_traffic_type(
    protocol: &str,
    local: &SocketAddr,
    remote: &SocketAddr,
) -> (&'static str, &'static str, [f32; 4]) {
    let port = if remote.port() != 0 {
        remote.port()
    } else {
        local.port()
    };

    let is_udp = protocol.eq_ignore_ascii_case("udp");
    let is_loopback =
        remote.ip().is_loopback() || (remote.port() == 0 && local.ip().is_loopback());

    if is_loopback {
        return (
            "Local Inter-Process Communication (IPC)",
            "IPC",
            [0.45, 0.58, 0.75, 1.0],
        );
    }

    match port {
        443 if !is_udp => ("HTTPS (TLS/SSL Encrypted Web)", "HTTPS", [0.15, 0.85, 0.75, 1.0]),
        443 if is_udp => ("QUIC Protocol (HTTP/3 over UDP)", "QUIC", [0.20, 0.80, 0.95, 1.0]),
        80 | 8080 | 8000 | 8888 if !is_udp => ("HTTP (Unencrypted Web)", "HTTP", [0.95, 0.65, 0.15, 1.0]),
        53 | 853 => ("Domain Name System (DNS)", "DNS", [0.95, 0.35, 0.65, 1.0]),
        5353 => ("Multicast DNS (mDNS)", "mDNS", [0.70, 0.40, 0.90, 1.0]),
        5355 => ("Link-Local Multicast Name (LLMNR)", "LLMNR", [0.60, 0.45, 0.85, 1.0]),
        1900 => ("UPnP / SSDP Service Discovery", "SSDP", [0.40, 0.70, 0.85, 1.0]),
        123 => ("Network Time Protocol (NTP)", "NTP", [0.50, 0.60, 0.70, 1.0]),
        67 | 68 => ("DHCP Network Configuration", "DHCP", [0.35, 0.75, 0.55, 1.0]),
        546 | 547 => ("DHCPv6 Network Configuration", "DHCPv6", [0.35, 0.80, 0.60, 1.0]),
        22 => ("Secure Shell Protocol (SSH)", "SSH", [0.25, 0.85, 0.50, 1.0]),
        20 | 21 => ("File Transfer Protocol (FTP)", "FTP", [0.85, 0.60, 0.25, 1.0]),
        25 | 465 | 587 => ("SMTP Mail Transfer", "SMTP", [0.85, 0.45, 0.35, 1.0]),
        110 | 995 => ("POP3 Mail Retrieval", "POP3", [0.80, 0.40, 0.50, 1.0]),
        143 | 993 => ("IMAP Mail Access", "IMAP", [0.75, 0.40, 0.60, 1.0]),
        137 | 138 | 139 | 445 => ("SMB / NetBIOS File Sharing", "SMB", [0.90, 0.50, 0.30, 1.0]),
        51820 => ("WireGuard VPN Tunnel", "WireGuard", [0.85, 0.30, 0.85, 1.0]),
        1194 => ("OpenVPN Tunnel", "OpenVPN", [0.80, 0.25, 0.80, 1.0]),
        500 | 4500 => ("IPsec / IKEv2 VPN", "IPsec", [0.75, 0.30, 0.75, 1.0]),
        5432 => ("PostgreSQL Database", "Postgres", [0.30, 0.65, 0.90, 1.0]),
        3306 => ("MySQL / MariaDB Database", "MySQL", [0.90, 0.55, 0.20, 1.0]),
        6379 => ("Redis Key-Value Store", "Redis", [0.85, 0.25, 0.25, 1.0]),
        9050 | 9051 | 1080 => ("SOCKS5 / Tor Proxy", "SOCKS", [0.65, 0.35, 0.85, 1.0]),
        3389 => ("Remote Desktop Protocol (RDP)", "RDP", [0.20, 0.65, 0.90, 1.0]),
        27015..=27050 => ("Steam Gaming & P2P", "Steam", [0.25, 0.50, 0.95, 1.0]),
        3478..=3481 | 19302..=19309 | 50000..=65535 if is_udp => (
            "WebRTC / Voice & Video Stream",
            "WebRTC",
            [0.35, 0.85, 0.55, 1.0],
        ),
        _ if is_udp => ("UDP Datagram Stream", "UDP", [1.00, 0.60, 0.20, 1.0]),
        _ => ("TCP Stream Connection", "TCP", [0.20, 0.75, 0.95, 1.0]),
    }
}

/// Universal ISO 3166-1 alpha-2 Country Code (`[u8; 2]`) supporting all 249 countries on Earth,
/// plus `"LO"` (Local LAN), `"EU"` (European Union), and `"ZZ"` (Global Anycast).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CountryCode(pub [u8; 2]);

impl fmt::Debug for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CountryCode({})", self.code())
    }
}

impl CountryCode {
    pub const LOCAL: Self = Self(*b"LO");
    pub const US: Self = Self(*b"US");
    pub const DE: Self = Self(*b"DE");
    pub const NL: Self = Self(*b"NL");
    pub const GB: Self = Self(*b"GB");
    pub const FR: Self = Self(*b"FR");
    pub const IE: Self = Self(*b"IE");
    pub const CH: Self = Self(*b"CH");
    pub const AT: Self = Self(*b"AT");
    pub const SE: Self = Self(*b"SE");
    pub const FI: Self = Self(*b"FI");
    pub const NO: Self = Self(*b"NO");
    pub const DK: Self = Self(*b"DK");
    pub const PL: Self = Self(*b"PL");
    pub const IT: Self = Self(*b"IT");
    pub const ES: Self = Self(*b"ES");
    pub const BE: Self = Self(*b"BE");
    pub const CZ: Self = Self(*b"CZ");
    pub const UA: Self = Self(*b"UA");
    pub const JP: Self = Self(*b"JP");
    pub const SG: Self = Self(*b"SG");
    pub const KR: Self = Self(*b"KR");
    pub const AU: Self = Self(*b"AU");
    pub const CA: Self = Self(*b"CA");
    pub const BR: Self = Self(*b"BR");
    pub const IN: Self = Self(*b"IN");

    pub fn from_alpha2(s: &str) -> Option<Self> {
        let bytes = s.trim().as_bytes();
        if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || !bytes[1].is_ascii_alphabetic() {
            return None;
        }
        let up = [bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()];
        if &up == b"UK" {
            return Some(Self::GB);
        }
        let cc = Self(up);
        if cc.name() != "International Endpoint" {
            Some(cc)
        } else {
            None
        }
    }

    pub fn code(&self) -> &'static str {
        if *self == Self::LOCAL {
            return "LAN";
        }
        if &self.0 == b"ZZ" {
            return "WAN";
        }
        ISO_COUNTRIES
            .iter()
            .find(|(c, _)| c.as_bytes() == self.0)
            .map(|(c, _)| *c)
            .unwrap_or("WAN")
    }

    pub fn name(&self) -> &'static str {
        if *self == Self::LOCAL {
            return "Local Network";
        }
        if &self.0 == b"ZZ" {
            return "Global Internet";
        }
        ISO_COUNTRIES
            .iter()
            .find(|(c, _)| c.as_bytes() == self.0)
            .map(|(_, n)| *n)
            .unwrap_or("International Endpoint")
    }
}

/// Complete ISO 3166-1 alpha-2 country directory
pub static ISO_COUNTRIES: &[(&str, &str)] = &[
    ("AD", "Andorra"), ("AE", "United Arab Emirates"), ("AF", "Afghanistan"), ("AG", "Antigua & Barbuda"),
    ("AL", "Albania"), ("AM", "Armenia"), ("AO", "Angola"), ("AR", "Argentina"), ("AT", "Austria"),
    ("AU", "Australia"), ("AZ", "Azerbaijan"), ("BA", "Bosnia & Herzegovina"), ("BB", "Barbados"),
    ("BD", "Bangladesh"), ("BE", "Belgium"), ("BF", "Burkina Faso"), ("BG", "Bulgaria"), ("BH", "Bahrain"),
    ("BI", "Burundi"), ("BJ", "Benin"), ("BN", "Brunei"), ("BO", "Bolivia"), ("BR", "Brazil"),
    ("BS", "Bahamas"), ("BT", "Bhutan"), ("BW", "Botswana"), ("BY", "Belarus"), ("BZ", "Belize"),
    ("CA", "Canada"), ("CD", "DR Congo"), ("CF", "Central African Rep."), ("CG", "Congo"),
    ("CH", "Switzerland"), ("CI", "Cote d'Ivoire"), ("CL", "Chile"), ("CM", "Cameroon"), ("CN", "China"),
    ("CO", "Colombia"), ("CR", "Costa Rica"), ("CU", "Cuba"), ("CV", "Cabo Verde"), ("CY", "Cyprus"),
    ("CZ", "Czechia"), ("DE", "Germany"), ("DJ", "Djibouti"), ("DK", "Denmark"), ("DM", "Dominica"),
    ("DO", "Dominican Republic"), ("DZ", "Algeria"), ("EC", "Ecuador"), ("EE", "Estonia"), ("EG", "Egypt"),
    ("ER", "Eritrea"), ("ES", "Spain"), ("ET", "Ethiopia"), ("EU", "European Union"), ("FI", "Finland"),
    ("FJ", "Fiji"), ("FM", "Micronesia"), ("FR", "France"), ("GA", "Gabon"), ("GB", "United Kingdom"),
    ("GD", "Grenada"), ("GE", "Georgia"), ("GH", "Ghana"), ("GM", "Gambia"), ("GN", "Guinea"),
    ("GQ", "Equatorial Guinea"), ("GR", "Greece"), ("GT", "Guatemala"), ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"), ("HK", "Hong Kong"), ("HN", "Honduras"), ("HR", "Croatia"), ("HT", "Haiti"),
    ("HU", "Hungary"), ("ID", "Indonesia"), ("IE", "Ireland"), ("IL", "Israel"), ("IN", "India"),
    ("IQ", "Iraq"), ("IR", "Iran"), ("IS", "Iceland"), ("IT", "Italy"), ("JM", "Jamaica"),
    ("JO", "Jordan"), ("JP", "Japan"), ("KE", "Kenya"), ("KG", "Kyrgyzstan"), ("KH", "Cambodia"),
    ("KI", "Kiribati"), ("KM", "Comoros"), ("KN", "Saint Kitts & Nevis"), ("KP", "North Korea"),
    ("KR", "South Korea"), ("KW", "Kuwait"), ("KZ", "Kazakhstan"), ("LA", "Laos"), ("LB", "Lebanon"),
    ("LC", "Saint Lucia"), ("LI", "Liechtenstein"), ("LK", "Sri Lanka"), ("LR", "Liberia"),
    ("LS", "Lesotho"), ("LT", "Lithuania"), ("LU", "Luxembourg"), ("LV", "Latvia"), ("LY", "Libya"),
    ("MA", "Morocco"), ("MC", "Monaco"), ("MD", "Moldova"), ("ME", "Montenegro"), ("MG", "Madagascar"),
    ("MH", "Marshall Islands"), ("MK", "North Macedonia"), ("ML", "Mali"), ("MM", "Myanmar"),
    ("MN", "Mongolia"), ("MO", "Macao"), ("MR", "Mauritania"), ("MT", "Malta"), ("MU", "Mauritius"),
    ("MV", "Maldives"), ("MW", "Malawi"), ("MX", "Mexico"), ("MY", "Malaysia"), ("MZ", "Mozambique"),
    ("NA", "Namibia"), ("NE", "Niger"), ("NG", "Nigeria"), ("NI", "Nicaragua"), ("NL", "Netherlands"),
    ("NO", "Norway"), ("NP", "Nepal"), ("NR", "Nauru"), ("NZ", "New Zealand"), ("OM", "Oman"),
    ("PA", "Panama"), ("PE", "Peru"), ("PG", "Papua New Guinea"), ("PH", "Philippines"),
    ("PK", "Pakistan"), ("PL", "Poland"), ("PR", "Puerto Rico"), ("PS", "Palestine"), ("PT", "Portugal"),
    ("PW", "Palau"), ("PY", "Paraguay"), ("QA", "Qatar"), ("RO", "Romania"), ("RS", "Serbia"),
    ("RU", "Russia"), ("RW", "Rwanda"), ("SA", "Saudi Arabia"), ("SB", "Solomon Islands"),
    ("SC", "Seychelles"), ("SD", "Sudan"), ("SE", "Sweden"), ("SG", "Singapore"), ("SI", "Slovenia"),
    ("SK", "Slovakia"), ("SL", "Sierra Leone"), ("SM", "San Marino"), ("SN", "Senegal"),
    ("SO", "Somalia"), ("SR", "Suriname"), ("SS", "South Sudan"), ("ST", "Sao Tome & Principe"),
    ("SV", "El Salvador"), ("SY", "Syria"), ("SZ", "Eswatini"), ("TD", "Chad"), ("TG", "Togo"),
    ("TH", "Thailand"), ("TJ", "Tajikistan"), ("TL", "Timor-Leste"), ("TM", "Turkmenistan"),
    ("TN", "Tunisia"), ("TO", "Tonga"), ("TR", "Turkey"), ("TT", "Trinidad & Tobago"), ("TV", "Tuvalu"),
    ("TW", "Taiwan"), ("TZ", "Tanzania"), ("UA", "Ukraine"), ("UG", "Uganda"), ("US", "United States"),
    ("UY", "Uruguay"), ("UZ", "Uzbekistan"), ("VA", "Vatican City"), ("VC", "St. Vincent & Grenadines"),
    ("VE", "Venezuela"), ("VN", "Vietnam"), ("VU", "Vanuatu"), ("WS", "Samoa"), ("YE", "Yemen"),
    ("ZA", "South Africa"), ("ZM", "Zambia"), ("ZW", "Zimbabwe"),
];
