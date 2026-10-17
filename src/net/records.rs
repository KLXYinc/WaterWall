use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use super::dns::DnsEvent;
use super::geoip::{classify_ip_location_with_domain, IpLocationInfo};
use super::protocol::{classify_traffic_type, CountryCode};
use super::scanner::VpnInterfaceInfo;
use super::socket::{is_remote_ip, AppNetworkInfo, SocketState};

pub const HISTORY_LEN: usize = 60;
pub const MAX_SECURITY_ALERTS: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertKind {
    FirstAppActivity,
    NewCountryEndpoint,
    HighBandwidthSpike,
}

impl AlertKind {
    pub fn badge(self) -> (&'static str, [f32; 4]) {
        match self {
            AlertKind::FirstAppActivity => ("FIRST SEEN", [0.15, 0.88, 0.68, 1.0]),
            AlertKind::NewCountryEndpoint => ("NEW COUNTRY", [0.22, 0.78, 0.98, 1.0]),
            AlertKind::HighBandwidthSpike => ("TRAFFIC SPIKE", [0.98, 0.76, 0.18, 1.0]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SecurityAlert {
    pub id: u64,
    pub kind: AlertKind,
    pub app_name: String,
    pub detail: String,
    pub country: Option<CountryCode>,
    pub age_secs: u64,
    pub created_at: Instant,
}

/// Shared per-application byte & socket counters used by both `HostRecord` and `ProtocolRecord`
#[derive(Clone, Debug, Default)]
pub struct EndpointTrafficStats {
    pub total_bytes: u64,
    pub app_bytes: HashMap<String, u64>,
    pub active_sockets: usize,
    pub app_sockets: HashMap<String, usize>,
    pub app_names: Vec<String>,
}

impl EndpointTrafficStats {
    pub fn new(initial_bytes: u64) -> Self {
        Self {
            total_bytes: initial_bytes,
            ..Self::default()
        }
    }

    pub fn reset_sockets(&mut self) {
        self.active_sockets = 0;
        self.app_sockets.clear();
    }

    pub fn record_sample(&mut self, app_key_lower: &str, app_name: &str, byte_inc: u64) {
        self.active_sockets += 1;
        *self.app_sockets.entry(app_key_lower.to_string()).or_insert(0) += 1;
        self.total_bytes = self.total_bytes.saturating_add(byte_inc);
        let entry = self.app_bytes.entry(app_key_lower.to_string()).or_insert(2048);
        *entry = entry.saturating_add(byte_inc);
        if !self.app_names.iter().any(|n| n.eq_ignore_ascii_case(app_name)) {
            self.app_names.push(app_name.to_string());
        }
    }

    pub fn bytes_for_app(&self, app_filter: Option<&str>) -> u64 {
        match app_filter {
            Some(app) => self.app_bytes.get(&app.to_lowercase()).copied().unwrap_or(0),
            None => self.total_bytes,
        }
    }

    pub fn sockets_for_app(&self, app_filter: Option<&str>) -> usize {
        match app_filter {
            Some(app) => self.app_sockets.get(&app.to_lowercase()).copied().unwrap_or(0),
            None => self.active_sockets,
        }
    }

    pub fn matches_app(&self, app_filter: Option<&str>) -> bool {
        match app_filter {
            Some(app) => self.app_bytes.contains_key(&app.to_lowercase()),
            None => true,
        }
    }
}

/// Persistent record for a remote or local Host/IP endpoint across sampling ticks.
#[derive(Clone, Debug)]
pub struct HostRecord {
    pub key: String,
    pub display_title: String,
    pub ip: IpAddr,
    pub port: u16,
    pub ip_port_str: String,
    pub domain: Option<String>,
    pub country_code: CountryCode,
    pub country: &'static str,
    pub organization: &'static str,
    pub is_local: bool,
    pub is_listen: bool,
    pub stats: EndpointTrafficStats,
    pub protocols: Vec<&'static str>,
    pub first_seen_id: u64,
}

impl HostRecord {
    pub fn bytes_for_app(&self, app_filter: Option<&str>) -> u64 {
        self.stats.bytes_for_app(app_filter)
    }

    pub fn sockets_for_app(&self, app_filter: Option<&str>) -> usize {
        self.stats.sockets_for_app(app_filter)
    }

    pub fn matches_app(&self, app_filter: Option<&str>) -> bool {
        self.stats.matches_app(app_filter)
    }
}

/// Persistent record for a classified Protocol / Traffic Type across sampling ticks.
#[derive(Clone, Debug)]
pub struct ProtocolRecord {
    pub code: &'static str,
    pub full_desc: &'static str,
    pub color: [f32; 4],
    pub is_local: bool,
    pub stats: EndpointTrafficStats,
    pub ports: Vec<u16>,
    pub first_seen_id: u64,
}

impl ProtocolRecord {
    pub fn bytes_for_app(&self, app_filter: Option<&str>) -> u64 {
        self.stats.bytes_for_app(app_filter)
    }

    pub fn sockets_for_app(&self, app_filter: Option<&str>) -> usize {
        self.stats.sockets_for_app(app_filter)
    }

    pub fn matches_app(&self, app_filter: Option<&str>) -> bool {
        self.stats.matches_app(app_filter)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkSnapshot {
    pub apps: Vec<AppNetworkInfo>,
    pub hosts: Vec<HostRecord>,
    pub protocols: Vec<ProtocolRecord>,
    pub dns_events: Vec<DnsEvent>,
    pub alerts: Vec<SecurityAlert>,
    pub vpn_interfaces: Vec<VpnInterfaceInfo>,
    pub system_download_speed: f64,
    pub system_upload_speed: f64,
    pub session_total_download: u64,
    pub session_total_upload: u64,
    pub session_wan_bytes: u64,
    pub session_lan_bytes: u64,
    pub total_active_connections: usize,
    pub total_sockets_count: usize,
    pub download_history: Vec<f32>,
    pub upload_history: Vec<f32>,
    pub last_updated: Option<Instant>,
}

#[derive(Default)]
pub struct PersistentSessionState {
    pub next_id: u64,
    pub next_alert_id: u64,
    pub app_first_seen: HashMap<String, u64>,
    pub seen_countries: HashSet<CountryCode>,
    pub spiked_apps: HashSet<String>,
    pub alerts: VecDeque<SecurityAlert>,
    pub app_down_hist: HashMap<String, Vec<f32>>,
    pub app_up_hist: HashMap<String, Vec<f32>>,
    pub hosts: HashMap<String, HostRecord>,
    pub protocols: HashMap<&'static str, ProtocolRecord>,
    pub session_wan_bytes: u64,
    pub session_lan_bytes: u64,
}

impl PersistentSessionState {
    pub fn push_alert(
        &mut self,
        kind: AlertKind,
        app_name: String,
        detail: String,
        country: Option<CountryCode>,
    ) {
        self.next_alert_id += 1;
        if self.alerts.len() >= MAX_SECURITY_ALERTS {
            self.alerts.pop_back();
        }
        self.alerts.push_front(SecurityAlert {
            id: self.next_alert_id,
            kind,
            app_name,
            detail,
            country,
            age_secs: 0,
            created_at: Instant::now(),
        });
    }

    pub fn reset_socket_counters(&mut self) {
        for host in self.hosts.values_mut() {
            host.stats.reset_sockets();
        }
        for proto in self.protocols.values_mut() {
            proto.stats.reset_sockets();
        }
    }

    pub fn update_app_and_endpoints(
        &mut self,
        mut app: AppNetworkInfo,
        dt: f64,
        incognito: bool,
    ) -> AppNetworkInfo {
        let group_key = if app.pid == 0 {
            format!("system_{}", app.name)
        } else {
            app.name.to_lowercase()
        };

        let is_new_app = !self.app_first_seen.contains_key(&group_key);
        let first_seen = *self.app_first_seen.entry(group_key.clone()).or_insert_with(|| {
            self.next_id += 1;
            self.next_id
        });
        app.first_seen_id = first_seen;

        if is_new_app && !incognito && app.pid != 0 {
            self.push_alert(
                AlertKind::FirstAppActivity,
                app.name.clone(),
                format!("First network activity ({} sockets)", app.connections.len()),
                None,
            );
        }

        let live_spd = app.download_speed + app.upload_speed;
        if !incognito && live_spd > 5.0 * 1024.0 * 1024.0 && self.spiked_apps.insert(group_key.clone()) {
            self.push_alert(
                AlertKind::HighBandwidthSpike,
                app.name.clone(),
                format!("High throughput spike ({:.1} MB/s)", live_spd / (1024.0 * 1024.0)),
                None,
            );
        }

        let d_hist = self.app_down_hist.entry(group_key.clone()).or_insert_with(|| vec![0.0; HISTORY_LEN]);
        d_hist.remove(0);
        d_hist.push(app.download_speed as f32);
        app.download_history = d_hist.clone();

        let u_hist = self.app_up_hist.entry(group_key).or_insert_with(|| vec![0.0; HISTORY_LEN]);
        u_hist.remove(0);
        u_hist.push(app.upload_speed as f32);
        app.upload_history = u_hist.clone();

        if app.is_blocked && !app.connections.is_empty() {
            super::killer::terminate_sockets(&app.connections);
        }

        if incognito {
            return app;
        }

        let conn_count = app.connections.len().max(1) as u64;
        let step_bytes = ((live_spd * dt) as u64) / conn_count;
        let app_key_lower = app.name.to_lowercase();

        for conn in &app.connections {
            let (ip, port, is_listen) =
                if conn.remote_addr.port() != 0 && !conn.remote_addr.ip().is_unspecified() {
                    (conn.remote_addr.ip(), conn.remote_addr.port(), false)
                } else if conn.state == SocketState::Listen {
                    (conn.local_addr.ip(), conn.local_addr.port(), true)
                } else if !conn.local_addr.ip().is_unspecified() && conn.local_addr.port() != 0 {
                    (conn.local_addr.ip(), conn.local_addr.port(), false)
                } else {
                    continue;
                };

            if !is_listen && is_remote_ip(&ip) {
                self.session_wan_bytes = self.session_wan_bytes.saturating_add(step_bytes);
            } else {
                self.session_lan_bytes = self.session_lan_bytes.saturating_add(step_bytes);
            }

            let loc = if is_listen {
                IpLocationInfo {
                    country_code: CountryCode::LOCAL,
                    country: "Local Host",
                    organization: "Listening Service",
                    is_local: true,
                }
            } else {
                classify_ip_location_with_domain(&ip, conn.domain.as_deref())
            };

            if !loc.is_local && self.seen_countries.insert(loc.country_code) {
                self.push_alert(
                    AlertKind::NewCountryEndpoint,
                    app.name.clone(),
                    format!("Connected to {} ({}:{} · {})", loc.country, ip, port, loc.organization),
                    Some(loc.country_code),
                );
            }

            let (full_desc, proto_code, proto_col) = classify_traffic_type(
                conn.protocol.as_str(),
                &conn.local_addr,
                &conn.remote_addr,
            );

            let host_key = if is_listen { format!("listen:{}:{}", ip, port) } else { format!("{}:{}", ip, port) };
            let ip_port_str = format!("{}:{}", ip, port);
            let display_title = if let Some(dom) = &conn.domain {
                dom.clone()
            } else if is_listen {
                format!("Listen :{} ({})", port, conn.protocol.as_str())
            } else {
                ip_port_str.clone()
            };

            let next_id_ref = &mut self.next_id;
            let host_entry = self.hosts.entry(host_key.clone()).or_insert_with(|| {
                *next_id_ref += 1;
                HostRecord {
                    key: host_key,
                    display_title: display_title.clone(),
                    ip,
                    port,
                    ip_port_str,
                    domain: conn.domain.clone(),
                    country_code: loc.country_code,
                    country: loc.country,
                    organization: loc.organization,
                    is_local: loc.is_local,
                    is_listen,
                    stats: EndpointTrafficStats::new(4096),
                    protocols: Vec::new(),
                    first_seen_id: *next_id_ref,
                }
            });

            if host_entry.domain.is_none() && conn.domain.is_some() {
                host_entry.domain = conn.domain.clone();
                if let Some(dom) = &conn.domain {
                    host_entry.display_title = dom.clone();
                    let updated_loc = classify_ip_location_with_domain(&ip, Some(dom.as_str()));
                    host_entry.country_code = updated_loc.country_code;
                    host_entry.country = updated_loc.country;
                    host_entry.organization = updated_loc.organization;
                }
            }

            let byte_inc = step_bytes.max(128);
            host_entry.stats.record_sample(&app_key_lower, &app.name, byte_inc);
            if !host_entry.protocols.contains(&proto_code) {
                host_entry.protocols.push(proto_code);
            }

            let proto_entry = self.protocols.entry(proto_code).or_insert_with(|| {
                *next_id_ref += 1;
                ProtocolRecord {
                    code: proto_code,
                    full_desc,
                    color: proto_col,
                    is_local: loc.is_local,
                    stats: EndpointTrafficStats::new(4096),
                    ports: Vec::new(),
                    first_seen_id: *next_id_ref,
                }
            });

            proto_entry.stats.record_sample(&app_key_lower, &app.name, byte_inc);
            if port != 0 && !proto_entry.ports.contains(&port) && proto_entry.ports.len() < 4 {
                proto_entry.ports.push(port);
            }
        }

        app
    }
}
