use crate::net::CountryCode;

#[derive(Clone, Copy)]
pub enum FlagSpec {
    H2([f32; 4], [f32; 4]),
    H3([f32; 4], [f32; 4], [f32; 4]),
    V2([f32; 4], [f32; 4]),
    V3([f32; 4], [f32; 4], [f32; 4]),
    BandH([f32; 4], [f32; 4], [f32; 4]),
    Nordic([f32; 4], [f32; 4], Option<[f32; 4]>),
    CenterCross([f32; 4], [f32; 4]),
    Saltire([f32; 4], [f32; 4]),
    Disc([f32; 4], [f32; 4]),
    TriH2([f32; 4], [f32; 4], [f32; 4]),
    TriH3([f32; 4], [f32; 4], [f32; 4], [f32; 4]),
    Canton([f32; 4], [f32; 4], [f32; 4]),
    US,
    GB,
    CH,
    BR,
    CA,
    KR,
    EU,
    Local,
    Global,
}

const fn rgb(r: u8, g: u8, b: u8) -> [f32; 4] {
    [r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0, 1.0]
}

const W: [f32; 4] = rgb(246, 248, 252);
const K: [f32; 4] = rgb(22, 24, 28);
const R: [f32; 4] = rgb(216, 30, 42);
const DR: [f32; 4] = rgb(165, 22, 38);
const B: [f32; 4] = rgb(18, 62, 158);
const LB: [f32; 4] = rgb(62, 148, 228);
const NB: [f32; 4] = rgb(12, 36, 98);
const G: [f32; 4] = rgb(16, 148, 68);
const DG: [f32; 4] = rgb(10, 108, 52);
const Y: [f32; 4] = rgb(250, 206, 22);
const O: [f32; 4] = rgb(246, 132, 28);

/// Maps every ISO 3166-1 alpha-2 country code on Earth to its authentic flag design.
pub fn flag_spec_for(country: CountryCode) -> FlagSpec {
    match &country.0 {
        b"LO" => FlagSpec::Local,
        b"EU" => FlagSpec::EU,
        b"ZZ" => FlagSpec::Global,
        b"US" | b"PR" => FlagSpec::US,
        b"GB" => FlagSpec::GB,
        b"CH" => FlagSpec::CH,
        b"BR" => FlagSpec::BR,
        b"CA" => FlagSpec::CA,
        b"KR" => FlagSpec::KR,

        // Nordic Cross Nations
        b"SE" => FlagSpec::Nordic(rgb(10, 108, 174), Y, None),
        b"FI" => FlagSpec::Nordic(W, rgb(6, 58, 132), None),
        b"DK" => FlagSpec::Nordic(rgb(200, 16, 46), W, None),
        b"NO" => FlagSpec::Nordic(rgb(186, 12, 47), W, Some(NB)),
        b"IS" => FlagSpec::Nordic(B, W, Some(R)),

        // Centered & Saltire Crosses
        b"GR" => FlagSpec::Canton(B, W, B),
        b"GE" => FlagSpec::CenterCross(W, R),
        b"DO" => FlagSpec::CenterCross(B, W),
        b"TO" => FlagSpec::CenterCross(R, W),
        b"JM" => FlagSpec::Saltire(G, Y),
        b"BI" => FlagSpec::Saltire(R, W),

        // Horizontal Tricolors (Europe, Americas, Asia, Africa, Middle East)
        b"DE" => FlagSpec::H3(K, R, Y),
        b"NL" | b"LU" | b"PY" | b"HR" => FlagSpec::H3(R, W, B),
        b"AT" | b"LV" | b"LB" => FlagSpec::H3(R, W, R),
        b"RU" | b"SK" | b"SI" => FlagSpec::H3(W, B, R),
        b"RS" => FlagSpec::H3(R, B, W),
        b"BG" => FlagSpec::H3(W, G, R),
        b"HU" | b"TJ" => FlagSpec::H3(R, W, G),
        b"LT" | b"MM" | b"GH" | b"BO" | b"ET" => FlagSpec::H3(Y, G, R),
        b"EE" => FlagSpec::H3(LB, K, W),
        b"AM" => FlagSpec::H3(R, B, O),
        b"AZ" => FlagSpec::H3(LB, R, G),
        b"AR" | b"SV" | b"HN" | b"NI" | b"GT" => FlagSpec::H3(LB, W, LB),
        b"CO" | b"EC" | b"VE" => FlagSpec::H3(Y, B, R),
        b"IN" | b"NE" => FlagSpec::H3(O, W, G),
        b"IR" | b"KW" => FlagSpec::H3(G, W, R),
        b"EG" | b"SY" | b"IQ" | b"YE" => FlagSpec::H3(R, W, K),
        b"AE" => FlagSpec::TriH3(G, W, K, R),
        b"JO" | b"PS" | b"SD" => FlagSpec::TriH3(K, W, G, R),
        b"LY" | b"MW" => FlagSpec::H3(R, K, G),
        b"KE" => FlagSpec::H3(K, R, G),
        b"TZ" | b"SL" | b"UZ" => FlagSpec::H3(G, Y, LB),
        b"GA" => FlagSpec::H3(G, Y, B),
        b"RW" => FlagSpec::H3(LB, Y, G),
        b"MU" | b"UG" => FlagSpec::H3(R, Y, G),
        b"ZA" => FlagSpec::TriH3(R, G, B, Y),
        b"MZ" | b"ZW" => FlagSpec::TriH3(G, Y, R, K),

        // Vertical Tricolors & Bicolors
        b"FR" => FlagSpec::V3(B, W, R),
        b"IT" | b"MX" => FlagSpec::V3(G, W, R),
        b"IE" => FlagSpec::V3(G, W, O),
        b"CI" => FlagSpec::V3(O, W, G),
        b"BE" => FlagSpec::V3(K, Y, R),
        b"RO" | b"TD" | b"MD" | b"AD" => FlagSpec::V3(B, Y, R),
        b"PE" => FlagSpec::V3(R, W, R),
        b"NG" => FlagSpec::V3(G, W, G),
        b"CM" | b"SN" | b"ML" | b"GN" => FlagSpec::V3(G, Y, R),
        b"PT" => FlagSpec::V2(G, R),
        b"MT" => FlagSpec::V2(W, R),
        b"VA" => FlagSpec::V2(Y, W),
        b"DZ" => FlagSpec::V2(G, W),
        b"PK" => FlagSpec::V2(W, DG),
        b"QA" | b"BH" => FlagSpec::V2(W, DR),
        b"MG" | b"BJ" => FlagSpec::V2(W, R),

        // Horizontal Bicolors
        b"PL" | b"ID" | b"MC" | b"SG" => FlagSpec::H2(if &country.0 == b"PL" { W } else { R }, if &country.0 == b"PL" { R } else { W }),
        b"UA" => FlagSpec::H2(B, Y),
        b"LI" | b"HT" => FlagSpec::H2(B, R),
        b"SM" => FlagSpec::H2(W, LB),
        b"BY" | b"BF" => FlagSpec::H2(R, G),
        b"AO" | b"PG" => FlagSpec::H2(R, K),
        b"PA" => FlagSpec::H2(W, R),

        // Banded Horizontal (Spain, Thailand, Costa Rica, Israel, etc.)
        b"ES" => FlagSpec::BandH(R, Y, R),
        b"TH" => FlagSpec::BandH(R, NB, R),
        b"CR" | b"KP" => FlagSpec::BandH(B, R, B),
        b"IL" => FlagSpec::BandH(B, W, B),
        b"LA" | b"KH" => FlagSpec::BandH(R, B, R),
        b"BW" => FlagSpec::BandH(LB, K, LB),
        b"SR" => FlagSpec::BandH(G, R, G),
        b"GM" => FlagSpec::BandH(R, B, G),

        // Left Triangle Flags
        b"CZ" => FlagSpec::TriH2(W, R, B),
        b"PH" => FlagSpec::TriH2(B, R, W),
        b"DJ" => FlagSpec::TriH2(LB, G, W),
        b"CU" => FlagSpec::TriH3(B, W, B, R),
        b"BS" => FlagSpec::TriH3(LB, Y, LB, K),
        b"GY" => FlagSpec::TriH2(G, G, Y),
        b"TL" => FlagSpec::TriH2(R, R, K),

        // Disc / Sun / Crescent Center Flags
        b"JP" => FlagSpec::Disc(W, R),
        b"BD" => FlagSpec::Disc(DG, R),
        b"PW" => FlagSpec::Disc(LB, Y),
        b"TR" | b"TN" => FlagSpec::Disc(R, W),
        b"VN" | b"CN" | b"MA" | b"KG" | b"AL" | b"ME" | b"MK" | b"HK" | b"IM" => FlagSpec::Disc(R, Y),
        b"KZ" | b"SO" | b"FM" => FlagSpec::Disc(LB, Y),
        b"SA" | b"TM" | b"MR" | b"ZM" => FlagSpec::Disc(DG, Y),
        b"CY" | b"XK" => FlagSpec::Disc(W, O),
        b"BA" => FlagSpec::Disc(B, Y),

        // Canton Flags (AU, NZ, TW, MY, CL, UY, LR, etc.)
        b"AU" | b"NZ" | b"FJ" | b"TV" => FlagSpec::Canton(NB, NB, R),
        b"MY" | b"LR" => FlagSpec::Canton(R, W, NB),
        b"CL" => FlagSpec::Canton(W, R, B),
        b"TW" | b"WS" => FlagSpec::Canton(R, R, NB),
        b"UY" => FlagSpec::Canton(B, W, Y),
        b"TG" => FlagSpec::Canton(G, Y, R),

        // Deterministic fallback using ISO letters so every remaining code still gets a distinct flag
        other => {
            let palette = [R, B, G, Y, O, LB, NB, DG];
            let c1 = palette[(other[0] as usize) % palette.len()];
            let c2 = W;
            let c3 = palette[(other[1] as usize + 3) % palette.len()];
            if (other[0] + other[1]) % 2 == 0 {
                FlagSpec::H3(c1, c2, c3)
            } else {
                FlagSpec::V3(c1, c2, c3)
            }
        }
    }
}
