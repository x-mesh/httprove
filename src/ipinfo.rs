//! IP 인텔리전스 (--asn): 연결 IP의 ASN/조직/등록국가(Team Cymru DNS) + reverse DNS(PTR) +
//! 인프라 분류(CDN/cloud/origin). httprove의 자체 DNS 클라이언트(dns.rs)를 재사용하므로
//! 의존성 추가나 오프라인 GeoIP DB 없이 "이 IP가 누구의 인프라인지"를 식별한다.
//!
//! Team Cymru: `<reversed-ip>.origin.asn.cymru.com` TXT → "ASN | prefix | CC | registry | date",
//! `AS<n>.asn.cymru.com` TXT → "ASN | CC | registry | date | org". 등록 국가(CC)는 ASN 할당
//! 국가라 anycast/CDN은 물리 위치와 다를 수 있다(인프라 식별엔 충분).

use std::net::IpAddr;

use crate::dns;

/// 인프라 종류 추정.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraKind {
    Cdn,
    Cloud,
    Origin,
    Unknown,
}

impl InfraKind {
    pub fn label(self) -> &'static str {
        match self {
            InfraKind::Cdn => "CDN",
            InfraKind::Cloud => "cloud/LB",
            InfraKind::Origin => "origin",
            InfraKind::Unknown => "?",
        }
    }
}

/// 한 IP의 인텔리전스. 조회 실패 부분은 None으로 남는다.
#[derive(Debug, Clone, Default)]
pub struct IpInfo {
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub country: Option<String>,
    pub prefix: Option<String>,
    pub ptr: Option<String>,
}

/// Team Cymru DNS + PTR로 IP 인텔리전스를 조회한다. 모든 실패는 부분 결과로 흡수(패닉 없음).
pub async fn lookup(ip: IpAddr, resolver: IpAddr) -> IpInfo {
    let mut info = IpInfo::default();

    // reverse DNS (PTR).
    let rev = reverse_arpa(ip);
    info.ptr = dns::query_ptr(resolver, &rev).await.ok().flatten();

    // origin.asn.cymru.com TXT → "ASN | prefix | CC | registry | date".
    if let Ok(txts) = dns::query_txt(resolver, &cymru_name(ip)).await
        && let Some(first) = txts.first()
    {
        let f: Vec<&str> = first.split('|').map(str::trim).collect();
        info.asn = f
            .first()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok());
        info.prefix = f.get(1).filter(|s| !s.is_empty()).map(|s| s.to_string());
        info.country = f.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string());
    }

    // AS<asn>.asn.cymru.com TXT → "ASN | CC | registry | date | org" — org는 마지막 필드.
    if let Some(asn) = info.asn
        && let Ok(txts) = dns::query_txt(resolver, &format!("AS{asn}.asn.cymru.com")).await
        && let Some(first) = txts.first()
        && let Some(org) = first.rsplit('|').next().map(str::trim)
        && !org.is_empty()
    {
        info.org = Some(org.to_string());
    }

    info
}

/// org/ptr/server 헤더 문자열로 인프라 종류를 추정한다.
pub fn classify(info: &IpInfo, server_header: Option<&str>) -> InfraKind {
    let hay = format!(
        "{} {} {}",
        info.org.as_deref().unwrap_or(""),
        info.ptr.as_deref().unwrap_or(""),
        server_header.unwrap_or("")
    )
    .to_ascii_lowercase();

    const CDN: &[&str] = &[
        "cloudflare",
        "akamai",
        "fastly",
        "cloudfront",
        "edgecast",
        "stackpath",
        "bunny",
        "cdn77",
        "limelight",
        "incapsula",
        "imperva",
    ];
    const CLOUD: &[&str] = &[
        "amazon",
        "aws",
        "google",
        "gcp",
        "azure",
        "microsoft",
        "digitalocean",
        "linode",
        "vultr",
        "oracle",
        "alibaba",
        "hetzner",
        "ovh",
    ];

    if CDN.iter().any(|k| hay.contains(k)) {
        InfraKind::Cdn
    } else if CLOUD.iter().any(|k| hay.contains(k)) {
        InfraKind::Cloud
    } else if info.org.is_some() {
        InfraKind::Origin
    } else {
        InfraKind::Unknown
    }
}

/// IPv4 a.b.c.d → "d.c.b.a.origin.asn.cymru.com" (IPv6는 origin6).
fn cymru_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => format!("{}origin6.asn.cymru.com", nibbles_reversed(&v6.octets())),
    }
}

/// IP → reverse DNS 이름. IPv4 a.b.c.d → "d.c.b.a.in-addr.arpa".
fn reverse_arpa(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => format!("{}ip6.arpa", nibbles_reversed(&v6.octets())),
    }
}

/// IPv6 16바이트를 nibble 역순 "x.x.…." 접두(끝에 점 포함)로 만든다.
fn nibbles_reversed(octets: &[u8; 16]) -> String {
    let mut s = String::with_capacity(64);
    for b in octets.iter().rev() {
        s.push_str(&format!("{:x}.{:x}.", b & 0x0f, b >> 4));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cymru_and_arpa_names_ipv4() {
        let ip: IpAddr = "223.130.192.247".parse().unwrap();
        assert_eq!(cymru_name(ip), "247.192.130.223.origin.asn.cymru.com");
        assert_eq!(reverse_arpa(ip), "247.192.130.223.in-addr.arpa");
    }

    #[test]
    fn classify_cdn_cloud_origin() {
        let cf = IpInfo {
            org: Some("Cloudflare, Inc.".to_string()),
            ..Default::default()
        };
        assert_eq!(classify(&cf, None), InfraKind::Cdn);

        let aws = IpInfo {
            org: Some("Amazon.com, Inc.".to_string()),
            ..Default::default()
        };
        assert_eq!(classify(&aws, None), InfraKind::Cloud);

        let naver = IpInfo {
            org: Some("NAVER Cloud Corp.".to_string()),
            ..Default::default()
        };
        // 하이퍼스케일러 키워드(amazon/google/azure…)가 없으므로 origin으로 분류한다
        // (조직명의 일반 단어 "Cloud"는 분류 키워드가 아님 — 오분류 방지).
        assert_eq!(classify(&naver, None), InfraKind::Origin);

        let plain = IpInfo {
            org: Some("Some Telecom KR".to_string()),
            ..Default::default()
        };
        assert_eq!(classify(&plain, None), InfraKind::Origin);

        let empty = IpInfo::default();
        assert_eq!(classify(&empty, None), InfraKind::Unknown);
    }

    #[test]
    fn classify_uses_server_header_and_ptr() {
        let info = IpInfo {
            ptr: Some("server-1.cloudfront.net".to_string()),
            ..Default::default()
        };
        assert_eq!(classify(&info, None), InfraKind::Cdn);
        let info2 = IpInfo::default();
        assert_eq!(classify(&info2, Some("cloudflare")), InfraKind::Cdn);
    }
}
