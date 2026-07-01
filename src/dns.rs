//! 다중 리졸버 / EDNS-client-subnet 비교 — 최소 DNS-over-UDP 클라이언트 직접 구현.
//!
//! 담당 기능:
//! - ⑩ 여러 리졸버(예: 8.8.8.8, 1.1.1.1, 사내 DNS)에 같은 호스트를 질의해 응답 IP를 비교.
//!   EDNS0 client-subnet(ECS)을 붙여 CDN/anycast POP 분기를 노출한다.
//!
//! 새 의존성 없이 DNS 와이어 포맷을 손으로 만든다 (tokio UdpSocket만 사용).
//!
//! ## run_via_resolvers(cfg, resolvers, ecs, color) -> Result<ExitCode>
//! 각 resolver(IpAddr)에 대해:
//! 1. cfg.url의 호스트 이름으로 A(그리고 ip_family가 V6면 AAAA) 질의 패킷을 만든다.
//!    ecs가 Some(cidr)이면 EDNS0 OPT RR에 client-subnet 옵션(RFC 7871)을 포함한다.
//! 2. resolver:53 으로 UDP 송신, 응답 수신(타임아웃은 cfg.timeout 활용), 응답 IP들을 파싱.
//! 3. 첫 번째 응답 IP로 프로브한다(cfg.clone, resolve=Some(ip)) — fanout과 같은 트릭.
//! 4. 표 출력: `resolver | resolved IPs | status | ttfb | total`.
//!    리졸버별로 다른 IP/POP이 나오면 그 분기가 바로 보인다.
//!
//! 종료 코드: 어떤 리졸버라도 질의 실패 또는 프로브 실패면 ExitCode::from(1), 전부 OK면 SUCCESS.
//!
//! ## DNS 와이어 포맷 (직접 구현)
//! ### 질의 인코더 (encode_query)
//! - Header(12B): id(임의/카운터), flags=0x0100(RD=1), qdcount=1,
//!   ancount=0, nscount=0, arcount=(ecs면 1 else 0).
//! - Question: QNAME(라벨 길이-접두 + 0 종단), QTYPE(A=1 / AAAA=28), QCLASS(IN=1).
//! - ecs면 Additional에 OPT RR(TYPE=41, name=root(0)):
//!   UDP payload size(예: 4096), ext-rcode/version/flags=0,
//!   RDATA = OPTION-CODE(8=client-subnet) + OPTION-LENGTH +
//!   FAMILY(IPv4=1/IPv6=2) + SOURCE-PREFIX + SCOPE-PREFIX(0) + 주소 바이트(prefix 비트만).
//!   cidr 문자열("203.0.113.0/24")을 파싱해 family/prefix/address를 채운다.
//!
//! ### 응답 파서 (parse_answers)
//! - 헤더의 ancount만큼 RR을 읽되, NAME은 압축 포인터(0xC0..)일 수 있으니
//!   포인터(2바이트)면 건너뛰고 아니면 라벨 시퀀스를 스킵한다.
//! - TYPE==A(1)이고 RDLENGTH==4면 IPv4Addr, TYPE==AAAA(28)이고 RDLENGTH==16이면 IPv6Addr 수집.
//!   CNAME/기타 RR은 건너뛴다. 경계 검사 필수 — 패닉 금지(슬라이스 OOB 방지).
//!
//! ## 테스트 (#[cfg(test)] 필수)
//! - encode_query: 알려진 호스트("example.com")에 대해 헤더/QNAME/QTYPE 바이트를 검증.
//! - parse_answers: 캡처한 실제 응답 패킷(바이트 리터럴)을 넣어 기대 IP 집합이 나오는지 검증.
//!   (압축 포인터가 포함된 패킷 1개를 권장.)
//!
//! ## 구현 메모
//! - 모든 fallible 경로는 Result/Option (unwrap 금지). 패킷 파싱은 길이 검사 후 인덱싱.
//! - UDP 송수신은 tokio::net::UdpSocket + tokio::time::timeout.
//! - 표 출력 톤은 fanout.rs와 맞춘다. color면 분기/실패를 강조.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use colored::Colorize;
use tokio::net::UdpSocket;
use tokio::time::Instant as TokioInstant;

use crate::types::{IpFamily, ProbeConfig};

/// DNS 레코드 타입.
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_PTR: u16 = 12;
const QTYPE_TXT: u16 = 16;
/// EDNS0 OPT pseudo-RR 타입.
const RR_OPT: u16 = 41;
/// IN 클래스.
const QCLASS_IN: u16 = 1;
/// EDNS0 client-subnet 옵션 코드 (RFC 7871).
const EDNS_OPT_CLIENT_SUBNET: u16 = 8;
/// OPT RR이 광고하는 UDP payload 크기.
const EDNS_UDP_PAYLOAD: u16 = 4096;
/// DNS 질의 1회의 UDP 송수신 타임아웃.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// --dns 경로에서 한 서버에 할당하는 질의 예산 상한. 남은 전체 예산을 남은 서버 수로
/// 나눈 값과 이 상한 중 작은 쪽을 쓴다 (정상 서버는 ms 안에 응답하므로 상한은 죽은
/// 서버가 예산을 다 먹지 않게 하는 안전판이다).
const DNS_QUERY_CAP: Duration = Duration::from_secs(3);
/// --dns Auto에서 먼저 응답한 패밀리 확보 후, 다른 패밀리를 추가로 기다리는 짧은 유예.
/// 한 패밀리가 조용히 드롭돼도 전체 해석이 그만큼만 지연되게 한다 (happy-eyeballs 유사).
const DNS_SECOND_FAMILY_GRACE: Duration = Duration::from_millis(150);
/// 응답 수신 버퍼 (표준 UDP DNS는 512B, EDNS면 더 클 수 있어 넉넉히 잡는다).
const RECV_BUF: usize = 4096;

/// 한 리졸버에 대한 질의/프로브 결과 한 줄.
struct ResolverRow {
    /// 질의한 리졸버 IP.
    resolver: IpAddr,
    /// 응답에서 얻은 IP들 (정렬됨). 질의 실패면 비어 있음.
    resolved: Vec<IpAddr>,
    /// status 칼럼 텍스트 (코드 또는 에러 단계). 질의 실패면 그 사유.
    status: String,
    /// TTFB ms (프로브 성공 시).
    ttfb_ms: Option<f64>,
    /// total ms (프로브 성공 시).
    total_ms: Option<f64>,
    /// 이 리졸버가 "성공"(질의 + 프로브 OK)인지.
    ok: bool,
}

/// 여러 리졸버에 호스트를 질의(선택적 ECS)하고 각 응답 IP로 프로브해 표로 비교한다.
pub async fn run_via_resolvers(
    cfg: &ProbeConfig,
    resolvers: &[IpAddr],
    ecs: Option<&str>,
    color: bool,
) -> anyhow::Result<std::process::ExitCode> {
    // 질의할 호스트 이름. IP 리터럴이거나 호스트가 없으면 의미가 없으므로 에러.
    let host = cfg
        .url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("--via: URL has no host to resolve"))?;
    if cfg.url.host().map(is_ip_literal).unwrap_or(false) {
        anyhow::bail!("--via: URL host {host} is an IP literal, nothing to resolve");
    }

    // ip_family에 따라 질의할 레코드 타입을 정한다. V6만이면 AAAA만, 그 외엔 A(+ V6 허용 시 AAAA).
    // 표는 첫 IP로 프로브하므로, A를 우선 질의하고 부족하면 AAAA를 시도한다.
    let qtypes: &[u16] = match cfg.ip_family {
        IpFamily::V6 => &[QTYPE_AAAA],
        IpFamily::V4 => &[QTYPE_A],
        IpFamily::Auto => &[QTYPE_A, QTYPE_AAAA],
    };

    // ECS CIDR을 미리 한 번만 파싱한다 (리졸버마다 동일).
    let ecs_subnet = match ecs {
        Some(cidr) => Some(parse_ecs(cidr)?),
        None => None,
    };

    let mut rows: Vec<ResolverRow> = Vec::with_capacity(resolvers.len());
    let mut any_fail = false;

    for &resolver in resolvers {
        // 1) 이 리졸버에서 IP들을 모은다 (qtypes 순서대로, family 필터 적용).
        let mut resolved: Vec<IpAddr> = Vec::new();
        let mut query_err: Option<String> = None;
        for &qtype in qtypes {
            match query_resolver(resolver, host, qtype, ecs_subnet.as_ref()).await {
                Ok(ips) => {
                    for ip in ips {
                        if family_matches(ip, cfg.ip_family) && !resolved.contains(&ip) {
                            resolved.push(ip);
                        }
                    }
                }
                Err(e) => {
                    // 첫 실패 사유만 기억한다. (A는 되는데 AAAA만 빈 응답인 경우는 정상)
                    if query_err.is_none() {
                        query_err = Some(e);
                    }
                }
            }
        }
        resolved.sort();

        // 질의 자체가 실패(주소 0개 + 에러)면 그 리졸버는 fail.
        if resolved.is_empty() {
            any_fail = true;
            let reason = query_err.unwrap_or_else(|| "no address records".to_string());
            rows.push(ResolverRow {
                resolver,
                resolved,
                status: format!("query failed: {reason}"),
                ttfb_ms: None,
                total_ms: None,
                ok: false,
            });
            continue;
        }

        // 2) 첫 번째 IP로 프로브 (fanout과 동일한 resolve override 트릭).
        let target_ip = resolved[0];
        let mut pcfg = cfg.clone();
        pcfg.resolve = Some(target_ip);
        pcfg.ip_family = IpFamily::Auto; // resolve가 우선이므로 패밀리는 무관.
        let result = crate::probe::probe(&pcfg, 0).await;

        if let Some(err) = &result.error {
            any_fail = true;
            let timeout_note = if err.timed_out { " (timeout)" } else { "" };
            rows.push(ResolverRow {
                resolver,
                resolved,
                status: format!("{}{timeout_note}", err.phase),
                ttfb_ms: None,
                total_ms: None,
                ok: false,
            });
        } else {
            let timings = result.summed_timings();
            let status = result
                .status()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            rows.push(ResolverRow {
                resolver,
                resolved,
                status,
                ttfb_ms: Some(timings.ttfb_ms),
                total_ms: Some(timings.total_ms),
                ok: true,
            });
        }
    }

    print_table(host, &rows, color);

    if any_fail {
        Ok(std::process::ExitCode::from(1))
    } else {
        Ok(std::process::ExitCode::SUCCESS)
    }
}

/// url::Host가 IP 리터럴인지.
fn is_ip_literal(h: url::Host<&str>) -> bool {
    matches!(h, url::Host::Ipv4(_) | url::Host::Ipv6(_))
}

/// IP가 선택한 패밀리에 맞는지 (probe.rs의 family_matches와 동일 의미).
fn family_matches(ip: IpAddr, family: IpFamily) -> bool {
    match family {
        IpFamily::Auto => true,
        IpFamily::V4 => ip.is_ipv4(),
        IpFamily::V6 => ip.is_ipv6(),
    }
}

/// 단일 리졸버에 1개 레코드 타입을 질의하고 응답 IP들을 반환한다.
/// 리졸버에 한 번의 UDP 질의를 보내고 raw 응답 바이트를 받는다 (파싱은 호출자가).
async fn query_raw(
    resolver: IpAddr,
    host: &str,
    qtype: u16,
    ecs: Option<&EcsSubnet>,
) -> Result<Vec<u8>, String> {
    let query = encode_query(rand_id(), host, qtype, ecs)?;

    // 리졸버 패밀리에 맞는 로컬 주소로 UDP 소켓을 연다.
    let bind_addr: SocketAddr = match resolver {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    let dst = SocketAddr::new(resolver, 53);

    // 송신 + 수신을 한 타임아웃 예산 안에서 처리한다.
    tokio::time::timeout(DNS_TIMEOUT, async {
        socket
            .send_to(&query, dst)
            .await
            .map_err(|e| format!("udp send to {resolver}: {e}"))?;
        let mut buf = vec![0u8; RECV_BUF];
        let (n, _from) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("udp recv from {resolver}: {e}"))?;
        buf.truncate(n);
        Ok::<Vec<u8>, String>(buf)
    })
    .await
    .map_err(|_| format!("dns query to {resolver} timed out"))?
}

async fn query_resolver(
    resolver: IpAddr,
    host: &str,
    qtype: u16,
    ecs: Option<&EcsSubnet>,
) -> Result<Vec<IpAddr>, String> {
    let buf = query_raw(resolver, host, qtype, ecs).await?;
    parse_answers(&buf).map_err(|e| format!("parse dns response from {resolver}: {e}"))
}

/// `--ecs` CIDR 문자열의 형식을 CLI 단에서 미리 검증한다 (실패 시 하드 에러).
/// parse_ecs를 재사용하되 내부 타입을 노출하지 않기 위해 결과는 버린다.
pub(crate) fn validate_ecs(cidr: &str) -> anyhow::Result<()> {
    parse_ecs(cidr).map(|_| ())
}

/// `--dns`용: 커스텀 DNS 서버들로 호스트를 해석해 IP 목록을 반환한다 (일반 프로브 경로).
///
/// `run_via_resolvers`(비교 표 전용)와 달리, 이 함수는 일반 프로브 흐름에서 시스템
/// 리졸버를 대체하는 순수 해석기다. 서버를 순서대로 시도해 첫 성공 응답을 쓴다(failover).
/// `ecs`가 있으면 EDNS0 client-subnet 옵션을 붙인다.
///
/// **예산 배분(failover 보장):** 남은 시간(`deadline - now`)을 남은 서버 수로 나눠 각
/// 서버에 할당하므로, 앞선 죽은 서버가 뒤의 정상 서버 기회를 굶기지 않는다.
///
/// **Auto 패밀리:** A/AAAA를 동시에 질의하고, 먼저 온 패밀리 확보 후 다른 쪽을 짧은
/// 유예(DNS_SECOND_FAMILY_GRACE)만 더 기다린다 — 한 패밀리가 조용히 드롭돼도 전체가
/// 그만큼만 지연된다. 반환 순서는 IPv4 우선(가장 넓은 호스트에서 안전한 연결 기본값;
/// 특정 패밀리 강제는 -4/-6).
///
/// 어떤 서버에서도 주소를 얻지 못하면 마지막 실패 사유를 담은 Err를 반환한다.
pub async fn resolve_via_servers(
    servers: &[SocketAddr],
    host: &str,
    family: IpFamily,
    ecs: Option<&str>,
    deadline: TokioInstant,
) -> Result<Vec<IpAddr>, String> {
    if servers.is_empty() {
        return Err("no DNS servers configured".to_string());
    }
    let ecs_subnet = match ecs {
        Some(cidr) => Some(parse_ecs(cidr).map_err(|e| e.to_string())?),
        None => None,
    };

    let mut last_err: Option<String> = None;
    for (i, &server) in servers.iter().enumerate() {
        let now = TokioInstant::now();
        if now >= deadline {
            last_err.get_or_insert_with(|| "DNS resolution deadline exceeded".to_string());
            break;
        }
        // 남은 예산을 남은 서버 수로 나눠 이 서버의 질의 예산을 정한다 (상한은 DNS_QUERY_CAP).
        let slots = (servers.len() - i) as u32;
        let budget = (deadline.duration_since(now) / slots).min(DNS_QUERY_CAP);

        match query_server_family(server, host, family, ecs_subnet.as_ref(), budget).await {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => last_err = Some(format!("{server}: no address records")),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| "all DNS servers failed".to_string()))
}

/// 한 서버에서 `family`에 맞는 주소를 조회한다. Auto는 A/AAAA를 동시에 질의해
/// 직렬화 지연을 없애고(한 패밀리 드롭에도 유예만큼만 대기), IPv4 우선으로 정렬한다.
async fn query_server_family(
    server: SocketAddr,
    host: &str,
    family: IpFamily,
    ecs: Option<&EcsSubnet>,
    budget: Duration,
) -> Result<Vec<IpAddr>, String> {
    match family {
        IpFamily::V4 => {
            let mut ips = query_server(server, host, QTYPE_A, ecs, budget).await?;
            ips.retain(IpAddr::is_ipv4);
            ips.sort();
            ips.dedup();
            Ok(ips)
        }
        IpFamily::V6 => {
            let mut ips = query_server(server, host, QTYPE_AAAA, ecs, budget).await?;
            ips.retain(IpAddr::is_ipv6);
            ips.sort();
            ips.dedup();
            Ok(ips)
        }
        IpFamily::Auto => {
            // A/AAAA 동시 질의. 먼저 끝난 쪽을 받고, 남은 쪽은 짧은 유예만 더 기다린다.
            let a_fut = query_server(server, host, QTYPE_A, ecs, budget);
            let aaaa_fut = query_server(server, host, QTYPE_AAAA, ecs, budget);
            tokio::pin!(a_fut, aaaa_fut);

            let mut v4: Vec<IpAddr> = Vec::new();
            let mut v6: Vec<IpAddr> = Vec::new();
            let mut err: Option<String> = None;
            let mut a_done = false;
            let mut aaaa_done = false;

            // 1) 둘 중 먼저 완료되는 것을 기다린다.
            tokio::select! {
                r = &mut a_fut => { a_done = true; collect(r, &mut v4, &mut err); }
                r = &mut aaaa_fut => { aaaa_done = true; collect(r, &mut v6, &mut err); }
            }
            // 2) 아직 안 끝난 패밀리는 유예만큼만 더 기다린다 (막힌 패밀리가 전체를 끌지 않게).
            if !a_done
                && let Ok(r) = tokio::time::timeout(DNS_SECOND_FAMILY_GRACE, &mut a_fut).await
            {
                collect(r, &mut v4, &mut err);
            }
            if !aaaa_done
                && let Ok(r) = tokio::time::timeout(DNS_SECOND_FAMILY_GRACE, &mut aaaa_fut).await
            {
                collect(r, &mut v6, &mut err);
            }

            v4.retain(IpAddr::is_ipv4);
            v6.retain(IpAddr::is_ipv6);
            v4.sort();
            v4.dedup();
            v6.sort();
            v6.dedup();

            // IPv4 우선으로 병합.
            let mut ips = v4;
            for ip in v6 {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            // 둘 다 실패해 주소가 없으면 실제 실패 사유를 전달한다.
            if ips.is_empty()
                && let Some(e) = err
            {
                return Err(e);
            }
            Ok(ips)
        }
    }
}

/// query_server 결과를 목적지 벡터/에러 슬롯에 반영한다 (Auto 병합 헬퍼).
fn collect(r: Result<Vec<IpAddr>, String>, dst: &mut Vec<IpAddr>, err: &mut Option<String>) {
    match r {
        Ok(ips) => dst.extend(ips),
        Err(e) => {
            if err.is_none() {
                *err = Some(e);
            }
        }
    }
}

/// 지정한 서버(IP:PORT)에 1개 레코드 타입을 질의하고 응답 IP들을 반환한다.
/// query_raw와 달리 (1) 리졸버 포트/타임아웃을 호출자가 지정하고 (--dns 커스텀 포트),
/// (2) 소켓을 서버에 connect해 커널이 다른 소스의 데이터그램을 걸러내며,
/// (3) 응답의 트랜잭션 ID와 QR 비트를 검증해 스트레이/스푸핑 응답을 건너뛴다.
async fn query_server(
    server: SocketAddr,
    host: &str,
    qtype: u16,
    ecs: Option<&EcsSubnet>,
    timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    let id = rand_id();
    let query = encode_query(id, host, qtype, ecs)?;

    let bind_addr: SocketAddr = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    // connect로 커널이 server 외 소스의 데이터그램을 폐기하게 한다 (오프패스 스푸핑 완화).
    socket
        .connect(server)
        .await
        .map_err(|e| format!("udp connect {server}: {e}"))?;

    tokio::time::timeout(timeout, async {
        socket
            .send(&query)
            .await
            .map_err(|e| format!("udp send to {server}: {e}"))?;
        let mut buf = vec![0u8; RECV_BUF];
        // 트랜잭션 ID/QR가 맞는 응답이 올 때까지 (예산 안에서) 스트레이 데이터그램을 건너뛴다.
        loop {
            let n = socket
                .recv(&mut buf)
                .await
                .map_err(|e| format!("udp recv from {server}: {e}"))?;
            // 헤더 최소 길이 + QR=1(응답) + 질의와 같은 트랜잭션 ID인지 확인.
            if n >= 12 && (buf[2] & 0x80) != 0 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return parse_answers(&buf[..n])
                    .map_err(|e| format!("parse dns response from {server}: {e}"));
            }
            // 일치하지 않는 데이터그램은 무시하고 계속 기다린다.
        }
    })
    .await
    .map_err(|_| format!("dns query to {server} timed out"))?
}

/// 리졸버에 TXT 질의를 보내 TXT 문자열들을 받는다 (Team Cymru ASN 조회용, --asn).
pub(crate) async fn query_txt(resolver: IpAddr, host: &str) -> Result<Vec<String>, String> {
    let buf = query_raw(resolver, host, QTYPE_TXT, None).await?;
    parse_txt(&buf).map_err(|e| format!("parse TXT from {resolver}: {e}"))
}

/// 리졸버에 PTR 질의를 보내 첫 호스트명을 받는다 (reverse DNS, --asn).
pub(crate) async fn query_ptr(resolver: IpAddr, host: &str) -> Result<Option<String>, String> {
    let buf = query_raw(resolver, host, QTYPE_PTR, None).await?;
    parse_ptr(&buf).map_err(|e| format!("parse PTR from {resolver}: {e}"))
}

/// 표를 출력한다 (fanout.rs 톤). color면 실패/분기를 강조.
fn print_table(host: &str, rows: &[ResolverRow], color: bool) {
    println!("DNS resolver comparison for {host}");
    println!();

    // 칼럼 폭 계산 (resolver, resolved IPs).
    let resolver_w = rows
        .iter()
        .map(|r| r.resolver.to_string().len())
        .max()
        .unwrap_or(8)
        .max("resolver".len());
    let ips_w = rows
        .iter()
        .map(|r| join_ips(&r.resolved).len())
        .max()
        .unwrap_or(12)
        .max("resolved IPs".len());

    println!(
        "{:<rw$}  {:<iw$}  {:>6}  {:>9}  {:>9}",
        "resolver",
        "resolved IPs",
        "status",
        "ttfb",
        "total",
        rw = resolver_w,
        iw = ips_w,
    );

    // 분기 탐지: 응답 IP 집합이 리졸버마다 다른지.
    let diverged = ip_sets_diverge(rows);

    for r in rows {
        let ips_str = join_ips(&r.resolved);
        let ttfb = r
            .ttfb_ms
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "-".to_string());
        let total = r
            .total_ms
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "-".to_string());

        // status 색칠: 실패면 빨강, 2xx면 초록, 그 외 노랑.
        let status_cell = if color {
            paint_status(&r.status, r.ok)
        } else {
            r.status.clone()
        };
        // IP가 분기되면 IP 칼럼을 노랑으로 강조.
        let ips_cell = if color && diverged && !r.resolved.is_empty() {
            ips_str.yellow().to_string()
        } else {
            ips_str.clone()
        };

        // 패딩은 색 코드가 폭 계산을 망치므로, 원본 길이 기준으로 직접 패딩한다.
        let resolver_pad = " ".repeat(resolver_w.saturating_sub(r.resolver.to_string().len()));
        let ips_pad = " ".repeat(ips_w.saturating_sub(ips_str.len()));

        println!(
            "{}{}  {}{}  {:>6}  {:>9}  {:>9}",
            r.resolver, resolver_pad, ips_cell, ips_pad, status_cell, ttfb, total,
        );
    }

    if diverged {
        println!();
        let note = "note: resolvers returned different IPs — CDN/anycast POP divergence";
        if color {
            println!("{}", note.yellow());
        } else {
            println!("{note}");
        }
    }
}

/// status 셀을 색칠한다.
fn paint_status(status: &str, ok: bool) -> String {
    if !ok {
        return status.red().bold().to_string();
    }
    match status.parse::<u16>() {
        Ok(code) if (200..300).contains(&code) => status.green().bold().to_string(),
        Ok(code) if (300..400).contains(&code) => status.yellow().to_string(),
        Ok(_) => status.red().bold().to_string(),
        Err(_) => status.to_string(),
    }
}

/// IP 목록을 콤마로 연결 (빈 목록이면 "-").
fn join_ips(ips: &[IpAddr]) -> String {
    if ips.is_empty() {
        "-".to_string()
    } else {
        ips.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// 둘 이상의 리졸버가 서로 다른 (비어 있지 않은) IP 집합을 반환했는지.
fn ip_sets_diverge(rows: &[ResolverRow]) -> bool {
    let mut first: Option<&Vec<IpAddr>> = None;
    for r in rows {
        if r.resolved.is_empty() {
            continue;
        }
        match first {
            None => first = Some(&r.resolved),
            Some(f) if f != &r.resolved => return true,
            _ => {}
        }
    }
    false
}

// ===========================================================================
// DNS 와이어 포맷
// ===========================================================================

/// EDNS0 client-subnet 옵션에 쓸 파싱된 서브넷.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EcsSubnet {
    /// FAMILY: IPv4=1, IPv6=2.
    family: u16,
    /// SOURCE PREFIX-LENGTH (유효 비트 수).
    source_prefix: u8,
    /// prefix 비트를 담을 만큼의 주소 바이트 (ceil(prefix/8)).
    addr_bytes: Vec<u8>,
}

/// CIDR 문자열("203.0.113.0/24" 또는 "2001:db8::/48")을 EcsSubnet으로 파싱한다.
fn parse_ecs(cidr: &str) -> anyhow::Result<EcsSubnet> {
    let (ip_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("--ecs expects CIDR like 203.0.113.0/24, got: {cidr}"))?;
    let ip: IpAddr = ip_part
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("--ecs invalid IP in {cidr}: {e}"))?;
    let prefix: u8 = prefix_part
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("--ecs invalid prefix in {cidr}: {e}"))?;

    let (family, full): (u16, Vec<u8>) = match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                anyhow::bail!("--ecs IPv4 prefix must be 0..=32, got /{prefix}");
            }
            (1, v4.octets().to_vec())
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                anyhow::bail!("--ecs IPv6 prefix must be 0..=128, got /{prefix}");
            }
            (2, v6.octets().to_vec())
        }
    };

    // prefix 비트만 전송한다 (RFC 7871: ADDRESS는 SOURCE PREFIX-LENGTH 비트로 잘린다).
    let nbytes = prefix.div_ceil(8) as usize;
    let mut addr_bytes = full[..nbytes].to_vec();
    // 마지막 바이트에서 prefix를 넘는 비트는 0으로 마스킹한다.
    if let Some(last) = addr_bytes.last_mut() {
        let used_bits = prefix % 8;
        if used_bits != 0 {
            let mask: u8 = 0xFFu8 << (8 - used_bits);
            *last &= mask;
        }
    }

    Ok(EcsSubnet {
        family,
        source_prefix: prefix,
        addr_bytes,
    })
}

/// DNS 질의 패킷을 인코딩한다.
///
/// - id: 트랜잭션 ID.
/// - host: 질의할 호스트 이름.
/// - qtype: A(1) / AAAA(28).
/// - ecs: Some이면 EDNS0 OPT RR에 client-subnet 옵션을 추가한다.
fn encode_query(
    id: u16,
    host: &str,
    qtype: u16,
    ecs: Option<&EcsSubnet>,
) -> Result<Vec<u8>, String> {
    let mut pkt = Vec::with_capacity(64);

    // --- Header (12 bytes) ---
    let arcount: u16 = if ecs.is_some() { 1 } else { 0 };
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    pkt.extend_from_slice(&arcount.to_be_bytes()); // ARCOUNT

    // --- Question: QNAME + QTYPE + QCLASS ---
    encode_qname(&mut pkt, host)?;
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());

    // --- Additional: OPT RR with client-subnet (RFC 6891 + 7871) ---
    if let Some(subnet) = ecs {
        // NAME = root (single 0 byte).
        pkt.push(0);
        // TYPE = OPT (41).
        pkt.extend_from_slice(&RR_OPT.to_be_bytes());
        // CLASS = requestor's UDP payload size.
        pkt.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
        // TTL = ext-rcode(1) | version(1) | flags(2), 모두 0.
        pkt.extend_from_slice(&0u32.to_be_bytes());

        // RDATA = OPTION-CODE + OPTION-LENGTH + OPTION-DATA.
        // OPTION-DATA = FAMILY(2) + SOURCE-PREFIX(1) + SCOPE-PREFIX(1) + ADDRESS.
        let option_data_len = 4 + subnet.addr_bytes.len();
        let rdlength = (4 + option_data_len) as u16; // OPTION-CODE(2)+OPTION-LENGTH(2)+data
        pkt.extend_from_slice(&rdlength.to_be_bytes());
        pkt.extend_from_slice(&EDNS_OPT_CLIENT_SUBNET.to_be_bytes()); // OPTION-CODE=8
        pkt.extend_from_slice(&(option_data_len as u16).to_be_bytes()); // OPTION-LENGTH
        pkt.extend_from_slice(&subnet.family.to_be_bytes()); // FAMILY
        pkt.push(subnet.source_prefix); // SOURCE PREFIX-LENGTH
        pkt.push(0); // SCOPE PREFIX-LENGTH (질의에서는 0)
        pkt.extend_from_slice(&subnet.addr_bytes); // ADDRESS (prefix 비트만)
    }

    Ok(pkt)
}

/// 호스트 이름을 DNS QNAME(라벨 길이-접두 + 0 종단)으로 인코딩한다.
fn encode_qname(pkt: &mut Vec<u8>, host: &str) -> Result<(), String> {
    // 후행 점은 무시하고, 빈 라벨은 허용하지 않는다.
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        // root — 종단 0만.
        pkt.push(0);
        return Ok(());
    }
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            return Err(format!("empty label in host name: {host:?}"));
        }
        if bytes.len() > 63 {
            return Err(format!("DNS label too long (>63): {label:?}"));
        }
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0); // 종단.
    Ok(())
}

/// DNS 응답에서 A/AAAA 레코드의 IP들을 파싱한다.
///
/// 헤더의 ANCOUNT만큼 RR을 읽되, NAME은 압축 포인터(0xC0..)일 수 있으므로 안전하게 스킵한다.
/// 모든 인덱싱 전에 경계를 검사해 패닉(슬라이스 OOB)을 방지한다.
fn parse_answers(buf: &[u8]) -> Result<Vec<IpAddr>, String> {
    if buf.len() < 12 {
        return Err(format!("response too short: {} bytes", buf.len()));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = 12usize;

    // Question 섹션을 건너뛴다: 각 question = QNAME + QTYPE(2) + QCLASS(2).
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        // QTYPE + QCLASS = 4바이트.
        pos = pos
            .checked_add(4)
            .ok_or_else(|| "question section overflow".to_string())?;
        if pos > buf.len() {
            return Err("truncated question section".to_string());
        }
    }

    // Answer 섹션의 각 RR을 읽는다.
    let mut ips = Vec::new();
    for _ in 0..ancount {
        // NAME (압축 포인터 가능).
        pos = skip_name(buf, pos)?;
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10바이트.
        let fixed_end = pos
            .checked_add(10)
            .ok_or_else(|| "rr header overflow".to_string())?;
        if fixed_end > buf.len() {
            return Err("truncated rr header".to_string());
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = fixed_end;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| "rdata overflow".to_string())?;
        if rdata_end > buf.len() {
            return Err("truncated rdata".to_string());
        }

        match rtype {
            QTYPE_A if rdlength == 4 => {
                let octets: [u8; 4] = [
                    buf[rdata_start],
                    buf[rdata_start + 1],
                    buf[rdata_start + 2],
                    buf[rdata_start + 3],
                ];
                ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            QTYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[rdata_start..rdata_end]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {
                // CNAME/기타 RR — 건너뛴다.
            }
        }
        pos = rdata_end;
    }

    Ok(ips)
}

/// Question 섹션을 건너뛰고 Answer 섹션 시작 위치와 ancount를 돌려준다.
fn answer_section_start(buf: &[u8]) -> Result<(usize, u16), String> {
    if buf.len() < 12 {
        return Err(format!("response too short: {} bytes", buf.len()));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos
            .checked_add(4)
            .ok_or_else(|| "question section overflow".to_string())?;
        if pos > buf.len() {
            return Err("truncated question section".to_string());
        }
    }
    Ok((pos, ancount))
}

/// 응답의 모든 TXT RR 문자열(세그먼트 이어붙임)을 반환한다.
fn parse_txt(buf: &[u8]) -> Result<Vec<String>, String> {
    let (mut pos, ancount) = answer_section_start(buf)?;
    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        let fixed_end = pos
            .checked_add(10)
            .ok_or_else(|| "rr header overflow".to_string())?;
        if fixed_end > buf.len() {
            return Err("truncated rr header".to_string());
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = fixed_end;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| "rdata overflow".to_string())?;
        if rdata_end > buf.len() {
            return Err("truncated rdata".to_string());
        }
        if rtype == QTYPE_TXT {
            // TXT RDATA = <len><bytes> 세그먼트들의 연속.
            let mut p = rdata_start;
            let mut s = String::new();
            while p < rdata_end {
                let seg_len = buf[p] as usize;
                p += 1;
                let seg_end = (p + seg_len).min(rdata_end);
                s.push_str(&String::from_utf8_lossy(&buf[p..seg_end]));
                p = seg_end;
            }
            out.push(s);
        }
        pos = rdata_end;
    }
    Ok(out)
}

/// 응답에서 첫 PTR RR의 도메인 네임을 반환한다 (없으면 None).
fn parse_ptr(buf: &[u8]) -> Result<Option<String>, String> {
    let (mut pos, ancount) = answer_section_start(buf)?;
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        let fixed_end = pos
            .checked_add(10)
            .ok_or_else(|| "rr header overflow".to_string())?;
        if fixed_end > buf.len() {
            return Err("truncated rr header".to_string());
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = fixed_end;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| "rdata overflow".to_string())?;
        if rdata_end > buf.len() {
            return Err("truncated rdata".to_string());
        }
        if rtype == QTYPE_PTR {
            let (name, _) = parse_name(buf, rdata_start)?;
            return Ok(Some(name));
        }
        pos = rdata_end;
    }
    Ok(None)
}

/// pos에서 시작하는 DNS NAME을 압축 포인터를 따라가며 문자열로 파싱한다.
/// 반환은 (이름, 압축 포인터를 처음 만나기 전까지 소비한 다음 위치).
fn parse_name(buf: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut next = start;
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 128 {
            return Err("name compression loop".to_string());
        }
        let len = *buf.get(pos).ok_or_else(|| "name length oob".to_string())?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    if !jumped {
                        next = pos + 1;
                    }
                    break;
                }
                let s = pos + 1;
                let e = s + len as usize;
                if e > buf.len() {
                    return Err("label oob".to_string());
                }
                labels.push(String::from_utf8_lossy(&buf[s..e]).into_owned());
                pos = e;
            }
            0xC0 => {
                let b2 = *buf.get(pos + 1).ok_or_else(|| "pointer oob".to_string())?;
                let ptr = (((len & 0x3F) as usize) << 8) | b2 as usize;
                if !jumped {
                    next = pos + 2;
                    jumped = true;
                }
                pos = ptr;
            }
            _ => return Err("invalid label type".to_string()),
        }
    }
    Ok((labels.join("."), next))
}

/// pos에서 시작하는 DNS NAME(라벨 시퀀스 또는 압축 포인터)을 건너뛰고 그 다음 위치를 반환한다.
///
/// - 0x00 라벨: 이름 종단.
/// - 상위 2비트가 11(0xC0..): 압축 포인터(2바이트). 포인터를 따라가지 않고 길이만 소비한다.
/// - 그 외: 길이-접두 라벨. 길이만큼 건너뛴다.
fn skip_name(buf: &[u8], start: usize) -> Result<usize, String> {
    let mut pos = start;
    loop {
        let len = *buf
            .get(pos)
            .ok_or_else(|| "name length byte out of bounds".to_string())?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    // 종단.
                    return pos
                        .checked_add(1)
                        .ok_or_else(|| "name terminator overflow".to_string());
                }
                // 일반 라벨: 길이 바이트 + 라벨 바이트.
                pos = pos
                    .checked_add(1 + len as usize)
                    .ok_or_else(|| "label overflow".to_string())?;
                if pos > buf.len() {
                    return Err("label exceeds buffer".to_string());
                }
            }
            0xC0 => {
                // 압축 포인터: 2바이트. 포인터를 따라가지 않고 소비만 한다.
                let after = pos
                    .checked_add(2)
                    .ok_or_else(|| "pointer overflow".to_string())?;
                if after > buf.len() {
                    return Err("compression pointer truncated".to_string());
                }
                return Ok(after);
            }
            _ => {
                // 0x40/0x80: 예약된 라벨 타입 — 손상된 패킷으로 본다.
                return Err(format!("reserved/invalid label type: 0x{len:02X}"));
            }
        }
    }
}

/// 트랜잭션 ID 생성기 — 새 의존성 없이 단조 카운터 + 시간 시드로 충분하다.
/// (보안 목적의 난수성이 아니라 응답 매칭/캐시 우회 정도의 변화만 필요하다.)
fn rand_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    seed ^ n ^ 0x55AA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_header_and_question() {
        // 고정 ID로 인코딩해 헤더/QNAME/QTYPE/QCLASS 바이트를 검증한다.
        let pkt = encode_query(0x1234, "example.com", QTYPE_A, None).expect("encode");

        // --- Header (12B) ---
        assert_eq!(&pkt[0..2], &[0x12, 0x34], "transaction id");
        assert_eq!(&pkt[2..4], &[0x01, 0x00], "flags RD=1");
        assert_eq!(&pkt[4..6], &[0x00, 0x01], "qdcount=1");
        assert_eq!(&pkt[6..8], &[0x00, 0x00], "ancount=0");
        assert_eq!(&pkt[8..10], &[0x00, 0x00], "nscount=0");
        assert_eq!(&pkt[10..12], &[0x00, 0x00], "arcount=0 (no ecs)");

        // --- Question: QNAME "example.com" ---
        // 7 'e''x''a''m''p''l''e' 3 'c''o''m' 0
        let expected_qname: &[u8] = &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let qname_end = 12 + expected_qname.len();
        assert_eq!(&pkt[12..qname_end], expected_qname, "qname labels");

        // QTYPE=A(1), QCLASS=IN(1).
        assert_eq!(&pkt[qname_end..qname_end + 2], &[0x00, 0x01], "qtype A");
        assert_eq!(
            &pkt[qname_end + 2..qname_end + 4],
            &[0x00, 0x01],
            "qclass IN"
        );

        // ECS 없으면 추가 RR이 없어 여기서 끝.
        assert_eq!(pkt.len(), qname_end + 4, "no trailing bytes without ecs");
    }

    #[test]
    fn encode_query_with_ecs_opt_rr() {
        // ECS가 있으면 ARCOUNT=1 + OPT RR이 붙는다.
        let ecs = parse_ecs("203.0.113.0/24").expect("parse ecs");
        assert_eq!(ecs.family, 1);
        assert_eq!(ecs.source_prefix, 24);
        // /24 → 3바이트 (203, 0, 113).
        assert_eq!(ecs.addr_bytes, vec![203, 0, 113]);

        let pkt = encode_query(0x0001, "example.com", QTYPE_A, Some(&ecs)).expect("encode");
        assert_eq!(&pkt[10..12], &[0x00, 0x01], "arcount=1 with ecs");

        // OPT RR은 패킷 끝쪽에 위치한다. NAME=root(0), TYPE=41.
        // 마지막 OPTION-DATA = FAMILY(0,1) SOURCE(24) SCOPE(0) ADDR(203,0,113).
        let tail = &pkt[pkt.len() - 7..];
        assert_eq!(
            tail,
            &[0x00, 0x01, 24, 0x00, 203, 0, 113],
            "ecs option data"
        );

        // OPT RR 헤더 TYPE=41(0x00,0x29)이 어딘가 존재해야 한다.
        assert!(
            pkt.windows(2).any(|w| w == [0x00, 0x29]),
            "OPT RR type present"
        );
    }

    #[test]
    fn parse_ecs_masks_partial_byte() {
        // /20은 마지막(3번째) 바이트의 상위 4비트만 유효 → 하위 4비트 마스킹.
        let ecs = parse_ecs("10.20.30.40/20").expect("parse");
        assert_eq!(ecs.source_prefix, 20);
        // ceil(20/8)=3 바이트. 3번째 바이트 30(0x1E) → 상위 4비트만: 0x10 = 16.
        assert_eq!(ecs.addr_bytes, vec![10, 20, 16]);
    }

    #[test]
    fn parse_answers_two_a_records_with_compression() {
        // 손으로 만든 응답 패킷: 질의 "a.com" A, 답변 A 레코드 2개.
        // 두 번째 답변 NAME은 첫 질의 이름을 가리키는 압축 포인터(0xC00C)를 사용한다.
        let mut p: Vec<u8> = Vec::new();

        // --- Header ---
        p.extend_from_slice(&[0x12, 0x34]); // id
        p.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
        p.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        p.extend_from_slice(&[0x00, 0x02]); // ancount=2
        p.extend_from_slice(&[0x00, 0x00]); // nscount=0
        p.extend_from_slice(&[0x00, 0x00]); // arcount=0

        // --- Question: "a.com" A IN --- (offset 12에서 시작)
        p.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0]); // QNAME
        p.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // --- Answer 1: NAME=ptr(0xC00C) -> offset 12, A IN, TTL=60, RDLENGTH=4, 1.2.3.4 ---
        p.extend_from_slice(&[0xC0, 0x0C]); // 압축 포인터 -> 12
        p.extend_from_slice(&[0x00, 0x01]); // TYPE A
        p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        p.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        p.extend_from_slice(&[1, 2, 3, 4]); // RDATA 1.2.3.4

        // --- Answer 2: NAME=ptr(0xC00C), A IN, TTL=60, RDLENGTH=4, 5.6.7.8 ---
        p.extend_from_slice(&[0xC0, 0x0C]); // 압축 포인터 -> 12
        p.extend_from_slice(&[0x00, 0x01]); // TYPE A
        p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        p.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        p.extend_from_slice(&[5, 6, 7, 8]); // RDATA 5.6.7.8

        let ips = parse_answers(&p).expect("parse");
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ]
        );
    }

    #[test]
    fn parse_answers_skips_cname_and_collects_aaaa() {
        // CNAME 답변 1개 + AAAA 답변 1개. CNAME은 무시되고 AAAA만 수집되어야 한다.
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(&[0x00, 0x01]); // id
        p.extend_from_slice(&[0x81, 0x80]); // flags
        p.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        p.extend_from_slice(&[0x00, 0x02]); // ancount=2
        p.extend_from_slice(&[0x00, 0x00]); // nscount
        p.extend_from_slice(&[0x00, 0x00]); // arcount

        // Question "h" AAAA IN. (offset 12)
        p.extend_from_slice(&[1, b'h', 0]); // QNAME "h"
        p.extend_from_slice(&[0x00, 0x1C]); // QTYPE AAAA(28)
        p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Answer 1: CNAME (TYPE=5). NAME=ptr(0xC00C). RDATA = "t" 0 (라벨 1개).
        p.extend_from_slice(&[0xC0, 0x0C]); // 포인터
        p.extend_from_slice(&[0x00, 0x05]); // TYPE CNAME
        p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        p.extend_from_slice(&[0x00, 0x03]); // RDLENGTH=3
        p.extend_from_slice(&[1, b't', 0]); // RDATA "t"

        // Answer 2: AAAA. NAME=ptr(0xC00C). RDATA = ::1.
        p.extend_from_slice(&[0xC0, 0x0C]); // 포인터
        p.extend_from_slice(&[0x00, 0x1C]); // TYPE AAAA
        p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        p.extend_from_slice(&[0x00, 0x10]); // RDLENGTH=16
        let v6 = Ipv6Addr::LOCALHOST.octets();
        p.extend_from_slice(&v6); // ::1

        let ips = parse_answers(&p).expect("parse");
        assert_eq!(ips, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }

    #[test]
    fn parse_answers_rejects_truncated() {
        // 짧은 버퍼는 패닉 없이 Err.
        assert!(parse_answers(&[0u8; 4]).is_err());
    }

    #[test]
    fn skip_name_handles_plain_and_pointer() {
        // 평범한 이름 "a" 0 → 3바이트 소비.
        let plain = [1u8, b'a', 0];
        assert_eq!(skip_name(&plain, 0).expect("plain"), 3);

        // 포인터 → 2바이트 소비 (따라가지 않음).
        let ptr = [0xC0u8, 0x0C];
        assert_eq!(skip_name(&ptr, 0).expect("ptr"), 2);

        // 경계 밖이면 Err (패닉 금지).
        assert!(skip_name(&[1u8, b'a'], 0).is_err());
    }

    #[test]
    fn validate_ecs_accepts_and_rejects() {
        assert!(validate_ecs("203.0.113.0/24").is_ok());
        assert!(validate_ecs("2001:db8::/48").is_ok());
        // 슬래시 없음 / 잘못된 prefix / 잘못된 IP → 에러.
        assert!(validate_ecs("203.0.113.0").is_err());
        assert!(validate_ecs("203.0.113.0/40").is_err());
        assert!(validate_ecs("not-an-ip/24").is_err());
    }

    #[tokio::test]
    async fn resolve_via_servers_empty_is_err() {
        // 서버가 없으면 네트워크 시도 없이 즉시 Err.
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        let r = resolve_via_servers(&[], "example.com", IpFamily::Auto, None, deadline).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn resolve_via_servers_bad_ecs_is_err() {
        // 잘못된 ECS CIDR은 네트워크 시도 전에 걸러진다.
        let server: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let deadline = TokioInstant::now() + Duration::from_millis(50);
        let r = resolve_via_servers(
            &[server],
            "example.com",
            IpFamily::Auto,
            Some("bad-cidr"),
            deadline,
        )
        .await;
        assert!(r.is_err());
    }
}
