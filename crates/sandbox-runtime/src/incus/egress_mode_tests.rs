//! Security-critical unit tests for the default-open egress ACL compiler,
//! the open / allowlist resolver renderers and the plan reference rule
//! (see docs/guide/network.md).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use sandbox_protocol::{EgressMode, EgressPolicy, SandboxErrorCode};

use super::dns::{
    allowlist_dnsmasq_base, base_dnsmasq_config, render_open_dnsmasq_config,
    render_published_dnsmasq_config,
};
use super::network::*;
use crate::egress::{
    DomainBlocklist, EgressRefusal, EgressSettings, MAX_ACL_BODY_BYTES, MAX_BLOCKED_DOMAINS,
    MAX_DNSMASQ_BODY_BYTES, sandbox_public_v4_text,
};

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 1);

fn limits() -> CompileLimits<'static> {
    CompileLimits {
        deadline: Instant::now() + Duration::from_secs(5),
        cancelled: None,
    }
}

fn policy(mode: EgressMode, domains: &[&str], cidrs: &[&str]) -> (EgressPolicy, String) {
    let policy = EgressPolicy {
        mode,
        domains: domains.iter().map(|d| d.to_string()).collect(),
        cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
    };
    let hash = policy_hash_hex(&policy);
    (policy, hash)
}

fn settings(block_smtp: bool, block_external_dns: bool) -> EgressSettings {
    EgressSettings {
        block_smtp,
        block_external_dns,
        ..Default::default()
    }
}

fn compile_with(
    policy: &EgressPolicy,
    hash: &str,
    settings: &EgressSettings,
    resolve: DomainResolver,
) -> Result<SandboxNetworkPlan, crate::RuntimeError> {
    compile_network_plan_with(
        "sbx-1",
        Some(policy),
        Some(hash),
        settings,
        resolve,
        GATEWAY,
        &limits(),
    )
}

fn no_dns(_: &str, _: Duration) -> Result<Vec<IpAddr>, crate::RuntimeError> {
    panic!("this plan must not resolve domains")
}

fn open_plan(settings: &EgressSettings) -> SandboxNetworkPlan {
    let (policy, hash) = policy(EgressMode::Open, &[], &[]);
    compile_with(&policy, &hash, settings, &no_dns).expect("open plan")
}

fn allowlist_plan(settings: &EgressSettings) -> SandboxNetworkPlan {
    let (policy, hash) = policy(
        EgressMode::Allowlist,
        &["mail.example.com"],
        &["128.66.0.0/24"],
    );
    compile_with(&policy, &hash, settings, &|_, _| {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    })
    .expect("allowlist plan")
}

/// Compact golden form: `direction action [protocol] destination|- [dport] tag`
/// with the PUBLIC_V4 list abbreviated.
fn golden(plan: &SandboxNetworkPlan) -> Vec<String> {
    let public = sandbox_public_v4_text().unwrap();
    plan.rules
        .iter()
        .map(|rule| {
            let destination = rule
                .destination
                .as_deref()
                .or(rule.source.as_deref())
                .unwrap_or("-");
            let destination = if destination == public {
                "PUBLIC_V4"
            } else {
                destination
            };
            format!(
                "{} {} {} {} {} {}",
                rule.direction.as_str(),
                rule.action.as_str(),
                rule.protocol.as_deref().unwrap_or("any"),
                destination,
                rule.destination_port.as_deref().unwrap_or("-"),
                rule.description
            )
        })
        .collect()
}

const INFRA_EGRESS: [&str; 3] = [
    "egress allow udp 255.255.255.255/32 67 wssp-dhcp",
    "egress allow udp 10.9.9.1/32 53 wssp-dns-udp",
    "egress allow tcp 10.9.9.1/32 53 wssp-dns-tcp",
];
const INFRA_INGRESS: [&str; 3] = [
    "ingress allow udp 10.9.9.1/32 68 wssp-dhcp-reply",
    "ingress allow udp 10.9.9.1/32 - wssp-dns-udp-reply",
    "ingress allow tcp 10.9.9.1/32 - wssp-dns-tcp-reply",
];
const EXT_DNS: [&str; 2] = [
    "egress reject tcp PUBLIC_V4 53,853 wssp-extdns-reject",
    "egress reject udp PUBLIC_V4 53,853 wssp-extdns-reject",
];
const SMTP: &str = "egress reject tcp PUBLIC_V4 25 wssp-smtp-reject";

fn expected(middle: &[&str]) -> Vec<String> {
    INFRA_EGRESS
        .iter()
        .chain(middle)
        .chain(INFRA_INGRESS.iter())
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn open_mode_rule_goldens_with_and_without_the_setting_rejects() {
    let open = "egress allow any PUBLIC_V4 - wssp-open";
    for (smtp, ext, middle) in [
        (false, false, vec![open]),
        (true, false, vec![open, SMTP]),
        (false, true, vec![open, EXT_DNS[0], EXT_DNS[1]]),
        (true, true, vec![open, EXT_DNS[0], EXT_DNS[1], SMTP]),
    ] {
        let plan = open_plan(&settings(smtp, ext));
        assert_eq!(golden(&plan), expected(&middle), "smtp={smtp} ext={ext}");
        assert_eq!(plan.mode, EgressMode::Open);
        assert!(plan.grants.is_empty());
        assert_eq!(plan.settings, Some(settings(smtp, ext)));
    }
}

#[test]
fn allowlist_mode_rule_goldens_with_and_without_the_setting_rejects() {
    let grant = "egress allow any 128.66.0.0/24 - wssp-grant";
    let tag = dns_tag_hex("mail.example.com");
    let domain = [
        format!("egress reject udp 93.184.216.34/32 53 wssp-dns-reject-g0-{tag}"),
        format!("egress reject tcp 93.184.216.34/32 53 wssp-dns-reject-g0-{tag}"),
        format!("egress reject tcp 93.184.216.34/32 853 wssp-dns-reject-g0-{tag}"),
        format!("egress allow any 93.184.216.34/32 - wssp-dns-g0-{tag}"),
    ];
    for (smtp, ext, setting) in [
        (false, false, vec![]),
        (true, false, vec![SMTP]),
        (false, true, vec![EXT_DNS[0], EXT_DNS[1]]),
        (true, true, vec![EXT_DNS[0], EXT_DNS[1], SMTP]),
    ] {
        let plan = allowlist_plan(&settings(smtp, ext));
        let mut middle: Vec<&str> = vec![grant];
        middle.extend(setting);
        middle.extend(domain.iter().map(String::as_str));
        assert_eq!(golden(&plan), expected(&middle), "smtp={smtp} ext={ext}");
        assert_eq!(plan.mode, EgressMode::Allowlist);
        assert_eq!(plan.dnsmasq_base, base_dnsmasq_config());
    }
}

#[test]
fn every_reject_is_confined_to_public_v4_in_both_modes() {
    // Property over compiled plans: every reject destination ⊂ PUBLIC_V4, so
    // disjoint from the protected set, the bridge /24 and the gateway.
    let grant_sets: [&[&str]; 4] = [
        &[],
        &["128.66.0.0/24"],
        &["1.0.0.0/8", "8.8.8.8/32"],
        &["93.184.216.0/24"],
    ];
    for smtp in [false, true] {
        for ext in [false, true] {
            let s = settings(smtp, ext);
            let mut plans = vec![open_plan(&s)];
            for cidrs in grant_sets {
                let (policy, hash) = policy(EgressMode::Allowlist, &["a.example.com"], cidrs);
                plans.push(
                    compile_with(&policy, &hash, &s, &|_, _| {
                        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
                    })
                    .unwrap(),
                );
            }
            for plan in plans {
                public_v4_invariant(&plan.rules).expect("invariant");
                let bridge = (u32::from(GATEWAY) & 0xffff_ff00, 24u8);
                for rule in plan
                    .rules
                    .iter()
                    .filter(|rule| rule.action == AclAction::Reject)
                {
                    for part in rule.destination.as_deref().unwrap().split(',') {
                        let net = crate::egress::parse_ipv4_net(part).unwrap();
                        assert!(!crate::egress::nets_intersect(net, bridge), "{part}");
                        for protected in crate::egress::sandbox_protected_v4().unwrap() {
                            assert!(!crate::egress::nets_intersect(net, *protected), "{part}");
                        }
                    }
                }
            }
        }
    }
    // The invariant itself refuses a reject touching protected space.
    let mut plan = open_plan(&settings(true, false));
    plan.rules.push(AclRule {
        action: AclAction::Reject,
        direction: AclDirection::Egress,
        protocol: None,
        source: None,
        destination: Some("10.0.0.0/8".into()),
        source_port: None,
        destination_port: None,
        description: "evil".into(),
    });
    assert!(public_v4_invariant(&plan.rules).is_err());
}

fn pkt(protocol: Option<&'static str>, destination: &str, dport: Option<u16>) -> Packet {
    Packet {
        from_guest: true,
        established_reply: false,
        protocol,
        source: "10.9.9.50".parse().unwrap(),
        destination: destination.parse().unwrap(),
        source_port: Some(40000),
        destination_port: dport,
    }
}

#[test]
fn open_mode_packet_model() {
    let plan = open_plan(&settings(true, false));
    // Allowed: public TCP/UDP/ICMP, QUIC, public DNS while 2c is off.
    for packet in [
        pkt(Some("tcp"), "1.1.1.1", Some(443)),
        pkt(Some("udp"), "1.1.1.1", Some(443)),
        pkt(Some("icmp4"), "1.1.1.1", None),
        pkt(Some("udp"), "8.8.8.8", Some(53)),
        pkt(Some("tcp"), "9.9.9.9", Some(853)),
        pkt(Some("tcp"), "168.63.129.15", Some(80)),
        pkt(Some("tcp"), "100.128.0.1", Some(80)),
    ] {
        assert!(plan_allows(&plan, &packet), "{packet:?}");
    }
    // Dropped by the default: private, loopback, metadata, wireserver,
    // tailnet/CGNAT, other gateway ports, IPv6.
    for packet in [
        pkt(Some("tcp"), "10.0.0.5", Some(22)),
        pkt(Some("tcp"), "172.16.1.1", Some(80)),
        pkt(Some("tcp"), "192.168.1.1", Some(80)),
        pkt(Some("tcp"), "127.0.0.1", Some(80)),
        pkt(Some("tcp"), "169.254.169.254", Some(80)),
        pkt(Some("tcp"), "168.63.129.16", Some(80)),
        pkt(Some("tcp"), "100.100.100.200", Some(80)),
        pkt(Some("tcp"), "100.64.1.2", Some(22)),
        pkt(Some("tcp"), "10.9.9.1", Some(22)),
        pkt(Some("tcp"), "2606:4700::1111", Some(443)),
    ] {
        assert!(!plan_allows(&plan, &packet), "{packet:?}");
    }
    // Gateway services still work.
    assert!(plan_allows(&plan, &pkt(Some("udp"), "10.9.9.1", Some(53))));
    // Rejected: SMTP in open mode.
    assert!(!plan_allows(&plan, &pkt(Some("tcp"), "1.2.3.4", Some(25))));
    assert!(plan_allows(&plan, &pkt(Some("tcp"), "1.2.3.4", Some(587))));
    // 2c on: public DNS/DoT rejected, the gateway resolver still allowed.
    let plan = open_plan(&settings(true, true));
    for packet in [
        pkt(Some("udp"), "8.8.8.8", Some(53)),
        pkt(Some("tcp"), "8.8.8.8", Some(53)),
        pkt(Some("tcp"), "1.1.1.1", Some(853)),
        pkt(Some("udp"), "1.1.1.1", Some(853)),
    ] {
        assert!(!plan_allows(&plan, &packet), "{packet:?}");
    }
    assert!(plan_allows(&plan, &pkt(Some("udp"), "10.9.9.1", Some(53))));
    assert!(plan_allows(&plan, &pkt(Some("tcp"), "10.9.9.1", Some(53))));
}

#[test]
fn allowlist_mode_packet_model() {
    let plan = allowlist_plan(&settings(true, false));
    // Granted destinations allowed; tcp/25 rejected even to a granted
    // address (M12), submission ports still allowed.
    assert!(plan_allows(
        &plan,
        &pkt(Some("tcp"), "128.66.0.9", Some(443))
    ));
    assert!(plan_allows(
        &plan,
        &pkt(Some("tcp"), "93.184.216.34", Some(587))
    ));
    assert!(!plan_allows(
        &plan,
        &pkt(Some("tcp"), "93.184.216.34", Some(25))
    ));
    assert!(!plan_allows(
        &plan,
        &pkt(Some("tcp"), "128.66.0.9", Some(25))
    ));
    // Non-granted public destinations dropped.
    assert!(!plan_allows(&plan, &pkt(Some("tcp"), "1.1.1.1", Some(443))));
    // SMTP setting off: the granted mail host is reachable on 25.
    let plan = allowlist_plan(&settings(false, false));
    assert!(plan_allows(
        &plan,
        &pkt(Some("tcp"), "128.66.0.9", Some(25))
    ));
    // 2c applies in allowlist mode too: a CIDR grant no longer carries DNS.
    let plan = allowlist_plan(&settings(true, true));
    assert!(!plan_allows(
        &plan,
        &pkt(Some("udp"), "128.66.0.9", Some(53))
    ));
    assert!(plan_allows(&plan, &pkt(Some("udp"), "10.9.9.1", Some(53))));
}

#[test]
fn an_open_policy_carrying_grants_is_refused() {
    let (policy, hash) = policy(EgressMode::Open, &[], &["128.66.0.0/24"]);
    let err = compile_with(&policy, &hash, &EgressSettings::default(), &no_dns).unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::ProtocolError);
}

fn deny_settings(names: &[&str]) -> EgressSettings {
    EgressSettings {
        domain_blocklist: DomainBlocklist {
            root_digest: Some("sha256:root".into()),
            deployment_digest: None,
            names: names.iter().map(|n| n.to_string()).collect(),
        },
        ..Default::default()
    }
}

#[test]
fn denied_grants_are_never_resolved_allowed_or_published() {
    let s = deny_settings(&["bad.example"]);
    let (policy, hash) = policy(
        EgressMode::Allowlist,
        &[
            "bad.example",
            "api.bad.example",
            "good.example",
            "example.com",
        ],
        &[],
    );
    let resolved = std::sync::Mutex::new(Vec::new());
    let plan = compile_with(&policy, &hash, &s, &|name, _| {
        resolved.lock().unwrap().push(name.to_string());
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    })
    .unwrap();
    assert_eq!(
        *resolved.lock().unwrap(),
        vec!["good.example".to_string(), "example.com".to_string()]
    );
    assert_eq!(plan.denied_grants, vec!["bad.example", "api.bad.example"]);
    let names: Vec<&str> = plan
        .resolved_domains
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    assert_eq!(names, vec!["good.example", "example.com"]);
    for denied in ["bad.example", "api.bad.example"] {
        let tag = dns_tag_hex(denied);
        assert!(
            plan.rules
                .iter()
                .all(|rule| !rule.description.contains(&tag)),
            "{denied} has no rule"
        );
    }
    // The policy identity is unchanged: the denied names stay recorded.
    assert_eq!(plan.policy_domains, policy.domains);
    // Allowlist base carries NXDOMAIN for the blocked domain.
    assert_eq!(
        plan.dnsmasq_base,
        format!("{}local=/bad.example/\n", base_dnsmasq_config())
    );
    // An open request's fallback grants on a forcing node are this same
    // allowlist policy, so they get the same treatment by construction.
}

#[test]
fn the_publication_boundary_refuses_a_denied_name() {
    let s = deny_settings(&["bad.example"]);
    let answers = vec![(
        "api.bad.example".to_string(),
        vec![Ipv4Addr::new(93, 184, 216, 34)],
    )];
    assert!(render_published_dnsmasq_config(&answers, 300, Some(&s)).is_err());
    let answers = vec![(
        "good.example".to_string(),
        vec![Ipv4Addr::new(93, 184, 216, 34)],
    )];
    let body = render_published_dnsmasq_config(&answers, 300, Some(&s)).unwrap();
    assert!(body.contains("host-record=good.example,93.184.216.34\n"));
    assert!(body.ends_with("local=/bad.example/\n"));
    // Legacy records (no settings) render exactly as before.
    assert_eq!(
        render_published_dnsmasq_config(&answers, 300, None).unwrap(),
        super::dns::render_dnsmasq_config(&answers, 300)
    );
}

#[test]
fn open_renderer_with_and_without_upstreams() {
    let body = render_open_dnsmasq_config(&EgressSettings::default()).unwrap();
    assert_eq!(
        body,
        "# wssp managed sandbox DNS (open egress)\nstop-dns-rebind\nbogus-priv\n\
         domain-needed\nno-hosts\ndns-forward-max=64\n"
    );
    assert!(!body.contains("no-resolv"));
    let s = EgressSettings {
        dns_upstreams: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)],
        ..deny_settings(&["bad.example", "worse.example"])
    };
    let body = render_open_dnsmasq_config(&s).unwrap();
    assert!(body.ends_with(
        "dns-forward-max=64\nno-resolv\nserver=9.9.9.9\nserver=1.1.1.1\n\
         local=/bad.example/\nlocal=/worse.example/\n"
    ));
    // m13: allowlist rendering ignores the upstreams.
    assert_eq!(
        allowlist_dnsmasq_base(&EgressSettings {
            dns_upstreams: vec![Ipv4Addr::new(9, 9, 9, 9)],
            ..Default::default()
        })
        .unwrap(),
        base_dnsmasq_config()
    );
    let (policy, hash) = policy(EgressMode::Open, &[], &[]);
    let plan = compile_with(&policy, &hash, &s, &no_dns).unwrap();
    assert_eq!(plan.dnsmasq_base, body);
}

/// A label of `len` chars from `seed` (valid DNS label characters).
fn label(seed: usize, len: usize) -> String {
    let mut out = format!("d{seed}");
    while out.len() < len {
        out.push('x');
    }
    out
}

#[test]
fn renderer_size_cap_at_exactly_64_kib_and_one_byte_over() {
    let header = render_open_dnsmasq_config(&EgressSettings::default())
        .unwrap()
        .len();
    // Each `local=/<name>/\n` line is name + 9 bytes. Fill with long names,
    // then size the last one to land exactly on the bound.
    let mut names = Vec::new();
    let mut total = header;
    let mut i = 0;
    let long = |i: usize| format!("{}.{}.example", label(i, 63), label(i, 63));
    while total + long(i).len() + 9 + 100 <= MAX_DNSMASQ_BODY_BYTES {
        total += long(i).len() + 9;
        names.push(long(i));
        i += 1;
    }
    // The last name takes exactly the remaining bytes (≤ 253, labels ≤ 63).
    let remaining = MAX_DNSMASQ_BODY_BYTES - total - 9;
    let mut name = String::from("example");
    let mut n = 0;
    while name.len() < remaining {
        let room = remaining - name.len() - 1;
        name = format!("{}.{name}", label(i * 10 + n, room.clamp(2, 63)));
        n += 1;
    }
    assert_eq!(name.len(), remaining);
    assert!(name.len() <= 253);
    names.push(name);
    let at = deny_settings(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let body = render_open_dnsmasq_config(&at).unwrap();
    assert_eq!(body.len(), MAX_DNSMASQ_BODY_BYTES);
    let last = names.pop().unwrap();
    names.push(format!("x{last}"));
    let over = deny_settings(&names.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(render_open_dnsmasq_config(&over).is_err());
    assert!(allowlist_dnsmasq_base(&over).is_err());
}

#[test]
fn blocklist_of_2048_domains_renders_and_2049_is_refused() {
    let names: Vec<String> = (0..MAX_BLOCKED_DOMAINS)
        .map(|i| format!("d{i}.example"))
        .collect();
    let s = deny_settings(&names.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(render_open_dnsmasq_config(&s).is_ok());
    let mut names = names;
    names.push("one-more.example".into());
    let s = deny_settings(&names.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(render_open_dnsmasq_config(&s).is_err());
}

#[test]
fn a_private_answer_and_nxdomain_fail_the_grant_identically() {
    let (policy, hash) = policy(EgressMode::Allowlist, &["internal.example"], &[]);
    let private = compile_with(&policy, &hash, &EgressSettings::default(), &|_, _| {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))])
    })
    .unwrap_err();
    let nxdomain = compile_with(&policy, &hash, &EgressSettings::default(), &|_, _| {
        Err(crate::RuntimeError::new(
            SandboxErrorCode::Internal,
            "Name or service not known",
        ))
    })
    .unwrap_err();
    let empty = compile_with(&policy, &hash, &EgressSettings::default(), &|_, _| {
        Ok(vec![])
    })
    .unwrap_err();
    for err in [&private, &nxdomain, &empty] {
        assert_eq!(err.code, SandboxErrorCode::EgressResolutionFailed);
        assert_eq!(err.message, private.message);
    }
}

/// The measured worst-case ACL bodies (m12). Policy limits are 128 domains
/// and 128 CIDRs; a domain's address count is bounded only by the record
/// bound. Printed for the report (`--no-capture`).
#[test]
fn acl_body_worst_cases_are_measured_against_the_bounds() {
    let public = sandbox_public_v4_text().unwrap();
    assert_eq!(public.len(), 1931);
    let cidrs: Vec<String> = (0..128).map(|i| format!("44.{i}.0.0/24")).collect();
    let cidr_refs: Vec<&str> = cidrs.iter().map(String::as_str).collect();
    let all = settings(true, true);
    // Open mode, both setting families: constant overhead, no grants.
    let open = open_plan(&all);
    let open_bytes = acl_put_body_bytes("sbx-1", &open.rules);
    // Allowlist: 128 CIDRs, both families, no domains.
    let (p, h) = policy(EgressMode::Allowlist, &[], &cidr_refs);
    let cidr_only = compile_with(&p, &h, &all, &no_dns).unwrap();
    let cidr_bytes = acl_put_body_bytes("sbx-1", &cidr_only.rules);
    // One resolved record (reject companions + allow) at worst-case tags.
    let (p1, h1) = policy(EgressMode::Allowlist, &["d0.example.com"], &[]);
    let one = compile_with(&p1, &h1, &all, &|_, _| {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(223, 255, 255, 254))])
    })
    .unwrap();
    let (p0, h0) = policy(EgressMode::Allowlist, &[], &[]);
    let zero = compile_with(&p0, &h0, &all, &no_dns).unwrap();
    let per_record =
        acl_put_body_bytes("sbx-1", &one.rules) - acl_put_body_bytes("sbx-1", &zero.rules);
    let records_at_64k = (MAX_ACL_BODY_BYTES - cidr_bytes) / per_record;
    let worst_128x1 = cidr_bytes + 128 * per_record;
    eprintln!(
        "ACL body: open+2c+2d={open_bytes} B; allowlist 128 CIDRs+2c+2d={cidr_bytes} B; \
         +{per_record} B per resolved record; records that fit 64 KiB beside 128 CIDRs: \
         {records_at_64k}; 128 CIDRs + 128 domains x 1 address = {worst_128x1} B; \
         x 4096 records = {} B",
        cidr_bytes + 4096 * per_record
    );
    assert!(open_bytes < 16 * 1024, "{open_bytes}");
    assert!(cidr_bytes < 32 * 1024, "{cidr_bytes}");
    // The worst case inside today's policy limits does NOT fit the bound:
    // it is enforced per compiled policy instead (refusal, never truncation).
    assert!(worst_128x1 > MAX_ACL_BODY_BYTES);
}

#[test]
fn acl_body_bound_at_exactly_64_kib_compiles_and_one_byte_over_is_refused() {
    let all = settings(true, true);
    let open = open_plan(&all);
    let base = acl_put_body_bytes("sbx-1", &open.rules);
    // Pad one static rule's description to land exactly on the bound.
    let pad_rule = |len: usize| AclRule {
        action: AclAction::Allow,
        direction: AclDirection::Ingress,
        protocol: None,
        source: Some("10.9.9.1/32".into()),
        destination: None,
        source_port: None,
        destination_port: None,
        description: "p".repeat(len),
    };
    let mut rules = open.rules.clone();
    rules.push(pad_rule(0));
    let empty = acl_put_body_bytes("sbx-1", &rules);
    assert!(empty > base);
    let fill = MAX_ACL_BODY_BYTES - empty;
    *rules.last_mut().unwrap() = pad_rule(fill);
    assert_eq!(acl_put_body_bytes("sbx-1", &rules), MAX_ACL_BODY_BYTES);
    assert!(check_acl_body_bound("sbx-1", &rules).is_ok());
    *rules.last_mut().unwrap() = pad_rule(fill + 1);
    let err = check_acl_body_bound("sbx-1", &rules).unwrap_err();
    assert_eq!(err.egress_refusal(), Some(EgressRefusal::PolicyTooLarge));
    assert_eq!(err.code, SandboxErrorCode::RequestTooLarge);
}

/// Coordinator ruling (byte budget): the refresh recompiles the body it
/// would leave installed; exactly at 64 KiB it publishes, one byte over it
/// keeps the last-good rules with `egress_refresh_over_budget`.
#[test]
fn refresh_budget_at_exactly_64_kib_publishes_and_one_byte_over_keeps_last_good() {
    let plan = allowlist_plan(&settings(true, true));
    let answers = vec![(
        "mail.example.com".to_string(),
        vec![
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(93, 184, 216, 35),
        ],
    )];
    let cidrs = vec!["128.66.0.0/24".to_string()];
    // The recorded rules carry the old DNS rules; the recompile replaces them.
    let pad = |len: usize| AclRule {
        action: AclAction::Allow,
        direction: AclDirection::Ingress,
        protocol: None,
        source: Some("10.9.9.1/32".into()),
        destination: None,
        source_port: None,
        destination_port: None,
        description: "p".repeat(len),
    };
    let mut recorded = plan.rules.clone();
    recorded.push(pad(0));
    let empty = refresh_acl_body_bytes("sbx-1", &recorded, &cidrs, &answers);
    let fill = MAX_ACL_BODY_BYTES - empty;
    *recorded.last_mut().unwrap() = pad(fill);
    let at = refresh_acl_body_bytes("sbx-1", &recorded, &cidrs, &answers);
    assert_eq!(at, MAX_ACL_BODY_BYTES);
    assert!(check_refresh_budget(at).is_ok());
    *recorded.last_mut().unwrap() = pad(fill + 1);
    let over = refresh_acl_body_bytes("sbx-1", &recorded, &cidrs, &answers);
    assert_eq!(over, MAX_ACL_BODY_BYTES + 1);
    let err = check_refresh_budget(over).unwrap_err();
    assert_eq!(err.egress_refusal(), Some(EgressRefusal::RefreshOverBudget));
    // The old DNS rules in the record never count twice: dropping the second
    // answer shrinks the measured body by exactly one record's rules.
    let one = vec![(
        "mail.example.com".to_string(),
        vec![Ipv4Addr::new(93, 184, 216, 34)],
    )];
    assert!(refresh_acl_body_bytes("sbx-1", &recorded, &cidrs, &one) < over);
}

/// CLI logins proxy mode combined with both modes:
/// the proxy port on the sandbox's own gateway is reachable over TCP, every
/// other gateway port (and UDP to the proxy port) stays dropped, no reject
/// ever covers the gateway, and a gateway rebind moves the allow with it.
#[test]
fn the_credential_proxy_allow_reaches_only_the_proxy_port_in_both_modes() {
    let gateway = GATEWAY.to_string();
    for (smtp, ext) in [(true, false), (true, true), (false, false)] {
        let with_proxy = EgressSettings {
            credential_proxy_port: Some(48080),
            ..settings(smtp, ext)
        };
        for plan in [open_plan(&with_proxy), allowlist_plan(&with_proxy)] {
            public_v4_invariant(&plan.rules).expect("invariant");
            assert!(
                golden(&plan).contains(&format!(
                    "egress allow tcp {gateway}/32 48080 wssp-credential-proxy"
                )),
                "{:#?}",
                golden(&plan)
            );
            assert!(plan_allows(&plan, &pkt(Some("tcp"), &gateway, Some(48080))));
            for packet in [
                pkt(Some("tcp"), &gateway, Some(48081)),
                pkt(Some("tcp"), &gateway, Some(22)),
                pkt(Some("tcp"), &gateway, Some(8080)),
                pkt(Some("udp"), &gateway, Some(48080)),
                // Another bridge's gateway on the proxy port.
                pkt(Some("tcp"), "10.9.8.1", Some(48080)),
            ] {
                assert!(!plan_allows(&plan, &packet), "{packet:?}");
            }
            // The gateway services still work beside it.
            assert!(plan_allows(&plan, &pkt(Some("udp"), &gateway, Some(53))));
        }
        // Without a proxied login there is no allow on that port.
        for plan in [
            open_plan(&settings(smtp, ext)),
            allowlist_plan(&settings(smtp, ext)),
        ] {
            assert!(!plan_allows(
                &plan,
                &pkt(Some("tcp"), &gateway, Some(48080))
            ));
        }
    }
    let mut plan = open_plan(&EgressSettings {
        credential_proxy_port: Some(48080),
        ..EgressSettings::default()
    });
    let moved = Ipv4Addr::new(10, 7, 7, 1);
    plan.set_gateway(moved);
    let rule = plan
        .rules
        .iter()
        .find(|rule| rule.description == "wssp-credential-proxy")
        .unwrap();
    assert_eq!(rule.destination.as_deref(), Some("10.7.7.1/32"));
}

#[test]
fn a_credential_proxy_port_aliasing_a_gateway_service_is_refused() {
    for port in [0, 53, 67] {
        let bad = EgressSettings {
            credential_proxy_port: Some(port),
            ..EgressSettings::default()
        };
        assert!(bad.validate().is_err(), "{port}");
    }
}
