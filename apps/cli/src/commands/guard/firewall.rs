//! `wssp guard install --configure-ufw` / `--configure-firewalld` and the
//! matching `uninstall` flags (docs/guide/hosts.md#host-firewall-ufwfirewalld).
//!
//! Opt-in only. Adds the minimal host-firewall rules a sandbox bridge
//! (`wsn-*`) needs and nothing more: DHCP (67/udp), DNS (53/udp and tcp) and
//! the login proxy (`credential_proxy_port`, tcp) in from the bridges, and
//! routing in and out of them. The egress guard still enforces every block
//! on top. Every command is printed before it runs. Idempotent: rules that
//! already exist are skipped, and a broad "allow everything in on wsn+"
//! rule is replaced by the tight set (announced first). Every rule carries
//! [`MANAGED_COMMENT`], and uninstall removes only those.

use std::time::Duration;

use anyhow::{Result, bail};

use super::tools;

/// The tag on every rule wssp adds (ufw comment, firewalld description).
pub const MANAGED_COMMENT: &str = "wssp-guard managed";
/// firewalld zone and policy wssp owns.
pub const FIREWALLD_ZONE: &str = "wssp-guard";
pub const FIREWALLD_POLICY: &str = "wssp-guard-out";

const TIMEOUT: Duration = Duration::from_secs(60);

/// Runs host firewall tools on a fixed PATH ([`tools::SYSTEM_PATH`] in
/// production, a fake tool directory in tests).
pub struct Host {
    pub path: String,
}

impl Host {
    pub fn system() -> Self {
        Self {
            path: tools::SYSTEM_PATH.to_string(),
        }
    }

    fn run(&self, program: &str, args: &[String]) -> Result<tools::ToolOutput> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        tools::run_on(&self.path, program, &args, None, TIMEOUT)
    }

    fn run_ok(&self, program: &str, args: &[String]) -> Result<tools::ToolOutput> {
        let output = self.run(program, args)?;
        if !output.success {
            bail!(
                "`{program} {}` failed: {}",
                args.join(" "),
                output.stderr_line()
            );
        }
        Ok(output)
    }
}

fn words(spec: &str) -> Vec<String> {
    spec.split_whitespace().map(str::to_string).collect()
}

/// The tight ufw rule set, as `ufw` arguments without the comment.
pub fn ufw_rules(proxy_port: u16) -> Vec<String> {
    vec![
        "allow in on wsn+ to any port 67 proto udp".into(),
        "allow in on wsn+ to any port 53 proto udp".into(),
        "allow in on wsn+ to any port 53 proto tcp".into(),
        format!("allow in on wsn+ to any port {proxy_port} proto tcp"),
        "route allow in on wsn+".into(),
        "route allow out on wsn+".into(),
    ]
}

/// The broad rule wssp replaces with the tight set.
const UFW_BROAD: &str = "allow in on wsn+";

/// One `ufw show added` line: its rule spec without the `ufw ` prefix and
/// the comment, and whether it is wssp's.
fn parse_added(line: &str) -> Option<(String, bool)> {
    let rest = line.trim().strip_prefix("ufw ")?;
    let (spec, comment) = match rest.find(" comment ") {
        Some(at) => (&rest[..at], Some(&rest[at + " comment ".len()..])),
        None => (rest, None),
    };
    let managed = comment
        .map(|c| c.trim_matches(|ch| ch == '\'' || ch == '"'))
        .is_some_and(|c| c == MANAGED_COMMENT);
    Some((words(spec).join(" "), managed))
}

fn ufw_added(host: &Host) -> Result<Vec<(String, bool)>> {
    let output = host
        .run("ufw", &words("show added"))
        .map_err(|_| anyhow::anyhow!("`--configure-ufw`: ufw is not installed on this node"))?;
    if !output.success {
        bail!("`ufw show added` failed: {}", output.stderr_line());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_added)
        .collect())
}

/// A parsed `ufw` rule on the sandbox bridges.
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    /// `allow in on wsn+ [proto P] [port N]` (no port: the broad rule).
    Allow { port: Option<u16>, proto: Proto },
    /// `route allow in|out on wsn+`.
    Route(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Any,
    Udp,
    Tcp,
}

/// Understand the shapes ufw prints for rules on `wsn+`; anything else
/// (other interfaces, sources, actions) is `None` and never touched.
fn parse_spec(spec: &str) -> Option<Parsed> {
    let mut tokens = spec.split_whitespace().peekable();
    let route = tokens.next_if_eq(&"route").is_some();
    if tokens.next()? != "allow" {
        return None;
    }
    let direction = tokens.next()?;
    if !matches!(direction, "in" | "out") || tokens.next()? != "on" || tokens.next()? != "wsn+" {
        return None;
    }
    let (mut port, mut proto) = (None, Proto::Any);
    while let Some(token) = tokens.next() {
        match token {
            "to" | "from" => {
                if tokens.next()? != "any" {
                    return None;
                }
            }
            "any" => {}
            "port" => port = Some(tokens.next()?.parse().ok()?),
            "proto" => {
                proto = match tokens.next()? {
                    "udp" => Proto::Udp,
                    "tcp" => Proto::Tcp,
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    if route {
        return (port.is_none() && proto == Proto::Any)
            .then(|| Parsed::Route(direction.to_string()));
    }
    (direction == "in").then_some(Parsed::Allow { port, proto })
}

/// The (port, protocol) pairs a port rule opens.
fn pairs(port: u16, proto: Proto) -> Vec<(u16, Proto)> {
    match proto {
        Proto::Any => vec![(port, Proto::Udp), (port, Proto::Tcp)],
        one => vec![(port, one)],
    }
}

/// Whether an untagged rule only repeats what the tight set already opens
/// (the same rule, or a wider spelling of it such as `53` for 53/udp +
/// 53/tcp), so the tagged set can replace it exactly.
fn is_covered_by(spec: &str, wanted: &[String]) -> bool {
    let Some(parsed) = parse_spec(spec) else {
        return false;
    };
    let wanted: Vec<Parsed> = wanted.iter().filter_map(|w| parse_spec(w)).collect();
    match parsed {
        Parsed::Route(direction) => wanted.contains(&Parsed::Route(direction)),
        Parsed::Allow { port: None, .. } => false,
        Parsed::Allow {
            port: Some(port),
            proto,
        } => {
            let opened: Vec<(u16, Proto)> = wanted
                .iter()
                .filter_map(|w| match w {
                    Parsed::Allow {
                        port: Some(p),
                        proto,
                    } => Some(pairs(*p, *proto)),
                    _ => None,
                })
                .flatten()
                .collect();
            pairs(port, proto).iter().all(|pair| opened.contains(pair))
        }
    }
}

/// Make the tight ufw rule set exactly the tagged one: add the missing
/// rules, replace untagged hand-made equivalents (announced, each delete
/// and add printed) and the broad `allow in on wsn+`.
pub fn configure_ufw(host: &Host, proxy_port: u16, say: &mut dyn FnMut(String)) -> Result<()> {
    let wanted = ufw_rules(proxy_port);
    let add = |rule: &str, say: &mut dyn FnMut(String)| -> Result<()> {
        let mut args = words(rule);
        args.extend(["comment".to_string(), MANAGED_COMMENT.to_string()]);
        say(format!(
            "adding ufw rule: ufw {rule} comment '{MANAGED_COMMENT}'"
        ));
        host.run_ok("ufw", &args)?;
        Ok(())
    };
    let delete = |spec: &str, say: &mut dyn FnMut(String)| -> Result<()> {
        let args = ufw_delete_args(spec);
        say(format!("removing ufw rule: ufw {}", args.join(" ")));
        host.run_ok("ufw", &args)?;
        Ok(())
    };
    let added = ufw_added(host)?;
    // Rules no existing rule spells identically go in first, so coverage
    // never lapses for them.
    for rule in &wanted {
        match added.iter().find(|(spec, _)| spec == rule) {
            Some((_, true)) => say(format!("ufw rule already present: ufw {rule}")),
            Some((_, false)) => {}
            None => add(rule, say)?,
        }
    }
    // Untagged equivalents (hand-made, or the same rule without the tag)
    // would survive `uninstall`: replace them with the tagged rules.
    let mut victims: Vec<&str> = Vec::new();
    for (spec, managed) in &added {
        if !managed && is_covered_by(spec, &wanted) && !victims.contains(&spec.as_str()) {
            victims.push(spec);
        }
    }
    for spec in victims {
        say(format!(
            "replacing the untagged rule `ufw {spec}` (it duplicates the tight set, and \
             uninstall would leave it behind) with the tagged rules"
        ));
        delete(spec, say)?;
    }
    // A delete matches by rule, so it may take a tagged twin along: re-read
    // and add whatever the tight set is still missing.
    let now = ufw_added(host)?;
    for rule in &wanted {
        if !now.iter().any(|(spec, managed)| spec == rule && *managed) {
            if now.iter().any(|(spec, _)| spec == rule) {
                delete(rule, say)?;
            }
            add(rule, say)?;
        }
    }
    if added.iter().any(|(spec, _)| spec == UFW_BROAD) {
        say(format!(
            "replacing the broad rule `ufw {UFW_BROAD}` (it allows every port in from the \
             sandboxes) with the tight set above: ufw delete {UFW_BROAD}"
        ));
        host.run_ok("ufw", &ufw_delete_args(UFW_BROAD))?;
    }
    Ok(())
}

/// `ufw` arguments that delete `spec`. ufw spells route deletes
/// `ufw route delete …`; `ufw delete route …` is a syntax error.
fn ufw_delete_args(spec: &str) -> Vec<String> {
    let mut parts = words(spec);
    if parts.first().map(String::as_str) == Some("route") {
        parts.remove(0);
        let mut args = vec!["route".to_string(), "delete".to_string()];
        args.extend(parts);
        args
    } else {
        let mut args = vec!["delete".to_string()];
        args.extend(parts);
        args
    }
}

/// Remove only the rules tagged [`MANAGED_COMMENT`].
pub fn remove_ufw(host: &Host, say: &mut dyn FnMut(String)) -> Result<usize> {
    let mut removed = 0;
    for (spec, managed) in ufw_added(host)? {
        if !managed {
            continue;
        }
        let args = ufw_delete_args(&spec);
        say(format!("removing ufw rule: ufw {}", args.join(" ")));
        host.run_ok("ufw", &args)?;
        removed += 1;
    }
    Ok(removed)
}

fn firewalld_running(host: &Host) -> Result<()> {
    match host.run("firewall-cmd", &words("--state")) {
        Ok(output) if output.success => Ok(()),
        Ok(_) => bail!("`--configure-firewalld`: firewalld is not running on this node"),
        Err(_) => bail!("`--configure-firewalld`: firewalld is not installed on this node"),
    }
}

fn firewalld_list(host: &Host, what: &str) -> Result<Vec<String>> {
    let output = host.run_ok("firewall-cmd", &words(&format!("--permanent --get-{what}")))?;
    Ok(words(&String::from_utf8_lossy(&output.stdout)))
}

fn firewall_cmd(host: &Host, say: &mut dyn FnMut(String), args: Vec<String>) -> Result<()> {
    say(format!("firewall-cmd {}", args.join(" ")));
    host.run_ok("firewall-cmd", &args)?;
    Ok(())
}

/// A `wssp-guard` zone holding `wsn+` with only DHCP, DNS and the login
/// proxy open, plus a `wssp-guard-out` policy that routes it out.
pub fn configure_firewalld(
    host: &Host,
    proxy_port: u16,
    say: &mut dyn FnMut(String),
) -> Result<()> {
    firewalld_running(host)?;
    let p = |rest: String| words(&format!("--permanent {rest}"));
    // An interface belongs to one zone: a broad trusted-zone entry goes
    // first (announced), then the tight zone takes it.
    let trusted = host.run(
        "firewall-cmd",
        &p("--zone=trusted --query-interface=wsn+".into()),
    )?;
    if trusted.success {
        say(
            "replacing the broad trusted-zone entry for wsn+ (it allows every port in from the \
             sandboxes) with the tight wssp-guard zone"
                .into(),
        );
        firewall_cmd(
            host,
            say,
            p("--zone=trusted --remove-interface=wsn+".into()),
        )?;
    }
    if !firewalld_list(host, "zones")?
        .iter()
        .any(|z| z == FIREWALLD_ZONE)
    {
        firewall_cmd(host, say, p(format!("--new-zone={FIREWALLD_ZONE}")))?;
    } else {
        say(format!("firewalld zone `{FIREWALLD_ZONE}` already present"));
    }
    let zone = format!("--zone={FIREWALLD_ZONE}");
    let mut description = p(zone.clone());
    description.push(format!("--set-description={MANAGED_COMMENT}"));
    firewall_cmd(host, say, description)?;
    for rule in [
        "--add-interface=wsn+".to_string(),
        "--add-port=67/udp".into(),
        "--add-port=53/udp".into(),
        "--add-port=53/tcp".into(),
        format!("--add-port={proxy_port}/tcp"),
    ] {
        firewall_cmd(host, say, p(format!("{zone} {rule}")))?;
    }
    if !firewalld_list(host, "policies")?
        .iter()
        .any(|z| z == FIREWALLD_POLICY)
    {
        firewall_cmd(host, say, p(format!("--new-policy={FIREWALLD_POLICY}")))?;
    } else {
        say(format!(
            "firewalld policy `{FIREWALLD_POLICY}` already present"
        ));
    }
    let policy = format!("--policy={FIREWALLD_POLICY}");
    let mut description = p(policy.clone());
    description.push(format!("--set-description={MANAGED_COMMENT}"));
    firewall_cmd(host, say, description)?;
    for rule in [
        format!("--add-ingress-zone={FIREWALLD_ZONE}"),
        "--add-egress-zone=ANY".into(),
        "--set-target=ACCEPT".into(),
    ] {
        firewall_cmd(host, say, p(format!("{policy} {rule}")))?;
    }
    firewall_cmd(host, say, words("--reload"))
}

/// Remove the `wssp-guard` policy and zone (and nothing else).
pub fn remove_firewalld(host: &Host, say: &mut dyn FnMut(String)) -> Result<usize> {
    firewalld_running(host)?;
    let p = |rest: String| words(&format!("--permanent {rest}"));
    let mut removed = 0;
    if firewalld_list(host, "policies")?
        .iter()
        .any(|z| z == FIREWALLD_POLICY)
    {
        firewall_cmd(host, say, p(format!("--delete-policy={FIREWALLD_POLICY}")))?;
        removed += 1;
    }
    if firewalld_list(host, "zones")?
        .iter()
        .any(|z| z == FIREWALLD_ZONE)
    {
        firewall_cmd(host, say, p(format!("--delete-zone={FIREWALLD_ZONE}")))?;
        removed += 1;
    }
    if removed > 0 {
        firewall_cmd(host, say, words("--reload"))?;
    }
    Ok(removed)
}

#[cfg(test)]
#[path = "firewall_tests.rs"]
mod tests;
