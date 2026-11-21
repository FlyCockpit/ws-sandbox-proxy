//! CLI help ↔ documentation comparison (C56).
//!
//! Two directions, both derived from the clap definitions that also render
//! `--help`:
//!
//! 1. `docs/cli-reference.md` carries a generated block (every command path,
//!    its about text, usage, arguments, value names, defaults and possible
//!    values). It must equal what this test renders from `wssp::cli::Cli`.
//!    Regenerate after a CLI change with
//!    `WSSP_BLESS_CLI_REFERENCE=1 cargo test -p wssp --test cli_reference`.
//! 2. Every `wssp …` invocation written in the product docs (inline code and
//!    fenced code blocks) must name real subcommands and real flags of the
//!    command it reaches, so prose cannot document a command or flag the CLI
//!    does not have.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command, CommandFactory};

const BEGIN: &str =
    "<!-- BEGIN GENERATED: WSSP_BLESS_CLI_REFERENCE=1 cargo test -p wssp --test cli_reference -->";
const END: &str = "<!-- END GENERATED -->";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    manifest_dir().join("../..")
}

fn cli() -> Command {
    let mut command = wssp::cli::Cli::command();
    command.build();
    command
}

/// One-line help: the first paragraph, joined, without a trailing period.
fn short_help(arg: &Arg) -> String {
    let text = arg
        .get_long_help()
        .or_else(|| arg.get_help())
        .map(|help| help.to_string())
        .unwrap_or_default();
    let first = text.split("\n\n").next().unwrap_or_default();
    let joined = first.split_whitespace().collect::<Vec<_>>().join(" ");
    joined.trim_end_matches('.').replace('|', "\\|")
}

fn about(command: &Command) -> String {
    command
        .get_about()
        .map(|about| about.to_string())
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_string()
}

/// Arguments whose clap default is computed per target or from the
/// environment (`host run --runtime`: Incus on Linux unless `WSSP_RUNTIME=fake`,
/// fake elsewhere).
const TARGET_DEPENDENT_DEFAULTS: &[&str] = &["runtime"];

fn takes_value(arg: &Arg) -> bool {
    matches!(arg.get_action(), ArgAction::Set | ArgAction::Append)
}

fn arg_label(arg: &Arg) -> String {
    let value = arg
        .get_value_names()
        .and_then(|names| names.first())
        .map(|name| name.to_string())
        .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
    if arg.is_positional() {
        return format!("`<{value}>`");
    }
    let mut label = String::new();
    if let Some(short) = arg.get_short() {
        let _ = write!(label, "`-{short}`, ");
    }
    if let Some(long) = arg.get_long() {
        let _ = write!(label, "`--{long}");
        if takes_value(arg) {
            let _ = write!(label, " <{value}>");
        }
        label.push('`');
    }
    if matches!(arg.get_action(), ArgAction::Count) {
        label.push_str(" (repeatable)");
    }
    label
}

fn arg_notes(arg: &Arg) -> String {
    let mut notes = Vec::new();
    if arg.is_required_set() {
        notes.push("required".to_string());
    }
    let defaults = arg
        .get_default_values()
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if TARGET_DEPENDENT_DEFAULTS.contains(&arg.get_id().as_str()) {
        // The rendered reference must not depend on the OS or environment
        // the test runs on (CI runs it on Linux, macOS and Windows).
        notes.push("default depends on the platform (see description)".to_string());
    } else if !defaults.is_empty() && takes_value(arg) {
        notes.push(format!("default `{}`", defaults.join(",")));
    }
    let values = arg
        .get_possible_values()
        .iter()
        .filter(|value| !value.is_hide_set())
        .map(|value| format!("`{}`", value.get_name()))
        .collect::<Vec<_>>();
    if !values.is_empty() && takes_value(arg) {
        notes.push(format!("one of {}", values.join(", ")));
    }
    notes.join("; ")
}

fn visible_args(command: &Command, globals: &[String]) -> Vec<Arg> {
    command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .filter(|arg| !matches!(arg.get_id().as_str(), "help" | "version"))
        .filter(|arg| !globals.iter().any(|id| id == arg.get_id().as_str()))
        .cloned()
        .collect()
}

fn render_args(out: &mut String, args: &[Arg]) {
    if args.is_empty() {
        out.push_str("No command-specific options.\n\n");
        return;
    }
    out.push_str("| Argument | Description | Notes |\n| --- | --- | --- |\n");
    for arg in args {
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            arg_label(arg),
            short_help(arg),
            arg_notes(arg)
        );
    }
    out.push('\n');
}

fn render_command(out: &mut String, command: &Command, path: &str, globals: &[String]) {
    let _ = writeln!(out, "### `{path}`\n");
    let _ = writeln!(out, "{}.\n", about(command));
    let usage = command
        .clone()
        .bin_name(path)
        .render_usage()
        .to_string()
        .replace("Usage: ", "");
    let _ = writeln!(out, "```text\n{}\n```\n", usage.trim());
    render_args(out, &visible_args(command, globals));
    for sub in command.get_subcommands() {
        if sub.get_name() == "help" || sub.is_hide_set() {
            continue;
        }
        render_command(out, sub, &format!("{path} {}", sub.get_name()), globals);
    }
}

fn render() -> String {
    let root = cli();
    let globals = root
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .map(|arg| arg.get_id().as_str().to_string())
        .collect::<Vec<_>>();
    let mut out = String::new();
    out.push_str("### Global options\n\n");
    out.push_str("Accepted by every command, before or after the subcommand.\n\n");
    let global_args = root
        .get_arguments()
        .filter(|arg| arg.is_global_set() && !arg.is_hide_set())
        .cloned()
        .collect::<Vec<_>>();
    render_args(&mut out, &global_args);
    for sub in root.get_subcommands() {
        if sub.get_name() == "help" || sub.is_hide_set() {
            continue;
        }
        render_command(&mut out, sub, &format!("wssp {}", sub.get_name()), &globals);
    }
    out
}

#[test]
fn cli_reference_matches_clap_definitions() {
    let path = manifest_dir().join("docs/cli-reference.md");
    let doc = fs::read_to_string(&path).expect("apps/cli/docs/cli-reference.md exists");
    let (Some(start), Some(end)) = (doc.find(BEGIN), doc.find(END)) else {
        panic!("cli-reference.md must contain the generated BEGIN/END markers");
    };
    let generated = &doc[start + BEGIN.len()..end];
    let expected = format!("\n\n{}", render());
    if generated == expected {
        return;
    }
    if std::env::var_os("WSSP_BLESS_CLI_REFERENCE").is_some() {
        let updated = format!("{}{BEGIN}{expected}{}", &doc[..start], &doc[end..]);
        fs::write(&path, updated).expect("write cli-reference.md");
        return;
    }
    panic!(
        "apps/cli/docs/cli-reference.md is out of date with the clap definitions.\n\
         Regenerate: WSSP_BLESS_CLI_REFERENCE=1 cargo test -p wssp --test cli_reference\n\
         --- expected ---\n{expected}"
    );
}

/// Markdown files whose `wssp …` invocations must match the CLI.
fn documented_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = vec![
        root.join("README.md"),
        root.join("apps/cli/README.md"),
        root.join("packages/sdk/README.md"),
    ];
    collect_markdown(&root.join("docs"), &mut files);
    collect_markdown(&root.join("apps/cli/docs"), &mut files);
    files.sort();
    files
}

fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
}

/// Code text of a markdown file, one entry per line: fenced block lines and
/// inline code spans. Prose outside code is not an invocation.
fn code_lines(markdown: &str) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    // `None` outside a fence; `Some(is_shell)` inside one. Only shell fences
    // hold invocations (a `text` diagram is not a command line).
    let mut fence: Option<bool> = None;
    for (index, line) in markdown.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fence = match fence {
                Some(_) => None,
                None => {
                    let info = trimmed.trim_start_matches(['`', '~']).trim();
                    Some(matches!(info, "sh" | "bash" | "shell" | "console" | "zsh"))
                }
            };
            continue;
        }
        if let Some(is_shell) = fence {
            if is_shell {
                lines.push((number, line.to_string()));
            }
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else {
                break;
            };
            lines.push((number, after[..close].to_string()));
            rest = &after[close + 1..];
        }
    }
    lines
}

const SEPARATORS: &[&str] = &["|", "||", "&&", ";", "$", "sudo", "exec", "time"];

fn is_placeholder(token: &str) -> bool {
    token.starts_with('<') || token.contains('…') || token.contains("...") || token.starts_with('[')
}

fn find_long<'a>(command: &'a Command, root: &'a Command, name: &str) -> Option<&'a Arg> {
    command
        .get_arguments()
        .chain(root.get_arguments().filter(|arg| arg.is_global_set()))
        .find(|arg| arg.get_long() == Some(name))
}

fn has_short(command: &Command, root: &Command, short: char) -> bool {
    command
        .get_arguments()
        .chain(root.get_arguments().filter(|arg| arg.is_global_set()))
        .any(|arg| arg.get_short() == Some(short))
}

/// Validate one invocation (the tokens after `wssp`). Returns problems.
fn check_invocation(root: &Command, tokens: &[&str]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut command = root;
    let mut path = String::from("wssp");
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].trim_matches(|c| c == '"' || c == '\'' || c == ',');
        index += 1;
        if token.is_empty() || token.starts_with('#') || SEPARATORS.contains(&token) {
            break;
        }
        if token == "\\" || is_placeholder(token) {
            continue;
        }
        // `--` ends the options: the rest is a guest argv (`sandbox shell`).
        if token == "--" {
            break;
        }
        if let Some(long) = token.strip_prefix("--") {
            let (name, inline_value) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            match find_long(command, root, name) {
                Some(arg) if takes_value(arg) && !inline_value => index += 1,
                Some(_) => {}
                None if matches!(name, "help" | "version") => {}
                None => problems.push(format!("`{path}` has no `--{name}` flag")),
            }
            continue;
        }
        if let Some(shorts) = token.strip_prefix('-') {
            for short in shorts.chars() {
                if !has_short(command, root, short) && !matches!(short, 'h' | 'V') {
                    problems.push(format!("`{path}` has no `-{short}` flag"));
                }
            }
            continue;
        }
        if command.has_subcommands() {
            match command
                .get_subcommands()
                .find(|sub| sub.get_name() == token && sub.get_name() != "help")
            {
                Some(sub) => {
                    path = format!("{path} {token}");
                    command = sub;
                }
                None if token == "help" => {}
                None => problems.push(format!("`{path}` has no `{token}` subcommand")),
            }
            continue;
        }
        // A positional value of a leaf command.
    }
    problems
}

/// `NAME=value`, a shell environment assignment prefix.
fn is_env_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// Tokens following each invocation of `wssp` in one code line.
fn invocations(line: &str) -> Vec<Vec<&str>> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let is_binary = *token == "wssp" || token.ends_with("/wssp");
        if !is_binary {
            continue;
        }
        let previous = index.checked_sub(1).map(|i| tokens[i]);
        let next = tokens.get(index + 1).copied();
        // `cargo run -p wssp -- <args>` is the source-tree spelling.
        if previous == Some("-p") {
            if next == Some("--") {
                found.push(tokens[index + 2..].to_vec());
            }
            continue;
        }
        // `WSSP_RUNTIME=fake wssp host run`: skip leading env assignments.
        let mut start = index;
        while start > 0 && is_env_assignment(tokens[start - 1]) {
            start -= 1;
        }
        let before = start.checked_sub(1).map(|i| tokens[i]);
        if before.is_none() || before.is_some_and(|p| SEPARATORS.contains(&p)) {
            found.push(tokens[index + 1..].to_vec());
        }
    }
    found
}

#[test]
fn documented_invocations_match_the_cli() {
    let root = cli();
    let mut problems = Vec::new();
    let mut checked = 0usize;
    for file in documented_files() {
        let text = fs::read_to_string(&file).expect("read documented markdown");
        let shown = file
            .strip_prefix(repo_root())
            .unwrap_or(&file)
            .display()
            .to_string();
        for (number, line) in code_lines(&text) {
            for tokens in invocations(&line) {
                checked += 1;
                for problem in check_invocation(&root, &tokens) {
                    problems.push(format!("{shown}:{number}: {problem} (`{}`)", line.trim()));
                }
            }
        }
    }
    assert!(
        checked >= 20,
        "expected the docs to document wssp invocations; found {checked}"
    );
    assert!(
        problems.is_empty(),
        "documented wssp invocations do not match the CLI:\n{}",
        problems.join("\n")
    );
}

#[test]
fn invocation_checker_rejects_unknown_commands_and_flags() {
    let root = cli();
    let check = |line: &str| {
        invocations(line)
            .into_iter()
            .flat_map(|tokens| check_invocation(&root, &tokens))
            .collect::<Vec<_>>()
    };
    assert!(check("wssp host run --server https://x --host-id h").is_empty());
    assert!(check("cargo run -p wssp -- host config --json show").is_empty());
    assert!(check("wssp host enroll --token-env WSSP_HOST_TOKEN").is_empty());
    assert!(check("brew install flycockpit/tap/wssp").is_empty());
    assert!(check("WSSP_RUNTIME=fake wssp host run --runtime fake").is_empty());
    assert_eq!(
        check("WSSP_RUNTIME=fake WSSP_LOG=debug wssp host run --nope").len(),
        1
    );
    assert_eq!(check("wssp host run --no-such-flag").len(), 1);
    assert_eq!(check("wssp deploy").len(), 1);
    assert_eq!(check("wssp host config frobnicate").len(), 1);
    assert_eq!(check("cargo run -p wssp -- host drain --wait").len(), 1);
}
