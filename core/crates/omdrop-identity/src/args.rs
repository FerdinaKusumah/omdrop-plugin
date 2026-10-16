//! `identity.py`'s argparse command line: the same subcommands, options,
//! help texts, error messages and exit status 2 on a usage error.

/// A parsed command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Cmd {
    Begin {
        name: String,
    },
    /// `None`: a valid integer too large to be any sequence number.
    Window {
        seq: Option<i128>,
    },
    StopBegin,
    StopEnd,
    Lock,
    Unlock,
    Status {
        json: bool,
    },
    Import {
        vault: Option<String>,
        title: String,
    },
    Use {
        item: String,
        vault: Option<String>,
        account: Option<String>,
    },
    OnePasswordOff,
    EnsureSelfSigned {
        name: String,
    },
}

/// Parsing either gives a command, or ends the program as argparse would.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parse {
    Run(Cmd),
    Exit { code: i32, out: String, err: String },
}

pub(crate) const DEFAULT_TITLE: &str = "Omdrop AirDrop identity";

const CHOICES: &str = "{begin,window,stop-begin,stop-end,lock,unlock,status,import,use,1password-off,ensure-self-signed}";

fn top_usage() -> String {
    format!("usage: identity.py [-h]\n                   {CHOICES} ...\n")
}

fn top_help() -> String {
    format!(
        "{}\npositional arguments:\n  {CHOICES}\n\noptions:\n  -h, --help            show this help message and exit\n",
        top_usage()
    )
}

struct Opt {
    long: &'static str,
    /// Takes a value (`--name NAME`) rather than being a flag.
    value: bool,
    required: bool,
}

struct Spec {
    name: &'static str,
    opts: &'static [Opt],
    positional: Option<&'static str>,
    usage: &'static str,
    /// The `options:` (and `positional arguments:`) part of `-h`.
    help: &'static str,
}

const fn opt(long: &'static str, value: bool, required: bool) -> Opt {
    Opt {
        long,
        value,
        required,
    }
}

const HELP_ONLY: &str = "options:\n  -h, --help  show this help message and exit\n";

const SPECS: &[Spec] = &[
    Spec {
        name: "begin",
        opts: &[opt("--name", true, true)],
        positional: None,
        usage: "usage: identity.py begin [-h] --name NAME\n",
        help: "options:\n  -h, --help   show this help message and exit\n  --name NAME\n",
    },
    Spec {
        name: "window",
        opts: &[opt("--seq", true, true)],
        positional: None,
        usage: "usage: identity.py window [-h] --seq SEQ\n",
        help: "options:\n  -h, --help  show this help message and exit\n  --seq SEQ\n",
    },
    Spec {
        name: "stop-begin",
        opts: &[],
        positional: None,
        usage: "usage: identity.py stop-begin [-h]\n",
        help: HELP_ONLY,
    },
    Spec {
        name: "stop-end",
        opts: &[],
        positional: None,
        usage: "usage: identity.py stop-end [-h]\n",
        help: HELP_ONLY,
    },
    Spec {
        name: "lock",
        opts: &[],
        positional: None,
        usage: "usage: identity.py lock [-h]\n",
        help: HELP_ONLY,
    },
    Spec {
        name: "unlock",
        opts: &[],
        positional: None,
        usage: "usage: identity.py unlock [-h]\n",
        help: HELP_ONLY,
    },
    Spec {
        name: "status",
        opts: &[opt("--json", false, false)],
        positional: None,
        usage: "usage: identity.py status [-h] [--json]\n",
        help: "options:\n  -h, --help  show this help message and exit\n  --json\n",
    },
    Spec {
        name: "import",
        opts: &[opt("--vault", true, false), opt("--title", true, false)],
        positional: None,
        usage: "usage: identity.py import [-h] [--vault VAULT] [--title TITLE]\n",
        help: "options:\n  -h, --help     show this help message and exit\n  --vault VAULT\n  --title TITLE\n",
    },
    Spec {
        name: "use",
        opts: &[opt("--vault", true, false), opt("--account", true, false)],
        positional: Some("item"),
        usage: "usage: identity.py use [-h] [--vault VAULT] [--account ACCOUNT] item\n",
        help: "positional arguments:\n  item\n\noptions:\n  -h, --help         show this help message and exit\n  --vault VAULT\n  --account ACCOUNT\n",
    },
    Spec {
        name: "1password-off",
        opts: &[],
        positional: None,
        usage: "usage: identity.py 1password-off [-h]\n",
        help: HELP_ONLY,
    },
    Spec {
        name: "ensure-self-signed",
        opts: &[opt("--name", true, true)],
        positional: None,
        usage: "usage: identity.py ensure-self-signed [-h] --name NAME\n",
        help: "options:\n  -h, --help   show this help message and exit\n  --name NAME\n",
    },
];

fn error(usage: &str, prog: &str, message: &str) -> Parse {
    Parse::Exit {
        code: 2,
        out: String::new(),
        err: format!("{usage}{prog}: error: {message}\n"),
    }
}

fn is_negative_number(tok: &str) -> bool {
    let Some(rest) = tok.strip_prefix('-') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match rest.split_once('.') {
        None => digits(rest),
        Some((a, b)) => (a.is_empty() || digits(a)) && digits(b),
    }
}

/// argparse's `_parse_optional`: does this token look like an option to a
/// parser whose options are `names`?
fn is_optional(tok: &str, names: &[&str]) -> bool {
    if !tok.starts_with('-') || tok == "-" {
        return false;
    }
    if names.contains(&tok) {
        return true;
    }
    let head = tok.split_once('=').map_or(tok, |(h, _)| h);
    if names.contains(&head) {
        return true;
    }
    if tok.starts_with("--") && names.iter().any(|n| n.starts_with(head)) {
        return true;
    }
    if is_negative_number(tok) || tok.contains(' ') {
        return false;
    }
    true
}

enum Match<'a> {
    Exact(&'a str),
    None,
    Ambiguous(Vec<&'a str>),
}

/// Exact name, else a unique `--` prefix (argparse's allow_abbrev).
fn lookup<'a>(head: &str, names: &[&'a str]) -> Match<'a> {
    if let Some(n) = names.iter().find(|n| **n == head) {
        return Match::Exact(n);
    }
    if !head.starts_with("--") {
        return Match::None;
    }
    let found: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with(head))
        .collect();
    match found.as_slice() {
        [] => Match::None,
        [one] => Match::Exact(one),
        _ => Match::Ambiguous(found),
    }
}

/// Python's `int(text)`: surrounding whitespace, a sign, digits with single
/// underscores between them. `Some(None)` for a valid integer beyond i128.
fn py_int(text: &str) -> Option<Option<i128>> {
    let t = text.trim();
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    if !body.bytes().all(|b| b.is_ascii_digit() || b == b'_') {
        return None;
    }
    let digits: String = body.chars().filter(|c| *c != '_').collect();
    Some(
        digits
            .parse::<i128>()
            .ok()
            .map(|n| if neg { -n } else { n }),
    )
}

/// Parse `identity.py`'s argv (without the program name).
pub(crate) fn parse(args: &[String]) -> Parse {
    let top_names = ["-h", "--help"];
    let mut extras: Vec<String> = Vec::new();
    let mut i = 0;
    let mut cmd = None;
    while i < args.len() {
        let tok = args[i].as_str();
        i += 1;
        if tok == "--" {
            cmd = args.get(i).map(String::as_str);
            i += 1;
            break;
        }
        if is_optional(tok, &top_names) {
            let head = tok.split_once('=').map_or(tok, |(h, _)| h);
            if matches!(lookup(head, &top_names), Match::Exact(_)) {
                return Parse::Exit {
                    code: 0,
                    out: top_help(),
                    err: String::new(),
                };
            }
            extras.push(tok.to_owned());
            continue;
        }
        cmd = Some(tok);
        break;
    }
    let Some(cmd) = cmd else {
        return error(
            &top_usage(),
            "identity.py",
            "the following arguments are required: cmd",
        );
    };
    let Some(spec) = SPECS.iter().find(|s| s.name == cmd) else {
        let choices: Vec<String> = SPECS.iter().map(|s| format!("'{}'", s.name)).collect();
        return error(
            &top_usage(),
            "identity.py",
            &format!(
                "argument cmd: invalid choice: '{cmd}' (choose from {})",
                choices.join(", ")
            ),
        );
    };
    let prog = format!("identity.py {}", spec.name);
    let mut names: Vec<&str> = vec!["-h", "--help"];
    names.extend(spec.opts.iter().map(|o| o.long));
    let mut values: Vec<(&str, String)> = Vec::new();
    let mut flags: Vec<&str> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut only_positionals = false;
    let mut seq = None;
    while i < args.len() {
        let tok = args[i].as_str();
        i += 1;
        if only_positionals || !is_optional(tok, &names) {
            positionals.push(tok.to_owned());
            continue;
        }
        if tok == "--" {
            only_positionals = true;
            continue;
        }
        let (head, inline) = match tok.split_once('=') {
            Some((h, v)) if tok.starts_with("--") => (h, Some(v)),
            _ => (tok, None),
        };
        let name = match lookup(head, &names) {
            Match::Exact(n) => n,
            Match::None => {
                extras.push(tok.to_owned());
                continue;
            }
            Match::Ambiguous(found) => {
                return error(
                    spec.usage,
                    &prog,
                    &format!("ambiguous option: {head} could match {}", found.join(", ")),
                );
            }
        };
        if name == "-h" || name == "--help" {
            return Parse::Exit {
                code: 0,
                out: format!("{}\n{}", spec.usage, spec.help),
                err: String::new(),
            };
        }
        let Some(o) = spec.opts.iter().find(|o| o.long == name) else {
            extras.push(tok.to_owned());
            continue;
        };
        if !o.value {
            if let Some(v) = inline {
                return error(
                    spec.usage,
                    &prog,
                    &format!("argument {name}: ignored explicit argument '{v}'"),
                );
            }
            flags.push(name);
            continue;
        }
        let value = match inline {
            Some(v) => v.to_owned(),
            None => match args.get(i) {
                Some(next) if !is_optional(next, &names) => {
                    i += 1;
                    next.clone()
                }
                _ => {
                    return error(
                        spec.usage,
                        &prog,
                        &format!("argument {name}: expected one argument"),
                    );
                }
            },
        };
        if name == "--seq" {
            match py_int(&value) {
                Some(n) => seq = Some(n),
                None => {
                    return error(
                        spec.usage,
                        &prog,
                        &format!("argument --seq: invalid int value: '{value}'"),
                    );
                }
            }
        }
        values.push((name, value));
    }
    let mut positional = None;
    let mut rest = positionals.into_iter();
    if spec.positional.is_some() {
        positional = rest.next();
    }
    extras.extend(rest);
    let mut missing: Vec<&str> = Vec::new();
    if let Some(p) = spec.positional
        && positional.is_none()
    {
        missing.push(p);
    }
    for o in spec.opts {
        if o.required && !values.iter().any(|(n, _)| *n == o.long) {
            missing.push(o.long);
        }
    }
    if !missing.is_empty() {
        return error(
            spec.usage,
            &prog,
            &format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ),
        );
    }
    if !extras.is_empty() {
        return error(
            &top_usage(),
            "identity.py",
            &format!("unrecognized arguments: {}", extras.join(" ")),
        );
    }
    // The last occurrence of an option wins, as in argparse.
    let get = |n: &str| {
        values
            .iter()
            .rev()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.clone())
    };
    let need = |n: &str| get(n).unwrap_or_default();
    Parse::Run(match spec.name {
        "begin" => Cmd::Begin {
            name: need("--name"),
        },
        "window" => Cmd::Window { seq: seq.flatten() },
        "stop-begin" => Cmd::StopBegin,
        "stop-end" => Cmd::StopEnd,
        "lock" => Cmd::Lock,
        "unlock" => Cmd::Unlock,
        "status" => Cmd::Status {
            json: flags.contains(&"--json"),
        },
        "import" => Cmd::Import {
            vault: get("--vault"),
            title: get("--title").unwrap_or_else(|| DEFAULT_TITLE.to_owned()),
        },
        "use" => Cmd::Use {
            item: positional.unwrap_or_default(),
            vault: get("--vault"),
            account: get("--account"),
        },
        "1password-off" => Cmd::OnePasswordOff,
        _ => Cmd::EnsureSelfSigned {
            name: need("--name"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Parse {
        parse(
            &line
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    }

    fn err(line: &str) -> String {
        match p(line) {
            Parse::Exit { code: 2, out, err } if out.is_empty() => err,
            other => panic!("{line}: {other:?}"),
        }
    }

    const TOP: &str = "usage: identity.py [-h]\n                   {begin,window,stop-begin,stop-end,lock,unlock,status,import,use,1password-off,ensure-self-signed} ...\n";

    #[test]
    fn commands_parse_like_argparse() {
        assert_eq!(
            p("begin --name Mac"),
            Parse::Run(Cmd::Begin { name: "Mac".into() })
        );
        assert_eq!(
            p("begin --na=Mac"),
            Parse::Run(Cmd::Begin { name: "Mac".into() })
        );
        assert_eq!(
            p("begin --name a --name b"),
            Parse::Run(Cmd::Begin { name: "b".into() })
        );
        assert_eq!(
            p("window --seq 7"),
            Parse::Run(Cmd::Window { seq: Some(7) })
        );
        assert_eq!(
            p("window --seq=+1_0"),
            Parse::Run(Cmd::Window { seq: Some(10) })
        );
        assert_eq!(
            p("window --seq -3"),
            Parse::Run(Cmd::Window { seq: Some(-3) })
        );
        assert_eq!(p("status --json"), Parse::Run(Cmd::Status { json: true }));
        assert_eq!(p("status --j"), Parse::Run(Cmd::Status { json: true }));
        assert_eq!(
            p("import"),
            Parse::Run(Cmd::Import {
                vault: None,
                title: DEFAULT_TITLE.into()
            })
        );
        assert_eq!(
            p("use --vault V item1 --account A"),
            Parse::Run(Cmd::Use {
                item: "item1".into(),
                vault: Some("V".into()),
                account: Some("A".into())
            })
        );
        assert_eq!(
            parse(&["begin".into(), "--name".into(), "-My Mac".into()]),
            Parse::Run(Cmd::Begin {
                name: "-My Mac".into()
            })
        );
    }

    #[test]
    fn usage_errors_match_argparse_text_and_exit_2() {
        assert_eq!(
            err(""),
            format!("{TOP}identity.py: error: the following arguments are required: cmd\n")
        );
        assert_eq!(
            err("--version"),
            format!("{TOP}identity.py: error: the following arguments are required: cmd\n")
        );
        assert_eq!(
            err("bogus"),
            format!(
                "{TOP}identity.py: error: argument cmd: invalid choice: 'bogus' (choose from 'begin', 'window', 'stop-begin', 'stop-end', 'lock', 'unlock', 'status', 'import', 'use', '1password-off', 'ensure-self-signed')\n"
            )
        );
        assert_eq!(
            err("begin"),
            "usage: identity.py begin [-h] --name NAME\nidentity.py begin: error: the following arguments are required: --name\n"
        );
        assert_eq!(
            err("window --seq x"),
            "usage: identity.py window [-h] --seq SEQ\nidentity.py window: error: argument --seq: invalid int value: 'x'\n"
        );
        assert_eq!(
            err("window --seq=5x"),
            "usage: identity.py window [-h] --seq SEQ\nidentity.py window: error: argument --seq: invalid int value: '5x'\n"
        );
        assert_eq!(
            err("status --json extra"),
            format!("{TOP}identity.py: error: unrecognized arguments: extra\n")
        );
        assert_eq!(
            err("status --nope"),
            format!("{TOP}identity.py: error: unrecognized arguments: --nope\n")
        );
        assert_eq!(
            err("use a b"),
            format!("{TOP}identity.py: error: unrecognized arguments: b\n")
        );
        assert_eq!(
            err("use"),
            "usage: identity.py use [-h] [--vault VAULT] [--account ACCOUNT] item\nidentity.py use: error: the following arguments are required: item\n"
        );
        assert_eq!(
            err("begin --name"),
            "usage: identity.py begin [-h] --name NAME\nidentity.py begin: error: argument --name: expected one argument\n"
        );
        assert_eq!(
            err("import --vault"),
            "usage: identity.py import [-h] [--vault VAULT] [--title TITLE]\nidentity.py import: error: argument --vault: expected one argument\n"
        );
    }

    #[test]
    fn help_goes_to_stdout_with_status_0() {
        let help = |line: &str| match p(line) {
            Parse::Exit { code: 0, out, err } if err.is_empty() => out,
            other => panic!("{line}: {other:?}"),
        };
        assert_eq!(
            help("-h"),
            format!(
                "{TOP}\npositional arguments:\n  {{begin,window,stop-begin,stop-end,lock,unlock,status,import,use,1password-off,ensure-self-signed}}\n\noptions:\n  -h, --help            show this help message and exit\n"
            )
        );
        assert_eq!(
            help("begin --name a --name b -h"),
            "usage: identity.py begin [-h] --name NAME\n\noptions:\n  -h, --help   show this help message and exit\n  --name NAME\n"
        );
        assert_eq!(
            help("use -h"),
            "usage: identity.py use [-h] [--vault VAULT] [--account ACCOUNT] item\n\npositional arguments:\n  item\n\noptions:\n  -h, --help         show this help message and exit\n  --vault VAULT\n  --account ACCOUNT\n"
        );
        assert_eq!(
            help("lock --help"),
            "usage: identity.py lock [-h]\n\noptions:\n  -h, --help  show this help message and exit\n"
        );
    }
}
