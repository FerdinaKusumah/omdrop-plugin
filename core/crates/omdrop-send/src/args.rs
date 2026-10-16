//! The subset of Python's argparse both programs' command lines use, with its
//! messages and exit status: `omdrop` and the tests drive these programs by
//! argv, read `--help` to learn what the installed version supports (it
//! greps for `[file ...]`, `--url`, `--names`, `--stream`), and pass argparse's
//! errors through to the person.
//!
//! Supported: long options with unique-prefix abbreviation, `--opt=value`,
//! short flags, `--`, appended options, `nargs='*'` positionals.

use std::collections::HashMap;

/// What an option takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `store_true` / `store_false`.
    Flag,
    /// One value; the last one given wins.
    Value,
    /// One value per use, collected (`action='append'`).
    Append,
}

/// One option.
#[derive(Clone, Copy, Debug)]
pub struct Opt {
    pub long: &'static str,
    pub short: Option<&'static str>,
    pub kind: Kind,
}

/// argparse's automatic `-h, --help`.
static HELP: Opt = Opt {
    long: "--help",
    short: Some("-h"),
    kind: Kind::Flag,
};

/// A command line's grammar and texts.
pub struct Spec {
    pub prog: &'static str,
    /// The full `usage: ...` block, wrapped as argparse wraps it.
    pub usage: &'static str,
    /// The text after the usage block in `--help`.
    pub help_body: &'static str,
    pub opts: &'static [Opt],
}

/// Parsed values.
#[derive(Debug, Default)]
pub struct Parsed {
    values: HashMap<&'static str, Vec<String>>,
    pub positionals: Vec<String>,
}

impl Parsed {
    pub fn flag(&self, long: &str) -> bool {
        self.values.contains_key(long)
    }

    pub fn value(&self, long: &str) -> Option<&str> {
        self.values
            .get(long)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    pub fn all(&self, long: &str) -> Vec<String> {
        self.values.get(long).cloned().unwrap_or_default()
    }
}

/// How parsing ended without values.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// `-h`: the text for stdout, exit 0.
    Help(String),
    /// An error: the text for stderr, exit 2.
    Error(String),
}

impl Spec {
    /// `ap.error(msg)`: usage, then `prog: error: msg`.
    pub fn error(&self, msg: &str) -> Exit {
        Exit::Error(format!("{}\n{}: error: {msg}\n", self.usage, self.prog))
    }

    pub fn help(&self) -> String {
        format!("{}\n\n{}", self.usage, self.help_body)
    }

    fn lookup(&self, name: &str) -> Result<&'static Opt, Exit> {
        // argparse's own -h/--help takes part in abbreviation like any option.
        let all = || std::iter::once(&HELP).chain(self.opts.iter());
        if name.starts_with("--") {
            if let Some(o) = all().find(|o| o.long == name) {
                return Ok(o);
            }
            let hits: Vec<&'static Opt> = all().filter(|o| o.long.starts_with(name)).collect();
            return match hits.as_slice() {
                [one] => Ok(one),
                [] => Err(Exit::Error(String::new())),
                many => {
                    let names: Vec<&str> = many.iter().map(|o| o.long).collect();
                    Err(self.error(&format!(
                        "ambiguous option: {name} could match {}",
                        names.join(", ")
                    )))
                }
            };
        }
        all()
            .find(|o| o.short == Some(name))
            .ok_or(Exit::Error(String::new()))
    }

    /// Parse `args` (without the program name).
    pub fn parse(&self, args: &[String]) -> Result<Parsed, Exit> {
        let mut parsed = Parsed::default();
        let mut unknown: Vec<String> = Vec::new();
        let mut i = 0;
        let mut rest_positional = false;
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            if rest_positional || !looks_like_option(arg) {
                parsed.positionals.push(arg.clone());
                continue;
            }
            if arg == "--" {
                rest_positional = true;
                continue;
            }
            let (name, inline) = match arg.split_once('=') {
                Some((n, v)) if n.starts_with("--") => (n, Some(v.to_owned())),
                _ => (arg.as_str(), None),
            };
            let opt = match self.lookup(name) {
                Ok(o) => o,
                Err(Exit::Error(e)) if e.is_empty() => {
                    unknown.push(arg.clone());
                    continue;
                }
                Err(e) => return Err(e),
            };
            if opt.long == HELP.long {
                return Err(Exit::Help(self.help()));
            }
            let shown = match opt.short {
                Some(s) => format!("{s}/{}", opt.long),
                None => opt.long.to_owned(),
            };
            match opt.kind {
                Kind::Flag => {
                    if inline.is_some() {
                        return Err(self.error(&format!(
                            "argument {shown}: ignored explicit argument {}",
                            str_quote(inline.as_deref().unwrap_or(""))
                        )));
                    }
                    parsed
                        .values
                        .entry(opt.long)
                        .or_default()
                        .push(String::new());
                }
                Kind::Value | Kind::Append => {
                    let value = match inline {
                        Some(v) => v,
                        None => match args.get(i) {
                            Some(v) if !looks_like_option(v) || v == "-" => {
                                i += 1;
                                v.clone()
                            }
                            _ => {
                                return Err(
                                    self.error(&format!("argument {shown}: expected one argument"))
                                );
                            }
                        },
                    };
                    let slot = parsed.values.entry(opt.long).or_default();
                    if opt.kind == Kind::Value {
                        slot.clear();
                    }
                    slot.push(value);
                }
            }
        }
        if !unknown.is_empty() {
            return Err(self.error(&format!("unrecognized arguments: {}", unknown.join(" "))));
        }
        Ok(parsed)
    }

    /// `type=float`: argparse's message for a value that does not parse.
    pub fn float(&self, parsed: &Parsed, long: &str, default: f64) -> Result<f64, Exit> {
        match parsed.value(long) {
            None => Ok(default),
            Some(v) => v.trim().parse::<f64>().map_err(|_| {
                self.error(&format!(
                    "argument {long}: invalid float value: {}",
                    str_quote(v)
                ))
            }),
        }
    }

    /// `type=int`.
    pub fn int(&self, parsed: &Parsed, long: &str, default: i64) -> Result<i64, Exit> {
        match parsed.value(long) {
            None => Ok(default),
            Some(v) => v.trim().replace('_', "").parse::<i64>().map_err(|_| {
                self.error(&format!(
                    "argument {long}: invalid int value: {}",
                    str_quote(v)
                ))
            }),
        }
    }
}

fn str_quote(v: &str) -> String {
    crate::pyfmt::str_repr(v)
}

/// argparse treats `-x`/`--x` as an option, but not `-` alone or a negative
/// number (neither program has options that look like numbers).
fn looks_like_option(arg: &str) -> bool {
    if !arg.starts_with('-') || arg == "-" {
        return false;
    }
    arg.parse::<f64>().is_err() || arg.starts_with("--")
}

/// A seconds value for a socket timeout: `None` for 0 (Python's
/// `settimeout(0 or None)` blocked), refused when negative or not finite.
pub fn timeout(spec: &Spec, long: &str, secs: f64) -> Result<Option<std::time::Duration>, Exit> {
    if secs == 0.0 {
        return Ok(None);
    }
    std::time::Duration::try_from_secs_f64(secs)
        .map(Some)
        .map_err(|_| {
            spec.error(&format!(
                "argument {long}: must be a non-negative number of seconds"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    static OPTS: &[Opt] = &[
        Opt {
            long: "--name",
            short: None,
            kind: Kind::Value,
        },
        Opt {
            long: "--names",
            short: Some("-n"),
            kind: Kind::Flag,
        },
        Opt {
            long: "--no-wake",
            short: None,
            kind: Kind::Flag,
        },
        Opt {
            long: "--url",
            short: None,
            kind: Kind::Append,
        },
        Opt {
            long: "--list",
            short: None,
            kind: Kind::Flag,
        },
    ];
    static SPEC: Spec = Spec {
        prog: "t",
        usage: "usage: t",
        help_body: "body\n",
        opts: OPTS,
    };

    fn parse(args: &[&str]) -> Result<Parsed, Exit> {
        SPEC.parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn options_values_and_positionals() {
        let p = parse(&[
            "--name", "Omarchy", "-n", "--url", "a", "--url=b", "--li", "--", "--x", "f",
        ])
        .unwrap();
        assert_eq!(p.value("--name"), Some("Omarchy"));
        assert!(p.flag("--names") && p.flag("--list") && !p.flag("--no-wake"));
        assert_eq!(p.all("--url"), ["a", "b"]);
        assert_eq!(p.positionals, ["--x", "f"]);
    }

    #[test]
    fn argparse_errors() {
        assert_eq!(parse(&["--n"]).unwrap_err(), Exit::Error("usage: t\nt: error: ambiguous option: --n could match --name, --names, --no-wake\n".into()));
        assert_eq!(
            parse(&["--bogus", "x"]).unwrap_err(),
            Exit::Error("usage: t\nt: error: unrecognized arguments: --bogus\n".into())
        );
        assert_eq!(
            parse(&["--name"]).unwrap_err(),
            Exit::Error("usage: t\nt: error: argument --name: expected one argument\n".into())
        );
        assert_eq!(
            parse(&["--url", "--list"]).unwrap_err(),
            Exit::Error("usage: t\nt: error: argument --url: expected one argument\n".into())
        );
        assert!(matches!(parse(&["x", "-h"]).unwrap_err(), Exit::Help(_)));
        assert!(matches!(parse(&["--he"]).unwrap_err(), Exit::Help(_)));
        // Negative numbers and a lone dash are values, not options.
        assert_eq!(parse(&["--name", "-5", "-"]).unwrap().positionals, ["-"]);
    }

    #[test]
    fn timeouts() {
        assert_eq!(timeout(&SPEC, "--t", 0.0).unwrap(), None);
        assert_eq!(
            timeout(&SPEC, "--t", 2.5).unwrap(),
            Some(std::time::Duration::from_millis(2500))
        );
        assert!(timeout(&SPEC, "--t", -1.0).is_err());
        assert!(timeout(&SPEC, "--t", f64::NAN).is_err());
    }
}
