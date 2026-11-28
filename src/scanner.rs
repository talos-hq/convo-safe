use crate::{RedactionOptions, SecretType};
use regex::Regex;
use std::{net::IpAddr, sync::LazyLock};

struct Rule {
    kind: SecretType,
    regex: Regex,
    assignment: bool,
}

const SEP: &str = r"(?:[_-]|%5f)?";
const PREFIXED_KEYS: &str = r"\b(?:sk-or-v1-[A-Fa-f0-9]{64}\b|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|npm_[A-Za-z0-9]{24,}|sk-(?:proj-|ant-api[0-9]+-|svcacct-)?[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}\b|AIza[A-Za-z0-9_-]{35}\b)";
const NAME: &str = r"(?:\p{Lu}\.|\p{Lu}[\p{L}\p{M}'’-]*)";

// Horizontal separators only. A match must never cross a message line.
const NUMBER_SEP: &str = r"[ \t\x{a0}\x{2009}\x{202f}\x{2010}\x{2011}-]";
const PHONE_SEP: &str = r"[ .\t\x{a0}\x{2009}\x{202f}\x{2010}\x{2011}-]";
const PHONE_EXT: &str = r"(?:;ext=|[ \t]*(?:x|ext(?:ension)?\.?)[ \t]*)[0-9]{1,6}";

impl Rule {
    fn new(kind: SecretType, pattern: &str) -> Self {
        Self {
            kind,
            regex: Regex::new(pattern).expect("static detector"),
            assignment: false,
        }
    }

    fn fields(kind: SecretType, labels: &str, unquoted: &str) -> [Self; 3] {
        [
            (r#"(?P<secret>(?:[^"\\\r\n]|\\[^\r\n])+)"#, "\""),
            (r"(?P<secret>(?:[^'\\\r\n]|\\[^\r\n])+)", "'"),
            (unquoted, ""),
        ]
        .map(|(value, quote)| {
            let mut rule = Self::new(
                kind,
                &format!(
                    r#"(?im)\b(?:{labels})["']?[ \t]*[:=][ \t]*{quote}{value}{}"#,
                    if quote.is_empty() {
                        String::new()
                    } else {
                        format!(r"(?:{quote}|\r?$)")
                    },
                ),
            );
            rule.assignment = quote.is_empty();
            rule
        })
    }
}

static CREDENTIAL_FIELDS: LazyLock<String> = LazyLock::new(|| {
    format!(
        r"(?:[a-z0-9]+(?:[_-]|%5f))*(?:password|passwd|pwd|secret(?:{SEP}key)?|(?:access{SEP}|auth{SEP}|refresh{SEP}|session{SEP})?token|api{SEP}key|client{SEP}secret|private{SEP}key|access{SEP}key(?:{SEP}id)?|authorization{SEP}token|credential(?:s)?|session{SEP}id|connect\.sid)"
    )
});
static YAML_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?im)^(?P<indent>[ ]*)(?:-[ ]+)?["']?(?:{})["']?[ \t]*:[ \t]*(?P<indicator>[|>](?:[1-9][+-]?|[+-][1-9]?)?)[ \t]*(?:#[^\r\n]*)?\r?\n"#,
        &*CREDENTIAL_FIELDS,
    )).expect("static YAML scalar grammar")
});

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    use SecretType::*;
    let names = format!(
        r"(?:person{SEP}|full{SEP}|first{SEP}|last{SEP}|patient{SEP}|customer{SEP}|contact{SEP})name"
    );
    let addresses = format!(
        r"(?:street{SEP}|mailing{SEP}|shipping{SEP}|billing{SEP}|home{SEP}|postal{SEP})?address"
    );
    let street = r"(?i:\b(?:[0-9]{1,7}[ \t]+[\p{L}\p{M}0-9.'’ -]+?[ \t]+(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Parkway|Pkwy\.?|Circle|Cir\.?)\b(?:[ \t]+(?:apt\.?|unit|suite|ste\.?|#)[ \t]*[A-Z0-9-]+)?|P\.?[ \t]*O\.?[ \t]+Box[ \t]+[0-9]+))";
    let mut rules = vec![
        Rule::new(
            PrivateKey,
            r"(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\z)",
        ),
        Rule::new(Credential, PREFIXED_KEYS),
        Rule::new(
            Credential,
            r#"(?i)\bAuthorization["']?[ \t]*:[ \t]*["']?Basic[ \t]+(?P<secret>[A-Za-z0-9+/]+={0,2})"#,
        ),
        Rule::new(
            Bearer,
            r#"(?i)\bAuthorization["']?[ \t]*:[ \t]*["']?Bearer[ \t]+(?P<secret>[A-Za-z0-9._~+/-]+={0,2})"#,
        ),
        Rule::new(
            Bearer,
            r"(?i)\bBearer[ \t]+(?P<secret>[A-Za-z0-9._~+/-]{8,}={0,2})",
        ),
        Rule::new(
            Credential,
            r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<secret>[^\s/@]+)@",
        ),
        Rule::new(
            BankRouting,
            r#"(?i)\b(?:aba(?:[ _-]*routing)?(?:[ _-]*number)?|(?:bank[ _-]*)?routing(?:[ _-]*transit)?[ _-]*(?:number|no\.?|#)?|rtn)["']?(?:[ \t]*[:=][ \t]*|[ \t]+(?:is[ \t]+)?|[ \t]*-[ \t]+)["']?(?P<secret>[0-9]{9})"#,
        ),
        Rule::new(
            BankAccount,
            &format!(
                r#"(?i)\b(?:bank[ _-]*account(?:[ _-]*(?:number|no\.?|#))?|(?:checking|savings)[ _-]*account[ _-]*(?:number|no\.?|#))["']?(?:[ \t]*[:=][ \t]*|[ \t]+(?:is[ \t]+)?|[ \t]*-[ \t]+)["']?(?P<secret>[0-9](?:{NUMBER_SEP}?[0-9]){{7,16}})"#
            ),
        ),
        Rule::new(Ssn, r"[0-9]{3}-[0-9]{2}-[0-9]{4}"),
        Rule::new(
            CreditCard,
            &format!(
                r"(?:[0-9]{{4}}(?:{NUMBER_SEP}[0-9]{{4}}){{2,3}}(?:{NUMBER_SEP}[0-9]{{1,3}})?|[0-9]{{4}}{NUMBER_SEP}[0-9]{{6}}{NUMBER_SEP}[0-9]{{4,5}}|[0-9]{{12,19}})"
            ),
        ),
        Rule::new(
            CreditCard,
            &format!(r"[0-9](?:{NUMBER_SEP}?[0-9]){{12,18}}"),
        ),
        Rule::new(
            Phone,
            &format!(
                r"(?i)(?:(?:\+1{PHONE_SEP}?|1{PHONE_SEP}?)?(?:\([2-9][0-9]{{2}}\){PHONE_SEP}?|[2-9][0-9]{{2}}{PHONE_SEP}?)[0-9]{{3}}{PHONE_SEP}?[0-9]{{4}}|\+[2-9](?:{PHONE_SEP}?[0-9]){{7,14}})(?:{PHONE_EXT})?"
            ),
        ),
        Rule::new(
            IpAddress,
            r"(?:[[:xdigit:]]{0,4}:){2,7}[[:xdigit:]:.]*(?:%[A-Za-z0-9_.-]+)?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
        ),
        Rule::new(
            PersonName,
            &format!(
                r"\b(?i:Dr|Mr|Mrs|Ms|Mx|Prof)\.[ \t]+(?P<secret>{NAME}(?:[ \t]+{NAME}){{0,3}})"
            ),
        ),
        Rule::new(
            PersonName,
            &format!(r"(?i:\bmy name is)[ \t]+(?P<secret>{NAME}(?:[ \t]+{NAME}){{0,3}})"),
        ),
        Rule::new(Address, street),
    ];
    rules.extend(Rule::fields(
        Credential,
        &CREDENTIAL_FIELDS,
        r#"(?P<secret>[^\s"'<>\x60,;}{\[\]]+)"#,
    ));
    rules.extend(Rule::fields(PersonName, &names, r"(?-i:(?P<secret>\p{L}[\p{L}\p{M}'’.-]*(?:[ \t]+(?:\p{Lu}\.|\p{Lu}[\p{L}\p{M}'’-]*)){0,4}))"));
    rules.extend(Rule::fields(
        Address,
        &addresses,
        r#"(?P<secret>[\p{L}0-9][^\r\n"'<>\x60;}{\[\]]*)"#,
    ));
    rules
});

fn is_reference(secret: &str) -> bool {
    static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:\\?\$(?:[a-zA-Z_][a-zA-Z0-9_]*|\{[A-Za-z_][A-Za-z_0-9]*\}?)|%[A-Za-z_][A-Za-z_0-9]*%|\.+|[xX]{4,})$")
            .expect("static reference grammar")
    });
    REFERENCE.is_match(secret)
        || matches!(secret, "$" | "\\$")
        || secret.strip_prefix("sk-or-v1-").is_some_and(|suffix| {
            suffix.len() != 64 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn luhn(number: &str) -> bool {
    let digits = number.bytes().filter(u8::is_ascii_digit);
    let sum: u32 = digits
        .rev()
        .enumerate()
        .map(|(offset, digit)| {
            let digit = u32::from(digit - b'0');
            if offset % 2 == 0 {
                digit
            } else {
                (2 * digit) / 10 + (2 * digit) % 10
            }
        })
        .sum();
    sum > 0 && sum.is_multiple_of(10)
}

fn identifier(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn bounded(text: &str, start: usize, end: usize) -> bool {
    !text[..start].chars().next_back().is_some_and(identifier)
        && !text[end..].chars().next().is_some_and(identifier)
}

fn valid_routing(number: &str) -> bool {
    let prefix = (number.as_bytes()[0] - b'0') * 10 + (number.as_bytes()[1] - b'0');
    matches!(prefix, 0..=12 | 21..=32 | 61..=72 | 80)
        && number != "000000000"
        && number
            .bytes()
            .zip([3, 7, 1].into_iter().cycle())
            .map(|(digit, weight)| u32::from(digit - b'0') * weight)
            .sum::<u32>()
            .is_multiple_of(10)
}

fn valid_email(text: &str, start: usize, end: usize, urls: &[Url]) -> bool {
    let (local, domain) = text[start..end].split_once('@').expect("email candidate");
    let domain_tail = &text[end..];
    let preceding = &text[..start];
    if local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || preceding.ends_with('@')
        || domain_tail.starts_with('@')
        || (domain_tail.starts_with('.')
            && domain_tail.trim_start_matches('.').starts_with(identifier))
    {
        return false;
    }
    let Some((_, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    let valid_tld = tld.chars().count() >= 2 && tld.chars().all(char::is_alphabetic)
        || tld.to_ascii_lowercase().starts_with("xn--") && tld.len() > 4;
    valid_tld
        && domain.split('.').all(|label| {
            label.chars().count() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && !label.contains('_')
        })
        && !url_at(urls, start)
            .and_then(|url| url.userinfo_end)
            .is_some_and(|at| start < at && at < end)
}

fn email_spans(text: &str, urls: &[Url]) -> Vec<(usize, usize)> {
    static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"[\p{L}\p{M}0-9.!#$%&'*+/?^_\x60{|}~-]+@(?:[\p{L}\p{M}0-9_-]+\.)+[\p{L}\p{M}0-9_-]+",
        )
        .expect("static email pattern")
    });
    if !text.contains('@') {
        return Vec::new();
    }
    EMAIL
        .find_iter(text)
        .filter_map(|candidate| {
            let mut start = candidate.start();
            let end = candidate.end();
            if let Some(url) = url_at(urls, end - 1)
                && start < url.start
            {
                // Slashes before the address in a URL belong to its authority or path.
                let at = start + candidate.as_str().find('@').expect("email candidate");
                start = url.start + text[url.start..at].rfind('/')? + 1;
            }
            (start < end && valid_email(text, start, end, urls)).then_some((start, end))
        })
        .collect()
}

fn inside_email(emails: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = emails.partition_point(|(email_start, _)| *email_start <= start);
    index > 0 && emails[index - 1].1 >= end
}

fn has_digit_continuation(tail: &str) -> bool {
    tail.strip_prefix([
        ' ', '\t', '\u{a0}', '\u{2009}', '\u{202f}', '\u{2010}', '\u{2011}', '-',
    ])
    .is_some_and(|tail| tail.starts_with(|c: char| c.is_ascii_digit()))
}

fn valid_match(
    kind: SecretType,
    text: &str,
    start: usize,
    end: usize,
    indicators: &[usize],
) -> bool {
    use SecretType::*;
    let value = &text[start..end];
    match kind {
        Credential | Bearer => !is_reference(value) && indicators.binary_search(&start).is_err(),
        Phone => bounded(text, start, end) && !text[end..].starts_with('@'),
        Ssn => bounded(text, start, end),
        BankAccount => bounded(text, start, end) && !has_digit_continuation(&text[end..]),
        BankRouting => bounded(text, start, end) && valid_routing(value),
        CreditCard => bounded(text, start, end) && luhn(value),
        IpAddress => valid_ip(text, start, end),
        _ => true,
    }
}

fn valid_ip(text: &str, start: usize, end: usize) -> bool {
    let value = &text[start..end];
    let (ip, zone) = value
        .split_once('%')
        .map_or((value, None), |(ip, zone)| (ip, Some(zone)));
    if !bounded(text, start, end) || text[..start].ends_with(':') || text[end..].starts_with("::") {
        return false;
    }
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => zone.is_none_or(|zone| !zone.is_empty()),
        Ok(IpAddr::V4(_)) => {
            let extension = |tail: &str| {
                tail.strip_prefix('.')
                    .and_then(|s| s.as_bytes().first())
                    .is_some_and(u8::is_ascii_digit)
            };
            zone.is_none()
                && !text[..start].ends_with('.')
                && !extension(&text[end..])
                && !version_context(&text[..start])
        }
        Err(_) => false,
    }
}

/// A dotted quad that reads as a version (`v1.2.3.4`, `pkg==2.2.3.3`, `version 10.0.0.1`).
fn version_context(before: &str) -> bool {
    const SIGILS: [&str; 7] = ["v", "V", "==", ">=", "<=", "~=", "@"];
    const WORDS: [&str; 4] = ["version", "release", "ver", "tag"];
    if SIGILS.iter().any(|sigil| before.ends_with(sigil)) {
        return true;
    }
    let word = before.trim_end_matches([' ', '\t', ':', '=', '"', '\'']);
    if word.len() == before.len() {
        return false;
    }
    let lower = word.to_ascii_lowercase();
    WORDS.iter().any(|w| {
        lower.ends_with(w)
            && lower[..lower.len() - w.len()]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric())
    })
}

struct Url {
    start: usize,
    end: usize,
    userinfo_end: Option<usize>,
    query: Option<(usize, usize)>,
}

fn urls(text: &str) -> Vec<Url> {
    static URL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://(?P<body>[^\s"'<>\x60,]+)"#)
            .expect("static URL grammar")
    });
    URL.captures_iter(text)
        .filter_map(|captures| {
            let body = captures.name("body")?;
            let value = body.as_str();
            let authority = value.split(['/', '?', '#']).next().unwrap_or_default();
            let before_fragment = value.split('#').next().unwrap_or_default();
            Some(Url {
                start: body.start(),
                end: body.end(),
                userinfo_end: authority.rfind('@').map(|at| body.start() + at),
                query: before_fragment
                    .find('?')
                    .map(|at| (body.start() + at, body.start() + before_fragment.len())),
            })
        })
        .collect()
}

fn url_at(urls: &[Url], offset: usize) -> Option<&Url> {
    let index = urls
        .partition_point(|url| url.start <= offset)
        .checked_sub(1)?;
    urls.get(index).filter(|url| offset < url.end)
}

fn is_query_field(text: &str, urls: &[Url], start: usize) -> bool {
    if !text[..start].ends_with(['?', '&']) {
        return false;
    }
    if let Some(url) = url_at(urls, start) {
        return url
            .query
            .is_some_and(|(first, end)| (first..end).contains(&start));
    }
    text[..start].ends_with('?')
}

fn yaml_secrets(text: &str, indicators: &mut Vec<usize>) -> Vec<(usize, usize, SecretType)> {
    YAML_SECRET
        .captures_iter(text)
        .filter_map(|capture| {
            indicators.push(capture.name("indicator")?.start());
            let header_end = capture.get(0)?.end();
            let parent_indent = capture.name("indent")?.as_str().len();
            let mut start = header_end;
            let mut end = header_end;
            let mut found_value = false;
            for line in text[header_end..].split_inclusive('\n') {
                let value = line.trim_ascii();
                let indent = line.len() - line.trim_start_matches(' ').len();
                if !value.is_empty() && indent <= parent_indent {
                    break;
                }
                if !found_value {
                    if value.is_empty() {
                        start += line.len();
                    } else {
                        start += indent;
                        found_value = true;
                    }
                }
                end += line.len();
            }
            found_value.then(|| {
                let value = text[start..end].trim_end();
                (start, start + value.len(), SecretType::Credential)
            })
        })
        .collect()
}

pub(crate) fn matches(text: &str, options: RedactionOptions) -> Vec<(usize, usize, SecretType)> {
    use SecretType::*;
    let urls = urls(text);
    let emails = email_spans(text, &urls);
    let mut indicators = Vec::new();
    let mut found = yaml_secrets(text, &mut indicators);
    if options.redact_email {
        found.extend(emails.iter().map(|&(start, end)| (start, end, Email)));
    }
    for rule in RULES.iter() {
        let mut next = 0;
        while let Some(captures) = rule.regex.captures_at(text, next) {
            let whole = captures.get(0).expect("capture zero");
            next = whole.end();
            let secret = captures.name("secret").unwrap_or(whole);
            let start = secret.start();
            let mut value = secret.as_str();
            if rule.kind == Credential
                && rule.assignment
                && is_query_field(text, &urls, whole.start())
            {
                value = value.split(['&', '#']).next().unwrap_or_default();
                next = start + value.len();
            }
            if matches!(rule.kind, Address | IpAddress) {
                value = if rule.kind == IpAddress {
                    value.trim_end_matches('.')
                } else {
                    value.trim_end()
                };
            }
            let end = start + value.len();
            if value.is_empty() {
                continue;
            }
            let numeric = matches!(
                rule.kind,
                Phone | CreditCard | BankAccount | BankRouting | Ssn
            );
            if (!numeric || !inside_email(&emails, start, end))
                && valid_match(rule.kind, text, start, end, &indicators)
            {
                found.push((start, end, rule.kind));
            }
        }
    }
    // Keep the earliest category (or longest at a shared start) and cover
    // the union so an overlapping detector cannot expose a secret's tail.
    found.sort_by_key(|(start, end, _)| (*start, std::cmp::Reverse(*end)));
    let mut merged: Vec<(usize, usize, SecretType)> = Vec::new();
    for span in found {
        if let Some(last) = merged.last_mut()
            && span.0 < last.1
        {
            last.1 = last.1.max(span.1);
        } else {
            merged.push(span);
        }
    }
    merged
}
