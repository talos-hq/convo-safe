use crate::SecretType;
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
            Email,
            r"[\p{L}\p{M}0-9.!#$%&'*+?^_`{|}~-]+@(?:[\p{L}\p{M}0-9-]+\.)+[\p{L}\p{M}]{2,63}",
        ),
        Rule::new(Ssn, r"[0-9]{3}-[0-9]{2}-[0-9]{4}"),
        Rule::new(CreditCard, r"[0-9](?:[ -]?[0-9]){12,18}"),
        Rule::new(
            Phone,
            r"(?:\+1[ .-]?)?(?:\([0-9]{3}\)[ .-]?|[0-9]{3}[ .-]?)[0-9]{3}[ .-]?[0-9]{4}",
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
            zone.is_none() && !text[..start].ends_with('.') && !extension(&text[end..])
        }
        Err(_) => false,
    }
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

pub(crate) fn matches(text: &str) -> Vec<(usize, usize, SecretType)> {
    use SecretType::*;
    let urls = urls(text);
    let mut indicators = Vec::new();
    let mut found = yaml_secrets(text, &mut indicators);
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
            let valid = match rule.kind {
                Credential | Bearer => {
                    !is_reference(value) && indicators.binary_search(&start).is_err()
                }
                Phone | Ssn => bounded(text, start, end),
                CreditCard => bounded(text, start, end) && luhn(value),
                IpAddress => valid_ip(text, start, end),
                Email => !url_at(&urls, start)
                    .and_then(|url| url.userinfo_end)
                    .is_some_and(|at| start < at && at < end),
                _ => true,
            };
            if valid {
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
