use convo_safe::{Keybox, SecretType};

const KEY: [u8; 32] = [48; 32];

fn check_spans(prefix: &str, cases: &[(&str, SecretType)], separator: &str, suffix: &str) {
    let mut keybox = Keybox::open(":memory:", &KEY).unwrap();
    let session = keybox.create_session().unwrap();
    let values: Vec<_> = cases.iter().map(|(value, _)| *value).collect();
    let prompt = format!("{prefix}{}{suffix}", values.join(separator));
    let redacted = keybox.redact(session, &prompt).unwrap();
    let markers: Vec<_> = cases
        .iter()
        .map(|(value, kind)| keybox.get_or_create(session, *kind, value).unwrap())
        .collect();
    assert_eq!(
        redacted,
        format!("{prefix}{}{suffix}", markers.join(separator))
    );
    for value in values {
        assert!(!redacted.contains(value), "unredacted value: {value}");
    }
    assert_eq!(keybox.restore(session, &redacted).unwrap(), prompt);
}

#[test]
fn email_and_phone_survive_punctuation_and_repeated_values() {
    use SecretType::{Email, Phone};

    check_spans(
        "Contact these fixtures (",
        &[
            ("name+tag@dept.example.org", Email),
            ("(555)124-4856", Phone),
            ("914-555-0106", Phone),
            ("914.555.0107", Phone),
            ("9145550108", Phone),
            ("+1 (212) 555-0109", Phone),
            ("name+tag@dept.example.org", Email),
        ],
        "; ",
        ").",
    );
}

#[test]
fn identifies_ssn_and_checksum_valid_payment_cards() {
    use SecretType::{CreditCard, Ssn};

    check_spans(
        "Synthetic identifiers: ",
        &[
            ("123-45-6789", Ssn),
            ("4111 1111 1111 1111", CreditCard),
            ("5555-5555-5555-4444", CreditCard),
            ("378282246310005", CreditCard),
        ],
        "; ",
        ".",
    );
}

#[test]
fn identifies_ipv4_and_ipv6_without_consuming_delimiters() {
    use SecretType::IpAddress;

    check_spans("", &[("192.0.2.21", IpAddress)], "", ":443, then retry.");
    check_spans(
        "Proxy [",
        &[("2001:db8::42", IpAddress)],
        "",
        "]:443, then retry.",
    );
    check_spans("Address ", &[("::ffff:192.0.2.21", IpAddress)], "", ".");
}

#[test]
fn recognizes_contextual_name_and_address_fields() {
    use SecretType::{Address, PersonName};

    check_spans(
        "My name is ",
        &[("Ana-María O’Neil", PersonName)],
        "",
        ". Please update the record.",
    );
    check_spans(
        r#"{"full_name":""#,
        &[
            ("Ana-María O’Neil", PersonName),
            ("123 Main Street, Apt 7, Springfield", Address),
        ],
        r#"","shipping_address":""#,
        r#"","active":true}"#,
    );
    check_spans(
        "customer:\r\n  mailing_address:\t'",
        &[("London, United Kingdom", Address)],
        "",
        "'\r\n  active: true\r\n",
    );
}

#[test]
fn recognizes_honorific_names_and_standalone_addresses() {
    let mut keybox = Keybox::open(":memory:", &KEY).unwrap();
    let session = keybox.create_session().unwrap();
    let prompt = "The reviewer was Dr. Ana-María O’Neil. The record is ready.";
    let redacted = keybox.redact(session, prompt).unwrap();
    assert!(!redacted.contains("Ana-María"));
    assert!(!redacted.contains("O’Neil"));
    assert!(redacted.contains("PERSON_NAME"));
    assert!(redacted.ends_with(". The record is ready."));
    assert_eq!(keybox.restore(session, &redacted).unwrap(), prompt);

    check_spans(
        "Meet at ",
        &[("123 Main Street", SecretType::Address)],
        "",
        "; bring the envelope.",
    );
    check_spans(
        "Send mail to ",
        &[("P.O. Box 541", SecretType::Address)],
        "",
        "; use a stamp.",
    );
}

#[test]
fn preserves_benign_lookalikes() {
    let mut keybox = Keybox::open(":memory:", &KEY).unwrap();
    let session = keybox.create_session().unwrap();
    let prompt = concat!(
        "Quarterly Planning Meeting\n",
        "Project ID 123456789; serial A9145550108B; order X123-45-6789Y.\n",
        "Invalid IPv4 256.0.2.21; version 1.2.3.4.5; clock 12:34:56.\n",
        "Invalid checksum 4111 1111 1111 1112; mention @department.\n",
        "Main Street is busy; address this issue before the meeting."
    );
    let redacted = keybox.redact(session, prompt).unwrap();
    assert_eq!(redacted, prompt);
    assert_eq!(keybox.restore(session, &redacted).unwrap(), prompt);
}

#[test]
fn handles_dense_comma_separated_email_lists() {
    let mut keybox = Keybox::open(":memory:", &KEY).unwrap();
    let session = keybox.create_session().unwrap();
    let email = "synthetic.fixture+batch@example.org";
    let prompt = format!("{email},").repeat(10_000);
    let marker = keybox
        .get_or_create(session, SecretType::Email, email)
        .unwrap();
    let redacted = keybox.redact(session, &prompt).unwrap();
    assert_eq!(redacted.matches(&marker).count(), 10_000);
    assert_eq!(keybox.restore(session, &redacted).unwrap(), prompt);
}
