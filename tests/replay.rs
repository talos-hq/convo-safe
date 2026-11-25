use convo_safe::{Error, Keybox, SecretType};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

const KEY: [u8; 32] = [123; 32];

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
        let dir = std::env::temp_dir().join(format!(
            "convo-safe-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn detects_and_restores_full_prompt() {
    let mut box_ = Keybox::open(":memory:", &KEY).unwrap();
    let session = box_.create_session().unwrap();
    let phone = "(555)124-4856";
    let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_PRIVATE_MATERIAL\n-----END OPENSSH PRIVATE KEY-----";
    let cases = [
        phone,
        "ghp_000000000000000000000000000000000000",
        "not-a-real-token",
        r#"fake\"with space"#,
        "smtp-fake",
        "demo%40secret",
        "inline-secret",
        pem,
    ];
    let prompt = format!(
        "🦜 Call {phone} twice {phone}. token={}\nAuthorization: Bearer {}\n{{\"api_key\":\"{}\"}}\nSMTP_PASSWORD='{}'\nConnect postgres://demo:{}@localhost/test. password={}\n{pem}\nleave serial 1555-124-485612",
        cases[1], cases[2], cases[3], cases[4], cases[5], cases[6]
    );
    let redacted = box_.redact(session, &prompt).unwrap();
    for secret in cases {
        assert!(!redacted.contains(secret), "{redacted}");
    }
    let marker = box_
        .get_or_create(session, SecretType::Phone, phone)
        .unwrap();
    assert_eq!(redacted.matches(&marker).count(), 2);
    assert!(redacted.contains("Authorization: Bearer "));
    assert!(redacted.ends_with("leave serial 1555-124-485612"));
    assert_eq!(box_.restore(session, &redacted).unwrap(), prompt);
}

#[test]
fn isolates_sessions_and_keyboxes_and_preserves_literal_markers() {
    let mut box_ = Keybox::open(":memory:", &KEY).unwrap();
    let session = box_.create_session().unwrap();
    let next = box_.create_session().unwrap();
    assert_eq!(next, session + 1);
    let secret = "invented-fixture";
    let marker = box_
        .get_or_create(session, SecretType::Credential, secret)
        .unwrap();
    let phone_marker = box_
        .get_or_create(session, SecretType::Phone, secret)
        .unwrap();
    assert_ne!(marker, phone_marker);
    let tampered = marker.replace("CREDENTIAL", "BEARER");
    assert_eq!(box_.restore(session, &tampered).unwrap(), tampered);
    assert_eq!(box_.restore(next, &marker).unwrap(), marker);
    let literal = format!("Input {marker} [[CONVO_SAFE:literal]]");
    let redacted = box_.redact(session, &literal).unwrap();
    assert_eq!(box_.restore(session, &redacted).unwrap(), literal);
    let mut other = Keybox::open(":memory:", &KEY).unwrap();
    assert_eq!(other.create_session().unwrap(), session);
    other
        .get_or_create(session, SecretType::Credential, "another-fixture")
        .unwrap();
    assert_eq!(other.restore(session, &marker).unwrap(), marker);
    assert_eq!(box_.redact(-1, "plain text"), Err(Error::UnknownSession));
}

#[test]
fn persists_ciphertext_and_rejects_wrong_key_and_tampering() {
    let scratch = Scratch::new();
    let path = scratch.0.join("box.sqlite");
    let secret = "local-generated-test-fixture";
    let (session, marker) = {
        let mut box_ = Keybox::open(&path, &KEY).unwrap();
        let session = box_.create_session().unwrap();
        (
            session,
            box_.get_or_create(session, SecretType::Credential, secret)
                .unwrap(),
        )
    };
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    assert!(matches!(
        Keybox::open(&path, &[42; 32]),
        Err(Error::InvalidKey)
    ));
    let mut box_ = Keybox::open(&path, &KEY).unwrap();
    assert_eq!(
        box_.get_or_create(session, SecretType::Credential, secret)
            .unwrap(),
        marker
    );
    assert_eq!(box_.restore(session, &marker).unwrap(), secret);
    assert_eq!(box_.create_session().unwrap(), session + 1);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE entries SET record = zeroblob(40)", [])
        .unwrap();
    assert_eq!(box_.restore(session, &marker), Err(Error::CorruptRecord));
}

#[test]
fn deduplicates_across_independent_concurrent_connections() {
    let scratch = Scratch::new();
    let path = scratch.0.join("box.sqlite");
    let session = Keybox::open(&path, &KEY).unwrap().create_session().unwrap();
    let barrier = Arc::new(Barrier::new(6));
    let workers: Vec<_> = (0..6)
        .map(|_| {
            let (path, barrier) = (path.clone(), barrier.clone());
            thread::spawn(move || {
                barrier.wait();
                let mut box_ = Keybox::open(path, &KEY).unwrap();
                box_.get_or_create(session, SecretType::Credential, "same-fixture")
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert!(results.iter().all(|marker| marker == &results[0]));
}

#[cfg(feature = "server")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "One process round trip covers streaming limits and replay isolation"
)]
fn worker_isolates_restore_and_speaks_json_lines() {
    use serde_json::{Value, json};
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    let scratch = Scratch::new();
    let key = scratch.0.join("box.key");
    let program = env!("CARGO_BIN_EXE_convo-safe");
    assert!(
        Command::new(program)
            .arg("init-key")
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );

    let log = scratch.0.join("session.jsonl");
    let mut redact = Command::new(program)
        .arg("serve")
        .arg(":memory:")
        .arg(&key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = redact.stdin.take().unwrap();
    let mut output = BufReader::new(redact.stdout.take().unwrap());
    let request = |input: &mut std::process::ChildStdin,
                   output: &mut BufReader<std::process::ChildStdout>,
                   value: Value| {
        writeln!(input, "{value}").unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let session = request(
        &mut input,
        &mut output,
        json!({"op":"create_session","session_log":log}),
    )["session"]
        .as_i64()
        .unwrap();
    let original = r#"Call (555)124-4856 and use password="fixture with spaces""#;
    for message in [
        json!({"op":"begin_message","session":session}),
        json!({"op":"chunk","session":session,"text":"Call (555)124-"}),
        json!({"op":"chunk","session":session,"text":"4856 and use password=\"fixture "}),
        json!({"op":"chunk","session":session,"text":"with spaces\""}),
    ] {
        assert_eq!(
            request(&mut input, &mut output, message),
            json!({"ok":true})
        );
    }
    let response = request(
        &mut input,
        &mut output,
        json!({"op":"finish_message","session":session}),
    );
    let redacted = response["text"].as_str().unwrap();
    assert!(!redacted.contains("(555)124-4856"));
    assert!(!redacted.contains("fixture with spaces"));
    let replay = json!({"op":"restore","session":session,"text":redacted});
    assert_eq!(
        request(
            &mut input,
            &mut output,
            json!({"op":"begin_message","session":session})
        ),
        json!({"ok":true}),
    );
    let too_long = "x".repeat(1024 * 1024 + 1);
    assert_eq!(
        request(
            &mut input,
            &mut output,
            json!({"op":"chunk","session":session,"text":too_long})
        ),
        json!({"error":"pending message capacity exceeded"}),
    );
    assert_eq!(
        request(
            &mut input,
            &mut output,
            json!({"op":"finish_message","session":session})
        ),
        json!({"error":"no open message"}),
    );
    let long_secret = "fixture".repeat(40_000);
    let marker = request(
        &mut input,
        &mut output,
        json!({"op":"get_or_create","session":session,"kind":"CREDENTIAL","secret":long_secret}),
    );
    let amplifying_replay = json!({
        "op":"restore","session":session,"text":marker["placeholder"].as_str().unwrap().repeat(40)
    });
    let expanded_original = " (555)124-4856".repeat(9_000);
    let expanded = request(
        &mut input,
        &mut output,
        json!({"op":"redact","session":session,"text":expanded_original}),
    );
    let expanded = expanded["text"].as_str().unwrap();
    assert!(expanded.len() > 1024 * 1024);
    let expanded_replay = json!({"op":"restore","session":session,"text":expanded});
    assert_eq!(
        request(&mut input, &mut output, replay.clone()),
        json!({"error":"restore is disabled"})
    );
    assert_eq!(
        request(
            &mut input,
            &mut output,
            json!({"op":"end_session","session":session})
        ),
        json!({"ok":true}),
    );
    assert!(
        request(
            &mut input,
            &mut output,
            json!({"op":"redact","session":session,"text":"anything"})
        )
        .get("error")
        .is_some()
    );
    drop(input);
    assert!(redact.wait().unwrap().success());

    let mut restore = Command::new(program)
        .arg("replay")
        .arg(&log)
        .arg(&key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = restore.stdin.take().unwrap();
    let mut output = BufReader::new(restore.stdout.take().unwrap());
    assert_eq!(
        request(&mut input, &mut output, replay),
        json!({"text":original})
    );
    assert_eq!(
        request(&mut input, &mut output, expanded_replay),
        json!({"text":expanded_original})
    );
    assert_eq!(
        request(&mut input, &mut output, amplifying_replay),
        json!({"error":"restored message exceeds output capacity"}),
    );
    drop(input);
    assert!(restore.wait().unwrap().success());
}

#[test]
fn overlapping_matches_do_not_expose_the_later_secret_tail() {
    let mut box_ = Keybox::open(":memory:", &KEY).unwrap();
    let session = box_.create_session().unwrap();
    let prompt =
        "password=x-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_MATERIAL\n-----END PRIVATE KEY-----";
    let redacted = box_.redact(session, prompt).unwrap();
    assert!(redacted.starts_with("password=[[CONVO_SAFE:"));
    assert!(!redacted.contains("FAKE_PRIVATE_MATERIAL"));
    assert_eq!(box_.restore(session, &redacted).unwrap(), prompt);
}

#[test]
fn appends_only_new_mappings_to_a_single_session_mirror_and_seals() {
    let scratch = Scratch::new();
    let log = scratch.0.join("turns.jsonl");
    let path = convo_safe::replay_path(&log).unwrap();
    let mut source = Keybox::open(":memory:", &KEY).unwrap();
    let session = source.create_session().unwrap();
    let other = source.create_session().unwrap();
    let first = source.redact(session, "Call (555)124-4856").unwrap();
    let other_marker = source
        .redact(other, "password=another-session-secret")
        .unwrap();
    source.checkpoint(session, &log).unwrap();
    source.checkpoint(session, &log).unwrap();
    {
        let mut replay = Keybox::open_replay(&log, &KEY).unwrap();
        assert_eq!(
            replay.restore(session, &first).unwrap(),
            "Call (555)124-4856"
        );
        assert_eq!(
            replay.restore(other, &other_marker),
            Err(Error::UnknownSession)
        );
        assert!(replay.create_session().is_err());
        assert!(matches!(
            Keybox::open(&path, &KEY),
            Err(Error::InvalidMirror)
        ));
    }
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER append_only_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'append only'); END;
         CREATE TRIGGER append_only_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'append only'); END;",
    ).unwrap();
    let later = source
        .redact(session, "Another email fixture@example.org")
        .unwrap();
    source.finalize_replay(session, &log).unwrap();
    source.finalize_replay(session, &log).unwrap();
    assert_eq!(source.checkpoint(other, &log), Err(Error::InvalidMirror));
    assert_eq!(
        source.checkpoint(session, &log),
        Err(Error::SessionFinalized)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        2
    );
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(b"fixture@example.org".len())
            .any(|window| window == b"fixture@example.org")
    );
    drop(source);
    let replay = Keybox::open_replay(&log, &KEY).unwrap();
    assert_eq!(
        replay.restore(session, &later).unwrap(),
        "Another email fixture@example.org"
    );
    assert!(matches!(
        Keybox::open_replay(&log, &[5; 32]),
        Err(Error::InvalidKey)
    ));
}

#[test]
fn stale_markers_cannot_resolve_to_different_values_after_snapshot_rollback() {
    let scratch = Scratch::new();
    let live = scratch.0.join("live.sqlite");
    let snapshot = scratch.0.join("snapshot.sqlite");
    let session = Keybox::open(&live, &KEY).unwrap().create_session().unwrap();
    fs::copy(&live, &snapshot).unwrap();
    let early = Keybox::open(&live, &KEY)
        .unwrap()
        .get_or_create(session, SecretType::Credential, "fixture before rollback")
        .unwrap();
    let mut restored = Keybox::open(&snapshot, &KEY).unwrap();
    let late = restored
        .get_or_create(session, SecretType::Credential, "fixture after rollback")
        .unwrap();
    assert_ne!(early, late);
    assert_eq!(restored.restore(session, &early).unwrap(), early);
    assert_eq!(
        restored.restore(session, &late).unwrap(),
        "fixture after rollback"
    );
}

#[test]
fn mirror_ignores_transplanted_sessions_and_leaves_unowned_databases_untouched() {
    let scratch = Scratch::new();
    let log = scratch.0.join("first.jsonl");
    let wrong_log = scratch.0.join("unrelated.jsonl");
    let other_log = scratch.0.join("second.jsonl");
    let mut source = Keybox::open(":memory:", &KEY).unwrap();
    let first = source.create_session().unwrap();
    let second = source.create_session().unwrap();
    let first_marker = source.redact(first, "password=first-fixture").unwrap();
    let second_marker = source.redact(second, "password=second-fixture").unwrap();

    let wrong_db =
        rusqlite::Connection::open(convo_safe::replay_path(&wrong_log).unwrap()).unwrap();
    wrong_db
        .execute("CREATE TABLE unrelated (data TEXT)", [])
        .unwrap();
    assert_eq!(
        source.checkpoint(first, wrong_log),
        Err(Error::InvalidMirror)
    );
    let count: i64 = wrong_db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    source.finalize_replay(first, &log).unwrap();
    source.finalize_replay(second, &other_log).unwrap();
    let sibling = convo_safe::replay_path(other_log).unwrap();
    let mirror_db = rusqlite::Connection::open(convo_safe::replay_path(&log).unwrap()).unwrap();
    mirror_db
        .execute("ATTACH DATABASE ? AS sibling", [sibling.to_str().unwrap()])
        .unwrap();
    mirror_db
        .execute_batch(
            "INSERT INTO sessions SELECT * FROM sibling.sessions;
                             INSERT INTO entries SELECT * FROM sibling.entries;",
        )
        .unwrap();
    let replay = Keybox::open_replay(&log, &KEY).unwrap();
    assert_eq!(
        replay.restore(second, &second_marker),
        Err(Error::UnknownSession)
    );
    assert_eq!(
        replay.restore(first, &first_marker).unwrap(),
        "password=first-fixture"
    );

    mirror_db
        .execute("UPDATE replay_end SET tag = zeroblob(32)", [])
        .unwrap();
    assert!(matches!(
        Keybox::open_replay(log, &KEY),
        Err(Error::InvalidMirror)
    ));
}

#[test]
fn repeated_markers_respect_the_restore_byte_limit() {
    let mut keybox = Keybox::open(":memory:", &KEY).unwrap();
    let session = keybox.create_session().unwrap();
    let value = "🐦".repeat(1024);
    let marker = keybox
        .get_or_create(session, SecretType::Credential, &value)
        .unwrap();
    let input = format!(">>{marker}.{marker}!");
    let exact = ">>".len() + 2 * value.len() + ".!".len();
    assert_eq!(
        keybox.restore_with_limit(session, &input, exact - 1),
        Err(Error::OutputLimit)
    );
    assert_eq!(
        keybox.restore_with_limit(session, &input, exact).unwrap(),
        format!(">>{value}.{value}!")
    );
}
