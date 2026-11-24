use convo_safe::{Keybox, SecretType, SessionId};

fn session() -> (Keybox, SessionId) {
    let mut keybox = Keybox::open(":memory:", &[67; 32]).unwrap();
    let session = keybox.create_session().unwrap();
    (keybox, session)
}

fn assert_redaction(
    keybox: &mut Keybox,
    session: SessionId,
    prompt: &str,
    secret: &str,
    kind: SecretType,
) {
    let placeholder = keybox.get_or_create(session, kind, secret).unwrap();
    let redacted = keybox.redact(session, prompt).unwrap();
    assert_eq!(redacted, prompt.replace(secret, &placeholder), "{prompt}");
    assert_eq!(keybox.restore(session, &redacted).unwrap(), prompt);
}

#[test]
fn openrouter_uses_one_credential_marker_across_contexts() {
    let (mut keybox, session) = session();
    let key = format!("sk-or-v1-{}", "0123456789abcdef".repeat(4));
    let prompt = format!(
        "Paste ({key})\nexport OPENROUTER_API_KEY='{key}' # leave this\n\
         {{\"key\":\"{key}\",\"label\":\"development\"}}\n\
         openrouterApiKey: \"{key}\"\n\
         curl -H 'Authorization: Bearer {key}' https://openrouter.ai/api/v1/models\n\
         https://example.invalid/check?api_key={key}&mode=keep#details\n\
         http://user:{key}@example.invalid/check"
    );
    assert_redaction(&mut keybox, session, &prompt, &key, SecretType::Credential);
}

#[test]
fn ignores_openrouter_examples_references_hashes_and_truncated_values() {
    let (mut keybox, session) = session();
    let hash = "0123456789abcdef".repeat(4);
    let prompt = format!(
        "openrouter/auto\nOPENROUTER_API_KEY=sk-or-v1-...\n\
         OPENROUTER_API_KEY=$OPENROUTER_API_KEY\n\
         openrouter_api_key: '${{OPENROUTER_API_KEY}}'\n\
         Authorization: Bearer $OPENROUTER_API_KEY\n\
         sample prefix: sk-or-v1-0123456789abcdef0123456789abcdef...\n\
         {{\"hash\":\"{hash}\",\"label\":\"development\"}}"
    );
    assert_eq!(keybox.redact(session, &prompt).unwrap(), prompt);
}

#[test]
fn credential_assignments_only_replace_the_value() {
    use SecretType::Credential;

    let (mut keybox, session) = session();
    let examples = [
        ("export CLIENT_SECRET='test only!' # keep", "test only!"),
        ("API_KEY=synthetic_value\nAPI_PORT=8080", "synthetic_value"),
        ("  api-key: fixture-value # example", "fixture-value"),
        (r#"{"apiKey": "fixture-key", "page": 5}"#, "fixture-key"),
        (
            r#"{"clientSecret": "test\"value\\part", "mode": "keep"}"#,
            r#"test\"value\\part"#,
        ),
        ("refreshToken: \"δοκιμή值\"", "δοκιμή值"),
        ("X-Api-Key: fake-header-token\r\n", "fake-header-token"),
        (
            "AWS_SECRET_ACCESS_KEY=not-a-real-aws-key",
            "not-a-real-aws-key",
        ),
    ];
    for (prompt, secret) in examples {
        assert_redaction(&mut keybox, session, prompt, secret, Credential);
    }
}

#[test]
fn authorization_redacts_generic_values_and_preserves_scheme() {
    let (mut keybox, session) = session();
    assert_redaction(
        &mut keybox,
        session,
        "Authorization: bEaReR fake.example-token==\r\nAccept: text/plain",
        "fake.example-token==",
        SecretType::Bearer,
    );
    assert_redaction(
        &mut keybox,
        session,
        "curl -H 'authorization: Basic ZmFrZTp0ZXN0' https://example.invalid",
        "ZmFrZTp0ZXN0",
        SecretType::Credential,
    );
}

#[test]
fn percent_encoded_uri_credentials_keep_their_exact_bytes_and_boundaries() {
    let (mut keybox, session) = session();
    for (prompt, secret) in [
        (
            "postgres://demo:fake%40test%2Fonly@localhost/db?sslmode=require",
            "fake%40test%2Fonly",
        ),
        (
            "https://example.invalid/check?access_token=fake%2Bvalue%3D&mode=keep#details",
            "fake%2Bvalue%3D",
        ),
        (
            "https://example.invalid/check?mode=keep&api_key=fixture%26key#details",
            "fixture%26key",
        ),
        (
            "https://example.invalid/check?access%5Ftoken=fake%25key&mode=keep",
            "fake%25key",
        ),
    ] {
        assert_redaction(&mut keybox, session, prompt, secret, SecretType::Credential);
    }
}

#[test]
fn ignores_placeholders_references_and_benign_fields() {
    let (mut keybox, session) = session();
    let prompt = concat!(
        "export API_KEY=\"$SERVICE_KEY\"\n",
        "export API_KEY=\"\\$SERVICE_KEY\"\n",
        "export API_KEY=\\${SERVICE_KEY}\n",
        "api-key: '${SERVICE_KEY}'\n",
        "PASSWORD=${DB_PASSWORD}\n",
        "Authorization: Bearer <token>\n",
        "API_KEY=<your-api-key>\n",
        "API_KEY=\"\"\n",
        "TOKEN=\n",
        "https://example.invalid/check?mode=keep#details\n",
        "{\"api_key_id\":\"key-123\",\"password_policy\":\"min-length\",\"token_count\":16}\n",
        "artifact ghp_too_short / AIZa-not-a-google-key / sk-or-v1-...\n",
        "leave serial A555-124-4856X\n",
    );
    assert_eq!(keybox.redact(session, prompt).unwrap(), prompt);
}

#[test]
fn redacts_common_provider_token_shapes_without_a_field_name() {
    let (mut keybox, session) = session();
    let examples = [
        format!("ghp_{}", "0".repeat(36)),
        format!("github_pat_{}", "test_0".repeat(12)),
        format!("glpat-{}", "test0".repeat(4)),
        "xoxb-000000000000-000000000000-testonly".to_owned(),
        format!("sk_live_{}", "0".repeat(24)),
        format!("rk_test_{}", "0".repeat(24)),
        format!("npm_{}", "0".repeat(36)),
        format!("sk-proj-{}", "test_0".repeat(5)),
        format!("sk-svcacct-{}", "test_0".repeat(5)),
        format!("sk-ant-api03-{}", "test_0".repeat(5)),
        "AKIA0000000000000000".to_owned(),
        "ASIA0000000000000000".to_owned(),
        format!("AIza{}", "0".repeat(35)),
    ];
    for secret in examples {
        let prompt = format!("🦜 `({secret})`, keep this punctuation!");
        assert_redaction(
            &mut keybox,
            session,
            &prompt,
            &secret,
            SecretType::Credential,
        );
    }
}

#[test]
fn handles_multiline_yaml_and_truncated_quoted_values() {
    let (mut keybox, session) = session();
    let block = "synthetic first line\r\n    synthetic second line";
    let prompt =
        format!("store:\r\n  password: |- # keep header\r\n    {block}\r\n  user: demo\r\n");
    assert_redaction(&mut keybox, session, &prompt, block, SecretType::Credential);
    assert_redaction(
        &mut keybox,
        session,
        "password: \"an incomplete fixture phrase\r\nnext: keep",
        "an incomplete fixture phrase",
        SecretType::Credential,
    );
    assert_redaction(
        &mut keybox,
        session,
        "Cookie: theme=dark; sessionId=fixture-cookie; language=en",
        "fixture-cookie",
        SecretType::Credential,
    );
}

#[test]
fn redacts_consecutive_sensitive_url_parameters() {
    let (mut keybox, session) = session();
    let url = "https://example.invalid/?api_key=first-fixture&client_secret=second-fixture&page=2#details";
    let redacted = keybox.redact(session, url).unwrap();
    assert!(!redacted.contains("first-fixture"));
    assert!(!redacted.contains("second-fixture"));
    assert!(redacted.contains("&client_secret="));
    assert!(redacted.ends_with("&page=2#details"));
    assert_eq!(keybox.restore(session, &redacted).unwrap(), url);
}
