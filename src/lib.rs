//! Local, reversible redaction for prompts and conversation replays.

mod mirror;
#[cfg(feature = "python")]
mod python;
mod scanner;

pub use mirror::replay_path;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, str::FromStr, sync::LazyLock, time::Duration};
use zeroize::Zeroizing;

const PREFIX: &str = "[[CONVO_SAFE:";
const ESCAPE: &str = "[[CONVO_SAFE:literal]]";
static MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"\[\[CONVO_SAFE:(?:literal|v1:\{"REDACTED":"([A-Z_]+)","#,
        r#""SESSIONID":([1-9][0-9]{0,18}),"CONTENTID":([1-9][0-9]{0,18}),"#,
        r#""TAG":"([0-9a-f]{64})"\})\]\]"#
    ))
    .expect("static placeholder grammar")
});

pub type SessionId = i64;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretType {
    Phone,
    Credential,
    PrivateKey,
    Bearer,
    Email,
    Ssn,
    CreditCard,
    IpAddress,
    PersonName,
    Address,
}

impl SecretType {
    fn name(self) -> &'static str {
        match self {
            Self::Phone => "PHONE",
            Self::Credential => "CREDENTIAL",
            Self::PrivateKey => "PRIVATE_KEY",
            Self::Bearer => "BEARER",
            Self::Email => "EMAIL",
            Self::Ssn => "SSN",
            Self::CreditCard => "CREDIT_CARD",
            Self::IpAddress => "IP_ADDRESS",
            Self::PersonName => "PERSON_NAME",
            Self::Address => "ADDRESS",
        }
    }
}

impl FromStr for SecretType {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        match text {
            "PHONE" => Ok(Self::Phone),
            "CREDENTIAL" => Ok(Self::Credential),
            "PRIVATE_KEY" => Ok(Self::PrivateKey),
            "BEARER" => Ok(Self::Bearer),
            "EMAIL" => Ok(Self::Email),
            "SSN" => Ok(Self::Ssn),
            "CREDIT_CARD" => Ok(Self::CreditCard),
            "IP_ADDRESS" => Ok(Self::IpAddress),
            "PERSON_NAME" => Ok(Self::PersonName),
            "ADDRESS" => Ok(Self::Address),
            _ => Err(Error::InvalidType),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Storage,
    InvalidKey,
    UnknownSession,
    InvalidType,
    InvalidSecret,
    CorruptRecord,
    Entropy,
    InvalidMirror,
    SessionFinalized,
    OutputLimit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Storage => "Keybox storage operation failed",
            Self::InvalidKey => "Keybox requires its original 32-byte master key",
            Self::UnknownSession => "unknown session ID",
            Self::InvalidType => "unknown secret type",
            Self::InvalidSecret => "secret must not be empty",
            Self::CorruptRecord => "Keybox record authentication failed",
            Self::Entropy => "system randomness unavailable",
            Self::InvalidMirror => "replay database does not match this session",
            Self::SessionFinalized => "session replay is finalized",
            Self::OutputLimit => "restored message exceeds output capacity",
        })
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

struct Keys {
    cipher: XChaCha20Poly1305,
    lookup: Zeroizing<[u8; 32]>,
    marker: Zeroizing<[u8; 32]>,
}

impl Keys {
    fn new(master: &[u8; 32], namespace: &[u8; 32]) -> Self {
        let isolated = Zeroizing::new(blake3::keyed_hash(master, namespace).as_bytes().to_owned());
        let cipher = Zeroizing::new(blake3::derive_key(
            "convo safe v1 record encryption",
            &*isolated,
        ));
        Self {
            cipher: XChaCha20Poly1305::new((&*cipher).into()),
            lookup: Zeroizing::new(blake3::derive_key(
                "convo safe v1 record lookup",
                &*isolated,
            )),
            marker: Zeroizing::new(blake3::derive_key(
                "convo safe v1 placeholder authentication",
                &*isolated,
            )),
        }
    }

    fn verifier(&self) -> blake3::Hash {
        blake3::keyed_hash(&self.lookup, b"convo safe v1 Keybox verifier")
    }

    fn fingerprint(&self, session: SessionId, kind: SecretType, secret: &str) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_keyed(&self.lookup);
        hasher.update(&session.to_be_bytes());
        hasher.update(kind.name().as_bytes());
        hasher.update(b"\0");
        hasher.update(secret.as_bytes());
        hasher.finalize()
    }

    fn encrypt(&self, identity: &str, secret: &str) -> Result<Vec<u8>> {
        let mut nonce = XNonce::default();
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Entropy)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: secret.as_bytes(),
                    aad: identity.as_bytes(),
                },
            )
            .map_err(|_| Error::InvalidSecret)?;
        let mut record = nonce.to_vec();
        record.extend(ciphertext);
        Ok(record)
    }

    fn decrypt(&self, identity: &str, record: &[u8]) -> Result<Zeroizing<String>> {
        let (nonce, ciphertext) = record.split_at_checked(24).ok_or(Error::CorruptRecord)?;
        let plaintext = self
            .cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: identity.as_bytes(),
                },
            )
            .map_err(|_| Error::CorruptRecord)?;
        String::from_utf8(plaintext)
            .map(Zeroizing::new)
            .map_err(|_| Error::CorruptRecord)
    }
}

fn identity(
    session: SessionId,
    content: i64,
    kind: SecretType,
    fingerprint: &blake3::Hash,
) -> String {
    format!(
        "{session}:{content}:{}:{}",
        kind.name(),
        fingerprint.to_hex()
    )
}

const SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS keybox (id INTEGER PRIMARY KEY CHECK (id = 1), namespace BLOB NOT NULL, verifier BLOB NOT NULL);
     CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT);
     CREATE TABLE IF NOT EXISTS entries (
         session INTEGER NOT NULL REFERENCES sessions(id),
         content INTEGER NOT NULL,
         kind TEXT NOT NULL,
         fingerprint BLOB NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (session, content),
         UNIQUE (session, fingerprint)
     );
     CREATE TABLE IF NOT EXISTS replay_owner (id INTEGER PRIMARY KEY CHECK (id = 1), session INTEGER NOT NULL REFERENCES sessions(id));
     CREATE TABLE IF NOT EXISTS replay_end (session INTEGER PRIMARY KEY REFERENCES sessions(id), tag BLOB NOT NULL);";

fn metadata(db: &Connection) -> Result<Option<([u8; 32], [u8; 32])>> {
    Ok(db
        .query_row(
            "SELECT namespace, verifier FROM keybox WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

/// An authenticated encrypted store. Keep the high-entropy master key in a separate secret store.
pub struct Keybox {
    db: Connection,
    keys: Keys,
    replay_session: Option<SessionId>,
}

impl Keybox {
    /// Open an existing Keybox or create it with the supplied 32-byte master key.
    pub fn open(path: impl AsRef<Path>, master: &[u8; 32]) -> Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.pragma_update(None, "foreign_keys", true)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        if mirror::owner(&tx)?.is_some() {
            return Err(Error::InvalidMirror);
        }
        let metadata = metadata(&tx)?;
        let namespace = if let Some((namespace, _)) = metadata {
            namespace
        } else {
            let mut namespace = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut namespace)
                .map_err(|_| Error::Entropy)?;
            namespace
        };
        let keys = Keys::new(master, &namespace);
        let check = keys.verifier();
        if let Some((_, verifier)) = metadata {
            if blake3::Hash::from_bytes(verifier) != check {
                return Err(Error::InvalidKey);
            }
        } else {
            tx.execute(
                "INSERT INTO keybox VALUES (1, ?, ?)",
                params![namespace, check.as_bytes()],
            )?;
        }
        tx.commit()?;
        Ok(Self {
            db,
            keys,
            replay_session: None,
        })
    }

    /// Allocate a stable, monotonically increasing session ID.
    pub fn create_session(&mut self) -> Result<SessionId> {
        self.db.execute("INSERT INTO sessions DEFAULT VALUES", [])?;
        Ok(self.db.last_insert_rowid())
    }

    /// Obtain a placeholder for this exact secret and type within a session.
    pub fn get_or_create(
        &mut self,
        session: SessionId,
        kind: SecretType,
        secret: &str,
    ) -> Result<String> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_session(&tx, session)?;
        let placeholder = insert(&tx, &self.keys, session, kind, secret)?;
        tx.commit()?;
        Ok(placeholder)
    }

    /// Replace recognized secrets. A failed storage operation produces no prompt output.
    pub fn redact(&mut self, session: SessionId, input: &str) -> Result<String> {
        let matches = scanner::matches(input);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_session(&tx, session)?;
        let mut result = String::with_capacity(input.len());
        let mut cursor = 0;
        for (start, end, kind) in matches {
            result.push_str(&input[cursor..start].replace(PREFIX, ESCAPE));
            result.push_str(&insert(&tx, &self.keys, session, kind, &input[start..end])?);
            cursor = end;
        }
        result.push_str(&input[cursor..].replace(PREFIX, ESCAPE));
        tx.commit()?;
        Ok(result)
    }

    /// Restore exact, authenticated markers for this session. Call only on a trusted replay path.
    pub fn restore(&self, session: SessionId, input: &str) -> Result<String> {
        self.restore_with_limit(session, input, usize::MAX)
    }

    /// Restore a replay while bounding the decoded response by its UTF-8 byte length.
    pub fn restore_with_limit(
        &self,
        session: SessionId,
        input: &str,
        max_bytes: usize,
    ) -> Result<String> {
        if self.replay_session.is_some_and(|owner| owner != session) {
            return Err(Error::UnknownSession);
        }
        require_session(&self.db, session)?;
        let mut result = Zeroizing::new(String::with_capacity(input.len().min(max_bytes)));
        let mut cursor = 0;
        for marker in MARKER.captures_iter(input) {
            let whole = marker.get(0).expect("capture zero");
            push_limited(&mut result, &input[cursor..whole.start()], max_bytes)?;
            cursor = whole.end();
            if whole.as_str() == ESCAPE {
                push_limited(&mut result, PREFIX, max_bytes)?;
            } else if let Some(secret) =
                self.restore_marker(session, &marker, max_bytes - result.len())?
            {
                push_limited(&mut result, &secret, max_bytes)?;
            } else {
                push_limited(&mut result, whole.as_str(), max_bytes)?;
            }
        }
        push_limited(&mut result, &input[cursor..], max_bytes)?;
        Ok(std::mem::take(&mut *result))
    }

    fn restore_marker(
        &self,
        session: SessionId,
        marker: &regex::Captures<'_>,
        available: usize,
    ) -> Result<Option<Zeroizing<String>>> {
        let (Ok(kind), Ok(marker_session), Ok(content), Ok(tag)) = (
            marker[1].parse::<SecretType>(),
            marker[2].parse::<SessionId>(),
            marker[3].parse::<i64>(),
            blake3::Hash::from_hex(&marker[4]),
        ) else {
            return Ok(None);
        };
        if marker_session != session {
            return Ok(None);
        }
        let entry: Option<([u8; 32], usize)> = self.db.query_row(
            "SELECT fingerprint, length(record) FROM entries WHERE session = ? AND content = ? AND kind = ?",
            params![session, content, kind.name()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let Some((fingerprint, record_len)) = entry else {
            return Ok(None);
        };
        let identity = identity(
            session,
            content,
            kind,
            &blake3::Hash::from_bytes(fingerprint),
        );
        if blake3::keyed_hash(&self.keys.marker, identity.as_bytes()) != tag {
            return Ok(None);
        }
        let secret_len = record_len
            .checked_sub(24 + 16)
            .ok_or(Error::CorruptRecord)?;
        if secret_len > available {
            return Err(Error::OutputLimit);
        }
        let record: Vec<u8> = self
            .db
            .query_row(
                "SELECT record FROM entries WHERE session = ? AND content = ? AND fingerprint = ?",
                params![session, content, fingerprint],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::CorruptRecord)?;
        self.keys.decrypt(&identity, &record).map(Some)
    }
}

fn push_limited(result: &mut String, text: &str, limit: usize) -> Result<()> {
    if text.len() > limit - result.len() {
        return Err(Error::OutputLimit);
    }
    result.push_str(text);
    Ok(())
}

fn require_session(db: &Connection, session: SessionId) -> Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?)",
        [session],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(Error::UnknownSession)
    }
}

fn insert(
    tx: &Transaction<'_>,
    keys: &Keys,
    session: SessionId,
    kind: SecretType,
    secret: &str,
) -> Result<String> {
    if secret.is_empty() {
        return Err(Error::InvalidSecret);
    }
    let fingerprint = keys.fingerprint(session, kind, secret);
    let existing = tx
        .query_row(
            "SELECT content FROM entries WHERE session = ? AND fingerprint = ?",
            params![session, fingerprint.as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let content = if let Some(content) = existing {
        content
    } else {
        let previous: i64 = tx.query_row(
            "SELECT COALESCE(MAX(content), 0) FROM entries WHERE session = ?",
            [session],
            |row| row.get(0),
        )?;
        let content = previous.checked_add(1).ok_or(Error::Storage)?;
        let record = keys.encrypt(&identity(session, content, kind, &fingerprint), secret)?;
        tx.execute(
            "INSERT INTO entries VALUES (?, ?, ?, ?, ?)",
            params![
                session,
                content,
                kind.name(),
                fingerprint.as_bytes(),
                record
            ],
        )?;
        content
    };
    let tag = blake3::keyed_hash(
        &keys.marker,
        identity(session, content, kind, &fingerprint).as_bytes(),
    );
    Ok(format!(
        r#"{PREFIX}v1:{{"REDACTED":"{}","SESSIONID":{session},"CONTENTID":{content},"TAG":"{tag}"}}]]"#,
        kind.name(),
        tag = tag.to_hex(),
    ))
}
