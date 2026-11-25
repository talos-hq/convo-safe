use crate::{Error, Keybox, Keys, Result, SCHEMA, SessionId, metadata, require_session};
use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

/// The replay database for a session log, e.g. `turns.jsonl.keybox.sqlite`.
pub fn replay_path(log: impl AsRef<Path>) -> Result<PathBuf> {
    let log = log.as_ref();
    let mut name = log.file_name().ok_or(Error::InvalidMirror)?.to_os_string();
    name.push(".keybox.sqlite");
    Ok(log.with_file_name(name))
}

pub(crate) fn owner(db: &Connection) -> Result<Option<SessionId>> {
    Ok(db
        .query_row("SELECT session FROM replay_owner WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?)
}

fn seal_tag(keys: &Keys, session: SessionId, highest_content: i64) -> blake3::Hash {
    blake3::keyed_hash(
        &keys.marker,
        format!("v1 replay end:{session}:{highest_content}").as_bytes(),
    )
}

pub(crate) fn is_finalized(
    db: &Connection,
    keys: &Keys,
    session: SessionId,
    highest_content: i64,
) -> Result<bool> {
    let stored: Option<[u8; 32]> = db
        .query_row(
            "SELECT tag FROM replay_end WHERE session = ?",
            [session],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(tag) = stored {
        if blake3::Hash::from_bytes(tag) != seal_tag(keys, session, highest_content) {
            return Err(Error::InvalidMirror);
        }
        return Ok(true);
    }
    Ok(false)
}

fn sidecar_tag(keys: &Keys, session: SessionId, nonce: [u8; 16]) -> blake3::Hash {
    let mut tag = blake3::Hasher::new_keyed(&keys.marker);
    tag.update(b"v1 replay sidecar:");
    tag.update(&session.to_le_bytes());
    tag.update(&nonce);
    tag.finalize()
}

fn read_sidecar_id(
    db: &Connection,
    keys: &Keys,
    session: SessionId,
) -> Result<Option<blake3::Hash>> {
    let exists = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'replay_sidecar')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let (nonce, stored) = db
        .query_row(
            "SELECT nonce, tag FROM replay_sidecar WHERE id = 1",
            [],
            |row| Ok((row.get::<_, [u8; 16]>(0)?, row.get::<_, [u8; 32]>(1)?)),
        )
        .map_err(|_| Error::InvalidMirror)?;
    let tag = sidecar_tag(keys, session, nonce);
    if tag != blake3::Hash::from_bytes(stored) {
        return Err(Error::InvalidMirror);
    }
    Ok(Some(tag))
}

pub(crate) fn tail(db: &Connection, session: SessionId) -> Result<i64> {
    Ok(db.query_row(
        "SELECT COALESCE(MAX(content), 0) FROM entries WHERE session = ?",
        [session],
        |row| row.get(0),
    )?)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyMode {
    Checkpoint,
    Finalize,
    Fork,
}

impl Keybox {
    /// Open the single-session mirror next to a log in read-only mode.
    pub fn open_replay(log: impl AsRef<Path>, master: &[u8; 32]) -> Result<Self> {
        Self::open_scoped(log.as_ref(), master, false)
    }

    /// Reopen an unsealed, single-session sidecar for continued redaction.
    pub fn resume_replay(log: impl AsRef<Path>, master: &[u8; 32]) -> Result<Self> {
        Self::open_scoped(log.as_ref(), master, true)
    }

    fn open_scoped(log: &Path, master: &[u8; 32], writable: bool) -> Result<Self> {
        let access = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let db = Connection::open_with_flags(
            replay_path(log)?,
            access | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        if writable {
            db.pragma_update(None, "foreign_keys", true)?;
            db.pragma_update(None, "synchronous", "FULL")?;
        }
        db.busy_timeout(Duration::from_secs(5))?;
        let session = owner(&db)?.ok_or(Error::InvalidMirror)?;
        require_session(&db, session)?;
        let (namespace, verifier) = metadata(&db)?.ok_or(Error::InvalidMirror)?;
        let keys = Keys::new(master, &namespace);
        if blake3::Hash::from_bytes(verifier) != keys.verifier() {
            return Err(Error::InvalidKey);
        }
        // Read the tail and seal from one snapshot, including during a checkpoint.
        let read = db.unchecked_transaction()?;
        let sealed = is_finalized(&read, &keys, session, tail(&read, session)?)?;
        let replay_sidecar_id = read_sidecar_id(&read, &keys, session)?;
        if writable && sealed {
            return Err(Error::SessionFinalized);
        }
        read.commit()?;
        Ok(Self {
            db,
            keys,
            replay_session: Some(session),
            replay_sidecar_id,
        })
    }

    /// Append newly committed encrypted entries to the replay database for the log.
    pub fn checkpoint(&self, session: SessionId, log: impl AsRef<Path>) -> Result<()> {
        self.sync_replay(session, log.as_ref(), CopyMode::Checkpoint)
    }

    /// Commit the remaining entries and seal the replay database. Retrying is safe.
    pub fn finalize_replay(&self, session: SessionId, log: impl AsRef<Path>) -> Result<()> {
        self.sync_replay(session, log.as_ref(), CopyMode::Finalize)
    }

    /// Return the sidecar's numeric session owner, if this is a scoped Keybox.
    pub fn replay_session(&self) -> Option<SessionId> {
        self.replay_session
    }

    /// A stable authenticated lineage identifier for the sidecar owner.
    pub fn replay_identity(&self) -> Option<String> {
        self.replay_session.map(|session| {
            blake3::keyed_hash(
                &self.keys.marker,
                format!("v1 replay identity:{session}").as_bytes(),
            )
            .to_hex()
            .to_string()
        })
    }

    /// Authenticated identity of this sidecar, distinct for each fork.
    /// Sidecars created before this identifier was introduced return `None`.
    pub fn replay_sidecar_id(&self) -> Option<String> {
        self.replay_sidecar_id.map(|id| id.to_hex().to_string())
    }

    /// Copy a consistent sidecar snapshot to a new log, preserving inherited markers.
    pub fn fork_replay(&self, new_log: impl AsRef<Path>) -> Result<()> {
        let session = self.replay_session.ok_or(Error::InvalidMirror)?;
        self.sync_replay(session, new_log.as_ref(), CopyMode::Fork)
    }

    /// Seal the resumed sidecar. Existing readers can continue locating its mappings.
    pub fn seal_replay(&mut self) -> Result<()> {
        let session = self.replay_session.ok_or(Error::InvalidMirror)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let highest = tail(&tx, session)?;
        if !is_finalized(&tx, &self.keys, session, highest)? {
            write_seal(&tx, &self.keys, session, highest)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn sync_replay(&self, session: SessionId, log: &Path, mode: CopyMode) -> Result<()> {
        let source = self.db.unchecked_transaction()?;
        require_session(&source, session)?;
        if mode != CopyMode::Fork && owner(&source)?.is_some() {
            return Err(Error::InvalidMirror);
        }
        let (namespace, verifier) = metadata(&source)?.ok_or(Error::InvalidMirror)?;
        let path = replay_path(log)?;
        let staging = match fs::symlink_metadata(&path) {
            Ok(_) if mode == CopyMode::Fork => return Err(Error::InvalidMirror),
            Ok(_) => None,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Some(StagedSidecar::create(&path)?)
            }
            Err(_) => return Err(Error::Storage),
        };
        let db_path = staging
            .as_ref()
            .map_or(path.as_path(), |staged| staged.0.as_path());
        let mut mirror = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        mirror.busy_timeout(Duration::from_secs(5))?;
        mirror.pragma_update(None, "foreign_keys", true)?;
        mirror.pragma_update(None, "synchronous", "FULL")?;
        let dest = mirror.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if staging.is_some() {
            dest.execute_batch(SCHEMA)?;
            dest.execute(
                "INSERT INTO keybox VALUES (1, ?, ?)",
                params![namespace, verifier],
            )?;
            dest.execute("INSERT INTO sessions VALUES (?)", [session])?;
            dest.execute("INSERT INTO replay_owner VALUES (1, ?)", [session])?;
            dest.execute_batch(
                "CREATE TABLE replay_sidecar (id INTEGER PRIMARY KEY CHECK (id = 1), nonce BLOB NOT NULL, tag BLOB NOT NULL);",
            )?;
            let mut nonce = [0; 16];
            OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| Error::Storage)?;
            let tag = sidecar_tag(&self.keys, session, nonce);
            dest.execute(
                "INSERT INTO replay_sidecar VALUES (1, ?, ?)",
                params![nonce, tag.as_bytes()],
            )?;
        } else if owner(&dest).map_err(|_| Error::InvalidMirror)? != Some(session)
            || metadata(&dest).map_err(|_| Error::InvalidMirror)? != Some((namespace, verifier))
        {
            return Err(Error::InvalidMirror);
        }
        read_sidecar_id(&dest, &self.keys, session)?;

        let copied = tail(&dest, session)?;
        let latest = tail(&source, session)?;
        if mode == CopyMode::Fork {
            is_finalized(&source, &self.keys, session, latest)?;
        }
        if copied > latest {
            return Err(Error::InvalidMirror);
        }
        if copied > 0 {
            let record_at_tail = |db: &Connection| {
                db.query_row(
                    "SELECT fingerprint, record FROM entries WHERE session = ? AND content = ?",
                    params![session, copied],
                    |row| Ok((row.get::<_, [u8; 32]>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
            };
            if record_at_tail(&source)? != record_at_tail(&dest)? {
                return Err(Error::InvalidMirror);
            }
        }
        if is_finalized(&dest, &self.keys, session, copied)? {
            return if copied == latest && mode == CopyMode::Finalize {
                Ok(())
            } else {
                Err(Error::SessionFinalized)
            };
        }

        copy_new_entries(&source, &dest, session, copied)?;
        if mode == CopyMode::Finalize {
            write_seal(&dest, &self.keys, session, latest)?;
        }
        dest.commit()?;
        if let Some(staged) = staging {
            drop(mirror);
            fs::hard_link(&staged.0, &path).map_err(|error| {
                if error.kind() == ErrorKind::AlreadyExists {
                    Error::InvalidMirror
                } else {
                    Error::Storage
                }
            })?;
            crate::platform::sync_parent(&path).map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}

fn copy_new_entries(
    source: &Connection,
    dest: &Connection,
    session: SessionId,
    copied: i64,
) -> Result<()> {
    let mut read = source.prepare(
                "SELECT content, kind, fingerprint, record FROM entries WHERE session = ? AND content > ? ORDER BY content",
            )?;
    let mut rows = read.query(params![session, copied])?;
    let mut write = dest.prepare("INSERT INTO entries VALUES (?, ?, ?, ?, ?)")?;
    while let Some(row) = rows.next()? {
        write.execute(params![
            session,
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, [u8; 32]>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ])?;
    }
    Ok(())
}

fn write_seal(db: &Connection, keys: &Keys, session: SessionId, highest: i64) -> Result<()> {
    let tag = seal_tag(keys, session, highest);
    db.execute(
        "INSERT INTO replay_end VALUES (?, ?)",
        params![session, tag.as_bytes()],
    )?;
    Ok(())
}

struct StagedSidecar(PathBuf);

impl StagedSidecar {
    fn create(dest: &Path) -> Result<Self> {
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Entropy)?;
        let name = format!(
            ".convo-safe-{}.pending",
            blake3::Hash::from_bytes(nonce).to_hex()
        );
        let path = dest.with_file_name(name);
        crate::platform::create_private(&path).map_err(|_| Error::Storage)?;
        Ok(Self(path))
    }
}

impl Drop for StagedSidecar {
    fn drop(&mut self) {
        // The name belongs to this process and has already been published or abandoned.
        let _ = fs::remove_file(&self.0);
    }
}
