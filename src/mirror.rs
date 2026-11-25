use crate::{Error, Keybox, Keys, Result, SCHEMA, SessionId, metadata, require_session};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
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

fn is_finalized(
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

fn tail(db: &Connection, session: SessionId) -> Result<i64> {
    Ok(db.query_row(
        "SELECT COALESCE(MAX(content), 0) FROM entries WHERE session = ?",
        [session],
        |row| row.get(0),
    )?)
}

impl Keybox {
    /// Open the single-session mirror next to a log in read-only mode.
    pub fn open_replay(log: impl AsRef<Path>, master: &[u8; 32]) -> Result<Self> {
        let db = Connection::open_with_flags(
            replay_path(log)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
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
        is_finalized(&read, &keys, session, tail(&read, session)?)?;
        read.commit()?;
        Ok(Self {
            db,
            keys,
            replay_session: Some(session),
        })
    }

    /// Append newly committed encrypted entries to the replay database for the log.
    pub fn checkpoint(&self, session: SessionId, log: impl AsRef<Path>) -> Result<()> {
        self.sync_replay(session, log.as_ref(), false)
    }

    /// Commit the remaining entries and seal the replay database. Retrying is safe.
    pub fn finalize_replay(&self, session: SessionId, log: impl AsRef<Path>) -> Result<()> {
        self.sync_replay(session, log.as_ref(), true)
    }

    fn sync_replay(&self, session: SessionId, log: &Path, finalize: bool) -> Result<()> {
        let source = self.db.unchecked_transaction()?;
        require_session(&source, session)?;
        if owner(&source)?.is_some() {
            return Err(Error::InvalidMirror);
        }
        let (namespace, verifier) = metadata(&source)?.ok_or(Error::InvalidMirror)?;
        let path = replay_path(log)?;
        let new = match crate::platform::create_private(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => false,
            Err(_) => return Err(Error::Storage),
        };
        let mut mirror = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        mirror.busy_timeout(Duration::from_secs(5))?;
        mirror.pragma_update(None, "foreign_keys", true)?;
        mirror.pragma_update(None, "synchronous", "FULL")?;
        let dest = mirror.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if new {
            dest.execute_batch(SCHEMA)?;
            dest.execute(
                "INSERT INTO keybox VALUES (1, ?, ?)",
                params![namespace, verifier],
            )?;
            dest.execute("INSERT INTO sessions VALUES (?)", [session])?;
            dest.execute("INSERT INTO replay_owner VALUES (1, ?)", [session])?;
        } else if owner(&dest).map_err(|_| Error::InvalidMirror)? != Some(session)
            || metadata(&dest).map_err(|_| Error::InvalidMirror)? != Some((namespace, verifier))
        {
            return Err(Error::InvalidMirror);
        }

        let copied = tail(&dest, session)?;
        let latest = tail(&source, session)?;
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
            return if copied == latest && finalize {
                Ok(())
            } else {
                Err(Error::SessionFinalized)
            };
        }

        {
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
        }
        if finalize {
            let tag = seal_tag(&self.keys, session, latest);
            dest.execute(
                "INSERT INTO replay_end VALUES (?, ?)",
                params![session, tag.as_bytes()],
            )?;
        }
        dest.commit()?;
        Ok(())
    }
}
