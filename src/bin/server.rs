use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use convo_safe::{Keybox, SecretType, SessionId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT: usize = 1024 * 1024;
const MAX_FRAME: usize = 8 * MAX_INPUT;
const MAX_SESSIONS: usize = 256;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    CreateSession {
        session_log: PathBuf,
    },
    GetOrCreate {
        session: SessionId,
        kind: SecretType,
        secret: String,
    },
    Redact {
        session: SessionId,
        text: String,
    },
    BeginMessage {
        session: SessionId,
    },
    Chunk {
        session: SessionId,
        text: String,
    },
    FinishMessage {
        session: SessionId,
    },
    AbortMessage {
        session: SessionId,
    },
    Checkpoint {
        session: SessionId,
    },
    EndSession {
        session: SessionId,
    },
    Restore {
        session: SessionId,
        text: String,
    },
}

impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::GetOrCreate { secret, .. } => secret.zeroize(),
            Self::Chunk { text, .. } | Self::Redact { text, .. } | Self::Restore { text, .. } => {
                text.zeroize()
            }
            _ => {}
        }
    }
}

struct Active {
    log: PathBuf,
    pending: Option<Zeroizing<String>>,
}

struct Worker {
    keybox: Keybox,
    active: HashMap<SessionId, Active>,
    mode: Mode,
}

#[derive(PartialEq)]
enum Mode {
    Redact,
    LocalReplay,
    ReplayOnly,
}

impl Worker {
    fn handle(&mut self, request: &Request) -> Result<Value, String> {
        if let Request::Restore { session, text } = request {
            return if self.mode == Mode::Redact {
                Err("restore is disabled".into())
            } else {
                let text = self
                    .keybox
                    .restore_with_limit(*session, text, MAX_FRAME - 1024)
                    .map_err(storage_error)?;
                text_reply(text)
            };
        }
        if self.mode == Mode::ReplayOnly {
            return Err("replay worker only accepts restore".into());
        }

        let session = match request {
            Request::CreateSession { session_log } => {
                if self.active.len() >= MAX_SESSIONS {
                    return Err("too many open sessions".into());
                }
                let session = self.keybox.create_session().map_err(storage_error)?;
                self.keybox
                    .checkpoint(session, session_log)
                    .map_err(storage_error)?;
                self.active.insert(
                    session,
                    Active {
                        log: session_log.clone(),
                        pending: None,
                    },
                );
                return Ok(json!({ "session": session }));
            }
            Request::GetOrCreate { session, .. }
            | Request::Redact { session, .. }
            | Request::BeginMessage { session }
            | Request::Chunk { session, .. }
            | Request::FinishMessage { session }
            | Request::AbortMessage { session }
            | Request::Checkpoint { session }
            | Request::EndSession { session } => *session,
            Request::Restore { .. } => unreachable!("restore handled before mutation"),
        };

        let pending_bytes = if matches!(request, Request::Chunk { .. }) {
            self.active
                .values()
                .filter_map(|state| state.pending.as_ref())
                .map(|text| text.len())
                .sum::<usize>()
        } else {
            0
        };
        let state = self
            .active
            .get_mut(&session)
            .ok_or("session is not open in this worker")?;
        match request {
            Request::GetOrCreate { kind, secret, .. } => {
                check_input(secret)?;
                let placeholder = self
                    .keybox
                    .get_or_create(session, *kind, secret)
                    .map_err(storage_error)?;
                self.keybox
                    .checkpoint(session, &state.log)
                    .map_err(storage_error)?;
                Ok(json!({ "placeholder": placeholder }))
            }
            Request::Redact { text, .. } => {
                check_input(text)?;
                redact(&mut self.keybox, session, state, text)
            }
            Request::BeginMessage { .. } => {
                if state.pending.is_some() {
                    return Err("a message is already open".into());
                }
                state.pending = Some(Zeroizing::new(String::new()));
                Ok(json!({ "ok": true }))
            }
            Request::Chunk { text, .. } => {
                let pending = state.pending.as_mut().ok_or("no open message")?;
                if text.len() > MAX_INPUT - pending.len() || text.len() > MAX_FRAME - pending_bytes
                {
                    state.pending = None;
                    return Err("pending message capacity exceeded".into());
                }
                pending.push_str(text);
                Ok(json!({ "ok": true }))
            }
            Request::FinishMessage { .. } => {
                let text = state.pending.as_ref().ok_or("no open message")?;
                let response = redact(&mut self.keybox, session, state, text)?;
                state.pending = None;
                Ok(response)
            }
            Request::AbortMessage { .. } => {
                state.pending = None;
                Ok(json!({ "ok": true }))
            }
            Request::Checkpoint { .. } => {
                self.keybox
                    .checkpoint(session, &state.log)
                    .map_err(storage_error)?;
                Ok(json!({ "ok": true }))
            }
            Request::EndSession { .. } => {
                if state.pending.is_some() {
                    return Err("finish or abort the open message first".into());
                }
                self.keybox
                    .finalize_replay(session, &state.log)
                    .map_err(storage_error)?;
                self.active.remove(&session);
                Ok(json!({ "ok": true }))
            }
            _ => unreachable!("request handled before locating a session"),
        }
    }

    fn close(&self) -> Result<(), String> {
        let mut end_error = None;
        for (&session, state) in &self.active {
            if let Err(error) = self.keybox.finalize_replay(session, &state.log) {
                end_error = Some(storage_error(error));
            }
        }
        end_error.map_or(Ok(()), Err)
    }
}

fn storage_error(error: convo_safe::Error) -> String {
    error.to_string()
}

fn check_input(text: &str) -> Result<(), String> {
    if text.len() > MAX_INPUT {
        return Err("message exceeds 1 MiB".into());
    }
    Ok(())
}

fn redact(
    keybox: &mut Keybox,
    session: SessionId,
    state: &Active,
    text: &str,
) -> Result<Value, String> {
    let redacted = keybox.redact(session, text).map_err(storage_error)?;
    let reply = text_reply(redacted)?;
    keybox
        .checkpoint(session, &state.log)
        .map_err(storage_error)?;
    Ok(reply)
}

fn text_reply(mut text: String) -> Result<Value, String> {
    // Count JSON escapes and leave space for the surrounding replay request.
    let encoded: usize = text
        .bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
            0..=31 => 6,
            _ => 1,
        })
        .sum();
    if encoded > MAX_FRAME - 1024 {
        text.zeroize();
        return Err("message exceeds replay capacity".into());
    }
    Ok(json!({ "text": text }))
}

fn serve(mut worker: Worker) -> Result<(), String> {
    let transport_error = |_| "stdio transport failed".to_owned();
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut line = Zeroizing::new(Vec::new());
    loop {
        if (&mut input)
            .take(MAX_FRAME as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(transport_error)?
            == 0
        {
            return worker.close();
        }
        if line.len() > MAX_FRAME {
            output
                .write_all(b"{\"error\":\"request exceeds 8 MiB\"}\n")
                .map_err(transport_error)?;
            output.flush().map_err(transport_error)?;
            return worker.close();
        }
        let mut reply = match serde_json::from_slice::<Request>(&line) {
            Ok(request) => worker
                .handle(&request)
                .unwrap_or_else(|error| json!({ "error": error })),
            Err(_) => json!({ "error": "invalid request" }),
        };
        line.zeroize();
        let written = serde_json::to_writer(&mut output, &reply);
        if let Some(Value::String(text)) = reply.get_mut("text") {
            text.zeroize();
        }
        written.map_err(|_| "stdio transport failed")?;
        output.write_all(b"\n").map_err(transport_error)?;
        output.flush().map_err(transport_error)?;
    }
}

fn create_key(path: &Path) -> Result<(), &'static str> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut *key)
        .map_err(|_| "system randomness unavailable")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| {
            file.write_all(&*key)?;
            file.sync_all()
        })
        .map_err(|_| "cannot create Keybox key file")
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut file = File::open(path).map_err(|_| "cannot open Keybox key file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect Keybox key file")?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err("Keybox key file must be a regular file containing 32 raw bytes");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Keybox key file must be private (mode 0600)");
        }
    }
    let mut key = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *key)
        .map_err(|_| "cannot read Keybox key file")?;
    Ok(key)
}

const USAGE: &str =
    "usage: convo-safe init-key KEY_FILE | convo-safe serve DB_FILE KEY_FILE [--allow-restore]";

fn run(args: &[OsString]) -> Result<(), String> {
    match args {
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        [cmd, key] if cmd == "init-key" => Ok(create_key(Path::new(key))?),
        [cmd, db, key, flags @ ..] if cmd == "serve" => {
            let mode = match flags {
                [] => Mode::Redact,
                [flag] if flag == "--allow-restore" => Mode::LocalReplay,
                _ => return Err(USAGE.to_owned()),
            };
            let master = read_key(Path::new(key))?;
            let keybox = Keybox::open(db, &master).map_err(|error| error.to_string())?;
            drop(master);
            serve(Worker {
                keybox,
                active: HashMap::new(),
                mode,
            })
        }
        [cmd, log, key] if cmd == "replay" => {
            let master = read_key(Path::new(key))?;
            let keybox = Keybox::open_replay(log, &master).map_err(storage_error)?;
            drop(master);
            serve(Worker {
                keybox,
                active: HashMap::new(),
                mode: Mode::ReplayOnly,
            })
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn main() -> ExitCode {
    match run(&env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
