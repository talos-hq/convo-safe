use crate::{Error, Keybox, RedactionOptions, SessionId};
use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn python_error(error: Error) -> PyErr {
    match error {
        Error::InvalidKey | Error::InvalidType | Error::InvalidSecret | Error::UnknownSession => {
            PyValueError::new_err(error.to_string())
        }
        _ => PyRuntimeError::new_err(error.to_string()),
    }
}

#[pyclass(unsendable, name = "Keybox", module = "convo_safe")]
struct PythonKeybox(Keybox);

#[pymethods]
impl PythonKeybox {
    #[new]
    fn open(path: PathBuf, master_key: &[u8]) -> PyResult<Self> {
        let key = Zeroizing::new(
            <[u8; 32]>::try_from(master_key).map_err(|_| python_error(Error::InvalidKey))?,
        );
        Keybox::open(path, &key).map(Self).map_err(python_error)
    }

    #[staticmethod]
    fn open_replay(session_log: PathBuf, master_key: &[u8]) -> PyResult<Self> {
        let key = Zeroizing::new(
            <[u8; 32]>::try_from(master_key).map_err(|_| python_error(Error::InvalidKey))?,
        );
        Keybox::open_replay(session_log, &key)
            .map(Self)
            .map_err(python_error)
    }

    #[staticmethod]
    fn resume_replay(session_log: PathBuf, master_key: &[u8]) -> PyResult<Self> {
        let key = Zeroizing::new(
            <[u8; 32]>::try_from(master_key).map_err(|_| python_error(Error::InvalidKey))?,
        );
        Keybox::resume_replay(session_log, &key)
            .map(Self)
            .map_err(python_error)
    }

    #[getter]
    fn replay_session(&self) -> Option<SessionId> {
        self.0.replay_session()
    }

    #[getter]
    fn replay_identity(&self) -> Option<String> {
        self.0.replay_identity()
    }

    fn fork_replay(&self, new_log: PathBuf) -> PyResult<()> {
        self.0.fork_replay(new_log).map_err(python_error)
    }

    fn seal_replay(&mut self) -> PyResult<()> {
        self.0.seal_replay().map_err(python_error)
    }

    fn checkpoint(&self, session: SessionId, session_log: PathBuf) -> PyResult<()> {
        self.0
            .checkpoint(session, session_log)
            .map_err(python_error)
    }

    fn finalize_replay(&self, session: SessionId, session_log: PathBuf) -> PyResult<()> {
        self.0
            .finalize_replay(session, session_log)
            .map_err(python_error)
    }

    fn create_session(&mut self) -> PyResult<SessionId> {
        self.0.create_session().map_err(python_error)
    }

    fn get_or_create(&mut self, session: SessionId, kind: &str, secret: &str) -> PyResult<String> {
        self.0
            .get_or_create(session, kind.parse().map_err(python_error)?, secret)
            .map_err(python_error)
    }

    #[pyo3(signature = (session, text, *, redact_email = false))]
    fn redact(&mut self, session: SessionId, text: &str, redact_email: bool) -> PyResult<String> {
        self.0
            .redact_with_options(session, text, RedactionOptions { redact_email })
            .map_err(python_error)
    }

    #[pyo3(signature = (session, text, *, redact_email = false))]
    fn redact_model_text(
        &mut self,
        session: SessionId,
        text: &str,
        redact_email: bool,
    ) -> PyResult<String> {
        self.0
            .redact_model_text(session, text, RedactionOptions { redact_email })
            .map_err(python_error)
    }

    fn validate_references(&self, session: SessionId, text: &str) -> PyResult<()> {
        self.0
            .validate_references(session, text)
            .map_err(python_error)
    }

    fn restore_strict(&self, session: SessionId, text: &str, max_bytes: usize) -> PyResult<String> {
        self.0
            .restore_strict(session, text, max_bytes)
            .map_err(python_error)
    }

    fn restore(&self, session: SessionId, text: &str) -> PyResult<String> {
        self.0.restore(session, text).map_err(python_error)
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PythonKeybox>()?;
    Ok(())
}
