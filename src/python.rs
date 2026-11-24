use crate::{Error, Keybox, SessionId};
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

    fn redact(&mut self, session: SessionId, text: &str) -> PyResult<String> {
        self.0.redact(session, text).map_err(python_error)
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
