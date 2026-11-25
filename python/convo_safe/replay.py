"""Bind a saved transcript to its authenticated Keybox sidecar."""

from . import Keybox


class ReplayBindingError(ValueError):
    """The saved transcript and Keybox sidecar do not belong together."""


def replay_binding(keybox):
    """Return JSON-compatible metadata for an opened, identified sidecar."""
    binding = {
        "scope": keybox.replay_session,
        "lineage": keybox.replay_identity,
        "sidecar": keybox.replay_sidecar_id,
    }
    if any(value is None for value in binding.values()):
        raise ReplayBindingError("replay sidecar has no authenticated binding")
    return binding


def open_bound_replay(session_log, master_key, expected_binding, *, writable=False):
    """Open a sidecar only when it matches the saved transcript metadata.

    The caller supplies the log path from trusted session storage and must
    still validate the saved records against the returned Keybox.
    """
    if not isinstance(expected_binding, dict):
        raise ReplayBindingError("saved transcript has no valid replay binding")
    scope = expected_binding.get("scope")
    if (
        not isinstance(scope, int)
        or isinstance(scope, bool)
        or not isinstance(expected_binding.get("lineage"), str)
        or not isinstance(expected_binding.get("sidecar"), str)
    ):
        raise ReplayBindingError("saved transcript has no valid replay binding")
    open_sidecar = Keybox.resume_replay if writable else Keybox.open_replay
    keybox = open_sidecar(session_log, master_key)
    if replay_binding(keybox) != expected_binding:
        raise ReplayBindingError(
            "saved transcript references a different replay sidecar"
        )
    return keybox
