"""Read-only web dashboard for HEIM (FastAPI + Jinja + htmx)."""
from __future__ import annotations

__all__ = ["create_app"]


def create_app(*args, **kwargs):
    """Lazy re-export so importing the package costs nothing without FastAPI."""
    from heim.dashboard.app import create_app as _create_app

    return _create_app(*args, **kwargs)
