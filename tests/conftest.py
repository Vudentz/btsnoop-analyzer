"""Shared pytest fixtures for btsnoop-analyzer tests."""

import pathlib

import pytest

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def le_audio_cis_text():
    """LE Audio unicast CIS trace excerpt (raw ATT + HCI CIS events)."""
    return (FIXTURES_DIR / "le_audio_cis.txt").read_text()


@pytest.fixture
def a2dp_text():
    """A2DP/AVDTP trace excerpt (signaling + media packets)."""
    return (FIXTURES_DIR / "a2dp.txt").read_text()


@pytest.fixture
def broadcast_text():
    """LE Audio broadcast receiver trace excerpt (PAST + PA reports)."""
    return (FIXTURES_DIR / "broadcast.txt").read_text()


@pytest.fixture
def broadcast_restart_text():
    """LE Audio broadcast trace with daemon restarts (MGMT Close/Open)."""
    return (FIXTURES_DIR / "broadcast_restart.txt").read_text()
