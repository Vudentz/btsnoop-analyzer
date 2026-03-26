"""Tests for auto-detection (detect.py)."""

from detect import detect


class TestDetectLEAudioCIS:
    """LE Audio unicast CIS trace should detect as le_audio."""

    def test_top_area_is_le_audio(self, le_audio_cis_text):
        results = detect(le_audio_cis_text)
        assert results, "detect() returned no results"
        assert results[0].area.name == "le_audio"

    def test_le_audio_has_activity(self, le_audio_cis_text):
        results = detect(le_audio_cis_text)
        le = next(r for r in results if r.area.name == "le_audio")
        assert le.activity_count > 0

    def test_le_audio_focus_string(self, le_audio_cis_text):
        results = detect(le_audio_cis_text)
        le = next(r for r in results if r.area.name == "le_audio")
        assert le.area.focus == "Audio / LE Audio"


class TestDetectA2DP:
    """A2DP trace should detect a2dp in results."""

    def test_a2dp_detected(self, a2dp_text):
        results = detect(a2dp_text)
        names = [r.area.name for r in results]
        assert "a2dp" in names

    def test_a2dp_has_activity(self, a2dp_text):
        results = detect(a2dp_text)
        a2dp = next(r for r in results if r.area.name == "a2dp")
        assert a2dp.activity_count > 0

    def test_a2dp_focus_string(self, a2dp_text):
        results = detect(a2dp_text)
        a2dp = next(r for r in results if r.area.name == "a2dp")
        assert a2dp.area.focus == "Audio / A2DP"


class TestDetectBroadcast:
    """Broadcast receiver trace should detect as le_audio."""

    def test_le_audio_detected(self, broadcast_text):
        results = detect(broadcast_text)
        names = [r.area.name for r in results]
        assert "le_audio" in names

    def test_broadcast_absence_error(self, broadcast_text):
        results = detect(broadcast_text)
        le = next(r for r in results if r.area.name == "le_audio")
        assert le.absence_errors, "Expected absence error for missing BIG Info"
        assert any("BIG Info" in msg for msg in le.absence_errors)

    def test_broadcast_has_errors_in_score(self, broadcast_text):
        results = detect(broadcast_text)
        le = next(r for r in results if r.area.name == "le_audio")
        # Absence errors add 10 to the score
        assert le.score > le.activity_count


class TestDetectEmpty:
    """Edge cases for empty or garbage input."""

    def test_empty_string(self):
        results = detect("")
        assert results == []

    def test_whitespace_only(self):
        results = detect("   \n  \n  ")
        assert results == []

    def test_garbage(self):
        results = detect("not a btmon trace\njust random text\n")
        assert results == []

    def test_btmon_header_only(self):
        results = detect("Bluetooth monitor ver 5.86\n")
        assert results == []


class TestDetectMutualExclusion:
    """LE Audio CIS fixture should not detect as A2DP, and vice versa."""

    def test_cis_not_a2dp(self, le_audio_cis_text):
        results = detect(le_audio_cis_text)
        names = [r.area.name for r in results]
        assert "a2dp" not in names

    def test_a2dp_not_le_audio(self, a2dp_text):
        results = detect(a2dp_text)
        names = [r.area.name for r in results]
        assert "le_audio" not in names
