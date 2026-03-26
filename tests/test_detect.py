"""Tests for auto-detection (detect.py)."""

from detect import detect, select_focus, DetectedArea, AREAS
from analyze import normalize_focus


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


class TestSelectFocus:
    """Tests for select_focus() — smarter area selection."""

    def _make_det(self, name, activity=0, errors=0):
        """Create a DetectedArea for a named AREAS entry."""
        area_def = next(a for a in AREAS if a.name == name)
        det = DetectedArea(area=area_def)
        det.activity_count = activity
        det.error_count = errors
        return det

    def test_empty_results(self):
        focus, absence, coex = select_focus([])
        assert focus == "General (full analysis)"

    def test_single_audio_area(self):
        results = [self._make_det("a2dp", activity=27)]
        focus, _, _ = select_focus(results)
        assert focus == "Audio / A2DP"

    def test_audio_over_advertising(self):
        """Audio area should be selected even if advertising scores higher."""
        results = [
            self._make_det("advertising", activity=532),
            self._make_det("a2dp", activity=27),
        ]
        # Sort by score descending (simulating detect() output)
        results.sort(key=lambda d: d.score, reverse=True)
        focus, _, _ = select_focus(results)
        assert focus == "Audio / A2DP"

    def test_combined_audio_when_close(self):
        """When A2DP and HFP are both active with close scores, use Audio."""
        results = [
            self._make_det("a2dp", activity=27),
            self._make_det("hfp", activity=43),
        ]
        results.sort(key=lambda d: d.score, reverse=True)
        focus, _, _ = select_focus(results)
        assert focus == "Audio"

    def test_single_audio_when_second_weak(self):
        """When second audio area is < 30% of top, use specific area."""
        results = [
            self._make_det("a2dp", activity=100),
            self._make_det("hfp", activity=5),
        ]
        results.sort(key=lambda d: d.score, reverse=True)
        focus, _, _ = select_focus(results)
        assert focus == "Audio / A2DP"

    def test_error_area_preferred(self):
        """Area with errors should be preferred over activity-only."""
        results = [
            self._make_det("advertising", activity=500),
            self._make_det("a2dp", activity=10, errors=1),
        ]
        results.sort(key=lambda d: d.score, reverse=True)
        focus, _, _ = select_focus(results)
        assert focus == "Audio / A2DP"

    def test_advertising_coexistence_note(self):
        """Heavy advertising with audio should produce coexistence note."""
        results = [
            self._make_det("advertising", activity=200),
            self._make_det("a2dp", activity=27),
        ]
        results.sort(key=lambda d: d.score, reverse=True)
        _, _, coex = select_focus(results)
        assert len(coex) == 1
        assert "advertising" in coex[0].lower()

    def test_no_coexistence_for_low_advertising(self):
        """Low advertising activity should NOT produce coexistence note."""
        results = [
            self._make_det("advertising", activity=10),
            self._make_det("a2dp", activity=27),
        ]
        results.sort(key=lambda d: d.score, reverse=True)
        _, _, coex = select_focus(results)
        assert len(coex) == 0

    def test_no_audio_uses_highest_score(self):
        """When no audio areas, use the highest-scoring area."""
        results = [
            self._make_det("advertising", activity=500),
            self._make_det("connections", activity=20),
        ]
        results.sort(key=lambda d: d.score, reverse=True)
        focus, _, _ = select_focus(results)
        assert focus == "Advertising / Scanning"

    def test_le_audio_select(self, le_audio_cis_text):
        """Real LE Audio trace should select Audio / LE Audio."""
        results = detect(le_audio_cis_text)
        focus, _, _ = select_focus(results)
        assert focus == "Audio / LE Audio"


class TestNormalizeFocus:
    """Tests for normalize_focus() — mapping user input to canonical keys."""

    def test_canonical_passthrough(self):
        assert normalize_focus("Audio / A2DP") == "Audio / A2DP"
        assert normalize_focus("Audio / LE Audio") == "Audio / LE Audio"
        assert normalize_focus("General (full analysis)") == \
            "General (full analysis)"

    def test_issue2_focus_string(self):
        """The actual focus string from issue #2 should map to Audio."""
        assert normalize_focus("Audio streaming (A2DP / LE Audio)") == \
            "Audio"

    def test_case_insensitive_alias(self):
        assert normalize_focus("a2dp") == "Audio / A2DP"
        assert normalize_focus("HFP") == "Audio / HFP"
        assert normalize_focus("LE Audio") == "Audio / LE Audio"

    def test_substring_match(self):
        assert normalize_focus("Audio streaming") == "Audio"
        assert normalize_focus("pairing") == "Pairing / Security"

    def test_canonical_key_substring(self):
        assert normalize_focus("Connection issues") == "Connection issues"

    def test_unknown_falls_back(self):
        assert normalize_focus("something unknown") == \
            "General (full analysis)"
