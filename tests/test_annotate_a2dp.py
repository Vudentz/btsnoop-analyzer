"""Tests for A2DP/AVDTP annotation."""

from annotate import annotate_trace


class TestA2DPAnnotation:
    """A2DP/AVDTP trace annotation correctness."""

    def _annotate(self, text):
        packets, diags, found = annotate_trace(text, "Audio / A2DP")
        return packets, diags, found

    def test_annotator_found(self, a2dp_text):
        _, _, found = self._annotate(a2dp_text)
        assert found

    def test_has_tagged_packets(self, a2dp_text):
        packets, _, _ = self._annotate(a2dp_text)
        tagged = [p for p in packets if p.tags]
        assert len(tagged) >= 10

    def test_has_key_packets(self, a2dp_text):
        packets, _, _ = self._annotate(a2dp_text)
        key = [p for p in packets if p.priority == "key"]
        assert len(key) >= 5

    # --- AVDTP tag correctness ---

    def test_avdtp_tags(self, a2dp_text):
        """AVDTP signaling should have AVDTP tag."""
        packets, _, _ = self._annotate(a2dp_text)
        avdtp_pkts = [p for p in packets if "AVDTP" in p.tags]
        assert len(avdtp_pkts) >= 5, f"Expected >=5 AVDTP packets"

    def test_avdtp_signaling_is_key(self, a2dp_text):
        """AVDTP signaling packets should be key priority."""
        packets, _, _ = self._annotate(a2dp_text)
        avdtp_pkts = [p for p in packets if "AVDTP" in p.tags
                      and "A2DP_MEDIA" not in p.tags]
        for p in avdtp_pkts:
            assert p.priority == "key", \
                f"AVDTP signaling should be key: {p.annotation[:60]}"

    # --- AVDTP operations ---

    def test_discover_annotated(self, a2dp_text):
        """AVDTP Discover should be annotated."""
        packets, _, _ = self._annotate(a2dp_text)
        disc = [p for p in packets if "Discover" in p.annotation]
        assert len(disc) >= 1

    def test_get_capabilities_annotated(self, a2dp_text):
        """AVDTP Get Capabilities should be annotated."""
        packets, _, _ = self._annotate(a2dp_text)
        caps = [p for p in packets
                if "Capabilities" in p.annotation or "Get Cap" in p.annotation]
        assert len(caps) >= 1

    # --- L2CAP signaling ---

    def test_l2cap_tags(self, a2dp_text):
        """L2CAP connection for AVDTP should have L2CAP tag."""
        packets, _, _ = self._annotate(a2dp_text)
        l2cap_pkts = [p for p in packets if "L2CAP" in p.tags]
        assert len(l2cap_pkts) >= 1

    # --- Media data ---

    def test_media_data_context(self, a2dp_text):
        """A2DP media data should be context priority."""
        packets, _, _ = self._annotate(a2dp_text)
        media = [p for p in packets if "A2DP_MEDIA" in p.tags]
        if media:  # May not have media in excerpt
            for p in media:
                assert p.priority == "context"

    # --- Diagnostics ---

    def test_media_count_diagnostic(self, a2dp_text):
        """Should report count of media data packets."""
        _, diags, _ = self._annotate(a2dp_text)
        assert any("media" in d.lower() or "A2DP" in d for d in diags), \
            f"Expected media count diagnostic, got: {diags}"
