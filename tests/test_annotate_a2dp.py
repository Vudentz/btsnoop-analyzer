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

    # --- SEID discovery and correlation ---

    def test_discover_response_shows_seps(self, a2dp_text):
        """Discover Response should list SEP IDs and types."""
        packets, _, _ = self._annotate(a2dp_text)
        disc_resp = [p for p in packets
                     if "Discover Response" in p.annotation]
        assert len(disc_resp) == 1
        ann = disc_resp[0].annotation
        assert "SEID 1" in ann
        assert "SEID 2" in ann
        assert "SNK" in ann
        # Should NOT contain raw hex like (0x01)
        assert "(0x01)" not in ann

    def test_seid_correlation_in_commands(self, a2dp_text):
        """Open/Start/Suspend commands should show correlated SEID."""
        packets, _, _ = self._annotate(a2dp_text)
        for op in ("Open", "Start", "Suspend"):
            cmds = [p for p in packets
                    if p.annotation.startswith(f"AVDTP {op} SEID")]
            assert len(cmds) >= 1, \
                f"Expected {op} command with SEID, got: {cmds}"

    def test_seid_correlation_in_responses(self, a2dp_text):
        """Response Accept for Open/Start/Suspend should show SEID."""
        packets, _, _ = self._annotate(a2dp_text)
        for op in ("Open", "Start", "Suspend"):
            resps = [p for p in packets
                     if f"{op} Accept SEID" in p.annotation]
            assert len(resps) >= 1, \
                f"Expected {op} Accept with SEID via label correlation"

    # --- Codec configuration ---

    def test_set_config_annotation_has_codec(self, a2dp_text):
        """Set Configuration should show codec name and params."""
        packets, _, _ = self._annotate(a2dp_text)
        sc = [p for p in packets
              if "Set Configuration" in p.annotation
              and "Accept" not in p.annotation]
        assert len(sc) == 1
        ann = sc[0].annotation
        assert "SBC" in ann
        assert "44100Hz" in ann
        assert "Joint Stereo" in ann

    def test_set_config_accept_has_config_summary(self, a2dp_text):
        """Set Configuration Accept should reference config via label."""
        packets, _, _ = self._annotate(a2dp_text)
        sca = [p for p in packets
               if "Set Configuration Accept" in p.annotation]
        assert len(sca) == 1
        ann = sca[0].annotation
        # Config correlated from command via label
        assert "SBC" in ann
        assert "44100Hz" in ann

    def test_config_diagnostic(self, a2dp_text):
        """Diagnostics should include CONFIG line with codec params."""
        _, diags, _ = self._annotate(a2dp_text)
        config_diags = [d for d in diags if d.startswith("CONFIG:")]
        assert len(config_diags) >= 1
        cfg = config_diags[0]
        assert "SEID 1" in cfg
        assert "SBC" in cfg
        assert "44100Hz" in cfg
        assert "Joint Stereo" in cfg
        assert "Bitpool 2-52" in cfg

    # --- State machine ---

    def test_state_transition_diagnostic(self, a2dp_text):
        """Diagnostics should include AVDTP state transition table."""
        _, diags, _ = self._annotate(a2dp_text)
        state_diags = [d for d in diags if d.startswith("STATE:")]
        assert len(state_diags) >= 1
        table = state_diags[0]
        assert "idle -> configured" in table
        assert "configured -> open" in table
        assert "open -> streaming" in table

    def test_state_suspend_and_restart(self, a2dp_text):
        """State table should show Suspend (streaming->open) and restart."""
        _, diags, _ = self._annotate(a2dp_text)
        state_diags = [d for d in diags if d.startswith("STATE:")]
        assert len(state_diags) >= 1
        table = state_diags[0]
        assert "streaming -> open" in table
        # After suspend, should restart to streaming
        lines = table.split("\n")
        streaming_transitions = [l for l in lines
                                 if "-> streaming" in l]
        assert len(streaming_transitions) >= 2, \
            "Expected at least 2 transitions to streaming (start + restart)"

    def test_streaming_session_count(self, a2dp_text):
        """Diagnostics should count streaming sessions."""
        _, diags, _ = self._annotate(a2dp_text)
        session_diags = [d for d in diags if "streaming session" in d]
        assert len(session_diags) == 1
        assert "2 streaming session" in session_diags[0]

    # --- Clean display (no raw hex) ---

    def test_no_hex_in_sep_type(self, a2dp_text):
        """SEP type should be clean (SNK not SNK (0x01))."""
        packets, _, _ = self._annotate(a2dp_text)
        for p in packets:
            if "Discover Response" in p.annotation:
                assert "(0x01)" not in p.annotation
                assert "(0x00)" not in p.annotation

    def test_no_zero_hz_in_annotations(self, a2dp_text):
        """No standalone '0Hz' should appear from bitmask frequency parsing."""
        import re
        packets, diags, _ = self._annotate(a2dp_text)
        # Match '0Hz' NOT preceded by a digit (rules out 44100Hz etc.)
        zero_hz_re = re.compile(r"(?<!\d)0Hz")
        for p in packets:
            assert not zero_hz_re.search(p.annotation), \
                f"Found standalone 0Hz in: {p.annotation}"
        for d in diags:
            assert not zero_hz_re.search(d), \
                f"Found standalone 0Hz in diagnostic: {d}"

    def test_capabilities_no_stray_comma(self, a2dp_text):
        """Get Capabilities should not have stray comma from empty freq."""
        packets, _, _ = self._annotate(a2dp_text)
        caps = [p for p in packets
                if "Get Capabilities Response" in p.annotation]
        for p in caps:
            assert "(," not in p.annotation, \
                f"Stray comma in: {p.annotation}"

    # --- Audio Streams diagnostic ---

    def test_stream_diagnostic(self, a2dp_text):
        """Diagnostics should include STREAM line for configured SEIDs."""
        _, diags, _ = self._annotate(a2dp_text)
        streams = [d for d in diags if d.startswith("STREAM:")]
        assert len(streams) >= 1
        s = streams[0]
        assert "id=1" in s
        assert "dir=SNK" in s
        assert "codec=SBC" in s
        assert "state=streaming" in s
        assert "44100Hz" in s
