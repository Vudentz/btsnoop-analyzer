"""Tests for LE Audio annotation (unicast CIS and broadcast)."""

from annotate import annotate_trace, parse_packets


class TestLEAudioCISAnnotation:
    """LE Audio unicast CIS trace annotation correctness."""

    def _annotate(self, text):
        packets, diags, found = annotate_trace(text, "Audio / LE Audio")
        return packets, diags, found

    def test_annotator_found(self, le_audio_cis_text):
        _, _, found = self._annotate(le_audio_cis_text)
        assert found

    def test_has_tagged_packets(self, le_audio_cis_text):
        packets, _, _ = self._annotate(le_audio_cis_text)
        tagged = [p for p in packets if p.tags]
        assert len(tagged) > 0

    def test_has_key_packets(self, le_audio_cis_text):
        packets, _, _ = self._annotate(le_audio_cis_text)
        key = [p for p in packets if p.priority == "key"]
        assert len(key) >= 10, f"Expected >=10 key packets, got {len(key)}"

    def test_has_context_packets(self, le_audio_cis_text):
        packets, _, _ = self._annotate(le_audio_cis_text)
        ctx = [p for p in packets if p.priority == "context"]
        assert len(ctx) >= 1, "Expected at least 1 context (ISO data) packet"

    # --- ASE CP tag correctness ---

    def test_ase_cp_tags(self, le_audio_cis_text):
        """ASE CP writes should have ASCS and ASE_CP tags."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        cp_pkts = [p for p in packets if "ASE_CP" in p.tags]
        assert len(cp_pkts) >= 3, f"Expected >=3 ASE_CP packets, got {len(cp_pkts)}"
        for p in cp_pkts:
            assert "ASCS" in p.tags, f"ASE_CP packet missing ASCS tag: {p.summary[:60]}"

    def test_ase_state_tags(self, le_audio_cis_text):
        """ASE state notifications should have ASCS and ASE_STATE tags."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        state_pkts = [p for p in packets if "ASE_STATE" in p.tags]
        assert len(state_pkts) >= 3, f"Expected >=3 ASE_STATE packets"
        for p in state_pkts:
            assert "ASCS" in p.tags

    # --- CIS HCI event tags ---

    def test_cis_hci_tags(self, le_audio_cis_text):
        """CIS HCI events should have CIS and HCI tags."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        cis_hci = [p for p in packets if "CIS" in p.tags and "HCI" in p.tags]
        assert len(cis_hci) >= 2, f"Expected >=2 CIS+HCI packets"

    def test_iso_data_tags(self, le_audio_cis_text):
        """ISO data packets should have CIS and ISO_DATA tags at context priority."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        iso = [p for p in packets if "ISO_DATA" in p.tags]
        assert len(iso) >= 1
        for p in iso:
            assert p.priority == "context"
            assert "CIS" in p.tags

    # --- Decoded annotations ---

    def test_config_codec_annotation(self, le_audio_cis_text):
        """Config Codec should decode codec name (LC3) and CC LTV."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        codec_pkts = [p for p in packets
                      if "Config Codec" in p.annotation
                      and "response" not in p.annotation]
        assert len(codec_pkts) >= 1
        ann = codec_pkts[0].annotation
        assert "LC3" in ann
        # CC LTV should decode sampling freq, frame duration, octets
        assert "48kHz" in ann
        assert "7.5ms" in ann
        assert "90oct" in ann

    def test_config_qos_annotation(self, le_audio_cis_text):
        """Config QoS should decode CIG and CIS IDs."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        qos_pkts = [p for p in packets
                    if "Config QoS" in p.annotation]
        assert len(qos_pkts) >= 1
        assert any("CIG" in p.annotation for p in qos_pkts)
        assert any("CIS" in p.annotation for p in qos_pkts)

    def test_enable_annotation(self, le_audio_cis_text):
        """Enable CP write should be annotated."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        enable_pkts = [p for p in packets if "Enable" in p.annotation
                       and "ASE_CP" in p.tags]
        assert len(enable_pkts) >= 1

    def test_cis_established_annotation(self, le_audio_cis_text):
        """CIS established event should be annotated."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        est = [p for p in packets
               if "established" in p.annotation.lower()
               and "CIS" in p.tags]
        assert len(est) >= 1

    # --- State machine flow ---

    def test_state_progression(self, le_audio_cis_text):
        """ASE states should follow valid progression."""
        packets, _, _ = self._annotate(le_audio_cis_text)
        state_anns = [p.annotation for p in packets if "ASE_STATE" in p.tags]
        # Expected states in order: Codec Configured -> QoS Configured -> Enabling -> Streaming
        expected_order = ["Codec Configured", "QoS Configured", "Enabling", "Streaming"]
        found = []
        for ann in state_anns:
            for state in expected_order:
                if state in ann and state not in found:
                    found.append(state)
        assert found == expected_order, f"State progression: {found}"

    # --- Diagnostics ---

    def test_iso_data_diagnostic(self, le_audio_cis_text):
        """Should have diagnostic about ISO data packet count."""
        _, diags, _ = self._annotate(le_audio_cis_text)
        assert any("ISO" in d or "CIS" in d for d in diags), \
            f"Expected ISO data diagnostic, got: {diags}"


class TestBroadcastAnnotation:
    """Broadcast receiver trace annotation correctness."""

    def _annotate(self, text):
        packets, diags, found = annotate_trace(text, "Audio / LE Audio")
        return packets, diags, found

    def test_annotator_found(self, broadcast_text):
        _, _, found = self._annotate(broadcast_text)
        assert found

    def test_has_pa_tags(self, broadcast_text):
        """Broadcast trace should have PA-tagged packets."""
        packets, _, _ = self._annotate(broadcast_text)
        pa_pkts = [p for p in packets if "PA" in p.tags]
        assert len(pa_pkts) >= 2, f"Expected >=2 PA packets, got {len(pa_pkts)}"

    def test_pa_sync_annotation(self, broadcast_text):
        """PA sync established should be annotated."""
        packets, _, _ = self._annotate(broadcast_text)
        sync_pkts = [p for p in packets
                     if "sync" in p.annotation.lower()
                     and "PA" in p.tags]
        assert len(sync_pkts) >= 1

    def test_pa_report_annotation(self, broadcast_text):
        """PA Report with BASE data should be annotated."""
        packets, _, _ = self._annotate(broadcast_text)
        report_pkts = [p for p in packets
                       if "BASE" in p.annotation
                       and "PA" in p.tags]
        assert len(report_pkts) >= 1

    def test_absence_diagnostic(self, broadcast_text):
        """Should flag absence of BIG Info."""
        _, diags, _ = self._annotate(broadcast_text)
        assert any("BIG Info" in d for d in diags), \
            f"Expected BIG Info absence diagnostic, got: {diags}"

    def test_all_signaling_is_key(self, broadcast_text):
        """All signaling packets should be key priority."""
        packets, _, _ = self._annotate(broadcast_text)
        tagged = [p for p in packets if p.tags]
        for p in tagged:
            assert p.priority == "key", \
                f"Expected key priority for {p.tags}, got {p.priority}"
