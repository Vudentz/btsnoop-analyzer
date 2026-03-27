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

    def test_stream_diagnostic(self, le_audio_cis_text):
        """Diagnostics should include STREAM line for configured ASEs."""
        _, diags, _ = self._annotate(le_audio_cis_text)
        streams = [d for d in diags if d.startswith("STREAM:")]
        assert len(streams) >= 1
        s = streams[0]
        assert "id=1" in s
        assert "codec=LC3" in s
        assert "48kHz" in s


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


class TestDaemonRestartDetection:
    """Daemon restart detection via MGMT Close/Open cycles (issue #5)."""

    def _annotate(self, text):
        packets, diags, found = annotate_trace(text, "Audio / LE Audio")
        return packets, diags, found

    def test_annotator_found(self, broadcast_restart_text):
        _, _, found = self._annotate(broadcast_restart_text)
        assert found

    def test_restart_count_diagnostic(self, broadcast_restart_text):
        """Should report exactly 3 bluetoothd restarts (Close/Open pairs)."""
        _, diags, _ = self._annotate(broadcast_restart_text)
        restart_diags = [d for d in diags if "restarted" in str(d)]
        assert len(restart_diags) == 1, f"Expected 1 restart diagnostic, got {restart_diags}"
        assert "3 time(s)" in str(restart_diags[0])

    def test_btmgmt_not_counted(self, broadcast_restart_text):
        """btmgmt Close/Open should NOT be counted as a daemon restart."""
        _, diags, _ = self._annotate(broadcast_restart_text)
        restart_diags = [d for d in diags if "restarted" in str(d)]
        # Only bluetoothd restarts counted — btmgmt pair is ignored
        assert "3 time(s)" in str(restart_diags[0]), \
            "btmgmt restart was incorrectly counted"

    def test_mgmt_packets_tagged(self, broadcast_restart_text):
        """MGMT Close/Open packets for bluetoothd should be tagged."""
        packets, _, _ = self._annotate(broadcast_restart_text)
        mgmt_pkts = [p for p in packets if "MGMT" in p.tags]
        # 3 restarts = 6 tagged packets (3 Close + 3 Open)
        assert len(mgmt_pkts) == 6, \
            f"Expected 6 MGMT-tagged packets, got {len(mgmt_pkts)}"

    def test_mgmt_close_annotation(self, broadcast_restart_text):
        """MGMT Close packets should be annotated as daemon restart."""
        packets, _, _ = self._annotate(broadcast_restart_text)
        close_pkts = [p for p in packets
                      if "MGMT" in p.tags and "closed" in p.annotation]
        assert len(close_pkts) == 3
        for p in close_pkts:
            assert "daemon restart" in p.annotation

    def test_mgmt_open_annotation(self, broadcast_restart_text):
        """MGMT Open packets should be annotated as daemon restart."""
        packets, _, _ = self._annotate(broadcast_restart_text)
        open_pkts = [p for p in packets
                     if "MGMT" in p.tags and "reopened" in p.annotation]
        assert len(open_pkts) == 3
        for p in open_pkts:
            assert "daemon restart" in p.annotation

    def test_mgmt_packets_are_key_priority(self, broadcast_restart_text):
        """MGMT daemon restart packets should have key priority."""
        packets, _, _ = self._annotate(broadcast_restart_text)
        mgmt_pkts = [p for p in packets if "MGMT" in p.tags]
        for p in mgmt_pkts:
            assert p.priority == "key", \
                f"MGMT packet should be key, got {p.priority}: {p.annotation}"

    def test_btmgmt_not_tagged(self, broadcast_restart_text):
        """btmgmt MGMT Close/Open should NOT be tagged."""
        packets, _, _ = self._annotate(broadcast_restart_text)
        mgmt_pkts = [p for p in packets if "MGMT" in p.tags]
        for p in mgmt_pkts:
            assert "btmgmt" not in p.summary, \
                f"btmgmt packet should not be MGMT-tagged: {p.summary}"

    def test_broadcast_flow_alongside_restarts(self, broadcast_restart_text):
        """Full broadcast flow should still be detected alongside restarts."""
        packets, diags, _ = self._annotate(broadcast_restart_text)
        pa_pkts = [p for p in packets if "PA" in p.tags]
        assert len(pa_pkts) >= 2, "PA packets should still be detected"
        big_pkts = [p for p in packets if "BIG" in p.tags]
        assert len(big_pkts) >= 2, "BIG packets should still be detected"

    def test_no_big_info_absence_with_big_present(self, broadcast_restart_text):
        """Should NOT flag BIG Info absence when BIG Info is in trace."""
        _, diags, _ = self._annotate(broadcast_restart_text)
        absence = [d for d in diags if "ABSENCE" in str(d) and "BIG Info" in str(d)]
        assert len(absence) == 0, \
            f"BIG Info absence should not be flagged: {absence}"
