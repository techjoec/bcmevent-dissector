# Changelog

## 1.1.0 - 2026-10-06

### Added

- Event data decoders for:
  - channel switch: completed (`CSA_COMPLETE_IND`, down to the single
    mode byte some firmware sends) and received (`CSA_RECV_IND`)
  - radar detection, CCA channel quality (CCA, full CCA and noise reports),
    mode switch (with `DYN160` details), bandwidth upgrade, OMN master,
    BSS color, EDCRS, traffic threshold
  - external authentication, RRM header, DPSTA interface, PMKID candidates
  - deauthentication and disassociation frame bodies, association and
    authentication bodies, SSID, scan results, ADDTS delay,
    country code, FIFO credits, credit borrowing, FT key, power-save mode,
    band change, action-frame completion, MBO status, ANQP queries
  - EAPOL frames, handed to Wireshark's EAPOL dissector with or without an
    Ethernet header in front
  - RSSI, TX delay statistics, health-check alerts with their stall and
    sounding reports, QoS management by opcode, the RSN element on WDS links
  - extended probe requests with RX metadata, FBT events, WNM events
  - AirIQ events (per-radio scan status; FFT, IQ and scan-complete messages)
    and LTE-U events (scan status, abort reason, IQ capture), with sample
    arrays bounded by their declared size
  - `WLC_E_MLD_UP` (MLD unit and link ID)
- 802.11 action bodies: BSS transition query, request and response; WNM
  notifications with their Hotspot 2.0 and MBO elements; the OUI of
  vendor-specific actions.
- AirIQ events sent with protocol `0x88b7`, as Linux hosts deliver them;
  other `0x88b7` traffic still goes to Wireshark's IEEE 802a dissector.
- `test/expect.txt`: display filters `test/check.sh` runs against the sample,
  so the tests check decoded values, not only that frames are claimed. The
  sample covers every decoder and its variants.

### Changed

- Event numbers above 170 decode only when the data has the expected
  version and size; DHD and CYW firmware give some of them other meanings.
- Data with no known layout stays as `bcmevent.payload`.

### Fixed

- `PRE_REASSOC_IND`: the current-AP address of the reassociation request was
  read as elements.
- Vendor-specific actions (categories 126 and 127): the first OUI byte was
  shown as an action code.
- Unprotected WNM actions (category 11) were decoded with WNM action codes.
- WNM notification type names.

## 1.0.0 - 2026-10-05

First release: the `bcmeth_hdr_t` and `wl_event_msg_t` headers, dongle
events, escan results with BSS information and 802.11 elements, management
frames and action bodies with RX metadata, interface, CEVENT, MACDBG
ratelinkmem, invalid-IE, channel-change and CAC events, and the DHD
`WLC_E_WSEC` event.
