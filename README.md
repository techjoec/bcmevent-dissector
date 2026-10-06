# bcmevent-dissector

[![Release](https://img.shields.io/github/v/release/techjoec/bcmevent-dissector)](https://github.com/techjoec/bcmevent-dissector/releases/latest)

Wireshark Lua dissector for Broadcom Wi-Fi firmware events (EtherType `0x886c`).

Broadcom FullMAC and HND (router) firmware reports scan results,
(re)associations, deauthentications, link changes and handshake progress to
the host as Ethernet frames with EtherType `0x886c`. They appear in captures
where the driver hands them to the network stack, such as on HND routers and
on USB adapters driven by Linux brcmfmac. Wireshark assigns `0x886c` to
HomePNA, so without this plugin they show up as `[Malformed Packet]`.

Not affiliated with Broadcom.

## Install

Needs Wireshark 2.4 or newer with Lua support, which the Windows and macOS
installers include.

Download [`bcmevent.lua`](https://github.com/techjoec/bcmevent-dissector/releases/latest/download/bcmevent.lua)
from the [latest release](https://github.com/techjoec/bcmevent-dissector/releases/latest)
and copy it into the folder that **About Wireshark > Folders** lists
as **Personal Lua Plugins** (**Personal Plugins** before 2.6), then restart
Wireshark or use **Analyze > Reload Lua Plugins** (Ctrl+Shift+L).

Remove any **Decode As** rule for EtherType `0x886c`. It overrides this plugin.

## Decodes

- `bcmeth_hdr_t` and `wl_event_msg_t`: event, status, reason, flags, station,
  interface; dongle event headers
- `WLC_E_ESCAN_RESULT`: each BSS with chanspec, RSSI, noise and its
  information elements
- 802.11 elements: SSID, rates, channel, country, RSN and WPS. WPA, WMM and
  Broadcom vendor elements are labeled.
- 802.11 management frames and action bodies carried in events, with their
  RX metadata
- `WLC_E_IF`, CEVENT, MACDBG ratelinkmem, invalid-IE, HND channel-change and
  CAC events, and the DHD `WLC_E_WSEC` event
- Channel switch (completed and received), radar detection, CCA channel
  quality, mode switch, bandwidth upgrade, OMN master, BSS color, EDCRS,
  traffic threshold, external authentication, RRM, DPSTA interface and PMKID
  candidate events
- Deauthentication and disassociation frame bodies, ADDTS delay, country
  code, FIFO credits, credit borrowing, FT key, power-save mode and band
  change

Event data with no public layout is shown as `bcmevent.payload`.

A length that runs past the data is flagged as malformed
(`bcmevent.truncated`), and so is a length or offset its structure cannot
have (`bcmevent.invalid`). Captures cut short by the snapshot length are not
flagged.

## Event numbers

Router (HND) and client FullMAC (DHD) firmware give most event numbers from
171 up different meanings, and Infineon/Cypress (CYW) firmware reuses a few
of them again. Events are named the HND way unless the event data shows the
sender, as with DHD's `WLC_E_WSEC` on 186. Where another family disagrees,
the tree also shows its name as `bcmevent.event.type_dhd` or
`bcmevent.event.type_cyw`.

## Filters

```
bcmevent
bcmevent.event.type == 69
bcmevent.event.addr == 02:00:00:00:00:02
bcmevent.bss.ssid contains "guest"
bcmevent.bss.band == "6 GHz"
bcmevent.rsn.akm contains "SAE"
```

## Test

Needs `tshark` and `python3`.

```sh
test/check.sh [capture]                 # defaults to test/sample.pcap
TSHARK=/path/to/tshark test/check.sh    # another Wireshark build
python3 test/make-sample.py             # rebuilds test/sample.pcap
```

`test/sample.pcap` is synthetic, with frames for every decoder.

## License

GPL-2.0-or-later
