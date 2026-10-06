# SPDX-License-Identifier: GPL-2.0-or-later
"""Build test/sample.pcap: synthetic 0x886c frames covering every decoder.

    python3 test/make-sample.py

Layouts follow the public driver headers. Addresses are locally administered
and every value is made up. Output is byte-identical on every run.
"""
import struct
from pathlib import Path

HOST = bytes.fromhex("020000000001")
STA = bytes.fromhex("020000000002")
AP = bytes.fromhex("020000000003")
BAD = bytes.fromhex("02000000000f")                 # source of the frames that must be flagged


def bcmeth(usr_subtype, body):
    # bcmeth_hdr_t; length counts from the version byte to the end of the frame
    return (struct.pack(">HHB", 0x8001, len(body) + 6, 0) + b"\x00\x10\x18"
            + struct.pack(">H", usr_subtype) + body)


def event(etype, data=b"", status=0, reason=0, flags=0, addr=STA, version=2, datalen=None):
    # wl_event_msg_t (network order), event data, then the 2-byte data pad
    dl = len(data) if datalen is None else datalen
    msg = struct.pack(">HHIIIII", version, flags, etype, status, reason, 0, dl)
    msg += addr + b"wl0".ljust(16, b"\0")
    if version == 2:
        msg += bytes([0, 0])                        # ifidx, bsscfgidx
    return bcmeth(1, msg + data + b"\0\0")


def ether(payload, vlan=None, src=HOST):
    tag = struct.pack(">HH", 0x8100, vlan) if vlan is not None else b""
    return HOST + src + tag + b"\x88\x6c" + payload


def ie(eid, body):
    return bytes([eid, len(body)]) + body


def suite(typ, oui=b"\x00\x0f\xac"):
    return oui + bytes([typ])


def rsn(akms, pairwise=4, caps=0):
    return ie(48, struct.pack("<H", 1) + suite(4) + struct.pack("<H", 1) + suite(pairwise)
              + struct.pack("<H", len(akms)) + b"".join(suite(a) for a in akms)
              + struct.pack("<H", caps))


def wps():
    def attr(t, v):
        return struct.pack(">HH", t, len(v)) + v
    return ie(221, b"\x00\x50\xf2\x04" + b"".join([
        attr(0x104a, b"\x10"),                      # version 1.0
        attr(0x1044, b"\x02"),                      # configured
        attr(0x103b, b"\x03"),                      # access point
        attr(0x1021, b"Example"),
        attr(0x1011, "Café".encode()),
        attr(0x1008, struct.pack(">H", 0x2688)),
        attr(0x103c, b"\x03"),                      # 2.4 and 5 GHz
        attr(0x1054, struct.pack(">H", 6) + b"\x00\x50\xf2\x04" + struct.pack(">H", 1)),
        attr(0x1049, b"\x00\x37\x2a\x00\x01\x20"),  # WFA extension, Version2 2.0
    ]))


def bss(ssid, chanspec, rssi, ctl, ies):
    # wl_bss_info_t v109: 128-byte fixed part, IEs at ie_offset
    b = bytearray(128)
    struct.pack_into("<II", b, 0, 109, 128 + len(ies))
    b[8:14] = AP
    struct.pack_into("<HH", b, 14, 100, 0x0411)
    b[18] = len(ssid)
    b[19:19 + len(ssid)] = ssid
    struct.pack_into("<HH", b, 72, chanspec, 0)
    b[76] = 1
    struct.pack_into("<hb", b, 78, rssi, -92)
    b[88] = ctl
    struct.pack_into("<HHI", b, 116, 128, 0, len(ies))
    struct.pack_into("<h", b, 124, rssi + 92)
    return bytes(b) + ies


def escan(records):
    body = b"".join(records)
    return struct.pack("<IIHH", 12 + len(body), 109, 0x1234, len(records)) + body


def rxmeta_v1(chanspec):
    return struct.pack(">HHiII", 1, chanspec, -52, 0x00012345, 0x0c)


def rxmeta_v2(chanspec):
    return struct.pack(">HHHHiII4b", 2, 24, chanspec, 0, -61, 0x00023456, 0x18, -60, -63, -128, -128)


def mgmt(subtype, body, da=AP, sa=STA, bssid=AP):
    return struct.pack("<HH", subtype << 4, 0x013a) + da + sa + bssid + struct.pack("<H", 0x0120) + body


def cevent(typ, subtype, msgtype, flags, data=b"\x01\x02\x03\x04"):
    # wl_cevent_t, host order: the 64-bit timestamp is aligned to offset 24
    hdr = struct.pack("<HHHHIII", 1, 32 + len(data), typ, 32, subtype, msgtype, flags)
    return hdr + bytes(4) + struct.pack("<Q", 1767225600123) + data


SCAN = escan([
    bss(b"example", 0x1006, -42, 6, ie(0, b"example") + ie(1, bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12]))
        + ie(3, b"\x06") + ie(7, b"US\x04" + b"\x01\x0b\x1e") + rsn([2]) + wps()
        + ie(221, b"\x00\x50\xf2\x02\x00\x01\x80") + ie(255, bytes([35]) + bytes(6))),
    bss(b"", 0xe02a, -67, 36, ie(0, b"") + rsn([8], caps=0x00c0)),
    bss("café".encode(), 0x7001, -71, 33, ie(0, "café".encode()) + rsn([24, 8], pairwise=8, caps=0x00c0)
        + ie(255, bytes([108]) + bytes(4))),
])
ASSOC_REQ_BODY = struct.pack("<HH", 0x0431, 10) + ie(0, b"example") + rsn([2])

frames = [
    ether(event(16, reason=1, flags=0x0005)),                            # LINK, BCN_LOSS
    ether(event(69, SCAN, status=8)),                                    # ESCAN_RESULT, 3 BSS
    ether(event(69, struct.pack("<IIHH", 12, 109, 0x1234, 0))),          # ESCAN_RESULT, scan done
    ether(event(54, bytes([1, 1, 0, 1, 1]))),                            # IF, FullMAC layout
    ether(event(54, bytes([2, 1, 0, 2, 1, 0, 2]) + STA)),                # IF, HND MLO layout
    ether(event(170, struct.pack("<HHIH", 1, 10, 1, 0xe02a) + b"\0\0", addr=bytes(6))),  # AP_CHAN_CHANGE
    ether(event(184, struct.pack("<HHHBBHH", 1, 28, 1, 0, 0, 1, 1)       # CAC_STATE_CHANGE
                + struct.pack("<IIHHHH", 1, 60000, 0xe02a, 0xe06a, 0, 0), addr=bytes(6))),
    ether(event(5, reason=3), vlan=100),                                 # DEAUTH in 802.1Q
    ether(event(69, SCAN[:40], datalen=len(SCAN)), src=BAD),             # data length overruns frame
    ether(event(137, rxmeta_v2(0xd024) + mgmt(4, ie(0, b"example") + ie(1, b"\x82\x84"), da=b"\xff" * 6))),
    ether(event(75, rxmeta_v1(0x1006) + bytes([0, 0, 1]) + ie(38, bytes([1, 0, 5]) + bytes(16)))),
    ether(event(91, rxmeta_v1(0x1006) + mgmt(11, struct.pack("<HHH", 3, 1, 0) + bytes(34)))),
    ether(event(61, rxmeta_v1(0x1006) + ASSOC_REQ_BODY)),               # PRE_ASSOC_IND
    ether(event(8, ie(0, b"example") + rsn([2]) + ie(127, bytes(8)))),  # ASSOC_IND
    ether(event(44, mgmt(4, ie(0, b"") + ie(1, b"\x82"), da=b"\xff" * 6))),  # PROBREQ_MSG
    ether(event(59, bytes([10, 6, 1]))),                                 # ACTION_FRAME
    ether(event(147, struct.pack("<HHHH", 1, 4, 1, 9), reason=5)),       # MACDBG, RATELINKMEM
    ether(event(162, struct.pack("<HHHH", 0, 4, 0x0080, 1) + ie(45, b"\xff\xff"))),  # INVALID_IE
    ether(event(180, cevent(2, 0, 3, 0x80000000))),                      # CEVENT A2C M1_TX
    ether(event(180, cevent(1, 18, 0, 0x80000001))),                     # CEVENT D2C AUTH_TX
    ether(event(186, mgmt(2, ASSOC_REQ_BODY[:4] + AP + ASSOC_REQ_BODY[4:]))),  # HND reassoc frame
    ether(event(186, struct.pack("<HHHH", 1, 36, 1, 0) + struct.pack(    # DHD WSEC PN sync error
        "<IIBBHHHIHHIII", 0x89abcdef, 0x01234567, 0, 6, 0, 2048, 0x10, 0, 3, 0x0e, 0, 120, 4))),
    ether(event(46, status=6)),                                          # PSK_SUP, KEYED
    ether(event(19, reason=1)),                                          # ROAM, LOW_RSSI
    ether(event(150, status=1)),                                         # PSK_AUTH, WPA_TIMOUT
    ether(event(188, status=1)),                                         # numbered differently per family
    ether(event(250, bytes(24))),                                        # unknown event
    ether(bcmeth(5, struct.pack(">HHHH", 1, 0, 2, 8) + struct.pack("<HH", 1, 4) + b"\x55" * 4 + b"\0\0")),
    ether(event(16, reason=2, version=1)),                               # wl_event_msg_t v1
    # error paths and less common layouts
    ether(event(69, escan([bss(b"n", 0x2b06, -50, 6, ie(0, b"n") + bytes([1, 10, 0x82]))])),
          src=BAD),                                                      # element overrun
    ether(event(69, struct.pack("<IIHH", 8, 109, 1, 1)), src=BAD),       # buflen below the header
    ether(event(69, escan([bss(b"w", cs, -60, 36, ies) for cs, ies in [  # chanspec layouts, vendor elements
        (0xf020, ie(221, b"\x00\x10\x18\x02\x00") + ie(48, b"\x01\x00" + suite(4) + b"\x01\x00" + suite(4)
                 + b"\x01\x00\x50\x6f\x9a\x02")),
        (0x4810, b""), (0xc824, b""), (0xc024, b""), (0x4001, b""), (0x7801, b""), (0xf824, b""), (0xda26, b"")]]))),
    ether(event(180, struct.pack(">HHHHIII", 1, 36, 1, 32, 18, 7, 0x40000000) + bytes(4)  # big-endian CEVENT
                + struct.pack(">Q", 5) + b"\x01\x02\x03\x04")),
    ether(event(147, struct.pack(">HHHH", 1, 4, 1, 9), reason=5)),       # big-endian RATELINKMEM
    ether(event(186, struct.pack("<HHHH", 1, 36, 1, 0) + bytes(10)), src=BAD),  # WSEC, short
    ether(event(162, struct.pack(">HHHH", 0, 4, 0x0080, 1) + ie(45, b"\xff\xff"))),  # big-endian INVALID_IE
    ether(event(54, bytes([2, 1, 0, 2, 1]) + STA)),                      # IF, HND layout
    ether(event(170, struct.pack("<HHIHH", 2, 12, 8, 0xe02a, 0xe06a), addr=bytes(6))),  # AP_CHAN_CHANGE v2
    ether(event(184, struct.pack("<HHHBBHH", 1, 28, 1, 0, 0, 1, 3)       # CAC, sub-status count overruns
                + struct.pack("<IIHHHH", 1, 6, 0xe02a, 0, 0, 0), addr=bytes(6)), src=BAD),
    ether(event(71, rxmeta_v1(0) + mgmt(5, bytes(12) + ie(0, b"example")))),  # PROBRESP_MSG
    ether(event(186, mgmt(12, struct.pack("<H", 3)))),                   # HND event 186, deauthentication
    ether(bcmeth(4, b"\x01\x02\x03")),                                   # other Broadcom user subtype
    ether(bcmeth(1, bytes(20)), src=BAD),                                # event message cut short
    ether(event(180, struct.pack("<HHHHII", 1, 28, 2, 24, 0, 0x80000000)  # older HND CEVENT, no msgtype
                + struct.pack("<Q", 1767225600123) + b"\x01\x02\x03\x04")),
    # fixed event structures
    ether(event(80, b"\x00", addr=bytes(6))),                            # CSA_COMPLETE_IND, mode only
    ether(event(80, struct.pack("<BBHBB", 1, 5, 0xe02a, 128, 0), addr=bytes(6))),  # full wl_chan_switch_t
    ether(event(209, struct.pack("<BBBBBBH", 1, 8, 1, 1, 0, 0, 0xe06a))),  # CSA_RECV_IND
    ether(event(124, struct.pack("<HHHHIII", 0, 0, 0x1006, 12, 1000, 250, 86400), addr=bytes(6))),
    ether(event(124, struct.pack("<HHHHIIIII", 0, 0x100, 0xe02a, 88, 1000, 120, 300, 15, 86400)
                + bytes(64) + struct.pack("<I", 7), addr=bytes(6))),     # CCA_CHAN_QUAL, FULL_CCA
    ether(event(124, struct.pack("<HHHHi", 0, 1, 0x1006, 4, -92), addr=bytes(6))),  # CCA_CHAN_QUAL, noise
    ether(event(140, struct.pack("<I", 2))),                             # DPSTA_INTF_IND, DWDS
    ether(event(141, struct.pack("<hhhh", 0, 8, 5, 1) + bytes(8))),      # RRM
    ether(event(160, struct.pack("<IHH", 1, 0xe034, 0xe02a)              # RADAR_DETECTED
                + struct.pack("<BxHHHHH", 2, 20, 40, 1428, 1428, 1) * 2, addr=bytes(6))),
    ether(event(163, struct.pack("<HHHHIHH", 1, 16, 0x0404, 0x0202, 0x8, 3, 16), addr=bytes(6))),  # MODE_SWITCH
    ether(event(183, struct.pack("<HHHH", 2, 4, 1, 10))),                # TXFAIL_TRFTHOLD
    ether(event(185, struct.pack("<HHHH", 1, 8, 0, 0xe832), addr=bytes(6))),  # REQ_BW_CHANGE
    ether(event(193, struct.pack("<I", 7) + b"example".ljust(32, b"\0") + AP + b"\0\0"
                + struct.pack("<Ii", 0x000fac08, 0))),                   # START_AUTH, 52 bytes
    ether(event(193, struct.pack("<I", 0) + bytes(32) + AP + b"\0\0"
                + struct.pack("<Ii", 0x000fac08, 0) + STA + b"\0\0")),   # START_AUTH with MLD address
    ether(event(194, struct.pack("<HHHHHH", 1, 12, 0, 0, 1, 30), addr=bytes(6))),  # OMN_MASTER
    ether(event(202, bytes([5, 1, 0, 0]) + bytes(4) + b"\x01" + bytes(58), addr=bytes(6))),  # COLOR
    ether(event(206, struct.pack("<HHHH", 1, 8, 1, 1), addr=bytes(6))),  # EDCRS_HI_EVENT
    ether(event(21, struct.pack("<I", 2) + AP + b"\x01" + STA + b"\x00")),  # PMKID_CACHE
    ether(event(21, struct.pack("<I", 3) + AP + b"\x01"), src=BAD),      # PMKID_CACHE, count overruns
    ether(event(12, struct.pack("<H", 8), reason=8)),                    # DISASSOC_IND, frame body
    ether(event(6, struct.pack("<H", 2) + ie(76, bytes(16)), reason=2)),  # DEAUTH_IND, reason and element
    ether(event(5, struct.pack("<H", 3) + b"\x01", reason=3)),           # DEAUTH, trailing byte stays payload
    ether(event(27, struct.pack("<I", 30))),                             # ADDTS_IND, TS delay
    ether(event(47, b"US\0", addr=bytes(6))),                            # COUNTRY_CODE_CHANGED
    ether(event(74, bytes([8, 4, 6, 2, 1, 0]), addr=bytes(6))),          # FIFO_CREDIT_MAP
    ether(event(117, struct.pack("<I", 1), addr=bytes(6))),              # ALLOW_CREDIT_BORROW
    ether(event(125, bytes(range(32)), addr=AP)),                        # BSSID, FT key
    ether(event(199, b"\x02", addr=bytes(6))),                           # PWR_SAVE_SYNC, 1 byte
    ether(event(199, struct.pack("<i", 0), addr=bytes(6))),              # PWR_SAVE_SYNC, int
    ether(event(201, struct.pack("<I", 2), addr=bytes(6))),              # BAND_CHANGE
    ether(event(0, b"example")),                                         # SET_SSID
    ether(event(7, struct.pack("<HHH", 0x0411, 0, 0xc001) + ie(1, b"\x82\x84") + ie(221, bytes(7)))),  # ASSOC
    ether(event(9, struct.pack("<HH", 0x0431, 10) + AP + ie(0, b"example"))),  # REASSOC, request body
    ether(event(26, struct.pack("<III", 12 + 128 + 9, 109, 1)          # SCAN_COMPLETE with results
                + bss(b"example", 0x1006, -55, 6, ie(0, b"example")))),
    ether(event(60, struct.pack("<I", 0x1234), status=0)),               # ACTION_FRAME_COMPLETE
    ether(event(149, ie(1, b"\x82\x84") + ie(45, bytes(26)), addr=AP)),  # PRE_ASSOC_RSEP_IND, elements
    ether(event(156, bytes([10, 8, 1, 0, 0]))),                          # BSSTRANS_RESP, WNM action body
    ether(event(187, mgmt(13, bytes([10, 7, 1, 0, 0])))),                # WNM_ERR, action frame
    ether(event(191, bytes([10, 7, 2, 1, 0, 0, 0, 0]))),                 # BSSTRANS_REQ
    ether(event(192, bytes([10, 6, 3, 0]))),                             # BSSTRANS_QUERY
    ether(event(196, bytes([10, 26, 4, 221]))),                          # WNM_NOTIFICATION_REQ
    ether(event(166, struct.pack("<HHHH", 1, 16, 2, 8) + struct.pack("<HHH", 2, 1, 0)
                + ie(54, b"\x01\x02\x00"))),                             # FBT, over-the-air auth body
    ether(event(188, struct.pack("<HHH", 0, 1, 0))),                     # ASSOC_FAIL, auth body
    ether(event(195, struct.pack("<HHBBBB", 1, 8, 3, 0x40, 1, 0), addr=bytes(6))),  # MBO_CAPABILITY_STATUS
    ether(event(198, struct.pack("<HH", 256, 4) + struct.pack("<HH", 258, 263))),  # GAS_RQST_ANQP_QUERY
    ether(event(200, rxmeta_v2(0x1006) + ie(0, b"") + ie(1, b"\x82"))),  # PROBREQ_MSG_RX_EXT, elements
    ether(event(172, b"\x01" + bytes(27) + struct.pack("<II", 7, 40) + b"\x05\x06\x07\x08",
                addr=bytes(6))),                                         # AIRIQ_EVENT
    ether(event(179, struct.pack("<BxxxI", 2, 12) + struct.pack("<I", 4), addr=bytes(6))),  # LTE_U_EVENT
    ether(event(172, bytes(30))),                                        # AIRIQ, length mismatch: payload
    ether(event(198, struct.pack("<HH", 256, 9) + bytes(2))),            # ANQP length overrun: payload
    ether(event(209, bytes(20))),                                        # DHD CSI_DATA: stays payload
    ether(event(202, bytes(40))),                                        # DHD PFN_PARTIAL_RESULT: payload
]
frames = [(f, len(f)) for f in frames]
snapped = ether(event(69, SCAN, status=8))
frames.append((snapped[:300], len(snapped)))                             # cut by snapshot length

out = Path(__file__).with_name("sample.pcap")
with out.open("wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, (data, orig) in enumerate(frames):
        fh.write(struct.pack("<IIII", 1767225600 + i, 0, len(data), orig) + data)
print(f"wrote {out} ({len(frames)} frames)")
