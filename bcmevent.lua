-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- bcmevent.lua - Broadcom Wi-Fi firmware events on EtherType 0x886c
-- https://github.com/techjoec/bcmevent-dissector
--
-- Broadcom FullMAC and HND firmware delivers events to the host as Ethernet
-- frames with EtherType 0x886c. Wireshark assigns that value to HomePNA and
-- shows them as malformed. Layouts follow Broadcom's public driver sources:
-- bcmevent.h, wlioctl.h and bcmwifi_channels.h in bcmdhd and HND releases,
-- fweh.h in brcmfmac. Not affiliated with Broadcom.

set_plugin_info({
    version = "1.0.0",
    description = "Broadcom Wi-Fi firmware event dissector (EtherType 0x886c)",
    author = "techjoec",
    repository = "https://github.com/techjoec/bcmevent-dissector"
})

local bcm = Proto("bcmevent", "Broadcom Wi-Fi Firmware Event")

-- Event numbers follow HND (router) firmware. Numbers HND leaves unused take
-- the name from the firmware that defines them. Client FullMAC (DHD) and
-- Infineon/Cypress (CYW) firmware give some numbers other meanings; those
-- are in the next two tables and shown next to the HND name.
local EVENT_NAMES = {
    [0]="WLC_E_SET_SSID", [1]="WLC_E_JOIN", [2]="WLC_E_START", [3]="WLC_E_AUTH",
    [4]="WLC_E_AUTH_IND", [5]="WLC_E_DEAUTH", [6]="WLC_E_DEAUTH_IND", [7]="WLC_E_ASSOC",
    [8]="WLC_E_ASSOC_IND", [9]="WLC_E_REASSOC", [10]="WLC_E_REASSOC_IND", [11]="WLC_E_DISASSOC",
    [12]="WLC_E_DISASSOC_IND", [13]="WLC_E_QUIET_START", [14]="WLC_E_QUIET_END",
    [15]="WLC_E_BEACON_RX", [16]="WLC_E_LINK", [17]="WLC_E_MIC_ERROR", [18]="WLC_E_NDIS_LINK",
    [19]="WLC_E_ROAM", [20]="WLC_E_TXFAIL", [21]="WLC_E_PMKID_CACHE",
    [22]="WLC_E_RETROGRADE_TSF", [23]="WLC_E_PRUNE", [24]="WLC_E_AUTOAUTH",
    [25]="WLC_E_EAPOL_MSG", [26]="WLC_E_SCAN_COMPLETE", [27]="WLC_E_ADDTS_IND",
    [28]="WLC_E_DELTS_IND", [29]="WLC_E_BCNSENT_IND", [30]="WLC_E_BCNRX_MSG",
    [31]="WLC_E_BCNLOST_MSG", [32]="WLC_E_ROAM_PREP", [33]="WLC_E_PFN_NET_FOUND",
    [34]="WLC_E_PFN_NET_LOST", [35]="WLC_E_RESET_COMPLETE", [36]="WLC_E_JOIN_START",
    [37]="WLC_E_ROAM_START", [38]="WLC_E_ASSOC_START", [39]="WLC_E_IBSS_ASSOC",
    [40]="WLC_E_RADIO", [41]="WLC_E_PSM_WATCHDOG", [42]="WLC_E_CCX_ASSOC_START",
    [43]="WLC_E_CCX_ASSOC_ABORT", [44]="WLC_E_PROBREQ_MSG", [45]="WLC_E_SCAN_CONFIRM_IND",
    [46]="WLC_E_PSK_SUP", [47]="WLC_E_COUNTRY_CODE_CHANGED", [48]="WLC_E_EXCEEDED_MEDIUM_TIME",
    [49]="WLC_E_ICV_ERROR", [50]="WLC_E_UNICAST_DECODE_ERROR",
    [51]="WLC_E_MULTICAST_DECODE_ERROR", [52]="WLC_E_TRACE", [53]="WLC_E_BTA_HCI_EVENT",
    [54]="WLC_E_IF",
    [55]="WLC_E_P2P_DISC_LISTEN_COMPLETE", [56]="WLC_E_RSSI", [57]="WLC_E_PFN_BEST_BATCHING",
    [58]="WLC_E_EXTLOG_MSG", [59]="WLC_E_ACTION_FRAME", [60]="WLC_E_ACTION_FRAME_COMPLETE",
    [61]="WLC_E_PRE_ASSOC_IND", [62]="WLC_E_PRE_REASSOC_IND", [63]="WLC_E_CHANNEL_ADOPTED",
    [64]="WLC_E_AP_STARTED", [65]="WLC_E_DFS_AP_STOP", [66]="WLC_E_DFS_AP_RESUME",
    [67]="WLC_E_WAI_STA_EVENT", [68]="WLC_E_WAI_MSG", [69]="WLC_E_ESCAN_RESULT",
    [70]="WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE", [71]="WLC_E_PROBRESP_MSG",
    [72]="WLC_E_P2P_PROBREQ_MSG", [73]="WLC_E_DCS_REQUEST", [74]="WLC_E_FIFO_CREDIT_MAP",
    [75]="WLC_E_ACTION_FRAME_RX", [76]="WLC_E_WAKE_EVENT", [77]="WLC_E_RM_COMPLETE",
    [78]="WLC_E_HTSFSYNC", [79]="WLC_E_OVERLAY_REQ", [80]="WLC_E_CSA_COMPLETE_IND",
    [81]="WLC_E_EXCESS_PM_WAKE_EVENT", [82]="WLC_E_PFN_SCAN_NONE / WLC_E_PFN_BSSID_NET_FOUND",
    [83]="WLC_E_PFN_SCAN_ALLGONE / WLC_E_PFN_BSSID_NET_LOST", [84]="WLC_E_GTK_PLUMBED",
    [85]="WLC_E_ASSOC_IND_NDIS", [86]="WLC_E_REASSOC_IND_NDIS", [87]="WLC_E_ASSOC_REQ_IE",
    [88]="WLC_E_ASSOC_RESP_IE", [89]="WLC_E_ASSOC_RECREATED", [90]="WLC_E_ACTION_FRAME_RX_NDIS",
    [91]="WLC_E_AUTH_REQ", [92]="WLC_E_TDLS_PEER_EVENT", [93]="WLC_E_SPEEDY_RECREATE_FAIL",
    [94]="WLC_E_NATIVE", [95]="WLC_E_PKTDELAY_IND", [96]="WLC_E_AWDL_AW",
    [97]="WLC_E_AWDL_ROLE", [98]="WLC_E_AWDL_EVENT", [99]="WLC_E_PSTA_PRIMARY_INTF_IND",
    [100]="WLC_E_NAN", [101]="WLC_E_BEACON_FRAME_RX", [102]="WLC_E_SERVICE_FOUND",
    [103]="WLC_E_GAS_FRAGMENT_RX", [104]="WLC_E_GAS_COMPLETE", [105]="WLC_E_P2PO_ADD_DEVICE",
    [106]="WLC_E_P2PO_DEL_DEVICE", [107]="WLC_E_WNM_STA_SLEEP", [108]="WLC_E_TXFAIL_THRESH",
    [109]="WLC_E_PROXD", [110]="WLC_E_IBSS_COALESCE / WLC_E_AIBSS_TXFAIL",
    [111]="WLC_E_PHY_TEMP", [114]="WLC_E_BSS_LOAD", [115]="WLC_E_MIMO_PWR_SAVE",
    [116]="WLC_E_LEAKY_AP_STATS", [117]="WLC_E_ALLOW_CREDIT_BORROW", [120]="WLC_E_MSCH",
    [121]="WLC_E_CSA_START_IND", [122]="WLC_E_CSA_DONE_IND", [123]="WLC_E_CSA_FAILURE_IND",
    [124]="WLC_E_CCA_CHAN_QUAL", [125]="WLC_E_BSSID", [126]="WLC_E_TX_STAT_ERROR",
    [127]="WLC_E_BCMC_CREDIT_SUPPORT", [128]="WLC_E_PEER_TIMEOUT",
    [130]="WLC_E_BT_WIFI_HANDOVER_REQ", [131]="WLC_E_SPW_TXINHIBIT",
    [132]="WLC_E_FBT_AUTH_REQ_IND", [133]="WLC_E_RSSI_LQM", [134]="WLC_E_PFN_GSCAN_FULL_RESULT",
    [135]="WLC_E_PFN_SWC", [136]="WLC_E_AUTHORIZED", [137]="WLC_E_PROBREQ_MSG_RX",
    [138]="WLC_E_PFN_SCAN_COMPLETE", [139]="WLC_E_RMC_EVENT", [140]="WLC_E_DPSTA_INTF_IND",
    [141]="WLC_E_RRM", [142]="WLC_E_PFN_SSID_EXT", [143]="WLC_E_ROAM_EXP_EVENT",
    [146]="WLC_E_ULP", [147]="WLC_E_MACDBG", [148]="WLC_E_RESERVED",
    [149]="WLC_E_PRE_ASSOC_RSEP_IND", [150]="WLC_E_PSK_AUTH", [151]="WLC_E_TKO",
    [152]="WLC_E_SDB_TRANSITION", [153]="WLC_E_NATOE_NFCT", [154]="WLC_E_TEMP_THROTTLE",
    [155]="WLC_E_LINK_QUALITY", [156]="WLC_E_BSSTRANS_RESP",
    [157]="WLC_E_TWT_SETUP / WLC_E_HE_TWT_SETUP", [158]="WLC_E_NAN_CRITICAL",
    [159]="WLC_E_NAN_NON_CRITICAL", [160]="WLC_E_RADAR_DETECTED", [161]="WLC_E_RANGING_EVENT",
    [162]="WLC_E_INVALID_IE", [163]="WLC_E_MODE_SWITCH", [164]="WLC_E_PKT_FILTER",
    [165]="WLC_E_DMA_TXFLUSH_COMPLETE", [166]="WLC_E_FBT", [167]="WLC_E_PFN_SCAN_BACKOFF",
    [168]="WLC_E_PFN_BSSID_SCAN_BACKOFF", [169]="WLC_E_AGGR_EVENT",
    [170]="WLC_E_AP_CHAN_CHANGE", [171]="WLC_E_PSTA_CREATE_IND", [172]="WLC_E_AIRIQ_EVENT",
    [173]="WLC_E_FRAME_FIRST_RX", [174]="WLC_E_BCN_STUCK", [175]="WLC_E_PROBSUP_IND",
    [176]="WLC_E_SAS_RSSI", [177]="WLC_E_RATE_CHANGE", [178]="WLC_E_AMT_CHANGE",
    [179]="WLC_E_LTE_U_EVENT", [180]="WLC_E_CEVENT", [181]="WLC_E_HWA_EVENT",
    [182]="WLC_E_DFS_HIT", [183]="WLC_E_TXFAIL_TRFTHOLD", [184]="WLC_E_CAC_STATE_CHANGE",
    [185]="WLC_E_REQ_BW_CHANGE", [186]="WLC_E_ASSOC_REASSOC_IND_EXT", [187]="WLC_E_WNM_ERR",
    [188]="WLC_E_ASSOC_FAIL", [189]="WLC_E_REASSOC_FAIL", [190]="WLC_E_AUTH_FAIL",
    [191]="WLC_E_BSSTRANS_REQ", [192]="WLC_E_BSSTRANS_QUERY", [193]="WLC_E_START_AUTH",
    [194]="WLC_E_OMN_MASTER", [195]="WLC_E_MBO_CAPABILITY_STATUS",
    [196]="WLC_E_WNM_NOTIFICATION_REQ", [197]="WLC_E_WNM_BSSTRANS_QUERY",
    [198]="WLC_E_GAS_RQST_ANQP_QUERY", [199]="WLC_E_PWR_SAVE_SYNC",
    [200]="WLC_E_PROBREQ_MSG_RX_EXT", [201]="WLC_E_BAND_CHANGE", [202]="WLC_E_COLOR",
    [203]="WLC_E_CAPTURE_RXFRAME", [204]="WLC_E_CAPTURE_TXFRAME", [205]="WLC_E_BUZZZ",
    [206]="WLC_E_EDCRS_HI_EVENT", [207]="WLC_E_QOS_MGMT", [208]="WLC_E_HEALTH_CHECK",
    [209]="WLC_E_CSA_RECV_IND", [210]="WLC_E_MLD_UP", [211]="WLC_E_PASN_AUTH",
    [212]="WLC_E_EDS_EVENT", [213]="WLC_E_ICM", [214]="WLC_E_AIRIQ_EVENT"
}

local DHD_EVENT_NAMES = {
    [171]="WLC_E_TVPM_MITIGATION", [172]="WLC_E_SCAN", [173]="WLC_E_MBO", [174]="WLC_E_PHY_CAL",
    [175]="WLC_E_RPSNOA", [176]="WLC_E_ADPS", [177]="WLC_E_SLOTTED_BSS_PEER_OP",
    [179]="WLC_E_GTK_KEYROT_NO_CHANSW", [180]="WLC_E_ONBODY_STATUS_CHANGE",
    [181]="WLC_E_BCNRECV_ABORTED", [182]="WLC_E_PMK_INFO", [183]="WLC_E_BSSTRANS",
    [184]="WLC_E_WA_LQM", [185]="WLC_E_ACTION_FRAME_OFF_CHAN_DWELL_COMPLETE",
    [186]="WLC_E_WSEC", [187]="WLC_E_OBSS_DETECTION", [188]="WLC_E_AP_BCN_MUTE",
    [189]="WLC_E_SC_CHAN_QUAL", [190]="WLC_E_DYNSAR", [191]="WLC_E_ROAM_CACHE_UPDATE",
    [192]="WLC_E_AP_BCN_DRIFT", [193]="WLC_E_PFN_SCAN_ALLGONE_EXT", [194]="WLC_E_AUTH_START",
    [195]="WLC_E_TWT", [196]="WLC_E_AMT", [197]="WLC_E_ROAM_SCAN_RESULT", [200]="WLC_E_MSCS",
    [201]="WLC_E_RXDMA_RECOVERY_ATMPT", [202]="WLC_E_PFN_PARTIAL_RESULT",
    [203]="WLC_E_MLO_LINK_INFO", [204]="WLC_E_C2C", [205]="WLC_E_BCN_TSF",
    [206]="WLC_E_OWE_INFO", [207]="WLC_E_ULMU_DISABLED_REASON_UPD",
    [208]="WLC_E_AMSDU_RX_WAKEUP", [209]="WLC_E_CSI_DATA", [211]="WLC_E_CSA_IGNORED"
}

local CYW_EVENT_NAMES = {
    [187]="WLC_E_EXT_AUTH_REQ", [188]="WLC_E_EXT_AUTH_FRAME_RX",
    [189]="WLC_E_MGMT_FRAME_TXSTATUS", [190]="WLC_E_MGMT_FRAME_OFF_CHAN_COMPLETE",
    [193]="WLC_E_DLTRO", [195]="WLC_E_TWT_TEARDOWN", [196]="WLC_E_EXT_ASSOC_FRAME_RX",
    [202]="WLC_E_ICMP_ECHO_REQ"
}

-- Status and reason names are the header macros without their prefix.
local STATUS_NAMES = {
    [0]="SUCCESS", [1]="FAIL", [2]="TIMEOUT", [3]="NO_NETWORKS", [4]="ABORT", [5]="NO_ACK",
    [6]="UNSOLICITED", [7]="ATTEMPT", [8]="PARTIAL", [9]="NEWSCAN", [10]="NEWASSOC",
    [11]="11HQUIET", [12]="SUPPRESS", [13]="NOCHANS", [14]="CCXFASTRM", [15]="CS_ABORT",
    [16]="ERROR", [17]="SLOTTED_PEER_ADD", [18]="SLOTTED_PEER_DEL", [19]="RXBCN",
    [20]="RXBCN_ABORT", [21]="LOWPOWER_ON_LOWSPAN", [22]="WAIT_RXBCN_TIMEOUT", [23]="6G_NO_TPE",
    [24]="CHANNELSWITCH", [25]="PREF_LINK_SWAP_FAIL", [26]="MLO_ROAM_FAIL", [30]="TRY_LATER",
    [255]="INVALID"
}

-- WLC_E_PSK_SUP puts the supplicant state (sup_auth_status_t) in the status.
local SUP_STATUS_NAMES = {
    [0]="DISCONNECTED", [1]="CONNECTING", [2]="IDREQUIRED", [3]="AUTHENTICATING",
    [4]="AUTHENTICATED", [5]="KEYXCHANGE", [6]="KEYED", [7]="TIMEOUT",
    [8]="KEYXCHANGE_WAIT_M3", [9]="KEYXCHANGE_PREP_M4", [10]="KEYXCHANGE_WAIT_G1",
    [11]="KEYXCHANGE_PREP_G2"
}

local PSK_AUTH_STATUS_NAMES = {
    [1]="WPA_TIMOUT", [2]="MIC_WPA_ERR", [3]="IE_MISMATCH_ERR", [4]="REPLAY_COUNT_ERR",
    [5]="PEER_BLACKISTED", [6]="GTK_REKEY_FAIL"
}

local SDB_STATUS_NAMES = {
    [1]="SDB_START", [2]="SDB_COMPLETE", [3]="SLICE_SWAP_START", [4]="SLICE_SWAP_COMPLETE",
    [5]="SDB_FAILED"
}

local LINK_REASON_NAMES = {
    [1]="BCN_LOSS", [2]="DISASSOC", [3]="ASSOC_REC", [4]="BSSCFG_DIS", [5]="ASSOC_FAIL",
    [6]="REASSOC_ROAM_FAIL", [7]="LOWRSSI_ROAM_FAIL", [8]="NO_FIRST_BCN_RX",
    [9]="COUNTRY_CHANGE"
}

local ROAM_REASON_NAMES = {
    [0]="INITIAL_ASSOC", [1]="LOW_RSSI", [2]="DEAUTH", [3]="DISASSOC", [4]="BCNS_LOST",
    [5]="FAST_ROAM_FAILED", [6]="DIRECTED_ROAM", [7]="TSPEC_REJECTED", [8]="BETTER_AP",
    [9]="MINTXRATE", [10]="TXFAIL", [11]="BSSTRANS_REQ", [12]="LOW_RSSI_CU",
    [13]="RADAR_DETECTED", [14]="LOW_RSSI_END / CSA", [15]="ESTM_LOW", [16]="SILENT_ROAM",
    [17]="INACTIVITY", [18]="ROAM_SCAN_TIMEOUT", [19]="REASSOC", [20]="CCA", [21]="BTCX_ROAM",
    [22]="MLD_REASSOC"
}

local PRUNE_REASON_NAMES = {
    [1]="ENCR_MISMATCH", [2]="BCAST_BSSID", [3]="MAC_DENY", [4]="MAC_NA", [5]="REG_PASSV",
    [6]="SPCT_MGMT", [7]="RADAR", [8]="RSN_MISMATCH", [9]="NO_COMMON_RATES",
    [10]="BASIC_RATES", [11]="CCXFAST_PREVAP", [12]="CIPHER_NA", [13]="KNOWN_STA",
    [14]="CCXFAST_DROAM", [15]="WDS_PEER", [16]="QBSS_LOAD", [17]="HOME_AP",
    [18]="AP_BLOCKED", [19]="NO_DIAG_SUPPORT", [20]="AUTH_RESP_MAC", [21]="ASSOC_RETRY_DELAY",
    [22]="RSSI_ASSOC_REJ", [23]="MAC_AVOID", [24]="TRANSITION_DISABLE",
    [25]="WRONG_COUNTRY_CODE", [26]="CHANNEL_NOT_IN_VLP", [27]="MFP_COMPAT_MISMATCH",
    [28]="CHAN_MISMATCH", [29]="MSTA", [30]="BLIST_BTM", [31]="BCN_MUTE_LOW_RSSI",
    [32]="6G_RSN_MISMATCH", [33]="INVALID_CHAN", [34]="MESH_CFG_MISMATCH",
    [35]="6G_RNR_INVALID_CHAN", [36]="BY_OWE", [37]="AP_RESTRICT_POLICY", [38]="SAE_PWE_PWDID",
    [39]="SAE_TRANSITION_DISABLE", [40]="BCNPROT_DISABLED", [41]="RNR_INVALID_OPCLASS"
}

local SUP_REASON_NAMES = {
    [0]="OTHER", [1]="DECRYPT_KEY_DATA", [2]="BAD_UCAST_WEP128", [3]="BAD_UCAST_WEP40",
    [4]="UNSUP_KEY_LEN", [5]="PW_KEY_CIPHER", [6]="MSG3_TOO_MANY_IE", [7]="MSG3_IE_MISMATCH",
    [8]="NO_INSTALL_FLAG", [9]="MSG3_NO_GTK", [10]="GRP_KEY_CIPHER", [11]="GRP_MSG1_NO_GTK",
    [12]="GTK_DECRYPT_FAIL", [13]="SEND_FAIL", [14]="DEAUTH", [15]="WPA_PSK_TMO",
    [16]="WPA_PSK_M1_TMO", [17]="WPA_PSK_M3_TMO", [18]="GTK_UPDATE_FAIL", [19]="TK_UPDATE_FAIL",
    [20]="KEY_INSTALL_FAIL", [21]="PTK_UPDATE", [22]="MSG1_PMKID_MISMATCH", [23]="GTK_UPDATE",
    [24]="KDK_UPDATE_FAIL", [25]="MSG3_NO_MLO_GTK", [26]="NO_IGTK", [27]="NO_BIGTK",
    [28]="NO_MLO_IGTK", [29]="NO_MLO_BIGTK", [30]="IGTK_DECRYPT_FAIL", [31]="IGTK_UPDATE_FAIL",
    [32]="BIGTK_DECRYPT_FAIL", [33]="BIGTK_UPDATE_FAIL", [34]="GTK_BAD_KEY_IDX",
    [35]="IGTK_BAD_KEY_IDX", [36]="BIGTK_BAD_KEY_IDX", [37]="BCN_PROT_DISABLED_AP",
    [38]="GTK_BAD_LINK_ID", [39]="IGTK_BAD_LINK_ID", [40]="BIGTK_BAD_LINK_ID",
    [41]="FT_ELEM_CNT_MISMATCH"
}

local MACDBG_REASON_NAMES = {
    [0]="LIST_PSM", [1]="LIST_PSMX", [2]="REGALL", [3]="LISTALL", [4]="DTRACE",
    [5]="RATELINKMEM"
}

local TDLS_REASON_NAMES = {
    [0]="PEER_DISCOVERED", [1]="PEER_CONNECTED", [2]="PEER_DISCONNECTED"
}

local SDB_REASON_NAMES = {
    [0]="HOST_DIRECT", [1]="INFRA_ASSOC", [2]="INFRA_ROAM", [3]="INFRA_DISASSOC",
    [4]="NO_MODE_CHANGE_NEEDED", [7]="SDB_MODESW_SLICE_CHANGE", [8]="SDB_MODESW_CHAIN_CHANGE",
    [9]="SDB_MODESW_SLICE_AND_CHAIN_CHANGE", [10]="SDB_MODESW_UNKNOWN",
    [11]="SDB_MODESW_TIMEOUT", [12]="SDB_MODESW_FAILED"
}

local QOS_MGMT_REASON_NAMES = {
    [1]="QOS_MAP_SET", [2]="QOS_MAP_ASSOC", [3]="MSCS_REQUEST", [4]="MSCS_ASSOC",
    [5]="SCS_REQUEST", [6]="DSCP_POLICY_QUERY", [7]="QOS_VENDOR_SPECIFIC_REQUEST",
    [8]="QOS_MSCS_STATE_CHANGE", [9]="QOS_ASR_STATE_CHANGE", [10]="MSCS_TERMINATE",
    [11]="QOS_SCS_STATE_CHANGE", [12]="DSCP_POLICY_ASSOC", [13]="QOS_VENDOR_SPECIFIC_AF",
    [14]="QOS_ASSOC"
}

-- IEEE 802.11 reason codes, as sent or received in deauthentication and
-- disassociation frames.
local DOT11_REASON_NAMES = {
    [1]="UNSPECIFIED", [2]="PREV_AUTH_NOT_VALID", [3]="DEAUTH_LEAVING",
    [4]="DISASSOC_DUE_TO_INACTIVITY", [5]="DISASSOC_AP_BUSY",
    [6]="CLASS2_FRAME_FROM_NONAUTH_STA", [7]="CLASS3_FRAME_FROM_NONASSOC_STA",
    [8]="DISASSOC_STA_HAS_LEFT", [9]="STA_REQ_ASSOC_WITHOUT_AUTH",
    [10]="PWR_CAPABILITY_NOT_VALID", [11]="SUPPORTED_CHANNEL_NOT_VALID",
    [12]="BSS_TRANSITION_DISASSOC", [13]="INVALID_IE", [14]="MICHAEL_MIC_FAILURE",
    [15]="4WAY_HANDSHAKE_TIMEOUT", [16]="GROUP_KEY_UPDATE_TIMEOUT", [17]="IE_IN_4WAY_DIFFERS",
    [18]="GROUP_CIPHER_NOT_VALID", [19]="PAIRWISE_CIPHER_NOT_VALID", [20]="AKMP_NOT_VALID",
    [21]="UNSUPPORTED_RSN_IE_VERSION", [22]="INVALID_RSN_IE_CAPAB",
    [23]="IEEE_802_1X_AUTH_FAILED", [24]="CIPHER_SUITE_REJECTED",
    [25]="TDLS_TEARDOWN_UNREACHABLE", [26]="TDLS_TEARDOWN_UNSPECIFIED",
    [27]="SSP_REQUESTED_DISASSOC", [28]="NO_SSP_ROAMING_AGREEMENT", [29]="BAD_CIPHER_OR_AKM",
    [30]="NOT_AUTHORIZED_THIS_LOCATION", [31]="SERVICE_CHANGE_PRECLUDES_TS",
    [32]="UNSPECIFIED_QOS_REASON", [33]="NOT_ENOUGH_BANDWIDTH", [34]="DISASSOC_LOW_ACK",
    [35]="EXCEEDED_TXOP", [36]="STA_LEAVING", [37]="END_TS_BA_DLS", [38]="UNKNOWN_TS_BA",
    [39]="TIMEOUT", [45]="PEERKEY_MISMATCH", [46]="AUTHORIZED_ACCESS_LIMIT_REACHED",
    [47]="EXTERNAL_SERVICE_REQUIREMENTS", [48]="INVALID_FT_ACTION_FRAME_COUNT",
    [49]="INVALID_PMKID", [50]="INVALID_MDE", [51]="INVALID_FTE", [52]="MESH_PEERING_CANCELLED",
    [53]="MESH_MAX_PEERS", [54]="MESH_CONFIG_POLICY_VIOLATION", [55]="MESH_CLOSE_RCVD",
    [56]="MESH_MAX_RETRIES", [57]="MESH_CONFIRM_TIMEOUT", [58]="MESH_INVALID_GTK",
    [59]="MESH_INCONSISTENT_PARAMS", [60]="MESH_INVALID_SECURITY_CAP",
    [61]="MESH_PATH_ERROR_NO_PROXY_INFO", [62]="MESH_PATH_ERROR_NO_FORWARDING_INFO",
    [63]="MESH_PATH_ERROR_DEST_UNREACHABLE", [64]="MAC_ADDRESS_ALREADY_EXISTS_IN_MBSS",
    [65]="MESH_CHANNEL_SWITCH_REGULATORY_REQ", [66]="MESH_CHANNEL_SWITCH_UNSPECIFIED"
}

local REASON_NAMES_BY_EVENT = {
    [5] = DOT11_REASON_NAMES,       -- DEAUTH
    [6] = DOT11_REASON_NAMES,       -- DEAUTH_IND
    [11] = DOT11_REASON_NAMES,      -- DISASSOC
    [12] = DOT11_REASON_NAMES,      -- DISASSOC_IND
    [16] = LINK_REASON_NAMES,       -- LINK
    [19] = ROAM_REASON_NAMES,       -- ROAM
    [23] = PRUNE_REASON_NAMES,      -- PRUNE
    [32] = ROAM_REASON_NAMES,       -- ROAM_PREP
    [37] = ROAM_REASON_NAMES,       -- ROAM_START
    [46] = SUP_REASON_NAMES,        -- PSK_SUP
    [92] = TDLS_REASON_NAMES,       -- TDLS_PEER_EVENT
    [147] = MACDBG_REASON_NAMES,    -- MACDBG
    [152] = SDB_REASON_NAMES,       -- SDB_TRANSITION
    [207] = QOS_MGMT_REASON_NAMES   -- QOS_MGMT
}

local IE_NAMES = {
    [0]="SSID", [1]="Supported Rates", [3]="DS Parameter Set", [5]="TIM", [7]="Country",
    [11]="BSS Load", [32]="Power Constraint", [35]="TPC Report", [42]="ERP Information",
    [45]="HT Capabilities", [48]="RSN", [50]="Extended Supported Rates",
    [51]="AP Channel Report", [54]="Mobility Domain", [59]="Supported Operating Classes",
    [61]="HT Operation", [70]="RRM Enabled Capabilities", [71]="Multiple BSSID",
    [74]="Overlapping BSS Scan Parameters", [107]="Interworking", [111]="Roaming Consortium",
    [127]="Extended Capabilities", [191]="VHT Capabilities", [192]="VHT Operation",
    [195]="Transmit Power Envelope", [201]="Reduced Neighbor Report", [221]="Vendor Specific",
    [244]="RSN Extension", [255]="Extension"
}

local EXT_IE_NAMES = {
    [32]="OWE Diffie-Hellman Parameter", [33]="Password Identifier", [35]="HE Capabilities",
    [36]="HE Operation", [38]="MU EDCA Parameter Set", [39]="Spatial Reuse Parameter Set",
    [55]="Multiple BSSID Configuration", [59]="HE 6 GHz Band Capabilities",
    [106]="EHT Operation", [107]="Multi-Link", [108]="EHT Capabilities"
}

local COUNTRY_ENV = {
    [0x01]="Operating classes in the United States", [0x02]="Operating classes in Europe",
    [0x03]="Operating classes in Japan", [0x04]="Global operating classes",
    [0x05]="S1G operating classes", [0x06]="Operating classes in China",
    [0x20]="All", [0x49]="Indoor", [0x4f]="Outdoor", [0x58]="Non Country Entity"
}

local CIPHER_NAMES = {
    [0]="Use group cipher", [1]="WEP-40", [2]="TKIP", [4]="CCMP-128", [5]="WEP-104",
    [6]="BIP-CMAC-128", [7]="No group-addressed traffic", [8]="GCMP-128", [9]="GCMP-256",
    [10]="CCMP-256"
}

local AKM_NAMES = {
    [1]="802.1X", [2]="PSK", [3]="FT-802.1X", [4]="FT-PSK", [5]="802.1X-SHA256",
    [6]="PSK-SHA256", [7]="TDLS", [8]="SAE", [9]="FT-SAE", [11]="Suite-B", [12]="Suite-B-192",
    [13]="FT-Suite-B-192", [14]="FILS-SHA256", [15]="FILS-SHA384", [16]="FT-FILS-SHA256",
    [17]="FT-FILS-SHA384", [18]="OWE", [19]="FT-PSK-SHA384", [20]="PSK-SHA384", [21]="PASN",
    [22]="FT-802.1X-SHA384", [23]="802.1X-SHA384", [24]="SAE-EXT-KEY", [25]="FT-SAE-EXT-KEY"
}

local WPS_ATTR_NAMES = {
    [0x1008]="Config Methods", [0x1011]="Device Name", [0x1021]="Manufacturer",
    [0x1023]="Model Name", [0x1024]="Model Number", [0x103b]="Response Type",
    [0x103c]="RF Bands", [0x1042]="Serial Number", [0x1044]="WPS State",
    [0x1047]="UUID-E", [0x1049]="Vendor Extension", [0x104a]="Version",
    [0x1054]="Primary Device Type"
}

local ACTION_CATEGORIES = {
    [0]="Spectrum Management", [1]="QoS", [2]="DLS", [3]="Block Ack", [4]="Public",
    [5]="Radio Measurement", [6]="Fast BSS Transition", [7]="HT", [8]="SA Query",
    [9]="Protected Dual of Public Action", [10]="WNM", [11]="Unprotected WNM", [12]="TDLS",
    [13]="Mesh", [15]="Self-protected", [17]="WMM", [21]="VHT", [30]="HE", [31]="Protected HE",
    [36]="EHT", [37]="Protected EHT", [126]="Vendor-specific Protected",
    [127]="Vendor-specific"
}

local MGMT_SUBTYPES = {
    [0]="Association Request", [1]="Association Response", [2]="Reassociation Request",
    [3]="Reassociation Response", [4]="Probe Request", [5]="Probe Response",
    [8]="Beacon", [9]="ATIM", [10]="Disassociation", [11]="Authentication",
    [12]="Deauthentication", [13]="Action"
}

local CEVENT_TYPE_NAMES = {[0]="CTRL", [1]="D2C", [2]="A2C", [3]="E2C", [4]="D2A", [5]="A2D"}

local CEVENT_SUBTYPE_NAMES = {
    [0]="NAS", [1]="WPS", [2]="WAI", [4]="MEVENT", [5]="BSD", [6]="SSD", [7]="DRSDBD",
    [8]="ASPM", [9]="VISDCOLL", [10]="CA", [11]="EVENTD", [12]="EAPD", [13]="PBCD",
    [14]="HOSTAPD", [15]="WPASUPP", [16]="WBD", [17]="ACSD", [18]="DRIVER"
}

local CEVENT_D2C_MSG_NAMES = {
    [0]="AUTH_TX", [1]="ASSOC_TX", [2]="EAP_TX", [3]="DISASSOC_TX", [4]="DEAUTH_TX",
    [6]="AUTH_RX", [7]="ASSOC_RX", [8]="EAP_RX", [9]="DISASSOC_RX", [10]="DEAUTH_RX",
    [12]="IF", [13]="BTM_REQ", [14]="BTM_RESP", [15]="BTM_QUERY", [16]="ARP_TX",
    [17]="ARP_RX", [18]="DHCP_TX", [19]="DHCP_RX", [20]="HC"
}

local CEVENT_A2C_MSG_NAMES = {
    [0]="PTK_INSTALL", [1]="GTK_INSTALL", [2]="M1_RX", [3]="M1_TX", [4]="M2_RX", [5]="M2_TX",
    [6]="M3_RX", [7]="M3_TX", [8]="M4_RX", [9]="M4_TX", [10]="NAS_TIMEOUT", [11]="ACS_CH_SW",
    [12]="BTM_REQ", [13]="BTM_BRUTE_FORCE", [14]="AUTH_COMMIT_TX", [15]="AUTH_COMMIT_RX",
    [16]="AUTH_CONFIRM_TX", [17]="AUTH_CONFIRM_RX"
}

local CHAN_CHANGE_REASONS = {
    [0]="CSA", [1]="DFS_AP_MOVE_START", [2]="DFS_AP_MOVE_RADAR_FOUND",
    [3]="DFS_AP_MOVE_ABORTED", [4]="DFS_AP_MOVE_SUCCESS", [5]="DFS_AP_MOVE_STUNT",
    [6]="DFS_AP_MOVE_STUNT_SUCCESS", [7]="CSA_TO_DFS_CHAN_FOR_CAC_ONLY",
    [8]="OBSS_AP_BW_SWITCH", [9]="ANY"
}

local CAC_STATES = {
    [0]="IDLE", [1]="PREISM_CAC", [2]="ISM", [3]="CSA", [4]="POSTISM_CAC", [5]="PREISM_OOC",
    [6]="POSTISM_OOC", [7]="ABORT_CAC"
}

local DNGL_EVENT_NAMES = {[2]="SOCRAM_IND", [3]="PROFILE_DATA_IND", [4]="SPMI_RESET_IND"}

local f = bcm.fields

-- bcmeth_hdr_t
f.bcm_subtype = ProtoField.uint16("bcmevent.bcm.subtype", "BCM Subtype", base.HEX)
f.bcm_length = ProtoField.uint16("bcmevent.bcm.length", "BCM Length", base.DEC)
f.bcm_version = ProtoField.uint8("bcmevent.bcm.version", "BCM Version", base.DEC)
f.bcm_oui = ProtoField.bytes("bcmevent.bcm.oui", "BCM OUI", base.COLON)
f.bcm_user_subtype = ProtoField.uint16("bcmevent.bcm.user_subtype", "BCM User Subtype", base.DEC,
    {[1]="Event", [5]="Dongle Event"})

-- wl_event_msg_t
f.evt_version = ProtoField.uint16("bcmevent.event.version", "Event Version", base.DEC)
f.evt_flags = ProtoField.uint16("bcmevent.event.flags", "Event Flags", base.HEX)
f.evt_flag_link = ProtoField.bool("bcmevent.event.flags.link", "LINK", 16, nil, 0x0001)
f.evt_flag_flushtxq = ProtoField.bool("bcmevent.event.flags.flushtxq", "FLUSHTXQ", 16, nil, 0x0002)
f.evt_flag_group = ProtoField.bool("bcmevent.event.flags.group", "GROUP", 16, nil, 0x0004)
f.evt_flag_unkbss = ProtoField.bool("bcmevent.event.flags.unkbss", "UNKBSS", 16, nil, 0x0008)
f.evt_flag_unkif = ProtoField.bool("bcmevent.event.flags.unkif", "UNKIF", 16, nil, 0x0010)
f.evt_flag_multilink = ProtoField.bool("bcmevent.event.flags.multilink", "MULTILINK", 16, nil, 0x0020)
f.evt_type = ProtoField.uint32("bcmevent.event.type", "Event Type", base.DEC, EVENT_NAMES)
f.evt_type_dhd = ProtoField.uint32("bcmevent.event.type_dhd", "Event Type (DHD)", base.DEC,
    DHD_EVENT_NAMES)
f.evt_type_cyw = ProtoField.uint32("bcmevent.event.type_cyw", "Event Type (CYW)", base.DEC,
    CYW_EVENT_NAMES)
f.evt_status = ProtoField.uint32("bcmevent.event.status", "Status", base.DEC, STATUS_NAMES)
f.evt_sup_status = ProtoField.uint32("bcmevent.event.sup_status", "Supplicant Status", base.DEC,
    SUP_STATUS_NAMES)
f.evt_psk_auth_status = ProtoField.uint32("bcmevent.event.psk_auth_status", "PSK Auth Status", base.DEC,
    PSK_AUTH_STATUS_NAMES)
f.evt_sdb_status = ProtoField.uint32("bcmevent.event.sdb_status", "SDB Status", base.DEC, SDB_STATUS_NAMES)
f.evt_reason = ProtoField.uint32("bcmevent.event.reason", "Reason", base.DEC)
f.evt_auth = ProtoField.uint32("bcmevent.event.auth_type", "Auth Type", base.DEC)
f.evt_datalen = ProtoField.uint32("bcmevent.event.data_len", "Data Length", base.DEC)
f.evt_addr = ProtoField.ether("bcmevent.event.addr", "Station Address")
f.evt_ifname = ProtoField.string("bcmevent.event.ifname", "Interface")
f.evt_ifidx = ProtoField.uint8("bcmevent.event.ifidx", "Interface Index", base.DEC)
f.evt_bssidx = ProtoField.uint8("bcmevent.event.bsscfgidx", "BSS Config Index", base.DEC)
f.payload = ProtoField.bytes("bcmevent.payload", "Payload")

-- Events that put other codes in the status field
local STATUS_BY_EVENT = {
    [46] = {f.evt_sup_status, SUP_STATUS_NAMES},            -- PSK_SUP
    [150] = {f.evt_psk_auth_status, PSK_AUTH_STATUS_NAMES}, -- PSK_AUTH
    [152] = {f.evt_sdb_status, SDB_STATUS_NAMES}            -- SDB_TRANSITION
}

local EVENT_FLAGS = {
    {f.evt_flag_link, 0x0001, "LINK"}, {f.evt_flag_flushtxq, 0x0002, "FLUSHTXQ"},
    {f.evt_flag_group, 0x0004, "GROUP"}, {f.evt_flag_unkbss, 0x0008, "UNKBSS"},
    {f.evt_flag_unkif, 0x0010, "UNKIF"}, {f.evt_flag_multilink, 0x0020, "MULTILINK"}
}

-- wl_escan_result_t and wl_bss_info_t
f.es_buflen = ProtoField.uint32("bcmevent.escan.buflen", "Scan Buffer Length", base.DEC)
f.es_version = ProtoField.uint32("bcmevent.escan.version", "Scan Version", base.DEC)
f.es_sync = ProtoField.uint16("bcmevent.escan.sync_id", "Scan Sync ID", base.HEX)
f.es_count = ProtoField.uint16("bcmevent.escan.bss_count", "BSS Count", base.DEC)
f.bss_version = ProtoField.uint32("bcmevent.bss.version", "BSS Info Version", base.DEC)
f.bss_length = ProtoField.uint32("bcmevent.bss.length", "BSS Record Length", base.DEC)
f.bss_bssid = ProtoField.ether("bcmevent.bss.bssid", "BSSID")
f.bss_beacon = ProtoField.uint16("bcmevent.bss.beacon_period", "Beacon Period", base.DEC)
f.bss_cap = ProtoField.uint16("bcmevent.bss.capability", "Capability", base.HEX)
f.bss_ssidlen = ProtoField.uint8("bcmevent.bss.ssid_len", "SSID Length", base.DEC)
f.bss_ssid = ProtoField.string("bcmevent.bss.ssid", "SSID")
f.bss_rates_count = ProtoField.uint32("bcmevent.bss.rates_count", "Rates Count", base.DEC)
f.bss_chanspec = ProtoField.uint16("bcmevent.bss.chanspec", "Chanspec", base.HEX)
f.bss_band = ProtoField.string("bcmevent.bss.band", "Band")
f.bss_bandwidth = ProtoField.uint16("bcmevent.bss.bandwidth", "Bandwidth", base.UNIT_STRING, {" MHz"})
f.bss_center_channel = ProtoField.uint8("bcmevent.bss.center_channel", "Center Channel", base.DEC)
f.bss_primary_channel = ProtoField.uint8("bcmevent.bss.primary_channel", "Primary Channel", base.DEC)
f.bss_sideband = ProtoField.string("bcmevent.bss.sideband", "Control Sideband")
f.bss_atim = ProtoField.uint16("bcmevent.bss.atim_window", "ATIM Window", base.DEC)
f.bss_dtim = ProtoField.uint8("bcmevent.bss.dtim_period", "DTIM Period", base.DEC)
f.bss_rssi = ProtoField.int16("bcmevent.bss.rssi", "RSSI", base.UNIT_STRING, {" dBm"})
f.bss_noise = ProtoField.int8("bcmevent.bss.noise", "PHY Noise", base.UNIT_STRING, {" dBm"})
f.bss_ncap = ProtoField.bool("bcmevent.bss.n_cap", "802.11n Capable", base.NONE)
f.bss_nbsscap = ProtoField.uint32("bcmevent.bss.nbss_cap", "HT/VHT BSS Capabilities", base.HEX)
f.bss_ctl = ProtoField.uint8("bcmevent.bss.control_channel", "Control Channel", base.DEC)
f.bss_vht_rx = ProtoField.uint16("bcmevent.bss.vht_rx_mcsmap", "VHT RX MCS Map", base.HEX)
f.bss_vht_tx = ProtoField.uint16("bcmevent.bss.vht_tx_mcsmap", "VHT TX MCS Map", base.HEX)
f.bss_flags = ProtoField.uint8("bcmevent.bss.flags", "BSS Flags", base.HEX)
f.bss_vhtcap = ProtoField.bool("bcmevent.bss.vht_cap", "VHT Capable", base.NONE)
f.bss_ieoff = ProtoField.uint16("bcmevent.bss.ie_offset", "IE Offset", base.DEC)
f.bss_ielen = ProtoField.uint32("bcmevent.bss.ie_length", "IE Length", base.DEC)
f.bss_snr = ProtoField.int16("bcmevent.bss.snr", "SNR", base.UNIT_STRING, {" dB"})

-- 802.11 elements
f.ie_id = ProtoField.uint8("bcmevent.ie.id", "Element ID", base.DEC, IE_NAMES)
f.ie_len = ProtoField.uint8("bcmevent.ie.length", "Length", base.DEC)
f.ie_ssid = ProtoField.string("bcmevent.ie.ssid", "SSID")
f.ie_channel = ProtoField.uint8("bcmevent.ie.channel", "Channel", base.DEC)
f.ie_country_code = ProtoField.string("bcmevent.ie.country_code", "Country Code")
f.ie_country_env = ProtoField.uint8("bcmevent.ie.country_environment", "Environment", base.HEX,
    COUNTRY_ENV)
f.ie_rates = ProtoField.string("bcmevent.ie.rates", "Rates")
f.ie_ext_id = ProtoField.uint8("bcmevent.ie.ext_id", "Extension ID", base.DEC, EXT_IE_NAMES)
f.vendor_oui = ProtoField.bytes("bcmevent.ie.vendor_oui", "Vendor OUI", base.COLON)
f.vendor_type = ProtoField.uint8("bcmevent.ie.vendor_type", "Vendor Type", base.DEC)
f.rsn_version = ProtoField.uint16("bcmevent.rsn.version", "RSN Version", base.DEC)
f.rsn_group = ProtoField.string("bcmevent.rsn.group_cipher", "Group Cipher")
f.rsn_pairwise_count = ProtoField.uint16("bcmevent.rsn.pairwise_count", "Pairwise Cipher Count", base.DEC)
f.rsn_pairwise = ProtoField.string("bcmevent.rsn.pairwise_cipher", "Pairwise Cipher")
f.rsn_akm_count = ProtoField.uint16("bcmevent.rsn.akm_count", "AKM Count", base.DEC)
f.rsn_akm = ProtoField.string("bcmevent.rsn.akm", "AKM Suite")
f.rsn_caps = ProtoField.uint16("bcmevent.rsn.capabilities", "RSN Capabilities", base.HEX)
f.wps_type = ProtoField.uint16("bcmevent.wps.attr_type", "WPS Attribute", base.HEX, WPS_ATTR_NAMES)
f.wps_len = ProtoField.uint16("bcmevent.wps.attr_len", "WPS Attribute Length", base.DEC)
f.wps_value = ProtoField.bytes("bcmevent.wps.value", "WPS Value")
f.wps_string = ProtoField.string("bcmevent.wps.string", "WPS String")
f.wps_version = ProtoField.string("bcmevent.wps.version", "WPS Version")
f.wps_state = ProtoField.uint8("bcmevent.wps.state", "WPS State", base.DEC,
    {[1]="Not Configured", [2]="Configured"})
f.wps_response = ProtoField.uint8("bcmevent.wps.response_type", "Response Type", base.DEC,
    {[0]="Enrollee Info", [1]="Enrollee Open 802.1X", [2]="Registrar", [3]="Access Point"})
f.wps_config_methods = ProtoField.string("bcmevent.wps.config_methods", "Config Methods")
f.wps_rf_bands = ProtoField.string("bcmevent.wps.rf_bands", "RF Bands")
f.wps_primary_device = ProtoField.string("bcmevent.wps.primary_device", "Primary Device Type")
f.wps_vendor_extension = ProtoField.string("bcmevent.wps.vendor_extension", "WFA Vendor Extension")

-- wl_event_rx_frame_data and 802.11 management frames
f.rx_version = ProtoField.uint16("bcmevent.rxmeta.version", "RX Metadata Version", base.DEC)
f.rx_len = ProtoField.uint16("bcmevent.rxmeta.length", "RX Metadata Length", base.DEC)
f.rx_chanspec = ProtoField.uint16("bcmevent.rxmeta.chanspec", "RX Chanspec", base.HEX)
f.rx_rssi = ProtoField.int32("bcmevent.rxmeta.rssi", "RX RSSI", base.UNIT_STRING, {" dBm"})
f.rx_mactime = ProtoField.uint32("bcmevent.rxmeta.mactime", "MAC Time", base.HEX)
f.rx_rate = ProtoField.uint32("bcmevent.rxmeta.rate", "RX Rate", base.HEX)
f.rx_core_rssi = ProtoField.int8("bcmevent.rxmeta.core_rssi", "Per-core RSSI", base.UNIT_STRING, {" dBm"})
f.mgmt_fc = ProtoField.uint16("bcmevent.mgmt.frame_control", "Frame Control", base.HEX)
f.mgmt_subtype = ProtoField.uint16("bcmevent.mgmt.subtype", "Subtype", base.DEC, MGMT_SUBTYPES, 0x00f0)
f.mgmt_duration = ProtoField.uint16("bcmevent.mgmt.duration", "Duration", base.DEC)
f.mgmt_da = ProtoField.ether("bcmevent.mgmt.da", "Destination")
f.mgmt_sa = ProtoField.ether("bcmevent.mgmt.sa", "Source")
f.mgmt_bssid = ProtoField.ether("bcmevent.mgmt.bssid", "BSSID")
f.mgmt_seq = ProtoField.uint16("bcmevent.mgmt.seq", "Sequence Control", base.HEX)
f.assoc_cap = ProtoField.uint16("bcmevent.mgmt.assoc.capability", "Capability", base.HEX)
f.assoc_listen = ProtoField.uint16("bcmevent.mgmt.assoc.listen_interval", "Listen Interval", base.DEC)
f.assoc_current_ap = ProtoField.ether("bcmevent.mgmt.assoc.current_ap", "Current AP")
f.auth_alg = ProtoField.uint16("bcmevent.mgmt.auth.algorithm", "Authentication Algorithm", base.DEC)
f.auth_seq = ProtoField.uint16("bcmevent.mgmt.auth.sequence", "Authentication Sequence", base.DEC)
f.auth_status = ProtoField.uint16("bcmevent.mgmt.auth.status", "Authentication Status", base.DEC)
f.reason_code = ProtoField.uint16("bcmevent.mgmt.reason", "Reason Code", base.DEC)
f.action_cat = ProtoField.uint8("bcmevent.mgmt.action.category", "Action Category", base.DEC,
    ACTION_CATEGORIES)
f.action_code = ProtoField.uint8("bcmevent.mgmt.action.code", "Action Code", base.DEC)

-- wl_event_data_if
f.if_ifidx = ProtoField.uint8("bcmevent.if_event.ifidx", "Interface Index", base.DEC)
f.if_opcode = ProtoField.uint8("bcmevent.if_event.opcode", "Opcode", base.DEC,
    {[1]="ADD", [2]="DEL", [3]="CHANGE", [4]="BSSCFG_UP", [5]="BSSCFG_DOWN"})
f.if_flags = ProtoField.uint8("bcmevent.if_event.flags", "Interface Flags", base.HEX)
f.if_bssidx = ProtoField.uint8("bcmevent.if_event.bssidx", "BSS Config Index", base.DEC)
f.if_role = ProtoField.uint8("bcmevent.if_event.role", "Role", base.DEC, {
    [0]="STA", [1]="AP", [2]="WDS", [3]="P2P_GO", [4]="P2P_CLIENT", [7]="AWDL", [8]="IBSS",
    [9]="NAN", [10]="MESH"
})
f.if_mld_unit = ProtoField.uint8("bcmevent.if_event.mld_unit", "MLD Unit", base.DEC)
f.if_nlinks = ProtoField.uint8("bcmevent.if_event.nlinks", "Number of Links", base.DEC)
f.if_peer = ProtoField.ether("bcmevent.if_event.peer_addr", "Peer Address")

-- wl_event_change_chan_t and wlc_cac_event_t (HND)
f.cc_version = ProtoField.uint16("bcmevent.chan_change.version", "Channel Change Version", base.DEC)
f.cc_length = ProtoField.uint16("bcmevent.chan_change.length", "Channel Change Length", base.DEC)
f.cc_reason = ProtoField.uint32("bcmevent.chan_change.reason", "Channel Change Reason", base.DEC,
    CHAN_CHANGE_REASONS)
f.cc_target = ProtoField.uint16("bcmevent.chan_change.target_chanspec", "Target Chanspec", base.HEX)
f.cc_current = ProtoField.uint16("bcmevent.chan_change.cur_chanspec", "Current Chanspec", base.HEX)
f.cac_version = ProtoField.uint16("bcmevent.cac.version", "CAC Version", base.DEC)
f.cac_length = ProtoField.uint16("bcmevent.cac.length", "CAC Length", base.DEC)
f.cac_type = ProtoField.uint16("bcmevent.cac.type", "CAC Type", base.DEC, {[1]="DFS_STATUS_ALL"})
f.cac_core = ProtoField.uint8("bcmevent.cac.scan_core", "Scan Core", base.DEC)
f.cac_status_version = ProtoField.uint16("bcmevent.cac.status_version", "Status Version", base.DEC)
f.cac_count = ProtoField.uint16("bcmevent.cac.num_sub_status", "Sub-status Count", base.DEC)
f.cac_state = ProtoField.uint32("bcmevent.cac.state", "State", base.DEC, CAC_STATES)
f.cac_duration = ProtoField.uint32("bcmevent.cac.duration", "Time in State", base.UNIT_STRING, {" ms"})
f.cac_chanspec = ProtoField.uint16("bcmevent.cac.chanspec", "Chanspec", base.HEX)
f.cac_cleared = ProtoField.uint16("bcmevent.cac.chanspec_last_cleared", "Last Cleared Chanspec", base.HEX)
f.cac_subtype = ProtoField.uint16("bcmevent.cac.sub_type", "Sub-type", base.DEC)

-- wl_cevent_t (HND)
f.ce_version = ProtoField.uint16("bcmevent.cevent.version", "CEVENT Version", base.DEC)
f.ce_length = ProtoField.uint16("bcmevent.cevent.length", "CEVENT Length", base.DEC)
f.ce_type = ProtoField.uint16("bcmevent.cevent.type", "CEVENT Type", base.DEC, CEVENT_TYPE_NAMES)
f.ce_data_offset = ProtoField.uint16("bcmevent.cevent.data_offset", "CEVENT Data Offset", base.DEC)
f.ce_subtype = ProtoField.uint32("bcmevent.cevent.subtype", "CEVENT Subtype", base.DEC,
    CEVENT_SUBTYPE_NAMES)
f.ce_msgtype = ProtoField.uint32("bcmevent.cevent.msgtype", "CEVENT Message Type", base.DEC)
f.ce_flags = ProtoField.uint32("bcmevent.cevent.flags", "CEVENT Flags", base.HEX)
f.ce_eth_hdr = ProtoField.bool("bcmevent.cevent.flags.eth_header", "Ethernet Header", 32, nil, 0x00000001)
f.ce_tx_status = ProtoField.uint32("bcmevent.cevent.flags.tx_status", "TX Status", base.DEC,
    {[0]="QUEUED", [1]="SUCCESS", [2]="FAIL", [3]="READY"}, 0x000000ff)
f.ce_rx = ProtoField.bool("bcmevent.cevent.flags.rx", "RX", 32, nil, 0x40000000)
f.ce_tx = ProtoField.bool("bcmevent.cevent.flags.tx", "TX", 32, nil, 0x80000000)
f.ce_timestamp = ProtoField.uint64("bcmevent.cevent.timestamp", "CEVENT Timestamp", base.UNIT_STRING,
    {" ms"})

-- wlc_rlm_event_t (MACDBG ratelinkmem)
f.rlm_version = ProtoField.uint16("bcmevent.macdbg.rlm.version", "Ratelinkmem Version", base.DEC)
f.rlm_length = ProtoField.uint16("bcmevent.macdbg.rlm.length", "Ratelinkmem Length", base.DEC)
f.rlm_action = ProtoField.uint16("bcmevent.macdbg.rlm.action", "Ratelinkmem Action", base.DEC)
f.rlm_entry = ProtoField.uint16("bcmevent.macdbg.rlm.entry", "Ratelinkmem Entry", base.DEC)

-- wlc_wsec_event_t (DHD WLC_E_WSEC)
f.wsec_version = ProtoField.uint16("bcmevent.wsec.version", "WSEC Version", base.DEC)
f.wsec_length = ProtoField.uint16("bcmevent.wsec.length", "WSEC Length", base.DEC)
f.wsec_type = ProtoField.uint16("bcmevent.wsec.type", "WSEC Event Type", base.DEC,
    {[1]="PTK_PN_SYNC_ERROR"})
f.wsec_tsf_low = ProtoField.uint32("bcmevent.wsec.tsf_low", "TSF Low", base.HEX)
f.wsec_tsf_high = ProtoField.uint32("bcmevent.wsec.tsf_high", "TSF High", base.HEX)
f.wsec_key_id = ProtoField.uint8("bcmevent.wsec.key_id", "Key ID", base.DEC)
f.wsec_tid = ProtoField.uint8("bcmevent.wsec.tid", "TID", base.DEC)
f.wsec_rx_seqn = ProtoField.uint16("bcmevent.wsec.rx_seqn", "RX Sequence", base.DEC)
f.wsec_pn_low = ProtoField.uint16("bcmevent.wsec.pn_low", "PN Low", base.HEX)
f.wsec_pn_high = ProtoField.uint32("bcmevent.wsec.pn_high", "PN High", base.HEX)
f.wsec_key_idx = ProtoField.uint16("bcmevent.wsec.key_idx", "Key Index", base.DEC)
f.wsec_rx_pn_low = ProtoField.uint16("bcmevent.wsec.rx_pn_low", "RX PN Low", base.HEX)
f.wsec_rx_pn_high = ProtoField.uint32("bcmevent.wsec.rx_pn_high", "RX PN High", base.HEX)
f.wsec_span_time = ProtoField.uint32("bcmevent.wsec.span_time", "Replay Span Time", base.DEC)
f.wsec_span_pkts = ProtoField.uint32("bcmevent.wsec.span_pkts", "Replay Span Packets", base.DEC)

-- wl_invalid_ie_event_t
f.inv_version = ProtoField.uint16("bcmevent.invalid_ie.version", "Invalid IE Version", base.DEC)
f.inv_length = ProtoField.uint16("bcmevent.invalid_ie.length", "Invalid IE Copy Length", base.DEC)
f.inv_type = ProtoField.uint16("bcmevent.invalid_ie.frame_type", "Containing Frame Type/Subtype", base.HEX)
f.inv_error = ProtoField.uint16("bcmevent.invalid_ie.error", "IE Error", base.DEC, {[1]="OUT_OF_RANGE"})

-- bcm_dngl_event_msg_t
f.dngl_version = ProtoField.uint16("bcmevent.dngl.version", "Dongle Event Version", base.DEC)
f.dngl_type = ProtoField.uint16("bcmevent.dngl.type", "Dongle Event Type", base.DEC, DNGL_EVENT_NAMES)
f.dngl_datalen = ProtoField.uint16("bcmevent.dngl.data_len", "Dongle Event Data Length", base.DEC)

-- A length that runs past the frame is malformed data, as in Wireshark's own
-- dissectors. A capture cut short by the snapshot length is not.
local ef = {
    truncated = ProtoExpert.new("bcmevent.truncated", "Length runs past the data",
        expert.group.MALFORMED, expert.severity.ERROR),
    invalid = ProtoExpert.new("bcmevent.invalid", "Invalid length or offset",
        expert.group.MALFORMED, expert.severity.ERROR)
}
bcm.experts = {ef.truncated, ef.invalid}

-- Set per packet when the event data is shorter than its declared length,
-- because of the snapshot length or an overrun already flagged on the length
-- field. Structures inside it that end early then get a plain note.
local cut = false

local function truncated(tree, range, text)
    if cut then
        tree:add(range, text):set_generated()
    else
        tree:add_tvb_expert_info(ef.truncated, range, text)
    end
end

-- Compare a declared data length with the frame, flag an overrun, and return
-- how much of it the capture holds.
local function data_present(item, declared, reported, captured)
    if declared > reported then
        item:add_proto_expert_info(ef.truncated,
            string.format("Data length %u exceeds the %u bytes in the frame", declared, reported))
    elseif declared > captured then
        item:append_text(string.format(" (%u captured)", captured))
    end
    return math.min(declared, captured)
end

local function trim_nul(s)
    local z = string.find(s, "\0", 1, true)
    if z then return string.sub(s, 1, z - 1) end
    return s
end

local function macstr(tvb, off)
    local a = {}
    for i = 0, 5 do a[#a+1] = string.format("%02x", tvb(off+i,1):uint()) end
    return table.concat(a, ":")
end

local function oui_string(tvb, off)
    return string.format("%02x:%02x:%02x", tvb(off,1):uint(), tvb(off+1,1):uint(), tvb(off+2,1):uint())
end

local function has_bit(v, bit)
    return math.floor(v / bit) % 2 == 1
end

local function u16x(tvb, off, le)
    return le and tvb(off,2):le_uint() or tvb(off,2):uint()
end

local function u32x(tvb, off, le)
    return le and tvb(off,4):le_uint() or tvb(off,4):uint()
end

local function add_x(tree, field, range, le)
    if le then return tree:add_le(field, range) end
    return tree:add(field, range)
end

-- Byte order of a struct that starts with a 16-bit version of 1.
local function version1_order(tvb, off)
    if tvb(off,2):le_uint() == 1 then return true end
    if tvb(off,2):uint() == 1 then return false end
    return nil
end

-- Broadcom chanspec (bcmwifi_channels.h): bits 0-7 channel, 8-10 control
-- sideband, 11-13 bandwidth, 14-15 band. Bandwidth codes 2-5 (20-160 MHz)
-- mean the same everywhere; the others depend on the firmware:
--   0  5 MHz, or 320 MHz in 6 GHz (DHD: channel id in bits 0-2, sideband 7-10)
--   1  10 MHz, or 160+160 MHz (160 MHz segment ids in bits 0-3 and 4-7)
--   6  80+80 MHz (80 MHz segment ids in bits 0-3 and 4-7), or 320 MHz in
--      6 GHz on newer HND (channel index 0-5 in bits 0-5, sideband 6-10)
--   7  240 MHz in 6 GHz (DHD: channel id in bits 0-1, sideband 7-10)
-- Firmware that reports WLC_GET_VERSION 1 uses the older D11N layout.
local CHANSPEC_BAND = {[0]="2.4 GHz", [1]="6 GHz", [2]="4 GHz", [3]="5 GHz"}
local CHANSPEC_BW = {[2]=20, [3]=40, [4]=80, [5]=160}
local CHANSPEC_EDGE = {[40]=2, [80]=6, [160]=14, [240]=22, [320]=30}
local CH80_5G = {[0]=42, 58, 106, 122, 138, 155, 171}
local CH160_5G = {[0]=50, 114, 163}
local CH320_DHD = {[0]=31, [1]=95, [2]=159, [4]=63, [5]=127, [6]=191}

local function segment_center(bandcode, id, width)
    if bandcode == 3 then return (width == 80 and CH80_5G or CH160_5G)[id] end
    if bandcode == 1 and width == 80 and id < 14 then return 7 + 16 * id end
    if bandcode == 1 and width == 160 and id < 7 then return 15 + 32 * id end
    return nil
end

-- Sideband letters, most significant bit first: 80 MHz sideband 1 is "LU".
local function sideband_letters(sb, nbits)
    local s = ""
    for i = nbits - 1, 0, -1 do
        s = s .. (math.floor(sb / 2^i) % 2 == 1 and "U" or "L")
    end
    return s
end

local function decode_d11n_chanspec(cs)
    local ch = cs % 256
    local sb = math.floor(cs / 0x100) % 4
    local bwcode = math.floor(cs / 0x400) % 4
    local c = {
        chan = ch, center = ch, primary = ch, bwcode = bwcode,
        bw = ({[1]=10, [2]=20, [3]=40})[bwcode],
        band = ({[1]="5 GHz", [2]="2.4 GHz"})[math.floor(cs / 0x1000) % 4] or "Unknown band"
    }
    if c.bw == 40 and sb == 1 then c.primary, c.sideband = ch - 2, "L"
    elseif c.bw == 40 and sb == 2 then c.primary, c.sideband = ch + 2, "U" end
    if c.primary < 1 or c.primary > 255 then c.primary = nil end
    return c
end

local function decode_chanspec(cs)
    local ch = cs % 256
    local sb = math.floor(cs / 0x100) % 8
    local bwcode = math.floor(cs / 0x800) % 8
    local bandcode = math.floor(cs / 0x4000) % 4
    -- D11AC and later never put a channel above 14 or more than 40 MHz in 2.4 GHz.
    if bandcode == 0 and (ch > 14 or bwcode >= 4) then return decode_d11n_chanspec(cs) end

    local c = {chan = ch, band = CHANSPEC_BAND[bandcode], bwcode = bwcode}
    if CHANSPEC_BW[bwcode] then
        c.bw, c.center, c.primary = CHANSPEC_BW[bwcode], ch, ch
        if c.bw > 20 then
            local nbits = bwcode - 2
            if sb < 2^nbits then
                c.primary = ch - CHANSPEC_EDGE[c.bw] + 4 * sb
                c.sideband = sideband_letters(sb, nbits)
            else
                c.primary = nil
            end
        end
    elseif bandcode == 1 and (bwcode == 0 or bwcode == 7 or (bwcode == 6 and cs % 64 < 6)) then
        local s
        if bwcode == 6 then
            c.bw, c.hnd, s = 320, true, math.floor(cs / 0x40) % 32
            c.center = 31 + 32 * (cs % 64)
        elseif bwcode == 0 then
            c.bw, s, c.center = 320, math.floor(cs / 0x80) % 16, CH320_DHD[cs % 8]
        else
            c.bw, s, c.center = 240, math.floor(cs / 0x80) % 16, 23 + 48 * (cs % 4)
        end
        if c.center and s < c.bw / 20 then
            c.primary = c.center - CHANSPEC_EDGE[c.bw] + 4 * s
            if c.bw == 320 then c.sideband = sideband_letters(s, 4) end
        end
    elseif bwcode == 1 or bwcode == 6 then
        local w = bwcode == 6 and 80 or 160
        local seg0 = segment_center(bandcode, ch % 16, w)
        local seg1 = segment_center(bandcode, math.floor(ch / 16), w)
        if seg0 and seg1 then
            c.bw, c.split, c.center, c.seg1 = 2 * w, w .. "+" .. w, seg0, seg1
            if sb < w / 20 then c.primary = seg0 - CHANSPEC_EDGE[w] + 4 * sb end
        elseif bwcode == 1 then
            c.bw, c.center, c.primary = 10, ch, ch
        end
    elseif bwcode == 0 then
        c.bw, c.center, c.primary = 5, ch, ch
    end
    if c.primary and (c.primary < 1 or c.primary > 255) then c.primary = nil end
    return c
end

local function chanspec_text(c)
    -- Without a known bandwidth the low bits are not a channel number.
    if not c.bw then return string.format("%s, bandwidth code %u", c.band, c.bwcode) end
    local ch = c.primary or c.center
    local s = ch and string.format("%s, channel %u", c.band, ch) or c.band
    if c.split then
        s = s .. string.format(", %s MHz, centers %u and %u", c.split, c.center, c.seg1)
    else
        s = s .. string.format(", %u MHz", c.bw)
        if c.bw > 20 and c.center then s = s .. string.format(", center %u", c.center) end
    end
    -- In 6 GHz, bandwidth code 6 is 320 MHz on newer HND and 80+80 elsewhere.
    if c.hnd then s = s .. " on newer HND" end
    return s
end

-- Returns the item and the decoded chanspec; 0 means no channel.
local function add_chanspec(tree, field, range, le)
    local item = add_x(tree, field, range, le)
    local v = le and range:le_uint() or range:uint()
    if v == 0 then
        item:append_text(" (none)")
        return item, nil
    end
    local c = decode_chanspec(v)
    item:append_text(" (" .. chanspec_text(c) .. ")")
    return item, c
end

local function suite_name(tvb, off, names)
    local oui = oui_string(tvb, off)
    local typ = tvb(off+3,1):uint()
    local name
    if oui == "00:0f:ac" then
        name = names[typ]
    elseif oui == "50:6f:9a" and names == AKM_NAMES and typ == 2 then
        name = "DPP"
    end
    return oui .. " " .. (name or ("type " .. typ))
end

local function rates_string(tvb, off, len)
    local a = {}
    for i = 0, len - 1 do
        local v = tvb(off+i,1):uint()
        local half = v % 128
        local r = half % 2 == 0 and string.format("%d", half / 2) or string.format("%d.5", (half - 1) / 2)
        a[#a+1] = r .. (v >= 128 and "(B)" or "")
    end
    return table.concat(a, ", ") .. " [Mbit/sec]"
end

local WPS_CONFIG_BITS = {
    {0x0001, "USB Flash Drive"}, {0x0002, "Ethernet"}, {0x0004, "Label"},
    {0x0010, "External NFC Token"}, {0x0020, "Integrated NFC Token"},
    {0x0040, "NFC Interface"}, {0x0100, "Keypad"}
}

local function decode_wps_config_methods(v)
    local out = {}
    for _, x in ipairs(WPS_CONFIG_BITS) do
        if has_bit(v, x[1]) then out[#out+1] = x[2] end
    end
    if has_bit(v, 0x2000) or has_bit(v, 0x4000) then
        if has_bit(v, 0x2000) then out[#out+1] = "Virtual Display" end
        if has_bit(v, 0x4000) then out[#out+1] = "Physical Display" end
    elseif has_bit(v, 0x0008) then
        out[#out+1] = "Display"
    end
    if has_bit(v, 0x0200) or has_bit(v, 0x0400) then
        if has_bit(v, 0x0200) then out[#out+1] = "Virtual Push Button" end
        if has_bit(v, 0x0400) then out[#out+1] = "Physical Push Button" end
    elseif has_bit(v, 0x0080) then
        out[#out+1] = "Push Button"
    end
    return #out > 0 and table.concat(out, ", ") or string.format("Unknown (0x%04x)", v)
end

local function decode_wps_rf_bands(v)
    local out = {}
    if has_bit(v, 0x01) then out[#out+1] = "2.4 GHz" end
    if has_bit(v, 0x02) then out[#out+1] = "5 GHz" end
    if has_bit(v, 0x04) then out[#out+1] = "60 GHz" end
    return #out > 0 and table.concat(out, ", ") or string.format("Unknown (0x%02x)", v)
end

local WPS_DEVICE_CATEGORY = {
    [1]="Computer", [2]="Input Device", [3]="Printer/Scanner", [4]="Camera",
    [5]="Storage", [6]="Network Infrastructure", [7]="Display", [8]="Multimedia",
    [9]="Gaming", [10]="Telephone", [11]="Audio"
}
local WPS_NETWORK_SUBCATEGORY = {[1]="Access Point", [2]="Router", [3]="Switch", [4]="Gateway", [5]="Bridge"}

local function decode_wps_primary_device(tvb, off)
    local cat = tvb(off,2):uint()
    local oui = string.format("%08x", tvb(off+2,4):uint())
    local sub = tvb(off+6,2):uint()
    local cname = WPS_DEVICE_CATEGORY[cat] or ("Category " .. cat)
    local sname = (cat == 6 and WPS_NETWORK_SUBCATEGORY[sub]) or ("Subcategory " .. sub)
    return string.format("%s / %s (%u-%s-%u)", cname, sname, cat, oui, sub)
end

local function decode_wfa_vendor_extension(tvb, off, len)
    if len < 3 or oui_string(tvb, off) ~= "00:37:2a" then return nil end
    local out = {"WFA OUI 00:37:2a"}
    local p, stop = off + 3, off + len
    while p + 2 <= stop do
        local id = tvb(p,1):uint()
        local l = tvb(p+1,1):uint()
        if p + 2 + l > stop then break end
        if id == 0 and l == 1 then
            local v = tvb(p+2,1):uint()
            out[#out+1] = string.format("Version2 %u.%u", math.floor(v / 16), v % 16)
        else
            out[#out+1] = string.format("subelement %u (%u bytes)", id, l)
        end
        p = p + 2 + l
    end
    return table.concat(out, "; ")
end

local WPS_STRING_ATTRS = {[0x1011]=true, [0x1021]=true, [0x1023]=true, [0x1024]=true, [0x1042]=true}

local function parse_wps(tvb, off, len, tree)
    local p, stop = off, off + len
    while p + 4 <= stop do
        local typ = tvb(p,2):uint()
        local alen = tvb(p+2,2):uint()
        if p + 4 + alen > stop then
            truncated(tree, tvb(p, stop - p),
                string.format("WPS attribute claims %u bytes, %u left", alen, stop - p - 4))
            return
        end
        local at = tree:add(tvb(p, 4 + alen), WPS_ATTR_NAMES[typ] or string.format("Attribute 0x%04x", typ))
        at:add(f.wps_type, tvb(p,2))
        at:add(f.wps_len, tvb(p+2,2))
        local vo = p + 4
        if alen == 0 then
            at:append_text(" (empty)")
        elseif WPS_STRING_ATTRS[typ] then
            at:add(f.wps_string, tvb(vo,alen), trim_nul(tvb(vo,alen):string(ENC_UTF_8)))
        elseif typ == 0x104a and alen == 1 then
            local v = tvb(vo,1):uint()
            at:add(f.wps_version, tvb(vo,1), string.format("%u.%u", math.floor(v / 16), v % 16))
        elseif typ == 0x1044 and alen == 1 then
            at:add(f.wps_state, tvb(vo,1))
        elseif typ == 0x103b and alen == 1 then
            at:add(f.wps_response, tvb(vo,1))
        elseif typ == 0x1008 and alen == 2 then
            at:add(f.wps_config_methods, tvb(vo,2), decode_wps_config_methods(tvb(vo,2):uint()))
        elseif typ == 0x103c and alen == 1 then
            at:add(f.wps_rf_bands, tvb(vo,1), decode_wps_rf_bands(tvb(vo,1):uint()))
        elseif typ == 0x1054 and alen == 8 then
            at:add(f.wps_primary_device, tvb(vo,8), decode_wps_primary_device(tvb, vo))
        elseif typ == 0x1049 and decode_wfa_vendor_extension(tvb, vo, alen) then
            at:add(f.wps_vendor_extension, tvb(vo,alen), decode_wfa_vendor_extension(tvb, vo, alen))
        else
            at:add(f.wps_value, tvb(vo,alen))
        end
        p = p + 4 + alen
    end
end

local function parse_rsn(tvb, off, len, tree)
    -- Every field after the version is optional, so stop quietly where the element ends.
    local p, stop = off, off + len
    if p + 2 > stop then return end
    tree:add_le(f.rsn_version, tvb(p,2)); p = p + 2
    if p + 4 > stop then return end
    tree:add(f.rsn_group, tvb(p,4), suite_name(tvb, p, CIPHER_NAMES)); p = p + 4
    if p + 2 > stop then return end
    local n = tvb(p,2):le_uint()
    tree:add_le(f.rsn_pairwise_count, tvb(p,2)); p = p + 2
    for _ = 1, n do
        if p + 4 > stop then return end
        tree:add(f.rsn_pairwise, tvb(p,4), suite_name(tvb, p, CIPHER_NAMES)); p = p + 4
    end
    if p + 2 > stop then return end
    n = tvb(p,2):le_uint()
    tree:add_le(f.rsn_akm_count, tvb(p,2)); p = p + 2
    for _ = 1, n do
        if p + 4 > stop then return end
        tree:add(f.rsn_akm, tvb(p,4), suite_name(tvb, p, AKM_NAMES)); p = p + 4
    end
    if p + 2 <= stop then tree:add_le(f.rsn_caps, tvb(p,2)) end
end

local VENDOR_IE_NAMES = {
    ["00:50:f2 1"]="WPA", ["00:50:f2 2"]="WMM/WME", ["00:50:f2 4"]="WPS"
}

local function parse_vendor_ie(tvb, off, len, tree)
    if len < 3 then return end
    tree:add(f.vendor_oui, tvb(off,3))
    local oui = oui_string(tvb, off)
    if oui == "00:10:18" then tree:append_text(": Broadcom") end
    if len < 4 then return end
    local typ = tvb(off+3,1):uint()
    tree:add(f.vendor_type, tvb(off+3,1))
    local name = VENDOR_IE_NAMES[oui .. " " .. typ]
    if name then tree:append_text(": " .. name) end
    if name == "WPS" then parse_wps(tvb, off + 4, len - 4, tree) end
end

local function parse_ies(tvb, off, len, tree)
    local p, stop = off, off + len
    local count = 0
    while p + 2 <= stop do
        local id = tvb(p,1):uint()
        local ilen = tvb(p+1,1):uint()
        if p + 2 + ilen > stop then
            truncated(tree, tvb(p, stop - p),
                string.format("Element %u claims %u bytes, %u left", id, ilen, stop - p - 2))
            return
        end
        count = count + 1
        if count > 512 then
            tree:add(tvb(p, stop - p), string.format("%u more bytes not decoded (element limit)", stop - p))
                :set_generated()
            return
        end
        local it = tree:add(tvb(p, 2 + ilen), IE_NAMES[id] or ("Element " .. id))
        it:add(f.ie_id, tvb(p,1))
        it:add(f.ie_len, tvb(p+1,1))
        local body = p + 2
        if id == 0 then
            local ssid = trim_nul(tvb(body,ilen):string(ENC_UTF_8))
            it:add(f.ie_ssid, tvb(body,ilen), ssid)
            if ssid ~= "" then it:append_text(": " .. ssid) end
        elseif (id == 1 or id == 50) and ilen > 0 then
            it:add(f.ie_rates, tvb(body,ilen), rates_string(tvb, body, ilen))
        elseif id == 3 and ilen >= 1 then
            it:add(f.ie_channel, tvb(body,1))
        elseif id == 7 and ilen >= 3 then
            it:add(f.ie_country_code, tvb(body,2), tvb(body,2):string())
            it:add(f.ie_country_env, tvb(body+2,1))
        elseif id == 48 then
            parse_rsn(tvb, body, ilen, it)
        elseif id == 221 then
            parse_vendor_ie(tvb, body, ilen, it)
        elseif id == 255 and ilen >= 1 then
            it:add(f.ie_ext_id, tvb(body,1))
            local extname = EXT_IE_NAMES[tvb(body,1):uint()]
            if extname then it:append_text(": " .. extname) end
        end
        p = p + 2 + ilen
    end
end

-- wl_event_rx_frame_data, network order. bcmdhd takes the frame from after
-- the 24-byte v2 struct and never reads its length field.
local function parse_rxmeta(tvb, off, len, tree)
    if len < 2 then return 0 end
    local ver = tvb(off,2):uint()
    local size = (ver == 1 and 16) or (ver == 2 and 24) or nil
    if not size or len < size then return 0 end
    local rt = tree:add(tvb(off,size), "RX Frame Metadata v" .. ver)
    rt:add(f.rx_version, tvb(off,2))
    local q = off + 4
    if ver == 2 then
        rt:add(f.rx_len, tvb(off+2,2))
        add_chanspec(rt, f.rx_chanspec, tvb(off+4,2), false)
        q = off + 8
    else
        add_chanspec(rt, f.rx_chanspec, tvb(off+2,2), false)
    end
    rt:add(f.rx_rssi, tvb(q,4))
    rt:add(f.rx_mactime, tvb(q+4,4))
    rt:add(f.rx_rate, tvb(q+8,4))
    if ver == 2 then
        for i = 0, 3 do
            rt:add(f.rx_core_rssi, tvb(off+20+i,1)):append_text(" (core " .. i .. ")")
        end
    end
    return size
end

local function looks_like_mgmt(tvb, off, len)
    if len < 24 then return false end
    local fc = tvb(off,2):le_uint()
    return fc % 16 == 0 and MGMT_SUBTYPES[math.floor(fc / 16) % 16] ~= nil
end

local function parse_action_body(tvb, off, len, tree)
    if len < 2 then
        tree:add(f.payload, tvb(off,len))
        return nil
    end
    local cat = tvb(off,1):uint()
    local at = tree:add(tvb(off,len), "802.11 Action")
    at:add(f.action_cat, tvb(off,1))
    at:add(f.action_code, tvb(off+1,1))
    local cname = ACTION_CATEGORIES[cat] or ("category " .. cat)
    at:append_text(": " .. cname)
    return "Action, " .. cname
end

local function parse_mgmt(tvb, off, len, tree)
    local fc = tvb(off,2):le_uint()
    local subtype = math.floor(fc / 16) % 16
    local sname = MGMT_SUBTYPES[subtype]
    local mt = tree:add(tvb(off,len), "802.11 Management Frame: " .. sname)
    mt:add_le(f.mgmt_fc, tvb(off,2)):add_le(f.mgmt_subtype, tvb(off,2))
    mt:add_le(f.mgmt_duration, tvb(off+2,2))
    mt:add(f.mgmt_da, tvb(off+4,6))
    mt:add(f.mgmt_sa, tvb(off+10,6))
    mt:add(f.mgmt_bssid, tvb(off+16,6))
    mt:add_le(f.mgmt_seq, tvb(off+22,2))
    local p, left = off + 24, len - 24
    if subtype == 0 and left >= 4 then
        mt:add_le(f.assoc_cap, tvb(p,2))
        mt:add_le(f.assoc_listen, tvb(p+2,2))
        parse_ies(tvb, p + 4, left - 4, mt)
    elseif subtype == 2 and left >= 10 then
        mt:add_le(f.assoc_cap, tvb(p,2))
        mt:add_le(f.assoc_listen, tvb(p+2,2))
        mt:add(f.assoc_current_ap, tvb(p+4,6))
        parse_ies(tvb, p + 10, left - 10, mt)
    elseif subtype == 11 and left >= 6 then
        local alg = tvb(p,2):le_uint()
        mt:add_le(f.auth_alg, tvb(p,2))
        mt:add_le(f.auth_seq, tvb(p+2,2))
        mt:add_le(f.auth_status, tvb(p+4,2))
        -- SAE (3) carries its own fields here; the other algorithms carry elements.
        if left > 6 then
            if alg == 3 then mt:add(f.payload, tvb(p+6,left-6)) else parse_ies(tvb, p + 6, left - 6, mt) end
        end
    elseif (subtype == 10 or subtype == 12) and left >= 2 then
        mt:add_le(f.reason_code, tvb(p,2))
    elseif subtype == 13 and left >= 2 then
        parse_action_body(tvb, p, left, mt)
    elseif subtype == 4 then
        parse_ies(tvb, p, left, mt)
    elseif (subtype == 5 or subtype == 8) and left >= 12 then
        -- timestamp (8), beacon interval (2), capability (2), then elements
        parse_ies(tvb, p + 12, left - 12, mt)
    end
    return sname
end

local function parse_escan(tvb, off, len, tree)
    if len < 12 then
        tree:add(f.payload, tvb(off,len))
        return nil
    end
    local buflen = tvb(off,4):le_uint()
    local count = tvb(off+10,2):le_uint()
    local et = tree:add(tvb(off,len), "Enhanced Scan Result")
    et:add_le(f.es_buflen, tvb(off,4))
    et:add_le(f.es_version, tvb(off+4,4))
    et:add_le(f.es_sync, tvb(off+8,2))
    et:add_le(f.es_count, tvb(off+10,2))
    et:append_text(string.format(", %u BSS", count))
    if buflen < 12 then
        et:add_tvb_expert_info(ef.invalid, tvb(off,4),
            string.format("Scan buffer length %u is shorter than its 12-byte header", buflen))
        return nil
    end

    local p, stop = off + 12, off + math.min(len, buflen)
    local summary
    for i = 1, count do
        if p + 124 > stop then
            if p < stop then
                truncated(et, tvb(p, stop - p), "Truncated BSS record")
            else
                truncated(et, tvb(off+10,2), string.format("BSS count is %u, but only %u records fit", count, i - 1))
            end
            break
        end
        local rec_len = tvb(p+4,4):le_uint()
        if rec_len < 124 then
            et:add_tvb_expert_info(ef.invalid, tvb(p+4,4),
                string.format("BSS record length %u is below the 124-byte minimum", rec_len))
            break
        end
        -- A record that runs past the data still has its 124-byte fixed part.
        local avail = math.min(rec_len, stop - p)
        local bt = et:add(tvb(p,avail), "BSS " .. i)
        bt:add_le(f.bss_version, tvb(p,4))
        bt:add_le(f.bss_length, tvb(p+4,4))
        bt:add(f.bss_bssid, tvb(p+8,6))
        bt:add_le(f.bss_beacon, tvb(p+14,2))
        bt:add_le(f.bss_cap, tvb(p+16,2))
        bt:add(f.bss_ssidlen, tvb(p+18,1))
        local slen = math.min(tvb(p+18,1):uint(), 32)
        local ssid = ""
        if slen > 0 then
            ssid = trim_nul(tvb(p+19,slen):string(ENC_UTF_8))
            bt:add(f.bss_ssid, tvb(p+19,slen), ssid)
        end
        bt:add_le(f.bss_rates_count, tvb(p+52,4))
        local ct, c = add_chanspec(bt, f.bss_chanspec, tvb(p+72,2), true)
        if c then
            ct:add(f.bss_band, tvb(p+72,2), c.band):set_generated()
            if c.bw then ct:add(f.bss_bandwidth, tvb(p+72,2), c.bw):set_generated() end
            if c.center then ct:add(f.bss_center_channel, tvb(p+72,2), c.center):set_generated() end
            if c.primary then ct:add(f.bss_primary_channel, tvb(p+72,2), c.primary):set_generated() end
            if c.sideband then ct:add(f.bss_sideband, tvb(p+72,2), c.sideband):set_generated() end
        end
        bt:add_le(f.bss_atim, tvb(p+74,2))
        bt:add(f.bss_dtim, tvb(p+76,1))
        local rssi = tvb(p+78,2):le_int()
        bt:add_le(f.bss_rssi, tvb(p+78,2))
        bt:add(f.bss_noise, tvb(p+80,1))
        bt:add(f.bss_ncap, tvb(p+81,1))
        bt:add_le(f.bss_nbsscap, tvb(p+84,4))
        local ctl = tvb(p+88,1):uint()
        bt:add(f.bss_ctl, tvb(p+88,1))
        bt:add_le(f.bss_vht_rx, tvb(p+92,2))
        bt:add_le(f.bss_vht_tx, tvb(p+94,2))
        bt:add(f.bss_flags, tvb(p+96,1))
        bt:add(f.bss_vhtcap, tvb(p+97,1))
        local ieoff = tvb(p+116,2):le_uint()
        local ielen = tvb(p+120,4):le_uint()
        bt:add_le(f.bss_ieoff, tvb(p+116,2))
        bt:add_le(f.bss_ielen, tvb(p+120,4))
        if avail >= 126 then bt:add_le(f.bss_snr, tvb(p+124,2)) end

        local name = ssid ~= "" and ssid or "<hidden>"
        bt:append_text(string.format(": %s, channel %u, %d dBm", name, ctl, rssi))
        summary = summary or string.format("%s %s ch %u %d dBm", name, macstr(tvb, p + 8), ctl, rssi)

        -- Newer firmware extends wl_bss_info_t, so ie_offset is authoritative.
        if ielen > 0 then
            if ieoff >= 124 and ieoff + ielen <= rec_len then
                local n = math.min(ielen, avail - ieoff)
                if n > 0 then
                    parse_ies(tvb, p + ieoff, n, bt:add(tvb(p+ieoff,n), "802.11 Information Elements"))
                end
            else
                bt:add_tvb_expert_info(ef.invalid, tvb(p+116,8),
                    string.format("Elements at offset %u, length %u do not fit the %u-byte record",
                        ieoff, ielen, rec_len))
            end
        end
        if avail < rec_len then
            truncated(et, tvb(p, avail), string.format("BSS record length %u runs past the data", rec_len))
            break
        end
        p = p + rec_len
    end
    if summary and count > 1 then summary = summary .. string.format(" (+%u)", count - 1) end
    return summary
end

local function parse_if_event(tvb, off, len, tree)
    if len < 5 then return false end
    -- 5 bytes on FullMAC. HND adds the peer address (11 bytes); its MLO
    -- builds put mld_unit and nlinks in front of it (13 bytes).
    local size = (len >= 13 and 13) or (len >= 11 and 11) or 5
    local t = tree:add(tvb(off,size), "Interface Change")
    t:add(f.if_ifidx, tvb(off,1))
    t:add(f.if_opcode, tvb(off+1,1))
    t:add(f.if_flags, tvb(off+2,1))
    t:add(f.if_bssidx, tvb(off+3,1))
    t:add(f.if_role, tvb(off+4,1))
    if size == 13 then
        t:add(f.if_mld_unit, tvb(off+5,1))
        t:add(f.if_nlinks, tvb(off+6,1))
        t:add(f.if_peer, tvb(off+7,6))
    elseif size == 11 then
        t:add(f.if_peer, tvb(off+5,6))
    end
    return true
end

-- HND structs below are in host order: little-endian on ARM routers.
local function parse_chan_change(tvb, off, len, tree)
    if len < 10 then return nil end
    local ver = tvb(off,2):le_uint()
    if ver ~= 1 and ver ~= 2 then return nil end
    local size = math.min(len, 12)
    local t = tree:add(tvb(off,size), "AP Channel Change")
    t:add_le(f.cc_version, tvb(off,2))
    t:add_le(f.cc_length, tvb(off+2,2))
    t:add_le(f.cc_reason, tvb(off+4,4))
    local _, c = add_chanspec(t, f.cc_target, tvb(off+8,2), true)
    if ver == 2 and len >= 12 then add_chanspec(t, f.cc_current, tvb(off+10,2), true) end
    local reason = tvb(off+4,4):le_uint()
    local s = CHAN_CHANGE_REASONS[reason] or ("reason " .. reason)
    return c and (s .. ", " .. chanspec_text(c)) or s
end

local function parse_cac(tvb, off, len, tree)
    if len < 12 or tvb(off,2):le_uint() ~= 1 or tvb(off+4,2):le_uint() ~= 1 then return nil end
    local n = tvb(off+10,2):le_uint()
    local t = tree:add(tvb(off,len), "CAC State Change")
    t:add_le(f.cac_version, tvb(off,2))
    t:add_le(f.cac_length, tvb(off+2,2))
    t:add_le(f.cac_type, tvb(off+4,2))
    t:add(f.cac_core, tvb(off+6,1))
    t:add_le(f.cac_status_version, tvb(off+8,2))
    t:add_le(f.cac_count, tvb(off+10,2))
    local p, stop = off + 12, off + len
    local summary
    for i = 1, n do
        if p + 16 > stop then
            truncated(t, p < stop and tvb(p, stop - p) or tvb(off+10,2),
                string.format("Sub-status count is %u, but only %u fit", n, i - 1))
            break
        end
        local state = tvb(p,4):le_uint()
        local sname = CAC_STATES[state] or ("state " .. state)
        local st = t:add(tvb(p,16), string.format("Sub-status %u: %s", i - 1, sname))
        st:add_le(f.cac_state, tvb(p,4))
        st:add_le(f.cac_duration, tvb(p+4,4))
        local _, c = add_chanspec(st, f.cac_chanspec, tvb(p+8,2), true)
        add_chanspec(st, f.cac_cleared, tvb(p+10,2), true)
        st:add_le(f.cac_subtype, tvb(p+12,2))
        summary = summary or (c and (sname .. ", " .. chanspec_text(c)) or sname)
        p = p + 16
    end
    return summary or "no sub-status"
end

-- wl_cevent_t is not packed: with 8-byte alignment the 64-bit timestamp sits
-- at offset 24 and the data at 32. Older HND has no msgtype, so its flags sit
-- at 12, the timestamp at 16 and the data at 24. A data_offset of 0 means the
-- full header.
local function parse_cevent(tvb, off, len, tree)
    if len < 20 then return nil end
    local le = version1_order(tvb, off)
    if le == nil then return nil end
    local declared = u16x(tvb, off + 2, le)
    local typ = u16x(tvb, off + 4, le)
    local dataoff = u16x(tvb, off + 6, le)
    if declared < 20 or declared > len or typ > 5 then return nil end
    if dataoff == 0 then dataoff = math.min(declared, 32) end
    if dataoff < 20 or dataoff > declared then return nil end
    local nomsg = dataoff == 24
    local fo = nomsg and 12 or 16
    local subtype = u32x(tvb, off + 8, le)
    local msg = not nomsg and u32x(tvb, off + 12, le) or nil
    local flags = u32x(tvb, off + fo, le)

    local t = tree:add(tvb(off,declared), "Connectivity Event (CEVENT)")
    if not le then t:append_text(", big-endian") end
    add_x(t, f.ce_version, tvb(off,2), le)
    add_x(t, f.ce_length, tvb(off+2,2), le)
    add_x(t, f.ce_type, tvb(off+4,2), le)
    add_x(t, f.ce_data_offset, tvb(off+6,2), le)
    add_x(t, f.ce_subtype, tvb(off+8,4), le)
    local mname
    if msg then
        local mi = add_x(t, f.ce_msgtype, tvb(off+12,4), le)
        mname = (typ == 1 and CEVENT_D2C_MSG_NAMES[msg]) or (typ == 2 and CEVENT_A2C_MSG_NAMES[msg]) or nil
        if mname then mi:set_text(string.format("CEVENT Message Type: %s (%u)", mname, msg)) end
    end
    local fl = add_x(t, f.ce_flags, tvb(off+fo,4), le)
    -- D2C TX messages (AUTH_TX to DEAUTH_TX) keep a TX status in the low byte.
    if typ == 1 and msg and msg < 5 then
        add_x(fl, f.ce_tx_status, tvb(off+fo,4), le)
    else
        add_x(fl, f.ce_eth_hdr, tvb(off+fo,4), le)
    end
    add_x(fl, f.ce_rx, tvb(off+fo,4), le)
    add_x(fl, f.ce_tx, tvb(off+fo,4), le)
    local tsoff = (nomsg and 16) or (dataoff >= 32 and 24) or (dataoff >= 28 and 20) or nil
    if tsoff then add_x(t, f.ce_timestamp, tvb(off+tsoff,8), le) end
    if declared > dataoff then t:add(f.payload, tvb(off+dataoff,declared-dataoff)) end

    local rx, tx = has_bit(flags, 0x40000000), has_bit(flags, 0x80000000)
    local dir = (rx and tx and " RX+TX") or (rx and " RX") or (tx and " TX") or ""
    local s = CEVENT_SUBTYPE_NAMES[subtype] or ("subtype " .. subtype)
    if msg then s = s .. " " .. (mname or ("msg " .. msg)) end
    return s .. dir
end

local function parse_rlm(tvb, off, len, tree)
    if len < 8 then return false end
    -- Firmware does not fill the length field as the header describes, and
    -- dhd_macdbg.c only checks the version, so do the same.
    local le = version1_order(tvb, off)
    if le == nil then return false end
    local t = tree:add(tvb(off,8), "Ratelinkmem Update")
    if not le then t:append_text(", big-endian") end
    add_x(t, f.rlm_version, tvb(off,2), le)
    add_x(t, f.rlm_length, tvb(off+2,2), le)
    add_x(t, f.rlm_action, tvb(off+4,2), le)
    add_x(t, f.rlm_entry, tvb(off+6,2), le)
    return true
end

local function parse_wsec(tvb, off, len, tree)
    if len < 8 then return false end
    -- version 1 and type 1 (PTK PN sync error), in the same byte order
    local le
    if tvb(off,2):le_uint() == 1 and tvb(off+4,2):le_uint() == 1 then le = true
    elseif tvb(off,2):uint() == 1 and tvb(off+4,2):uint() == 1 then le = false
    else return false end
    local t = tree:add(tvb(off,len), "WSEC Event: PTK PN sync error")
    if not le then t:append_text(", big-endian") end
    add_x(t, f.wsec_version, tvb(off,2), le)
    add_x(t, f.wsec_length, tvb(off+2,2), le)
    add_x(t, f.wsec_type, tvb(off+4,2), le)
    if len < 44 then
        truncated(t, len > 8 and tvb(off+8,len-8) or tvb(off+2,2),
            string.format("PTK PN sync error needs 36 bytes, %u present", len - 8))
        return true
    end
    local p = off + 8
    add_x(t, f.wsec_tsf_low, tvb(p,4), le)
    add_x(t, f.wsec_tsf_high, tvb(p+4,4), le)
    t:add(f.wsec_key_id, tvb(p+8,1))
    t:add(f.wsec_tid, tvb(p+9,1))
    add_x(t, f.wsec_rx_seqn, tvb(p+12,2), le)
    add_x(t, f.wsec_pn_low, tvb(p+14,2), le)
    add_x(t, f.wsec_pn_high, tvb(p+16,4), le)
    add_x(t, f.wsec_key_idx, tvb(p+20,2), le)
    add_x(t, f.wsec_rx_pn_low, tvb(p+22,2), le)
    add_x(t, f.wsec_rx_pn_high, tvb(p+24,4), le)
    add_x(t, f.wsec_span_time, tvb(p+28,4), le)
    add_x(t, f.wsec_span_pkts, tvb(p+32,4), le)
    return true
end

local function parse_invalid_ie(tvb, off, len, tree)
    if len < 8 or tvb(off,2):uint() ~= 0 then return false end
    -- Version 0 reads the same either way. The copy length (header plus copy
    -- fill the event data) or the error code (1) gives the byte order.
    local lle, lbe = tvb(off+2,2):le_uint(), tvb(off+2,2):uint()
    local le
    if lle ~= lbe and 8 + lle == len then le = true
    elseif lle ~= lbe and 8 + lbe == len then le = false
    elseif tvb(off+6,2):le_uint() == 1 then le = true
    elseif tvb(off+6,2):uint() == 1 then le = false
    else return false end
    local copylen = le and lle or lbe
    if copylen > len - 8 then return false end
    local t = tree:add(tvb(off,8+copylen), "Invalid IE Event")
    if not le then t:append_text(", big-endian") end
    add_x(t, f.inv_version, tvb(off,2), le)
    add_x(t, f.inv_length, tvb(off+2,2), le)
    add_x(t, f.inv_type, tvb(off+4,2), le)
    add_x(t, f.inv_error, tvb(off+6,2), le)
    if copylen > 0 then
        local it = t:add(tvb(off+8,copylen), "Invalid IE Copy")
        if copylen >= 2 and tvb(off+9,1):uint() + 2 <= copylen then
            parse_ies(tvb, off + 8, copylen, it)
        else
            it:add(f.payload, tvb(off+8,copylen))
        end
    end
    return true
end

-- Decode the event data. Returns an Info column suffix and, when the data
-- shows which firmware sent the event, the name to use instead of HND's.
local function dissect_data(tvb, etype, reason, off, len, tree)
    if etype == 69 then                                 -- ESCAN_RESULT
        return parse_escan(tvb, off, len, tree)

    elseif etype == 71 or etype == 72 or etype == 91 or etype == 137 then
        -- PROBRESP_MSG, P2P_PROBREQ_MSG, AUTH_REQ, PROBREQ_MSG_RX: RX metadata, then the frame
        local rh = parse_rxmeta(tvb, off, len, tree)
        if rh == 0 then
            tree:add(f.payload, tvb(off,len))
        elseif len > rh then
            if looks_like_mgmt(tvb, off + rh, len - rh) then return parse_mgmt(tvb, off + rh, len - rh, tree) end
            tree:add(f.payload, tvb(off+rh,len-rh))
        end

    elseif etype == 75 then                             -- ACTION_FRAME_RX
        -- RX metadata, then the action body only; drivers rebuild the header
        local rh = parse_rxmeta(tvb, off, len, tree)
        if rh == 0 then
            tree:add(f.payload, tvb(off,len))
        elseif len > rh then
            return parse_action_body(tvb, off + rh, len - rh, tree)
        end

    elseif etype == 61 or etype == 62 then              -- PRE_ASSOC_IND, PRE_REASSOC_IND
        local rh = parse_rxmeta(tvb, off, len, tree)
        if rh == 0 then
            tree:add(f.payload, tvb(off,len))
        elseif len >= rh + 4 then
            local at = tree:add(tvb(off+rh,len-rh), "802.11 Association Request Body")
            at:add_le(f.assoc_cap, tvb(off+rh,2))
            at:add_le(f.assoc_listen, tvb(off+rh+2,2))
            parse_ies(tvb, off + rh + 4, len - rh - 4, at)
        elseif len > rh then
            tree:add(f.payload, tvb(off+rh,len-rh))
        end

    elseif etype == 8 or etype == 10 or etype == 87 or etype == 88 then
        -- ASSOC_IND, REASSOC_IND, ASSOC_REQ_IE, ASSOC_RESP_IE: elements only
        if len >= 2 then parse_ies(tvb, off, len, tree) else tree:add(f.payload, tvb(off,len)) end

    elseif etype == 44 then                             -- PROBREQ_MSG: the frame alone
        if looks_like_mgmt(tvb, off, len) then return parse_mgmt(tvb, off, len, tree) end
        tree:add(f.payload, tvb(off,len))

    elseif etype == 59 then                             -- ACTION_FRAME
        return parse_action_body(tvb, off, len, tree)

    elseif etype == 54 then                             -- IF
        if not parse_if_event(tvb, off, len, tree) then tree:add(f.payload, tvb(off,len)) end

    elseif etype == 147 and reason == 5 then            -- MACDBG, RATELINKMEM
        if not parse_rlm(tvb, off, len, tree) then tree:add(f.payload, tvb(off,len)) end

    elseif etype == 162 then                            -- INVALID_IE
        if not parse_invalid_ie(tvb, off, len, tree) then tree:add(f.payload, tvb(off,len)) end

    elseif etype == 170 then                            -- HND AP_CHAN_CHANGE
        local s = parse_chan_change(tvb, off, len, tree)
        if s then return s end
        tree:add(f.payload, tvb(off,len))

    elseif etype == 180 then                            -- HND CEVENT
        local s = parse_cevent(tvb, off, len, tree)
        if s then return s end
        tree:add(f.payload, tvb(off,len))

    elseif etype == 184 then                            -- HND CAC_STATE_CHANGE
        local s = parse_cac(tvb, off, len, tree)
        if s then return s end
        tree:add(f.payload, tvb(off,len))

    elseif etype == 186 then
        -- HND ASSOC_REASSOC_IND_EXT carries the whole (re)association request;
        -- DHD uses 186 for WLC_E_WSEC.
        if parse_wsec(tvb, off, len, tree) then return "PTK_PN_SYNC_ERROR", DHD_EVENT_NAMES[186] end
        if looks_like_mgmt(tvb, off, len) then return parse_mgmt(tvb, off, len, tree) end
        tree:add(f.payload, tvb(off,len))

    else
        tree:add(f.payload, tvb(off,len))
    end
    return nil
end

local function dissect_dongle_event(tvb, root)
    -- bcm_dngl_event_msg_t, network order; its data is in host order
    if tvb:len() < 18 then
        truncated(root, tvb(10), string.format("Dongle event header needs 8 bytes, %u present", tvb:len() - 10))
        return nil
    end
    local dt = root:add(tvb(10,8), "Dongle Event")
    dt:add(f.dngl_version, tvb(10,2))
    dt:add(f.dngl_type, tvb(14,2))
    local dl = dt:add(f.dngl_datalen, tvb(16,2))
    cut = tvb(16,2):uint() > tvb:len() - 18
    local dlen = data_present(dl, tvb(16,2):uint(), tvb:reported_len() - 18, tvb:len() - 18)
    if dlen > 0 then dt:add(f.payload, tvb(18,dlen)) end
    local dtype = tvb(14,2):uint()
    return DNGL_EVENT_NAMES[dtype] or ("type " .. dtype)
end

-- Called from the ethertype table, so 802.1Q/QinQ tags are already stripped
-- and the tvb starts at the 0x886c payload. A Decode As rule for 0x886c
-- outranks this registration.
function bcm.dissector(tvb, pinfo, tree)
    -- bcmeth_hdr_t starts with BCMILCP_SUBTYPE_VENDOR_LONG and the Broadcom
    -- OUI. Anything else goes to Wireshark's data dissector.
    if tvb:len() < 10 or tvb(0,2):uint() ~= 0x8001 or tvb(5,3):uint() ~= 0x001018 then return 0 end
    cut = tvb:reported_len() > tvb:len()

    pinfo.cols.protocol = "BCMEVENT"
    local root = tree:add(bcm, tvb())
    local bh = root:add(tvb(0,10), "Broadcom Ethernet Header")
    bh:add(f.bcm_subtype, tvb(0,2))
    bh:add(f.bcm_length, tvb(2,2))
    bh:add(f.bcm_version, tvb(4,1))
    bh:add(f.bcm_oui, tvb(5,3))
    bh:add(f.bcm_user_subtype, tvb(8,2))

    local usr = tvb(8,2):uint()
    if usr == 5 then
        local name = dissect_dongle_event(tvb, root) or "truncated"
        pinfo.cols.info = "Dongle event " .. name
        root:append_text(", dongle event " .. name)
        return tvb:len()
    elseif usr ~= 1 then
        pinfo.cols.info = "Broadcom user subtype " .. usr
        if tvb:len() > 10 then root:add(f.payload, tvb(10)) end
        return tvb:len()
    end

    -- wl_event_msg_t, network order: 48 bytes, or 46 in version 1, which has
    -- no ifidx and bsscfgidx.
    local eo = 10
    local hlen = (tvb:len() >= eo + 2 and tvb(eo,2):uint() == 1) and 46 or 48
    if tvb:len() < eo + hlen then
        truncated(root, tvb:len() > eo and tvb(eo) or tvb(8,2),
            string.format("Event message needs %u bytes, %u present", hlen, tvb:len() - eo))
        pinfo.cols.info = "Truncated event message"
        return tvb:len()
    end

    local ev = root:add(tvb(eo,hlen), "Event Message")
    ev:add(f.evt_version, tvb(eo,2))
    local flags = tvb(eo+2,2):uint()
    local fi = ev:add(f.evt_flags, tvb(eo+2,2))
    for _, x in ipairs(EVENT_FLAGS) do
        fi:add(x[1], tvb(eo+2,2))
        if has_bit(flags, x[2]) then fi:append_text(", " .. x[3]) end
    end

    local etype = tvb(eo+4,4):uint()
    local status = tvb(eo+8,4):uint()
    local reason = tvb(eo+12,4):uint()
    local datalen = tvb(eo+20,4):uint()
    ev:add(f.evt_type, tvb(eo+4,4))
    if DHD_EVENT_NAMES[etype] then ev:add(f.evt_type_dhd, tvb(eo+4,4)):set_generated() end
    if CYW_EVENT_NAMES[etype] then ev:add(f.evt_type_cyw, tvb(eo+4,4)):set_generated() end

    local se = STATUS_BY_EVENT[etype]
    local sname = (se and se[2] or STATUS_NAMES)[status]
    ev:add(se and se[1] or f.evt_status, tvb(eo+8,4))
    local rnames = REASON_NAMES_BY_EVENT[etype]
    local rname = rnames and rnames[reason]
    local ri = ev:add(f.evt_reason, tvb(eo+12,4))
    if rname then ri:set_text(string.format("Reason: %s (%u)", rname, reason)) end

    ev:add(f.evt_auth, tvb(eo+16,4))
    local dl = ev:add(f.evt_datalen, tvb(eo+20,4))
    ev:add(f.evt_addr, tvb(eo+24,6))
    local ifname = trim_nul(tvb(eo+30,16):string())
    ev:add(f.evt_ifname, tvb(eo+30,16), ifname)
    if hlen == 48 then
        ev:add(f.evt_ifidx, tvb(eo+46,1))
        ev:add(f.evt_bssidx, tvb(eo+47,1))
    end

    local function info_text(ename)
        local info = {ename, "[" .. (sname or tostring(status)) .. "]"}
        if ifname ~= "" then info[#info+1] = ifname end
        -- ESCAN_RESULT puts the BSSID there, and the scan summary already shows it.
        local sta = macstr(tvb, eo + 24)
        if sta ~= "00:00:00:00:00:00" and etype ~= 69 then info[#info+1] = "sta=" .. sta end
        if rname then info[#info+1] = "reason=" .. rname end
        return table.concat(info, " ")
    end
    local ename = EVENT_NAMES[etype] or ("Unknown event " .. etype)
    pinfo.cols.info = info_text(ename)

    local po = eo + hlen
    cut = datalen > tvb:len() - po
    local plen = data_present(dl, datalen, tvb:reported_len() - po, tvb:len() - po)
    local suffix, name
    if plen > 0 then
        suffix, name = dissect_data(tvb, etype, reason, po, plen, root:add(tvb(po,plen), "Event Data"))
    end
    if name then
        ename = name
        pinfo.cols.info = info_text(ename)
    end
    if suffix then pinfo.cols.info:append(" | " .. suffix) end
    root:append_text(", " .. ename)
    return tvb:len()
end

DissectorTable.get("ethertype"):add(0x886c, bcm)
