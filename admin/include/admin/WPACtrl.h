/*
 * wpa_supplicant/hostapd control interface library
 * Copyright (c) 2004-2006, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef WPA_CTRL_H
#define WPA_CTRL_H

#include "air192.h"
#include "wifi_manager.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* wpa_supplicant control interface - fixed message prefixes */

/** Interactive request for identity/password/pin */
#define WPA_CTRL_REQ "CTRL-REQ-"

/** Response to identity/password/pin request */
#define WPA_CTRL_RSP "CTRL-RSP-"

/* Event messages with fixed prefix */
/** Authentication completed successfully and data connection enabled */
#define WPA_EVENT_CONNECTED "CTRL-EVENT-CONNECTED "
/** Disconnected, data connection is not available */
#define WPA_EVENT_DISCONNECTED "CTRL-EVENT-DISCONNECTED "
/** Association rejected during connection attempt */
#define WPA_EVENT_ASSOC_REJECT "CTRL-EVENT-ASSOC-REJECT "
/** wpa_supplicant is exiting */
#define WPA_EVENT_TERMINATING "CTRL-EVENT-TERMINATING "
/** Password change was completed successfully */
#define WPA_EVENT_PASSWORD_CHANGED "CTRL-EVENT-PASSWORD-CHANGED "
/** EAP-Request/Notification received */
#define WPA_EVENT_EAP_NOTIFICATION "CTRL-EVENT-EAP-NOTIFICATION "
/** EAP authentication started (EAP-Request/Identity received) */
#define WPA_EVENT_EAP_STARTED "CTRL-EVENT-EAP-STARTED "
/** EAP method proposed by the server */
#define WPA_EVENT_EAP_PROPOSED_METHOD "CTRL-EVENT-EAP-PROPOSED-METHOD "
/** EAP method selected */
#define WPA_EVENT_EAP_METHOD "CTRL-EVENT-EAP-METHOD "
/** EAP peer certificate from TLS */
#define WPA_EVENT_EAP_PEER_CERT "CTRL-EVENT-EAP-PEER-CERT "
/** EAP TLS certificate chain validation error */
#define WPA_EVENT_EAP_TLS_CERT_ERROR "CTRL-EVENT-EAP-TLS-CERT-ERROR "
/** EAP authentication completed successfully */
#define WPA_EVENT_EAP_SUCCESS "CTRL-EVENT-EAP-SUCCESS "
/** EAP authentication failed (EAP-Failure received) */
#define WPA_EVENT_EAP_FAILURE "CTRL-EVENT-EAP-FAILURE "
/** New scan results available */
#define WPA_EVENT_SCAN_RESULTS "CTRL-EVENT-SCAN-RESULTS "
/** wpa_supplicant state change */
#define WPA_EVENT_STATE_CHANGE "CTRL-EVENT-STATE-CHANGE "
/** A new BSS entry was added (followed by BSS entry id and BSSID) */
#define WPA_EVENT_BSS_ADDED "CTRL-EVENT-BSS-ADDED "
/** A BSS entry was removed (followed by BSS entry id and BSSID) */
#define WPA_EVENT_BSS_REMOVED "CTRL-EVENT-BSS-REMOVED "

/** WPS overlap detected in PBC mode */
#define WPS_EVENT_OVERLAP "WPS-OVERLAP-DETECTED "
/** Available WPS AP with active PBC found in scan results */
#define WPS_EVENT_AP_AVAILABLE_PBC "WPS-AP-AVAILABLE-PBC "
/** Available WPS AP with our address as authorized in scan results */
#define WPS_EVENT_AP_AVAILABLE_AUTH "WPS-AP-AVAILABLE-AUTH "
/** Available WPS AP with recently selected PIN registrar found in scan results
 */
#define WPS_EVENT_AP_AVAILABLE_PIN "WPS-AP-AVAILABLE-PIN "
/** Available WPS AP found in scan results */
#define WPS_EVENT_AP_AVAILABLE "WPS-AP-AVAILABLE "
/** A new credential received */
#define WPS_EVENT_CRED_RECEIVED "WPS-CRED-RECEIVED "
/** M2D received */
#define WPS_EVENT_M2D "WPS-M2D "
/** WPS registration failed after M2/M2D */
#define WPS_EVENT_FAIL "WPS-FAIL "
/** WPS registration completed successfully */
#define WPS_EVENT_SUCCESS "WPS-SUCCESS "
/** WPS enrollment attempt timed out and was terminated */
#define WPS_EVENT_TIMEOUT "WPS-TIMEOUT "

#define WPS_EVENT_ENROLLEE_SEEN "WPS-ENROLLEE-SEEN "

#define WPS_EVENT_OPEN_NETWORK "WPS-OPEN-NETWORK "

/* WPS ER events */
#define WPS_EVENT_ER_AP_ADD "WPS-ER-AP-ADD "
#define WPS_EVENT_ER_AP_REMOVE "WPS-ER-AP-REMOVE "
#define WPS_EVENT_ER_ENROLLEE_ADD "WPS-ER-ENROLLEE-ADD "
#define WPS_EVENT_ER_ENROLLEE_REMOVE "WPS-ER-ENROLLEE-REMOVE "
#define WPS_EVENT_ER_AP_SETTINGS "WPS-ER-AP-SETTINGS "
#define WPS_EVENT_ER_SET_SEL_REG "WPS-ER-AP-SET-SEL-REG "

/** P2P device found */
#define P2P_EVENT_DEVICE_FOUND "P2P-DEVICE-FOUND "
/** A P2P device requested GO negotiation, but we were not ready to start the
 * negotiation */
#define P2P_EVENT_GO_NEG_REQUEST "P2P-GO-NEG-REQUEST "
#define P2P_EVENT_GO_NEG_SUCCESS "P2P-GO-NEG-SUCCESS "
#define P2P_EVENT_GO_NEG_FAILURE "P2P-GO-NEG-FAILURE "
#define P2P_EVENT_GROUP_FORMATION_SUCCESS "P2P-GROUP-FORMATION-SUCCESS "
#define P2P_EVENT_GROUP_FORMATION_FAILURE "P2P-GROUP-FORMATION-FAILURE "
#define P2P_EVENT_GROUP_STARTED "P2P-GROUP-STARTED "
#define P2P_EVENT_GROUP_REMOVED "P2P-GROUP-REMOVED "
#define P2P_EVENT_CROSS_CONNECT_ENABLE "P2P-CROSS-CONNECT-ENABLE "
#define P2P_EVENT_CROSS_CONNECT_DISABLE "P2P-CROSS-CONNECT-DISABLE "
/* parameters: <peer address> <PIN> */
#define P2P_EVENT_PROV_DISC_SHOW_PIN "P2P-PROV-DISC-SHOW-PIN "
/* parameters: <peer address> */
#define P2P_EVENT_PROV_DISC_ENTER_PIN "P2P-PROV-DISC-ENTER-PIN "
/* parameters: <peer address> */
#define P2P_EVENT_PROV_DISC_PBC_REQ "P2P-PROV-DISC-PBC-REQ "
/* parameters: <peer address> */
#define P2P_EVENT_PROV_DISC_PBC_RESP "P2P-PROV-DISC-PBC-RESP "
/* parameters: <freq> <src addr> <dialog token> <update indicator> <TLVs> */
#define P2P_EVENT_SERV_DISC_REQ "P2P-SERV-DISC-REQ "
/* parameters: <src addr> <update indicator> <TLVs> */
#define P2P_EVENT_SERV_DISC_RESP "P2P-SERV-DISC-RESP "
#define P2P_EVENT_INVITATION_RECEIVED "P2P-INVITATION-RECEIVED "
#define P2P_EVENT_INVITATION_RESULT "P2P-INVITATION-RESULT "

/* hostapd control interface - fixed message prefixes */
#define WPS_EVENT_PIN_NEEDED "WPS-PIN-NEEDED "
#define WPS_EVENT_NEW_AP_SETTINGS "WPS-NEW-AP-SETTINGS "
#define WPS_EVENT_REG_SUCCESS "WPS-REG-SUCCESS "
#define WPS_EVENT_AP_SETUP_LOCKED "WPS-AP-SETUP-LOCKED "
#define WPS_EVENT_AP_SETUP_UNLOCKED "WPS-AP-SETUP-UNLOCKED "
#define WPS_EVENT_AP_PIN_ENABLED "WPS-AP-PIN-ENABLED "
#define WPS_EVENT_AP_PIN_DISABLED "WPS-AP-PIN-DISABLED "
#define AP_STA_CONNECTED "AP-STA-CONNECTED "
#define AP_STA_DISCONNECTED "AP-STA-DISCONNECTED "

#define WPA_CFG wpasup_cfg // "/usrdata/wpa_supplicant.conf"
#define WPA_CTRL "/var/run/wpa_supplicant"
#define WPA_CTRL_WLAN0 "/var/run/wpa_supplicant/wlan0"
#define WPA_BUF 4096

typedef enum {

	WPACTRL_SUCCESS                         = 0,    //< Success
	WPACTRL_PENDING                         = 1,    //< Pending
	WPACTRL_TIMEOUT                         = 2,    //< Timeout
	WPACTRL_PARTIAL_RESULTS                 = 3,    //< Partial results
	WPACTRL_INVALID_KEY                     = 4,    //< Invalid key
	WPACTRL_DOES_NOT_EXIST                  = 5,    //< Does not exist
	WPACTRL_NOT_AUTHENTICATED               = 6,    //< Not authenticated
	WPACTRL_NOT_KEYED                       = 7,    //< Not keyed
	WPACTRL_IOCTL_FAIL                      = 8,    //< IOCTL fail
	WPACTRL_BUFFER_UNAVAILABLE_TEMPORARY    = 9,    //< Buffer unavailable temporarily
	WPACTRL_BUFFER_UNAVAILABLE_PERMANENT    = 10,   //< Buffer unavailable permanently
	WPACTRL_WPS_PBC_OVERLAP                 = 11,   //< WPS PBC overlap
	WPACTRL_CONNECTION_LOST                 = 12,   //< Connection lost

	WPACTRL_ERROR                           = -1,   //< Generic Error
	WPACTRL_BADARG                          = -2,   //< Bad Argument
	DXWIFI_BADOPTION                       = -3,   //< Bad option
	DXWIFI_NOTUP                           = -4,   //< Not up
	DXWIFI_NOTDOWN                         = -5,   //< Not down
	DXWIFI_NOTAP                           = -6,   //< Not AP
	WPACTRL_NOTSTA                          = -7,   //< Not STA

	DXWIFI_BADKEYIDX                       = -8,   //< BAD Key Index
	DXWIFI_RADIOOFF                        = -9,   //< Radio Off
	DXWIFI_NOTBANDLOCKED                   = -10,  //< Not  band locked
	DXWIFI_NOCLK                           = -11,  //< No Clock
	DXWIFI_BADRATESET                      = -12,  //< BAD Rate valueset
	DXWIFI_BADBAND                         = -13,  //< BAD Band
	DXWIFI_BUFTOOSHORT                     = -14,  //< Buffer too short
	DXWIFI_BUFTOOLONG                      = -15,  //< Buffer too long
	DXWIFI_BUSY                            = -16,  //< Busy
	DXWIFI_NOTASSOCIATED                   = -17,  //< Not Associated
	DXWIFI_BADSSIDLEN                      = -18,  //< Bad SSID len
	DXWIFI_OUTOFRANGECHAN                  = -19,  //< Out of Range Channel
	DXWIFI_BADCHAN                         = -20,  //< Bad Channel
	DXWIFI_BADADDR                         = -21,  //< Bad Address
	DXWIFI_NORESOURCE                      = -22,  //< Not Enough Resources
	WPACTRL_UNSUPPORTED                     = -23,  //< Unsupported
	DXWIFI_BADLEN                          = -24,  //< Bad length
	DXWIFI_NOTREADY                        = -25,  //< Not Ready
	DXWIFI_EPERM                           = -26,  //< Not Permitted
	DXWIFI_NOMEM                           = -27,  //< No Memory
	DXWIFI_ASSOCIATED                      = -28,  //< Associated
	DXWIFI_RANGE                           = -29,  //< Not In Range
	WPACTRL_NOTFOUND                        = -30,  //< Not Found
	DXWIFI_WME_NOT_ENABLED                 = -31,  //< WME Not Enabled
	DXWIFI_TSPEC_NOTFOUND                  = -32,  //< TSPEC Not Found
	DXWIFI_ACM_NOTSUPPORTED                = -33,  //< ACM Not Supported
	DXWIFI_NOT_WME_ASSOCIATION             = -34,  //< Not WME Association
	DXWIFI_SDIO_ERROR                      = -35,  //< SDIO Bus Error
	DXWIFI_WLAN_DOWN                       = -36,  //< WLAN Not Accessible
	DXWIFI_BAD_VERSION                     = -37,  //< Incorrect version
	DXWIFI_TXFAIL                          = -38,  //< TX failure
	DXWIFI_RXFAIL                          = -39,  //< RX failure
	DXWIFI_NODEVICE                        = -40,  //< Device not present
	DXWIFI_UNFINISHED                      = -41,  //< To be finished
	DXWIFI_NONRESIDENT                     = -42,  //< access to nonresident overlay
	DXWIFI_DISABLED                        = -43   //< Disabled in this build

} WPACTRL_RET_CODE;

typedef enum {
	WPACTRL_EVENT_CODE_SCAN_RESULTS,
	WPACTRL_EVENT_CODE_NULL
} WPACTRL_EVENT_CODE;

#define WPA_SSID_MAX_NAME_LEN			32
#define WPA_PASSWORD_MAX_NAME_LEN		64
#define WPA_BSSID_MAX_LEN				6

typedef struct {

	char		ssid[ WPA_SSID_MAX_NAME_LEN + 4 ];
	short		ssid_len;
	short		channel;

	uint8_t		bssid[WPA_BSSID_MAX_LEN];
	uint32_t    security;
	int			rssi;

} WPA_ScanResult_t;

typedef enum {

	WPA_STATUS_ERROR    	= -1,
    WPA_STATUS_COMPLETED    = 0,
    WPA_STATUS_SCANNING,
    WPA_STATUS_ASSOCIATING,
    WPA_STATUS_INACTIVE,
    WPA_STATUS_DISCONNECTED,

} WPA_STATUS;

typedef enum {

	WIFI_MODE_NONE = 0,
	WIFI_MODE_STA,
	WIFI_MODE_AP

} WIFI_MODE;

typedef enum {

	WPACTRL_CHANNEL_PLAN_DEFAULT         = 0,
	WPACTRL_CHANNEL_PLAN_KOREA           = 1,
	WPACTRL_CHANNEL_PLAN_EU              = 2,
	WPACTRL_CHANNEL_PLAN_NORTH_AMERICA   = 3,
	WPACTRL_CHANNEL_PLAN_JAPAN           = 4,

} WPACTRL_CHANNEL_PLAN;

typedef enum {

	WPACTRL_ADAPTIVITY_DISABLE = 0,
	WPACTRL_ADAPTIVITY_NORMAL,           // CE
	WPACTRL_ADAPTIVITY_CARRIER_SENSE     // MKK

} WPACTRL_ADAPTIVITY;

/* wpa_supplicant/hostapd control interface access */

WPACTRL_RET_CODE WPACtrl_UpdateStatus( void );

BOOL WPACtrl_IsReady( void );

WIFI_MODE WPACtrl_GetMode( void );

WPACTRL_RET_CODE WPACtrl_GetSignalLevel(int *rssi);

uint32_t WPACtrl_Scan( WPA_ScanResult_t *results, uint32_t max_result );

uint32_t WPACtrl_SearchBySSID( const char *ssid, WPA_ScanResult_t *results, uint32_t max_result );

WPACTRL_RET_CODE WPACtrl_Disconnect( void );

WPACTRL_RET_CODE WPACtrl_Connect( uint8_t *bssid, char *ssid, char *password, WIFI_SECURITY security_type );

WPACTRL_RET_CODE WPACtrl_Start(const char* if_name);

WPACTRL_RET_CODE WPACtrl_GenConf( WIFI_MODE mode, WPACTRL_CHANNEL_PLAN ch, WPACTRL_ADAPTIVITY adv );

WIFI_SECURITY WPACtrl_ConvertSecurity( char *flag );

WPACTRL_RET_CODE WPACtrl_Init(const char* if_name);

#ifdef CONFIG_CTRL_IFACE_UDP
#define WPA_CTRL_IFACE_PORT 9877
#define WPA_GLOBAL_CTRL_IFACE_PORT 9878
#endif /* CONFIG_CTRL_IFACE_UDP */

#ifdef  __cplusplus
}
#endif

#endif /* WPA_CTRL_H */
