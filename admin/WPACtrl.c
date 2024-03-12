/*
 * wpa_supplicant/hostapd control interface library
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
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

//==========================================================================
// Include File
//==========================================================================
//#include "dexatek/main_application/include/app/app_common.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/un.h>
#include <pthread.h>
#include <stdint.h>

#include <admin/WPACtrl.h>

//==========================================================================
// Type Declaration
//==========================================================================
const static char* tag = "wpa_ctrl";

/**
 * struct wpa_ctrl - Internal structure for control interface library
 *
 * This structure is used by the wpa_supplicant/hostapd control interface
 * library to store internal data. Programs using the library should not touch
 * this data directly. They can only use the pointer to the data structure as
 * an identifier for the control interface connection and use this as one of
 * the arguments for most of the control interface library functions.
 */
struct wpa_ctrl {
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

//typedef struct {
//	dxEventHandler_t	ScanResultHdl;
//	void				*user_data;
//} wpa_scan_ctx;

#ifndef CONFIG_CTRL_IFACE_CLIENT_DIR
#define CONFIG_CTRL_IFACE_CLIENT_DIR "/var"
#endif /* CONFIG_CTRL_IFACE_CLIENT_DIR */

#ifndef CONFIG_CTRL_IFACE_CLIENT_PREFIX
#define CONFIG_CTRL_IFACE_CLIENT_PREFIX "wpa_ctrl_"
#endif /* CONFIG_CTRL_IFACE_CLIENT_PREFIX */

#define SCAN_RESULT_DEFAULT_WORKER_PRIORITY          DXTASK_PRIORITY_IDLE
#define SCAN_RESULT_WORKER_THREAD_STACK_SIZE         1024
#define SCAN_RESULT_WORKER_THREAD_MAX_EVENT_QUEUE    2

//==========================================================================
// Static Params
//==========================================================================
static pthread_mutex_t	mutex = PTHREAD_MUTEX_INITIALIZER;
static struct {
    WPA_STATUS      status;
    int				mode;
    uint8_t         ip[ 4 ];
    uint8_t         mac[ 6 ];
	int             signal_level;
} _wpa_info = {
    WPA_STATUS_ERROR,
    WIFI_MODE_NONE,
	{ 0, },
	{ 0, },
	0,
};

//static dxWorkweTask_t   ScanResultWorkerThread = {
//	.WTask			= NULL,
//	.WEventQueue	= NULL
//};

//==========================================================================
// Static Functions
//==========================================================================
static WPACTRL_RET_CODE
wpa_ctrl_open( const char *ctrl_path, struct wpa_ctrl *ctrl )
{
	static int counter = 0;
	int ret;
	size_t res;
	int tries = 0;

	memset( ctrl, 0, sizeof( struct wpa_ctrl ) );

	ctrl->s = socket( PF_UNIX, SOCK_DGRAM, 0 );
	if ( ctrl->s < 0 ) {
		return WPACTRL_ERROR;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter ++;

try_again:
	ret = snprintf( ctrl->local.sun_path, sizeof( ctrl->local.sun_path ),
									  CONFIG_CTRL_IFACE_CLIENT_DIR "/"
									  CONFIG_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
									  ( int ) getpid(), counter );
	if ( ret < 0 || ( size_t )ret >= sizeof( ctrl->local.sun_path ) ) {
		close( ctrl->s );
		return WPACTRL_ERROR;
	}

	tries ++;
	if ( bind( ctrl->s, ( struct sockaddr * )&ctrl->local, sizeof( ctrl->local ) ) < 0 ) {
		if ( errno == EADDRINUSE && tries < 2 ) {
			/*
			 * getpid() returns unique identifier for this instance
			 * of wpa_ctrl, so the existing socket file must have
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink( ctrl->local.sun_path );
			goto try_again;
		}
		close( ctrl->s );
		return WPACTRL_ERROR;
	}

	ctrl->dest.sun_family = AF_UNIX;
	res = snprintf( ctrl->dest.sun_path, sizeof( ctrl->dest.sun_path ), "%s", ctrl_path );
	if ( res >= sizeof( ctrl->dest.sun_path ) ) {
		close( ctrl->s );
		return WPACTRL_ERROR;
	}

	if ( connect( ctrl->s, ( struct sockaddr * ) &ctrl->dest, sizeof( ctrl->dest ) ) < 0 ) {
		close( ctrl->s );
		unlink( ctrl->local.sun_path );
		return WPACTRL_ERROR;
	}

	return WPACTRL_SUCCESS;
}

static void
wpa_ctrl_close( struct wpa_ctrl *ctrl )
{
	if ( ctrl == NULL ) {
		return;
	}

	unlink( ctrl->local.sun_path );
	if ( ctrl->s >= 0 ) {
		close( ctrl->s );
	}
}

static int
wpa_ctrl_request( struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len, char *reply, int reply_len )
{
	struct timeval tv;
	int res;
	fd_set rfds;

	if ( send( ctrl->s, cmd, cmd_len, 0 ) < 0 ) {
		return -1;
	}

	tv.tv_sec	= 10;
	tv.tv_usec	= 0;

	FD_ZERO( &rfds );
	FD_SET( ctrl->s, &rfds );

	res = select( ctrl->s + 1, &rfds, NULL, NULL, &tv );
	if ( res < 0 ) {
		return FAIL;
	}

	if ( FD_ISSET( ctrl->s, &rfds ) ) {
		res = recv( ctrl->s, reply, reply_len, 0 );

		if ( res < 0 ) {
			return FAIL;
		}
		reply[ res ] = 0;
		return res;
	} else {
		return SUCCESS;
	}
}

static WPACTRL_RET_CODE
wpa_ctrl_set( struct wpa_ctrl *ctrl, char *cmd )
{
	char buf[ WPA_BUF + 1 ];

	size_t len = wpa_ctrl_request( ctrl, cmd, strlen( cmd ), buf, WPA_BUF );

	if ( len <= 0 ) {
	    // ecam2_log_warn("'%s' command failed.", cmd );
	    return WPACTRL_ERROR;
	} else if ( memcmp( buf, "OK", 2 ) ) {
		buf[ len ] = '\0';
		// ecam2_log_warn("Do %s Failed: %s", cmd, buf );
		return WPACTRL_ERROR;
	}

	return WPACTRL_SUCCESS;
}

static int
wpa_ctrl_get( struct wpa_ctrl *ctrl, char *cmd, char *buf, int buf_len )
{
	size_t len = wpa_ctrl_request( ctrl, cmd, strlen( cmd ), buf, buf_len - 1 );

	if ( len < 0 ) {
	    ecam2_log_warn("'%s' command failed.", cmd );
	    return len;
	}

	buf[ len ] = '\0';

	return len;
}

static WPACTRL_RET_CODE
wpa_ctrl_setup( struct wpa_ctrl *ctrl, uint8_t *bssid, char *ssid, char *password, WIFI_SECURITY security_type )
{
	char buf[ WPA_BUF ];
	char cmd[ 256 ];

	if ( wpa_ctrl_set( ctrl, "RECONNECT" ) ) {
		return WPACTRL_ERROR;
	}

    wpa_ctrl_set( ctrl, "REMOVE_NETWORK 0" );

	if ( wpa_ctrl_get( ctrl, "ADD_NETWORK", buf, WPA_BUF ) > 0 ) {
		if ( strncmp( buf, "0", 1 ) ) {
			return WPACTRL_ERROR;
		}
	} else {
		return WPACTRL_ERROR;
	}

	snprintf( cmd, sizeof( cmd ), "BSSID 0 %02x:%02x:%02x:%02x:%02x:%02x", bssid[ 0 ], bssid[ 1 ], bssid[ 2 ], bssid[ 3 ], bssid[ 4 ], bssid[ 5 ] );
	if ( wpa_ctrl_set( ctrl, cmd ) ) {
		return WPACTRL_BADARG;
	}

	snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 ssid \"%s\"", ssid );
	if ( wpa_ctrl_set( ctrl, cmd ) ) {
		return WPACTRL_BADARG;
	}

	if ( wpa_ctrl_set( ctrl, "SET_NETWORK 0 scan_ssid 1" ) ) {
		return WPACTRL_ERROR;
	}

	switch (security_type) {
		case WIFI_SECURITY_OPEN:
		case WIFI_SECURITY_WPS_OPEN:
			if ( wpa_ctrl_set( ctrl, "SET_NETWORK 0 key_mgmt NONE" ) ) {
				return WPACTRL_ERROR;
			}
			break;

		case WIFI_SECURITY_WEP_PSK:
		case WIFI_SECURITY_WEP_SHARED:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "NONE" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 wep_key0 %s", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 wep_tx_keyidx 0" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}
			break;

		case WIFI_SECURITY_WPA_TKIP_PSK:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "WPA-PSK" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 proto %s", "WPA" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 psk \"%s\"", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 pairwise %s", "TKIP" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}
			break;

		case WIFI_SECURITY_WPA_AES_PSK:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "WPA-PSK" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 proto %s", "WPA" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 psk \"%s\"", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 pairwise %s", "CCMP" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			break;

		case WIFI_SECURITY_WPA2_AES_PSK:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "WPA-PSK" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 proto %s", "RSN" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 psk \"%s\"", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 pairwise %s", "CCMP" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			break;

		case WIFI_SECURITY_WPA2_TKIP_PSK:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "WPA-PSK" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 proto %s", "RSN" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 psk \"%s\"", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 pairwise %s", "TKIP" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			break;

		case WIFI_SECURITY_WPA2_MIXED_PSK:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "WPA-PSK" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 proto %s", "RSN" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 psk \"%s\"", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 pairwise %s", "CCMP TKIP" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			break;

		case WIFI_SECURITY_WPA_WPA2_MIXED:
			if ( password == NULL ) {
				return WPACTRL_BADARG;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 key_mgmt %s", "WPA-PSK" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 proto %s", "RSN WPA" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 psk \"%s\"", password );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			snprintf( cmd, sizeof( cmd ), "SET_NETWORK 0 pairwise %s", "CCMP TKIP" );
			if ( wpa_ctrl_set( ctrl, cmd ) ) {
				return WPACTRL_ERROR;
			}

			break;

		case WIFI_SECURITY_WPS_SECURE:
			return WPACTRL_UNSUPPORTED;

		case WIFI_SECURITY_UNKNOWN:
			return WPACTRL_UNSUPPORTED;

		case WIFI_SECURITY_FORCE_32_BIT:
			return WPACTRL_UNSUPPORTED;

		default:
			return -5;
	}

	if ( wpa_ctrl_set( ctrl, "ENABLE_NETWORK 0" ) ) {
		return WPACTRL_ERROR;
	} else if ( wpa_ctrl_set( ctrl, "STA_AUTOCONNECT 0" ) ) {
		return WPACTRL_ERROR;
	}

	return WPACTRL_SUCCESS;
}

static WPACTRL_RET_CODE
wpa_ctrl_event_recv(WPACTRL_EVENT_CODE *event) {
	struct wpa_ctrl ctrl;
	char buf[ WPA_BUF ];
	struct timeval tv;
	fd_set rfds;
	int ret;

	*event = WPACTRL_EVENT_CODE_NULL;

	if ( wpa_ctrl_open( WPA_CTRL_WLAN0, &ctrl ) == WPACTRL_ERROR ) {
		ecam2_log_warn("Could not get ctrl interface!" );
		return WPACTRL_NOTFOUND;
	}

	ret = wpa_ctrl_set( &ctrl, "ATTACH" );

	if(ret != WPACTRL_SUCCESS) {
		return ret;
	}

	tv.tv_sec	= 0;
	tv.tv_usec	= 500000;

	FD_ZERO( &rfds );
	FD_SET( ctrl.s, &rfds );

	int res = select( ctrl.s + 1, &rfds, NULL, NULL, &tv );
	if ( res < 0 ) {
		goto exit;
	}

	if ( FD_ISSET( ctrl.s, &rfds ) ) {
		res = recv( ctrl.s, buf, WPA_BUF, 0 );

		if ( res < 0 ) {
			goto exit;
		}
		buf[ res ] = 0;
	}
// ecam2_log_debug("[%s] res %d %s", __FUNCTION__, res, buf);

	if(res > 0) {
		char* event_str = strstr(buf, WPA_EVENT_SCAN_RESULTS);
		if(event_str != NULL) {
			ecam2_log_debug("[%s] event: [%s]", __FUNCTION__, event_str);
			*event = WPACTRL_EVENT_CODE_SCAN_RESULTS;
		}
	}
	
exit:
	// ret = wpa_ctrl_set( &ctrl, "DETACH" );

	wpa_ctrl_close( &ctrl );

	return WPACTRL_SUCCESS;
}

/*
bssid=e8:94:f6:f3:29:af
ssid=test
id=0
passphrase=8888888888
psk=2fc43de3dd287c8a6f1cf8487e8872b48c6a498ac467a208c8fc8feabb486c
mode=station
pairwise_cipher=CCMP
group_cipher=TKIP
key_mgmt=WPA2-PSK
wpa_state=COMPLETED
ip_address=192.168.10.104
address=e0:b9:4d:75:49:14
signal_level=88
*/

static WPACTRL_RET_CODE
wpa_ctrl_parser_status( char *src )
{
	char *next, *value;
	memset( &_wpa_info, 0, sizeof( _wpa_info ) );
	_wpa_info.status = WPA_STATUS_ERROR;

	while ( src && src[ 0 ] ) {
		next	= strchr( src, '\n' );
		if ( next ) {
			next[ 0 ] = 0;
			next ++;
		}

		value = strchr( src, '=' );
		if ( value ) {
			value[ 0 ] = 0;
			value ++;
		} else {
			return WPACTRL_ERROR;
		}

		if ( memcmp( src, "wpa_state", 9 ) == 0 ) {
			if ( memcmp( value, "COMPLETED", 9 ) == 0 ) {
				_wpa_info.status = WPA_STATUS_COMPLETED;
			} else if ( memcmp( value, "SCANNING", 8 ) == 0 ) {
				_wpa_info.status = WPA_STATUS_SCANNING;
			} else if ( memcmp( value, "ASSOCIATING", 11 ) == 0 ) {
				_wpa_info.status = WPA_STATUS_ASSOCIATING;
			} else if ( memcmp( value, "INACTIVE", 8 ) == 0 ) {
				_wpa_info.status = WPA_STATUS_INACTIVE;
			} else if ( memcmp( value, "DISCONNECTED", 12 ) == 0 ) {
				_wpa_info.status = WPA_STATUS_DISCONNECTED;
			} else {
				_wpa_info.status = WPA_STATUS_ERROR;
			}
		} else if ( memcmp( src, "mode", 4 ) == 0 ) {
			if ( memcmp( value, "station", 7 ) == 0 ) {
				_wpa_info.mode	= WIFI_MODE_STA;
			} else if ( memcmp( value, "ap", 2 ) == 0 ) {
				_wpa_info.mode	= WIFI_MODE_AP;
			} else {
				_wpa_info.mode	= WIFI_MODE_NONE;
			}
		} else if ( memcmp( src, "address", 7 ) == 0 ) {
			sscanf( value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &_wpa_info.mac[ 0 ], &_wpa_info.mac[ 1 ], &_wpa_info.mac[ 2 ],
															&_wpa_info.mac[ 3 ], &_wpa_info.mac[ 4 ], &_wpa_info.mac[ 5 ] );
		} else if ( memcmp( src, "ip_address", 10 ) == 0 ) {
			sscanf( value, "%hhd.%hhd.%hhd.%hhd", &_wpa_info.ip[ 0 ], &_wpa_info.ip[ 1 ], &_wpa_info.ip[ 2 ], &_wpa_info.ip[ 3 ] );
		} else if ( memcmp( src, "signal_level", 12 ) == 0 ) {
			sscanf( value, "%d", &_wpa_info.signal_level );
		}
		

		src = next;
	}

	return WPACTRL_SUCCESS;
}

static WPACTRL_RET_CODE
wpa_ctrl_parser_siganl_poll( char *src )
{
	char *next, *value;
	memset( &_wpa_info, 0, sizeof( _wpa_info ) );
	_wpa_info.status = WPA_STATUS_COMPLETED;

	while ( src && src[ 0 ] ) {
		next = strchr( src, '\n' );
		if ( next ) {
			next[ 0 ] = 0;
			next ++;
		}

		value = strchr( src, '=' );
		if ( value ) {
			value[ 0 ] = 0;
			value ++;
		} else {
			return WPACTRL_ERROR;
		}

		if ( memcmp( src, "RSSI", 4 ) == 0 ) {
			sscanf( value, "%d", &_wpa_info.signal_level);
		}
		src = next;
	}

	return WPACTRL_SUCCESS;
}

static WPACTRL_RET_CODE
wpa_ctrl_get_signal_poll( void )
{
	struct wpa_ctrl ctrl;
	char buf[ WPA_BUF ];
	int ret;

	if ( wpa_ctrl_open( WPA_CTRL_WLAN0, &ctrl ) == WPACTRL_ERROR ) {
		ecam2_log_warn("Could not get ctrl interface!" );
		return WPACTRL_NOTFOUND;
	}

	ret = wpa_ctrl_get( &ctrl, "SIGNAL_POLL", buf, WPA_BUF );
	wpa_ctrl_close( &ctrl );

	if ( ret <= 0 ) {
		return WPACTRL_ERROR;
	} else {
		pthread_mutex_lock( &mutex );
		ret	= wpa_ctrl_parser_siganl_poll( buf );
		pthread_mutex_unlock( &mutex );

        return ret;
	}
}

static WPACTRL_RET_CODE
wpa_ctrl_get_status( void )
{
	struct wpa_ctrl ctrl;
	char buf[ WPA_BUF ];
	int ret;

	if ( wpa_ctrl_open( WPA_CTRL_WLAN0, &ctrl ) == WPACTRL_ERROR ) {
		ecam2_log_warn("Could not get ctrl interface!" );
		return WPACTRL_NOTFOUND;
	}

	ret = wpa_ctrl_get( &ctrl, "STATUS", buf, WPA_BUF );
	wpa_ctrl_close( &ctrl );

	if ( ret <= 0 ) {
		return WPACTRL_ERROR;
	} else {
		pthread_mutex_lock( &mutex );
		ret	= wpa_ctrl_parser_status( buf );
		pthread_mutex_unlock( &mutex );

        return ret;
	}
}

static WIFI_SECURITY
wpa_parser_security( char *flag )
{
	WIFI_SECURITY st = WIFI_SECURITY_UNKNOWN;

	if ( strstr( flag, "WEP" ) != NULL ) {
		st = WIFI_SECURITY_WEP_PSK;
	} else if ( strstr(flag, "WPA2-PSK-TKIP" ) != NULL ) {
		st = WIFI_SECURITY_WPA2_TKIP_PSK;
	} else if ( strstr( flag, "WPA-PSK-TKIP" ) != NULL ) {
        st = WIFI_SECURITY_WPA_TKIP_PSK;
	} else if ( strstr( flag, "WPA2-PSK-CCMP" ) != NULL ) {
        st = WIFI_SECURITY_WPA2_AES_PSK;
	} else if ( strstr( flag, "WPA-PSK-CCMP" ) != NULL ) {
        st = WIFI_SECURITY_WPA_AES_PSK;
	} else if ( strstr( flag, "WPA2-PSK-CCMP+TKIP" ) != NULL ) {
		st = WIFI_SECURITY_WPA2_MIXED_PSK;
		if ( strstr( flag, "WPA-PSK-CCMP+TKIP" ) != NULL ) {
			st = WIFI_SECURITY_WPA_WPA2_MIXED;
		}
	} else if ( strstr( flag, "WPA2-PSK+SAE-CCMP" ) != NULL ) {
        st = WIFI_SECURITY_WPA3;
	} else if ( strstr( flag, "WPA2-SAE-CCMP" ) != NULL ) {
        st = WIFI_SECURITY_WPA3;
	} else if ( ( strlen( flag ) == 0 ) ) {
		st = WIFI_SECURITY_OPEN;
	} else if ( ( !strncmp( flag, "[ESS]", 5 ) ) && ( strlen( flag ) == 5 ) ) {
		st = WIFI_SECURITY_OPEN;
	} else if ( ( !strncmp( flag, "[WPS][ESS]", 10 ) ) && ( strlen( flag ) == 10 ) ) {
		st = WIFI_SECURITY_WPS_OPEN;
	}

	return st;
}

static int
wpa_frequency_to_channel( int frequency )
{
	int i;

	static short band_24g[ 15 ]	= {
		2400, 2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484,
	};

	static struct {

		short	channel;
		short	frequency;

	} band_5g[ 28 ] = {
		{ 34,	5170, },
		{ 36,	5180, },
		{ 38,	5190, },
		{ 40,	5200, },
		{ 42,	5210, },
		{ 44,	5220, },
		{ 46,	5230, },
		{ 48,	5240, },
		{ 52,	5260, },
		{ 56,	5280, },
		{ 60,	5300, },
		{ 64,	5320, },
		{ 100,	5500, },
		{ 104,	5520, },
		{ 108,	5540, },
		{ 112,	5560, },
		{ 116,	5580, },
		{ 120,	5600, },
		{ 124,	5620, },
		{ 128,	5640, },
		{ 132,	5660, },
		{ 136,	5680, },
		{ 140,	5700, },
		{ 149,	5745, },
		{ 153,	5765, },
		{ 157,	5785, },
		{ 161,	5805, },
		{ 165,	5825, },
	};

	if ( ( frequency > 2400 ) && ( frequency < 2500 ) ) {
		for ( i = 0; i < 15; i ++ ) {
			if ( frequency == band_24g[ i ] ) {
				return i;
			}
		}
	} else if ( ( frequency > 5100 ) && ( frequency < 5900 ) ) {
		for ( i = 0; i < 28; i ++ ) {
			if ( frequency == band_5g[ i ].frequency ) {
				return band_5g[ i ].channel;
			}
		}
	}

	return 0;
}

static uint32_t
wpa_ctrl_scan_proc( const char *ssid, WPA_ScanResult_t *results, uint32_t max_result )
{
	struct wpa_ctrl	ctrl;
	uint32_t	aps = 0;

	WPACTRL_EVENT_CODE event_code = WPACTRL_EVENT_CODE_NULL;
	char buf[ WPA_BUF ] = { 0, };

	if ( wpa_ctrl_open( WPA_CTRL_WLAN0, &ctrl ) == WPACTRL_ERROR ) {
		ecam2_log_warn("Could not get ctrl interface!" );
		return 0;
	} else if ( wpa_ctrl_set( &ctrl, "SCAN" ) == WPACTRL_ERROR ) {
		time_delay_ms(500);
		wpa_ctrl_close( &ctrl );
		return 0;
	} else {
		int wait;
		for ( wait = 0; wait < 10; wait ++ ) {
			if ( wpa_ctrl_get( &ctrl, "STATUS", buf, WPA_BUF ) > 0 ) {
				pthread_mutex_lock( &mutex );
				wpa_ctrl_parser_status( buf );
				pthread_mutex_unlock( &mutex );

				wpa_ctrl_event_recv(&event_code);

				// ecam2_log_warn("[%s] + status %d event_code %d", __FUNCTION__, _wpa_info.status, event_code);
	
				if( (_wpa_info.status == WPA_STATUS_SCANNING) || \
					(_wpa_info.status == WPA_STATUS_COMPLETED) || \
					(event_code == WPACTRL_EVENT_CODE_SCAN_RESULTS)) {
					int cnt = 0;
					if( wpa_ctrl_get( &ctrl, "SCAN_RESULTS", buf, WPA_BUF ) > 0 ) {
						int frequency;
						char flags[ 64 ];
						char *p = NULL, *temp = NULL;

						p = strtok_r( buf, "\n", &temp );
						while ( ( p = strtok_r( NULL, "\n", &temp ) ) != NULL ) {						
							cnt = sscanf( p, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\t%d\t%d\t%127s\t%63[^\n]",
												&results[ aps ].bssid[ 0 ], &results[ aps ].bssid[ 1 ], &results[ aps ].bssid[ 2 ],
												&results[ aps ].bssid[ 3 ], &results[ aps ].bssid[ 4 ], &results[ aps ].bssid[ 5 ],
												&frequency, &results[ aps ].rssi, flags, results[ aps ].ssid );
							if ( cnt != 10 ) {
								continue;
							}

							if ( ( ssid == NULL ) || ( strcmp( ssid, results[ aps ].ssid ) == 0 ) ) {
								results[ aps ].channel = wpa_frequency_to_channel( frequency );

								if ( results[ aps ].channel ) {
									results[ aps ].ssid_len	= strlen( results[ aps ].ssid );
									results[ aps ].security	= wpa_parser_security( flags );
									aps ++;
								} else {
									ecam2_log_warn("Unsupported Channel: %d",frequency );
								}
							}

							if ( aps >= max_result ) {
								break;
							}
						}
					}
					if(cnt != 0)
						break;
				} else if(_wpa_info.status == WPA_STATUS_INACTIVE) {
					break;
				}
			} else {
				break;
			}
			time_delay_ms( 50 );
		}

		wpa_ctrl_close( &ctrl );

		return aps;
	}
	return 0;
}


//==========================================================================
// APIs
//==========================================================================
WPACTRL_RET_CODE
WPACtrl_UpdateStatus( void )
{
    return wpa_ctrl_get_status();
}

BOOL
WPACtrl_IsReady( void )
{
    WPA_STATUS status;

	pthread_mutex_lock( &mutex );
	if ( _wpa_info.status == WPA_STATUS_COMPLETED ) {
		status	= _wpa_info.status;
	} else {
		status	= WPA_STATUS_ERROR;
	}
	pthread_mutex_unlock( &mutex );

	if ( status == WPA_STATUS_COMPLETED ) {
		return TRUE;
	} else {
		return FALSE;
	}
}

WIFI_MODE
WPACtrl_GetMode( void )
{
    WIFI_MODE mode;

	pthread_mutex_lock( &mutex );
	if ( _wpa_info.status == WPA_STATUS_COMPLETED ) {
		mode	= _wpa_info.mode;
	} else {
		mode	= WIFI_MODE_NONE;
	}
	pthread_mutex_unlock( &mutex );

	return mode;
}


WPACTRL_RET_CODE
WPACtrl_GetSignalLevel( int *rssi )
{
	WPACTRL_RET_CODE ret = WPACTRL_SUCCESS;

	if ( rssi == NULL ) {
		ret = WPACTRL_BADARG;
	} else {
		if ( WPACTRL_SUCCESS == wpa_ctrl_get_signal_poll() ) {
			pthread_mutex_lock( &mutex );
			if ( _wpa_info.status == WPA_STATUS_COMPLETED ) {
				*rssi = _wpa_info.signal_level;
			} else {
				*rssi = 0;
			}
			pthread_mutex_unlock( &mutex );
			ret = WPACTRL_SUCCESS;
		} else {
			*rssi = 0;
			ret = WPACTRL_ERROR;
		}
	}

	return ret;
}

uint32_t
WPACtrl_Scan( WPA_ScanResult_t *results, uint32_t max_result )
{
	return wpa_ctrl_scan_proc( NULL, results, max_result );
}

uint32_t
WPACtrl_SearchBySSID(const char *ssid, WPA_ScanResult_t *results, uint32_t max_result )
{
	return wpa_ctrl_scan_proc( ssid, results, max_result );
}

WPACTRL_RET_CODE
WPACtrl_Disconnect( void )
{
	struct wpa_ctrl ctrl;
	int ret;

	if ( wpa_ctrl_open( WPA_CTRL_WLAN0, &ctrl ) == WPACTRL_ERROR ) {
		ecam2_log_warn("Could not get ctrl interface!" );
		return WPACTRL_NOTFOUND;
	}

	ret = wpa_ctrl_set( &ctrl, "DISCONNECT" );
	wpa_ctrl_close( &ctrl );

	return ret;
}

WPACTRL_RET_CODE
WPACtrl_Connect( uint8_t *bssid, char *ssid, char *password, WIFI_SECURITY security_type )
{
	struct wpa_ctrl ctrl;
	int ret = 0;

	if ( ssid == NULL ) {
		return WPACTRL_BADARG;
	}

	if ( _wpa_info.status == WPA_STATUS_DISCONNECTED ) {
		system( "ifconfig wlan0 0.0.0.0" );
	}

	if ( wpa_ctrl_open( WPA_CTRL_WLAN0, &ctrl ) == WPACTRL_ERROR ) {
		ecam2_log_warn("Could not get ctrl interface!" );
		return WPACTRL_NOTFOUND;
	}

	ret = wpa_ctrl_setup( &ctrl, bssid, ssid, password, security_type );
	wpa_ctrl_close( &ctrl );

	if ( ret != WPACTRL_SUCCESS ) {
		ecam2_log_error("WPACtrl_Connect Fail..." );
		return ret;
	}

	return WPACTRL_SUCCESS;
}

WPACTRL_RET_CODE
WPACtrl_Start(const char* if_name)
{
	char cmd[64];

	sprintf(cmd, "ifconfig %s down", if_name);
	system(cmd);
	sleep( 1 );

	sprintf(cmd, "ifconfig %s up", if_name);
	system(cmd);
	sleep( 1 );

	sprintf(cmd, "killall wpa_supplicant");
	system(cmd);
	sleep(1);

	sprintf(cmd, "wpa_supplicant -B -i %s -c %s", if_name, WPA_CFG);
	system(cmd);
	sleep(1);

	return WPACTRL_SUCCESS;
}

WPACTRL_RET_CODE
WPACtrl_GenConf( WIFI_MODE mode, WPACTRL_CHANNEL_PLAN ch, WPACTRL_ADAPTIVITY adv )
{
	FILE *fp;

	if ( mode != WIFI_MODE_STA ) {
		return WPACTRL_NOTSTA;
	}
	
	fp = fopen( WPA_CFG, "w" );
	if ( fp == NULL ) {
		return WPACTRL_ERROR;
	}

	switch ( ch ) {
		case WPACTRL_CHANNEL_PLAN_KOREA:
			fprintf( fp,"country=%s\n", "KR" );
			break;
		case WPACTRL_CHANNEL_PLAN_EU:
			fprintf( fp,"country=%s\n", "DE" );
			break;
		case WPACTRL_CHANNEL_PLAN_NORTH_AMERICA:
			fprintf( fp,"country=%s\n", "US" );
			break;
		case WPACTRL_CHANNEL_PLAN_JAPAN:
			fprintf( fp,"country=%s\n", "JP" );
			break;
		default:
			fprintf( fp,"country=%s\n", "US" );
			break;
	}

	fprintf( fp,"ctrl_interface=%s\n", WPA_CTRL );
	fprintf( fp,"update_config=1\n" );

	fclose( fp );
	
	return WPACTRL_SUCCESS;
}

WPACTRL_RET_CODE
WPACtrl_Init(const char* if_name)
{
	char cmd[64];
	sprintf(cmd, "ifconfig %s up", if_name);
	system(cmd);

	return WPACTRL_SUCCESS;
}

/*
int main(int argc, char** argv)
{
	struct wpa_ctrl *ctrl;
	int ret;

	ctrl = wpa_ctrl_open(WPA_CTRL_WLAN0);
	if (!ctrl){
		printf("Could not get ctrl interface!\n");
		return -1;
	}

	ret = wpa_ctrl_command(ctrl,"INTERFACES");
	ret = wpa_ctrl_command(ctrl,"SCAN");
	ret = wpa_ctrl_command(ctrl,"SCAN_RESULTS");
	ret = wpa_ctrl_command(ctrl,"STATUS");

        wpa_ctrl_close(ctrl);

	return 0;
}
*/
