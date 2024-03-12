//#include "dexatek/main_application/include/app/app_common.h"
//#include "dexatek/main_application/include/utilities/os_utilities.h"

#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#include <admin/WPACtrl.h>
#include <admin/air192.h>

#define WIFI_SCAN_RESULT_MAX								30
#define WIFI_PARAMETER_MAGIC								0x80503525
#define WIFI_PARAMETER_NAME_LENGTH							256
#define NETWORK_IPADDR_LEN									32

#define WIFI_INTERFACE_NAME									"wlan0"

static WPA_ScanResult_t _wifi_ap_list[WIFI_SCAN_RESULT_MAX];

const static char* tag = "wifi_manager";

#if 1

static uint64_t _dhcp_next_can_execute_time = 0;
static BOOL _wifi_in_zcip_mode = FALSE;

int wifi_manager_is_linked(void) 
{
	if ( WPACtrl_UpdateStatus() == WPACTRL_SUCCESS ) {
		return WPACtrl_IsReady();
	}

	return FALSE;
}

BOOL wifi_manager_dhcp_is_ready(const char* if_name) 
{
	BOOL ret = FALSE;

	struct ifreq ifr;
	int sock_fd;
	struct sockaddr_in *addr;

	memset( &ifr, 0, sizeof( struct ifreq ) );

	sock_fd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sock_fd < 0 ) {
		ecam2_log_warn("sock_fd < 0" );
		return FAIL;
	}

	strcpy( ifr.ifr_name, if_name );
	if ( ioctl( sock_fd, SIOCGIFFLAGS, &ifr ) < 0 ) {
		ecam2_log_warn("ioctl( sock_fd, SIOCGIFFLAGS, &ifr ) < 0" );
	} else if ( ioctl( sock_fd, SIOCGIFADDR, &ifr ) == 0 ) {
		addr = ( ( struct sockaddr_in * )&ifr.ifr_addr );

		if ( addr->sin_addr.s_addr ) {
			ret = TRUE;
		}
	}

	close( sock_fd );

	return ret;
}

int wifi_manager_zcip(const char* if_name, const char* script_path) 
{
	int ret = SUCCESS;

	char cmd[64];
	sprintf(cmd, "zcip %s %s", if_name, script_path);
	ret = system(cmd);

	ecam2_log_debug("[%s] + zcip ret =  %d", __FUNCTION__, ret);

	if (ret == SUCCESS) {
		_wifi_in_zcip_mode = TRUE;
	}

	return (ret == 0) ? SUCCESS : FAIL;
}

int wifi_manager_udhcpc(const char* if_name, WIFI_MANAGER_DHCP_TYPE type)
{
	int ret = SUCCESS;

	if (_wifi_in_zcip_mode == TRUE) {
		ecam2_log_debug("zcip mode, skip udhcpc");
		return SUCCESS;
	}

	system("killall -9 udhcpc");
	sleep( 1 );

	char cmd[64];
	if (type == WIFI_MANAGER_DHCP_TYPE_FOREGROUND) {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4", if_name);
	} else {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4 &", if_name);
	}
	ret = system(cmd);

	ecam2_log_info("[%s] udhcpc ret =  %d", __FUNCTION__, ret);
	
	return (ret == 0) ? SUCCESS : FAIL;
}

int wifi_manager_dhcp_force(const char* if_name, WIFI_MANAGER_DHCP_TYPE type)
{
	int ret = SUCCESS;

	_dhcp_next_can_execute_time = time64_get_current_ms() + (10 * SECOND);

	system("killall -9 udhcpc");
	system("killall -9 zcip");

	sleep( 1 );

	char cmd[64];
	if (type == WIFI_MANAGER_DHCP_TYPE_FOREGROUND) {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4", if_name);
	} else {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4 &", if_name);
	}
	ret = system(cmd);

	ecam2_log_info("[%s] udhcpc ret =  %d", __FUNCTION__, ret);

	return (ret == 0) ? SUCCESS : FAIL;
}

int wifi_manager_dhcp_with_parameter_force(const char* if_name, WIFI_MANAGER_DHCP_TYPE type, uint8_t secs, uint8_t retry)
{
	int i;
	int ret = SUCCESS;
	BOOL is_ready = FALSE;

	_dhcp_next_can_execute_time = time64_get_current_ms() + (10 * SECOND);

	system("killall -9 udhcpc");
	system("killall -9 zcip");

	sleep( 1 );

	char cmd[64];
	if (type == WIFI_MANAGER_DHCP_TYPE_FOREGROUND) {
		sprintf(cmd, "udhcpc -i %s -n -t %d -T %d", if_name, secs, retry);
	} else {
		sprintf(cmd, "udhcpc -i %s -n -t %d -T %d &", if_name, secs, retry);
	}
	ret = system(cmd);

	ecam2_log_info("[%s] udhcpc ret =  %d", __FUNCTION__, ret);

	return (ret == 0) ? SUCCESS : FAIL;
}

int wifi_manager_dhcp(const char* if_name, WIFI_MANAGER_DHCP_TYPE type)
{
	int ret = SUCCESS;

	if (_wifi_in_zcip_mode == TRUE) {
		ecam2_log_debug("zcip mode, skip dhcp");
		return SUCCESS;
	}

	if (time_after(time64_get_current_ms(), _dhcp_next_can_execute_time)) {
		_dhcp_next_can_execute_time = time64_get_current_ms() + (10 * SECOND);
	} else {
		ecam2_log_info("[%s] skip", __FUNCTION__);
		return SUCCESS;
	}

	system("killall -9 udhcpc");
	system("killall -9 zcip");

	sleep( 1 );

	char cmd[64];
	if (type == WIFI_MANAGER_DHCP_TYPE_FOREGROUND) {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4", if_name);
	} else {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4 &", if_name);
	}
	ret = system(cmd);

	ecam2_log_info("[%s] udhcpc ret =  %d", __FUNCTION__, ret);

	return (ret == 0) ? SUCCESS : FAIL;
}

int wifi_manager_ipsetup(const char* if_name,
		WIFI_MANAGER_DHCP_TYPE type, const char *cfg)
{
	int ret = SUCCESS;
	air192_ipsetup_t ipsetup;
	char cmd[200];

	_dhcp_next_can_execute_time = time64_get_current_ms() + (10 * SECOND);

	system("killall -9 udhcpc");
	system("killall -9 zcip");

	if (cfg == NULL) {
		if (strncasecmp(if_name, "eth", strlen("eth")) == 0) {
			cfg = eth_cfg;
		} else if (strncasecmp(if_name, "wlan", strlen("wlan")) == 0) {
			cfg = wlan_cfg;
		} else {
			cfg = wlan_cfg;
		}
	}

	/*
	 *
	 * ip=zcip
	 *
	 * ip=192.168.123.456
	 * netmask=255.255.255.0
	 * router=192.168.123.1
	 * dns=1.1.1.1
	 */

	air192_parse_ipsetup(cfg, &ipsetup);

	if ((ipsetup.parse_eno != 0)
			|| (ipsetup.ipmode & air192_ipmode_dhcp)
			|| (ipsetup.ipmode & air192_ipmode_auto)) {
//		ecam2_log_debug("%s config DHCP\n", cfg);
	} else if ((ipsetup.ipmode & air192_ipmode_zcip)) {
		ecam2_log_debug("%s config ZCIP\n", cfg);
		return FAIL;
	} else if (ipsetup.ip[0]) {
		ecam2_log_debug("%s %s ip: %s, msk: %s, gw: %s, dns: %s\n",
				cfg, if_name, ipsetup.ip, ipsetup.msk, ipsetup.gw, ipsetup.dns);

		sleep( 1 );

		snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s%s", if_name, ipsetup.ip,
				(ipsetup.msk[0] ? "netmask " : ""),
				(ipsetup.msk[0] ? ipsetup.msk : ""));
		if ((ret = system(cmd)) != 0) {
			ecam2_log_error("[%s] %s ret =  %d", __FUNCTION__, cmd, ret);
			return FAIL;
		}

		if (ipsetup.gw[0]) {
			snprintf(cmd, sizeof(cmd), "route add default gw %s dev %s",
					ipsetup.gw, if_name);
			if ((ret = system(cmd)) != 0) {
				ecam2_log_error("[%s] %s ret =  %d", __FUNCTION__, cmd, ret);
				return FAIL;
			}
		}

		if (ipsetup.dns[0]) {
			snprintf(cmd, sizeof(cmd), "rm -rf %s", resolv_cfg);
			if ((ret = system(cmd)) != 0) {
				ecam2_log_error("[%s] %s ret =  %d", __FUNCTION__, cmd, ret);
				return FAIL;
			}

			snprintf(cmd, sizeof(cmd), "/etc/init.d/func_test add_resolv_dns %s %s",
					resolv_cfg, ipsetup.dns);
			if ((ret = system(cmd)) != 0) {
				ecam2_log_error("[%s] %s ret =  %d", __FUNCTION__, cmd, ret);
				return FAIL;
			}
		}
		return SUCCESS;
	}

	sleep( 1 );

	if (type == WIFI_MANAGER_DHCP_TYPE_FOREGROUND) {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4", if_name);
	} else {
		sprintf(cmd, "udhcpc -i %s -n -t 15 -T 4 &", if_name);
	}
	ret = system(cmd);

	ecam2_log_info("[%s] udhcpc ret =  %d", __FUNCTION__, ret);
	
	return (ret == 0) ? SUCCESS : FAIL;
}

int wifi_manager_connect(const char* if_name, char *ssid, char *password) {
	int ret = SUCCESS;
	int results = 0;

	for(int i=0; i<5; i++) {
		results = WPACtrl_SearchBySSID(ssid, (WPA_ScanResult_t *)_wifi_ap_list, WIFI_SCAN_RESULT_MAX);
		ecam2_log_debug("[%s] + results %d", __FUNCTION__, results);
		if(results != 0) {
			break;
		}
	}

	if(results == 0) {
		ecam2_log_warn("[%s] SSID %s not found", __FUNCTION__, ssid);
		return FAIL;
	}

	WPA_ScanResult_t scan_result = _wifi_ap_list[0];

	WPACtrl_Connect(scan_result.bssid, scan_result.ssid, password, scan_result.security);

	BOOL is_linked = FALSE;

	for(int i=0; i<6; i++) {
		is_linked = wifi_manager_is_linked();
		if(is_linked == TRUE) {
			ecam2_log_debug("[%s] + ssid %s rssi %d ser %d", __FUNCTION__, scan_result.ssid, scan_result.rssi, scan_result.security);
			break;
		}
		sleep(1);
	}

	if(is_linked == FALSE) {
		ecam2_log_warn("[%s] fail ssid %s rssi %d ser %d", __FUNCTION__, scan_result.ssid, scan_result.rssi, scan_result.security);
		return FAIL;
	}

	wifi_manager_dhcp(WIFI_INTERFACE_NAME, WIFI_MANAGER_DHCP_TYPE_FOREGROUND);

	return ret;
}

int wifi_manager_scan(void) 
{
	for(int i=0; i<10; i++) {
		int results = WPACtrl_Scan((WPA_ScanResult_t *)_wifi_ap_list, WIFI_SCAN_RESULT_MAX);
		// ecam2_log_debug("[%s] + results %d", __FUNCTION__, results);
		for(int i=0; i<results; i++) {
			ecam2_log_debug("[%s] [%d] + ssid %s rssi %d ser %d", __FUNCTION__, i, _wifi_ap_list[i].ssid, _wifi_ap_list[i].rssi, _wifi_ap_list[i].security);
		}
		if(results != 0) {
			break;
		}
	}

	return SUCCESS;
}

int wifi_manager_rssi_get(int *rssi)
{
	return WPACtrl_GetSignalLevel(rssi);
}
#endif // air192 not used

int wifi_manager_ssid_security_get(const char *ssid, uint32_t *security)
{
	int results = 0;

	for(int i=0; i<10; i++) {
		results = WPACtrl_SearchBySSID(ssid, (WPA_ScanResult_t *)_wifi_ap_list, 1);
		if(results != 0) {
			break;
		}
	}

	if(results == 0) {
		return FAIL;
	}
	
	*security = _wifi_ap_list[0].security;

	return SUCCESS;
}

#if 0 // air192 not used
int wifi_manager_ssid_info(const char *ssid, short *channel, uint32_t *security, int *rssi)
{
	int results = 0;

	for(int i=0; i<20; i++) {
		results = WPACtrl_SearchBySSID(ssid, (WPA_ScanResult_t *)_wifi_ap_list, 1);
		if(results != 0) {
			break;
		}
	}

	if(results == 0) {
		return FAIL;
	}
	
	*channel = _wifi_ap_list[0].channel;
	*security = _wifi_ap_list[0].security;
	*rssi = _wifi_ap_list[0].rssi;

	return SUCCESS;
}

int wifi_manager_wpasup_stop(void)
{
	system("killall wpa_supplicant");
	// system("killall zcip");

	return SUCCESS;
}

int wifi_manager_wpasup_start(const char* if_name)
{	
	char cmd[64];
	sprintf(cmd, "wpa_supplicant -B -i %s -c %s", WIFI_INTERFACE_NAME, WPA_CFG);
	system(cmd);
	sleep(1);

	return SUCCESS;
}

int wifi_manager_init(const char* if_name) {
	int ret = 0;

	ecam2_log_debug("[%s] +", __FUNCTION__);

	// WPACtrl_Init(if_name);

	WPACtrl_GenConf(WIFI_MODE_STA, WPACTRL_CHANNEL_PLAN_DEFAULT, WPACTRL_ADAPTIVITY_DISABLE);

	WPACtrl_Start(if_name);

	sleep(1);

	return ret;
}
#endif // air192 not used
