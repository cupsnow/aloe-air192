#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum {

	WIFI_WEP_ENABLED		= ( 1 << 0 ),
	WIFI_SHARED_ENABLED		= ( 1 << 1 ),
	WIFI_WPA_SECURITY		= ( 1 << 2 ),
	WIFI_TKIP_ENABLED		= ( 1 << 3 ),
	WIFI_AES_ENABLED	    = ( 1 << 4 ),
	WIFI_WPA2_SECURITY		= ( 1 << 5 ),
	WIFI_WPA3_SECURITY		= ( 1 << 6 ),
	WIFI_WPS_ENABLED	    = ( 1 << 7 ),

};

typedef enum {

    WIFI_SECURITY_OPEN           = 0,                                                      //< Open security
    WIFI_SECURITY_WEP_PSK        = WIFI_WEP_ENABLED,                                         //< WEP Security with open authentication
    WIFI_SECURITY_WEP_SHARED     = ( WIFI_WEP_ENABLED | WIFI_SHARED_ENABLED ),                 //< WEP Security with shared authentication
    WIFI_SECURITY_WPA_TKIP_PSK   = ( WIFI_WPA_SECURITY  | WIFI_TKIP_ENABLED ),                 //< WPA Security with TKIP
    WIFI_SECURITY_WPA_AES_PSK    = ( WIFI_WPA_SECURITY  | WIFI_AES_ENABLED ),                  //< WPA Security with AES
    WIFI_SECURITY_WPA2_AES_PSK   = ( WIFI_WPA2_SECURITY | WIFI_AES_ENABLED ),                  //< WPA2 Security with AES
    WIFI_SECURITY_WPA2_TKIP_PSK  = ( WIFI_WPA2_SECURITY | WIFI_TKIP_ENABLED ),                 //< WPA2 Security with TKIP
    WIFI_SECURITY_WPA2_MIXED_PSK = ( WIFI_WPA2_SECURITY | WIFI_AES_ENABLED | WIFI_TKIP_ENABLED ),//< WPA2 Security with AES & TKIP
    WIFI_SECURITY_WPA_WPA2_MIXED = ( WIFI_WPA_SECURITY  | WIFI_WPA2_SECURITY ),                //< WPA/WPA2 Security
    WIFI_SECURITY_WPA3           = WIFI_WPA3_SECURITY,
    WIFI_SECURITY_WPS_OPEN       = WIFI_WPS_ENABLED,                                         //< WPS with open security
    WIFI_SECURITY_WPS_SECURE     = (WIFI_WPS_ENABLED | WIFI_AES_ENABLED),                      //< WPS with AES security

    WIFI_SECURITY_UNKNOWN        = -1,                                               //< May be returned by scan function if security is unknown.
                                                                                       //  Do not pass this to the join function!

    WIFI_SECURITY_FORCE_32_BIT   = 0x7fffffff                                        //< Exists only to force WIFI_SECURITY type to 32 bits

} WIFI_SECURITY;

typedef enum {
    WIFI_MANAGER_DHCP_TYPE_FOREGROUND,
    WIFI_MANAGER_DHCP_TYPE_BACKGROUND,
    WIFI_MANAGER_DHCP_TYPE_MAX
} WIFI_MANAGER_DHCP_TYPE;

int wifi_manager_init(const char* if_name);

int wifi_manager_scan(void);
int wifi_manager_ssid_info(const char *ssid, short *channel, uint32_t *security, int *rssi);
int wifi_manager_ssid_security_get(const char *ssid, uint32_t *security);

// TBC int wifi_manager_is_linked();
// TBC int wifi_manager_connect(const char* if_name, char *ssid, char *password);

int wifi_manager_rssi_get(int *rssi);

int wifi_manager_udhcpc(const char* if_name, WIFI_MANAGER_DHCP_TYPE type);
int wifi_manager_dhcp(const char* if_name, WIFI_MANAGER_DHCP_TYPE type);
int wifi_manager_dhcp_force(const char* if_name, WIFI_MANAGER_DHCP_TYPE type);
int wifi_manager_dhcp_with_parameter_force(const char* if_name, WIFI_MANAGER_DHCP_TYPE type, uint8_t secs, uint8_t retry);
int wifi_manager_ipsetup(const char* if_name, WIFI_MANAGER_DHCP_TYPE type, const char *cfg);
int wifi_manager_zcip(const char* if_name, const char* script_path);

int wifi_manager_wpasup_start(const char* if_name);
int wifi_manager_wpasup_stop(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WIFI_MANAGER_H */
