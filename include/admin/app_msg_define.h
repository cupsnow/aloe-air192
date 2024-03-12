#ifndef  DEXATEK_MAIN_APP_MSG_DEFINE_H_
#define  DEXATEK_MAIN_APP_MSG_DEFINE_H_

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------
								Includes
 ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
   								  Macros
 ---------------------------------------------------------------------------*/
typedef enum {
	MSG_GRP_BEGIN = 0x01,
	MSG_GRP_HOST = MSG_GRP_BEGIN,
	MSG_GRP_APP,
	MSG_GRP_MAX,
} msg_group_t;

typedef enum {
	/*-- 8 bits only, max is 0xFF !! */
	MSG_ID_HOST_BEGIN = 0x01,
	MSG_ID_HOST_A = MSG_ID_HOST_BEGIN,
	MSG_ID_HOST_MAX,
} msg_id_host_t;

typedef enum {
	/*-- 8 bits only, max is 0xFF !! */
	MSG_ID_APP_BEGIN = 0x01,
	MSG_ID_APP_SYS = MSG_ID_APP_BEGIN,
	MSG_ID_APP_LED,
	MSG_ID_APP_KEY,
	MSG_ID_APP_ISP,
	MSG_ID_APP_NET,
	MSG_ID_APP_HOMEKIT,
	MSG_ID_APP_MAX,
} msg_id_app_t;

#define MSG_CMD_MAKE(grp, id, cmd)  \
					( \
						((((unsigned int)grp)&0xFFu)<<24) \
						| ((((unsigned int)id)&0xFFu)<<16) \
						| (((unsigned int)cmd)&0xFFFFu) \
					)

#define MSG_GRP_GET(val)	(((val)&0xFF000000)>>24)
#define MSG_ID_GET(val)		(((val)&0x00FF0000)>>16)
#define MSG_CMD_GET(val)	((val)&0x0000FFFF)

#define MSG_APP_CMD_MAKE(id, cmd16)		MSG_CMD_MAKE(MSG_GRP_APP, id, cmd16)
#define MSG_HOST_CMD_MAKE(id, cmd16)	MSG_CMD_MAKE(MSG_GRP_HOST, id, cmd16)

/*---------------------------------------------------------------------------
								Constants
 ---------------------------------------------------------------------------*/
// Host MSG
#define MSG_HOST_A					MSG_HOST_CMD_MAKE(MSG_ID_HOST_A, 0x0000)
#define MSG_HOST_A1					MSG_HOST_CMD_MAKE(MSG_ID_HOST_A, 0x0001)
#define MSG_HOST_A2					MSG_HOST_CMD_MAKE(MSG_ID_HOST_A, 0x0002)
#define MSG_HOST_A3					MSG_HOST_CMD_MAKE(MSG_ID_HOST_A, 0x0003)

// App MSG
// @ sys
#define MSG_APP_SYS_REBOOT			MSG_APP_CMD_MAKE(MSG_ID_APP_SYS, 0x0000)
// @ LED 
#define MSG_APP_LED_OFF				MSG_APP_CMD_MAKE(MSG_ID_APP_LED, 0x0000)
#define MSG_APP_LED_RED				MSG_APP_CMD_MAKE(MSG_ID_APP_LED, 0x0001)
#define MSG_APP_LED_BLUE			MSG_APP_CMD_MAKE(MSG_ID_APP_LED, 0x0002)
// @ Key
#define MSG_APP_KEY_PRESS			MSG_APP_CMD_MAKE(MSG_ID_APP_KEY, 0x0000)
#define MSG_APP_KEY_RELEASE			MSG_APP_CMD_MAKE(MSG_ID_APP_KEY, 0x0001)
#define MSG_APP_KEY_LONG_RELEASE	MSG_APP_CMD_MAKE(MSG_ID_APP_KEY, 0x0002)
// @ ISP
#define MSG_APP_ISP_MIRROR_SET		MSG_APP_CMD_MAKE(MSG_ID_APP_ISP, 0x0000)
#define MSG_APP_ISP_FLIP_SET		MSG_APP_CMD_MAKE(MSG_ID_APP_ISP, 0x0001)
#define MSG_APP_ISP_FPS_SET_30		MSG_APP_CMD_MAKE(MSG_ID_APP_ISP, 0x0002)
#define MSG_APP_ISP_FPS_SET_25		MSG_APP_CMD_MAKE(MSG_ID_APP_ISP, 0x0003)
// @ network
#define MSG_APP_NET_IS_UP			MSG_APP_CMD_MAKE(MSG_ID_APP_NET, 0x0000)
#define MSG_APP_NET_IS_DOWN			MSG_APP_CMD_MAKE(MSG_ID_APP_NET, 0x0001)
#define MSG_APP_NET_BCT_DISCONNECT	MSG_APP_CMD_MAKE(MSG_ID_APP_NET, 0x0002)
#define MSG_APP_NET_BCT_RECONNECT	MSG_APP_CMD_MAKE(MSG_ID_APP_NET, 0x0003)
// @ homekit
#define MSG_APP_HOMEKIT_DHCP_DONE	MSG_APP_CMD_MAKE(MSG_ID_APP_HOMEKIT, 0x0000)
#define MSG_APP_HOMEKIT_LINK_SWITCH	MSG_APP_CMD_MAKE(MSG_ID_APP_HOMEKIT, 0x0001)
#define MSG_APP_HOMEKIT_ETHMON      MSG_APP_CMD_MAKE(MSG_ID_APP_HOMEKIT, 0x0002)
#define MSG_APP_HOMEKIT_DEFER_DHCP  MSG_APP_CMD_MAKE(MSG_ID_APP_HOMEKIT, 0x0003)

/*---------------------------------------------------------------------------
								Data Types
 ---------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* DEXATEK_MAIN_APP_MSG_DEFINE_H_ */
