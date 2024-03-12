#ifndef  DEXATEK_MAIN_APP_MSG_QUEUE_H_
#define  DEXATEK_MAIN_APP_MSG_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------
				Includes
 ---------------------------------------------------------------------------*/
#include <admin/WPACtrl.h>
#include <sys/msg.h>

/*---------------------------------------------------------------------------
				Constants
 ---------------------------------------------------------------------------*/
// message queue key
#define MSG_QUEUE_KEY_HOST		(556680)
#define	MSG_QUEUE_KEY_CMD		(556681)

// message queue command size
#define MSG_QUEUE_CMD_SIZE		350
#define MSG_QUEUE_PARAM_SIZE	4

// message queue command type
#define MSG_QUEUE_TYPE_HOST		(100)
#define MSG_QUEUE_TYPE_CMD		(101)

/*---------------------------------------------------------------------------
				Types
 ---------------------------------------------------------------------------*/
typedef struct {
	unsigned	use_keygen;		// flag to control how the key of the msgQ is assigned
	int			keygen_id;		// the ID of auto keygen by ftok( ), only 8-bit is recognized
	char*		keygen_sz;		// the string of auto keygen by ftok( ), can use the prog name
	key_t		key;			// the key to identify the msgQ to be created
	int			qid;			// the ID of the msgQ created
} msg_queue_ctl;

typedef struct {
	long int type;					 // the type of the message
	char cmd[MSG_QUEUE_CMD_SIZE];	 // the payload of the message
	int param[MSG_QUEUE_PARAM_SIZE]; // to pass message-specific parameters
} msg_queue_packet;

/*---------------------------------------------------------------------------
				Macros
 ---------------------------------------------------------------------------*/
#define MSG_QUEUE_PKT_SIZE	sizeof(msg_queue_packet)


/*---------------------------------------------------------------------------
				Function prototypes
 ---------------------------------------------------------------------------*/
int app_msg_queue_init(void);
int app_msg_queue_create(msg_queue_ctl *p_Qcb);
int app_msg_queue_remove(msg_queue_ctl *p_Qcb);
int app_msg_queue_send(msg_queue_ctl *p_Qcb, msg_queue_packet *msg, size_t msgsz);
int app_msg_queue_receive(msg_queue_ctl *p_Qcb, msg_queue_packet *msg, size_t msgsz, int type);

int app_msg_queue_send_host(unsigned int cmd, unsigned int param);
int app_msg_queue_recv_host(unsigned int *pcmd, unsigned int *pparam);

#ifdef __cplusplus
}
#endif

#endif /* DEXATEK_MAIN_APP_MSG_QUEUE_H_ */
