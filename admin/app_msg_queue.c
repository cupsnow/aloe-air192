
#include <admin/app_msg_queue.h>

/*---------------------------------------------------------------------------
							Defined Constants
 ---------------------------------------------------------------------------*/
static const char *tag = "app_msg_queue";

/*---------------------------------------------------------------------------
   								Variables
 ---------------------------------------------------------------------------*/
static msg_queue_ctl _host_queue = { .use_keygen = 0,
									 .key = (key_t) MSG_QUEUE_KEY_HOST};

/*---------------------------------------------------------------------------
   								Function prototypes
 ---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------
   								Implementation
 ---------------------------------------------------------------------------*/
int app_msg_queue_init(void)
{
	int ret = SUCCESS;
	ret |= app_msg_queue_create(&_host_queue);

	return ret;
}

int app_msg_queue_create(msg_queue_ctl *p_Qcb)
{
	if (!p_Qcb) {
		ecam2_log_error("%s, error... null  p_Qcb !", __FUNCTION__);
		return FAIL;
	}

	if (p_Qcb->use_keygen) {
		if (!p_Qcb->keygen_sz) {
			ecam2_log_error("%s, error... null  keygen_sz !", __FUNCTION__);
			return FAIL;
		}
		/*-- create unique key for message queue */
		if (-1== (p_Qcb->key = ftok(p_Qcb->keygen_sz,  p_Qcb->keygen_id))) {
			ecam2_log_error("%s: error...keygen failed !", __FUNCTION__);
			return FAIL;
		}
	}

	/*-- go and create the message queue */
	if (-1 == (p_Qcb->qid = msgget(p_Qcb->key, (0666|IPC_CREAT)))) {
		ecam2_log_error("%s: error...msgget failed !", __FUNCTION__);
		return FAIL;
	}

	return SUCCESS;
}

int app_msg_queue_send_host(const unsigned int cmd, const unsigned int param)
{
	msg_queue_packet msg;
	msg.type = MSG_QUEUE_TYPE_HOST;
 	memcpy(&msg.cmd[0], &cmd, sizeof(cmd));
 	memcpy(&msg.cmd[4], &param, sizeof(param));
	
	return app_msg_queue_send(&_host_queue, &msg, MSG_QUEUE_PKT_SIZE);
}

int app_msg_queue_recv_host(unsigned int *pcmd, unsigned int *pparam)
{
	int ret = SUCCESS;
	
	msg_queue_packet msg;
	unsigned int cmd = 0;
	unsigned int param = 0;

	if (MSG_QUEUE_PKT_SIZE == msgrcv(_host_queue.qid, &msg, MSG_QUEUE_PKT_SIZE, MSG_QUEUE_TYPE_HOST, IPC_NOWAIT)) {
		memcpy(&cmd, &msg.cmd[0], sizeof(cmd));
		memcpy(&param, &msg.cmd[4], sizeof(param));
		*pcmd = cmd;
		*pparam = param;
	} else {
		ret = FAIL;
	}
	
	return ret;
}

int app_msg_queue_send(msg_queue_ctl *p_Qcb, msg_queue_packet *msg, size_t msgsz)
{
	if (!p_Qcb) {
		ecam2_log_error("ASSERT, %s,%d", __FUNCTION__, __LINE__);
		return FAIL;
	}
	
    if (0 == msgsnd(p_Qcb->qid, (void *)msg, msgsz, IPC_NOWAIT))
		return SUCCESS;

	return FAIL;
}

int app_msg_queue_remove(msg_queue_ctl *p_Qcb)
{
	int ret = SUCCESS;

	if (!p_Qcb || (-1 == p_Qcb->qid)) {
		ecam2_log_error("null queue !");
		return FAIL;
	}

	if (0 == msgctl(p_Qcb->qid, IPC_RMID, NULL)) {
		ret = SUCCESS;
	} else {
		ecam2_log_error("ERROR: failed to remove msgQ");
		ret = FAIL;
	}

	p_Qcb->qid = p_Qcb->key = -1;
	
	return ret;
}

int app_msg_queue_receive(msg_queue_ctl *p_Qcb, msg_queue_packet *msg, size_t msgsz, int type)
{
	int ret_len;

	if (!p_Qcb) {
		ecam2_log_error("ASSERT, %s,%d !", __FUNCTION__, __LINE__);
		return FAIL;
	}

	ret_len = msgrcv(p_Qcb->qid, (void *)msg, msgsz, type, IPC_NOWAIT);

	if(msgsz == ret_len) {
		return SUCCESS;
	}
	
	return FAIL;
}
