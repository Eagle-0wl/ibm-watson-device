#include <stdio.h>
#include <signal.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <uci.h>
#include <syslog.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
/* Include header file of IBM Watson IoT platform C Client for devices */ 
#include "iotp_device.h"

struct Data {
	char *orgId;
	char *typeId;
	char *deviceId;
	char *token;
	int useEnv;
	int testCycle;
    IoTPConfig *config;
    IoTPDevice *device;
};

volatile int interrupt = 0;

enum {
	TOTAL_MEMORY,
	FREE_MEMORY,
	SHARED_MEMORY,
	BUFFERED_MEMORY,
	__MEMORY_MAX,
};

enum {
	MEMORY_DATA,
	__INFO_MAX,
};

static const struct blobmsg_policy memory_policy[__MEMORY_MAX] = {
	[TOTAL_MEMORY] = { .name = "total", .type = BLOBMSG_TYPE_INT64 },
	[FREE_MEMORY] = { .name = "free", .type = BLOBMSG_TYPE_INT64 },
	[SHARED_MEMORY] = { .name = "shared", .type = BLOBMSG_TYPE_INT64 },
	[BUFFERED_MEMORY] = { .name = "buffered", .type = BLOBMSG_TYPE_INT64 },
};

static const struct blobmsg_policy info_policy[__INFO_MAX] = {
	[MEMORY_DATA] = { .name = "memory", .type = BLOBMSG_TYPE_TABLE },
};

char *format_data (long long int ram){
    static char *data;
    size_t needed;
    char dataString[20];
    sprintf(dataString, "%lld", ram);	
	needed = snprintf(NULL, 0, "{\"Router\" : {\"SensorID\": \"Free ram in bytes\", \"Router system\": %s }}", dataString) + 1;
   	data = malloc(needed);
    sprintf(data, "{\"Router\" : {\"SensorID\": \"Free ram in bytes\", \"Router system\": %s }}", dataString);
    return data;
}

static void ubus_ram(struct ubus_request *req, int type, struct blob_attr *msg) {

    syslog(LOG_WARNING, "works4 ");
	char *data;
    struct Data *connection = (struct Data *)req->priv;
	struct blob_attr *tb[__INFO_MAX];
	struct blob_attr *memory[__MEMORY_MAX];

	blobmsg_parse(info_policy, __INFO_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[MEMORY_DATA]) {
		fprintf(stderr, "No memory data received\n");
		return;
	}

	blobmsg_parse(memory_policy, __MEMORY_MAX, memory,blobmsg_data(tb[MEMORY_DATA]), blobmsg_data_len(tb[MEMORY_DATA]));

    data=format_data(blobmsg_get_u64(memory[FREE_MEMORY]));
    IoTPDevice_sendEvent(connection->device,"status", data, "json", QoS0, NULL);
    free(data);
}

/* Usage text */
void usage(void) {
    syslog(LOG_INFO, "Usage: appIBM --organization orgID --type deviceType --deviceId deviceID --token TOKEN");
    exit(1);
}

void sigHandler(int signo) {
    signal(SIGINT, NULL);
    syslog(LOG_INFO, "Received signal: %d", signo);
    closelog();
    interrupt = 1;
}

/* Get and process command line options */
struct Data getopts(int argc, char** argv)
{
	struct Data Connection_data;
    int count = 1;
    while (count < argc){
        if (strcmp(argv[count], "--organization") == 0){
            if (++count < argc)
                Connection_data.orgId = argv[count];
            else
                usage();
        }
        if (strcmp(argv[count], "--type") == 0){
            if (++count < argc)
                Connection_data.typeId = argv[count];
            else
                usage();
        }
        if (strcmp(argv[count], "--deviceId") == 0){
            if (++count < argc)
                Connection_data.deviceId = argv[count];
            else
                usage();
        }
        if (strcmp(argv[count], "--token") == 0){
            if (++count < argc)
                Connection_data.token = argv[count];
            else
                usage();
        }
        if (strcmp(argv[count], "--useEnv") == 0) {
            Connection_data.useEnv = 1;
        }
        if (strcmp(argv[count], "--testCycle") == 0) {
            if (++count < argc)
                Connection_data.testCycle = atoi(argv[count]);
            else
                usage();
        }
        count++;
    }
    return Connection_data;
}

void MQTTTraceCallback (int level, char * message)
{
    if (level > 0)
    	syslog(LOG_INFO, "%s", message? message:"NULL");
    fflush(stdout);
}

static struct Data *Connect_device (struct Data Connection_data){
    int rc=0;
    static struct Data connection;
    Connection_data.config = NULL;
    Connection_data.device = NULL;

    IoTPConfig_create(&Connection_data.config, NULL);
	IoTPConfig_setProperty(Connection_data.config, "identity.orgId", Connection_data.orgId);
	IoTPConfig_setProperty(Connection_data.config, "identity.typeId", Connection_data.typeId);
	IoTPConfig_setProperty(Connection_data.config, "identity.deviceId", Connection_data.deviceId);
	IoTPConfig_setProperty(Connection_data.config, "auth.token", Connection_data.token);	
	IoTPDevice_create(&Connection_data.device, Connection_data.config);
	connection = Connection_data;

    /* Set MQTT Trace handler */
    rc = IoTPDevice_setMQTTLogHandler(Connection_data.device, &MQTTTraceCallback);
    if ( rc != 0 ) {
    	syslog(LOG_WARNING, "Failed to set MQTT Trace handler: rc=%d", rc);
    }

    /* Invoke connection API IoTPDevice_connect() to connect to WIoTP. */
    rc = IoTPDevice_connect(Connection_data.device);
    if ( rc != 0 ) {
    	syslog(LOG_ERR, "Failed to connect to Watson IoT Platform: rc=%d", rc);
    	syslog(LOG_ERR, "Returned error reason: %s\n", IOTPRC_toString(rc));
    	connection.token=NULL;
    }
    else
        syslog(LOG_WARNING, "Connection to IBM cloud successful");
return &connection;
}

/* Main program */
int main(int argc, char *argv[])
{
    int rc =0;
	int cycle = 0;
    struct Data Connection_data;
    struct Data *Connection_data_ptr;
    struct ubus_context *ctx;
    uint32_t id;
    struct sigaction action; 

	memset(&action, 0, sizeof(struct sigaction));
	ubus_free(ctx);
	openlog("appIBM", LOG_PID, LOG_USER);
    
    /* check for args */
    if ( argc < 8) 
        usage();

    /* Set signal handlers */
    signal(SIGINT, sigHandler);
    signal(SIGTERM, sigHandler);

    /* get argument options */
    Connection_data=getopts(argc, argv);
	
    /* Set IoTP Client log handler */
    rc = IoTPConfig_setLogHandler(IoTPLog_FileDescriptor, stdout);
    if ( rc != 0 ) {
    	syslog(LOG_WARNING, "Failed to set IoTP Client log handler: rc=%d", rc);
    	goto cleanUp;
    }
    Connection_data_ptr = Connect_device (Connection_data);
    if (Connection_data_ptr->token==NULL)
        goto cleanUp;

	sigaction(SIGTERM, &action, NULL);
    while(!interrupt) {	
	    ctx = ubus_connect(NULL);
		if (!ctx) {
			syslog(LOG_INFO, "Failed to connect to ubus");
			return -1;
		}

		if (ubus_lookup_id(ctx, "system", &id) || ubus_invoke(ctx, id, "info", NULL, ubus_ram, Connection_data_ptr, 3000)) {
            
			syslog(LOG_INFO, "cannot request memory info from procd");
            rc=-1;
		}

		if (rc==0)
			syslog(LOG_INFO, "Data published");
        else
        	syslog(LOG_INFO, "Failed to publish data");

        if ( Connection_data_ptr->testCycle > 0 ) {
            cycle += 1;
            if ( cycle >= Connection_data_ptr->testCycle ) {
                break;
            }
        }
        sleep(10);
    }

    syslog(LOG_INFO, "Publish event cycle is complete.");

    /* Disconnect device */
    rc = IoTPDevice_disconnect(Connection_data_ptr->device);
    if ( rc != IOTPRC_SUCCESS ) {
        syslog(LOG_ERR, "ERROR: Failed to disconnect from  Watson IoT Platform: rc=%d", rc);
    }
cleanUp:
    /* Destroy client */
    IoTPDevice_destroy(Connection_data_ptr->device);

    /* Clear configuration */
    IoTPConfig_clear(Connection_data_ptr->config);
    ubus_free(ctx);
	closelog();
    return 0;
}

