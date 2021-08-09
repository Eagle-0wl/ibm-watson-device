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
};

struct Ramdata {
 long long int free_ram;
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

int format_data (long long int ram, char **data)
{
    int rc=0;
    size_t needed;
    char dataString[20];
    sprintf(dataString, "%lld", ram);	
	needed = snprintf(NULL, 0, "{\"Router\" : {\"SensorID\": \"Free ram in bytes\", \"Router system\": %s }}", dataString) + 1;
   	*data = (char*) malloc(needed);
    if (*data==NULL)
        rc=-1;
    else 
        sprintf(*data, "{\"Router\" : {\"SensorID\": \"Free ram in bytes\", \"Router system\": %s }}", dataString);
    return rc;
}

static void get_ram_usage(struct ubus_request *req, int type, struct blob_attr *msg) 
{    
    struct Ramdata *ram = (struct Ramdata *)req->priv;
	struct blob_attr *tb[__INFO_MAX];
	struct blob_attr *memory[__MEMORY_MAX];
	blobmsg_parse(info_policy, __INFO_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[MEMORY_DATA]) {
		syslog(LOG_ERR, "No memory data received");
	}else{
        blobmsg_parse(memory_policy, __MEMORY_MAX, memory,blobmsg_data(tb[MEMORY_DATA]), blobmsg_data_len(tb[MEMORY_DATA]));
        ram->free_ram=blobmsg_get_u64(memory[FREE_MEMORY]);
    }
	
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
        count++;
    }
    return Connection_data;
}

void MQTT_Trace_Callback (int level, char * message)
{
     if (level > 0)
     	syslog(LOG_INFO, "%s", message? message:"NULL");
}

static int init_device_connection (struct Data Connection_data,IoTPConfig **config, IoTPDevice **device ){
    int rc=0;
    IoTPConfig_create(&*config, NULL);
	IoTPConfig_setProperty(*config, "identity.orgId", Connection_data.orgId);
	IoTPConfig_setProperty(*config, "identity.typeId", Connection_data.typeId);
	IoTPConfig_setProperty(*config, "identity.deviceId", Connection_data.deviceId);
	IoTPConfig_setProperty(*config, "auth.token", Connection_data.token);	
	IoTPDevice_create(&*device, *config);
    syslog(LOG_INFO, "IBM Watson configuration successfully initialized");

    /* Set MQTT Trace handler */
    rc = IoTPDevice_setMQTTLogHandler(*device, &MQTT_Trace_Callback);
    if ( rc != 0 ) {
    	syslog(LOG_WARNING, "Failed to set MQTT Trace handler");
    }

    /* Invoke connection API IoTPDevice_connect() to connect to WIoTP. */
    rc = IoTPDevice_connect(*device);
    if ( rc != 0 ) {
    	syslog(LOG_ERR, "Failed to connect to Watson IoT Platform");
    	syslog(LOG_ERR, "Returned error reason: %s\n", IOTPRC_toString(rc));
    	rc=-1;
    } else {
        syslog(LOG_INFO, "Connection to IBM cloud was successful");
    }
    return rc;
}

/* Main program */
int main(int argc, char *argv[])
{
    char *data=NULL;
    IoTPConfig *config;
    IoTPDevice *device;
    int rc =0;
	int cycle = 0;
    struct Data Connection_data;
    struct ubus_context *ctx;
    uint32_t id;
    struct sigaction action;
    struct Ramdata *ram = malloc(sizeof *ram);

	memset(&action, 0, sizeof(struct sigaction));
	openlog("app_ibm", LOG_PID, LOG_USER);
    /* check for args */
    if ( argc < 8) 
        usage();

    /* Set signal handlers */
    signal(SIGINT, sigHandler);
    signal(SIGTERM, sigHandler);
    sigaction(SIGTERM, &action, NULL);

    /* get argument options */
    Connection_data=getopts(argc, argv);
    /* Set IoTP Client log handler */
    rc = IoTPConfig_setLogHandler(IoTPLog_FileDescriptor, stdout);
    if ( rc != 0 ) {
    	syslog(LOG_WARNING, "Failed to set IoTP Client log handler");
    	goto cleanUp;
    }

    init_device_connection(Connection_data,&config, &device);
    ctx = ubus_connect(NULL);

    if (!ctx) {
	    syslog(LOG_INFO, "Failed to connect to ubus");
		goto cleanUp;
	}

    while(!interrupt) {	
        
		if (ubus_lookup_id(ctx, "system", &id) || ubus_invoke(ctx, id, "info", NULL, get_ram_usage, ram, 3000)) {
            
			syslog(LOG_WARNING, "cannot request memory info from procd");
            rc = -1;
		} else {
            rc = format_data(ram->free_ram, &data);
            if (rc == -1){
                syslog(LOG_ERR, "failed to format data");
            }
            rc = IoTPDevice_sendEvent(device,"status", data, "json", QoS0, NULL);
            if (rc == 0)
			    syslog(LOG_INFO, "Data published");
            else
        	    syslog(LOG_INFO, "Failed to publish data");
        sleep(10);
        }
    }

cleanUp:
    /* Disconnect device */
    rc = IoTPDevice_disconnect(device);
    if ( rc != IOTPRC_SUCCESS ) {
        syslog(LOG_ERR, "ERROR: Failed to disconnect from  Watson IoT Platform");
    }
    /* Destroy client */
    IoTPDevice_destroy(device);

    /* Clear configuration */
    IoTPConfig_clear(config);
    ubus_free(ctx);
	closelog();
    return 0;
}