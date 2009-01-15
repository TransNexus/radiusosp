/*
 * rlm_osp.c
 *
 * Version: $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  TransNexus, Inc. <support@transnexus.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "osp/osp.h"
#include "osp/osputils.h"

/*
 * OSP module constants.
 */
#define OSP_STRBUF_SIZE     256
#define OSP_LOGBUF_SIZE     1024

#define OSP_DEF_LOGLEVEL    "1"                         /* Mapping default log level, long */
#define OSP_DEF_HWACCE      "no"                        /* Mapping default hardware accelerate flag */
#define OSP_MAX_SPS         8                           /* OSP max number of service points */
#define OSP_DEF_SPURI       "http://osptestserver.transnexus.com:1080/osp"  /* OSP default service point URI */
#define OSP_DEF_SPWEIGHT    "1000"                      /* Mapping default service point weight */
#define OSP_DEF_AUDITURL    "http://localhost:1234"     /* OSP default Audit URL */
#define OSP_DEF_PRIVATEKEY  "${raddbdir}/pkey.pem"      /* OSP default private key file */
#define OSP_DEF_LOCALCERT   "${raddbdir}/localcert.pem" /* OSP default localcert file */
#define OSP_MAX_CAS         4                           /* OSP max number of cacert files */
#define OSP_DEF_CACERT      "${raddbdir}/cacert_0.pem"  /* OSP default cacert file */
#define OSP_DEF_VALIDATION  1                           /* OSP default token validation, locally */
#define OSP_DEF_SSLLIFETIME "300"                       /* Mapping default SSL life time in seconds */
#define OSP_DEF_MAXCONN     "20"                        /* Mapping default max number of connections */
#define OSP_MIN_MAXCONN     1                           /* OSP min max number of connections */
#define OSP_MAX_MAXCONN     1000                        /* OSP max max number of connections */
#define OSP_DEF_PERSISTENCE "60000"                     /* Mapping default HTTP persistence in ms*/
#define OSP_DEF_RETRYDELAY  "0"                         /* Mapping default retry delay */
#define OSP_MIN_RETRYDELAY  0                           /* OSP min retry delay */
#define OSP_MAX_RETRYDELAY  10                          /* OSP max retry delay */
#define OSP_DEF_RETRYLIMIT  "2"                         /* Mapping default retry times */
#define OSP_MIN_RETRYLIMIT  0                           /* OSP min retry times */
#define OSP_MAX_RETRYLIMIT  100                         /* OSP max retry times */
#define OSP_DEF_TIMEOUT     "10000"                     /* Mapping default timeout */
#define OSP_MIN_TIMEOUT     200                         /* OSP min timeout in ms */
#define OSP_MAX_TIMEOUT     60000                       /* OSP max timeout in ms */
#define OSP_DEF_CUSTOMERID  ""                          /* OSP default customer ID */
#define OSP_DEF_DEVICEID    ""                          /* OSP default device ID */
#define OSP_DEF_DEVICEIP    "localhost"                 /* OSP default device IP */
#define OSP_DEF_DEVICEPORT  "5060"                      /* Mapping default device port */
#define OSP_DEF_DESTCOUNT   0                           /* OSP default destination count, unset */
#define OSP_DEF_SLOST       -1                          /* OSP default lost send packets */
#define OSP_DEF_SLOSTFRACT  -1                          /* OSP default lost send packet fraction */
#define OSP_DEF_RLOST       -1                          /* OSP default lost receive packets */
#define OSP_DEF_RLOSTFRACT  -1                          /* OSP default lost receive packet fraction */

/*
 * Default RADIUS OSP mapping
 */
#define OSP_MAP_TRANSID         NULL                        /* Transaction ID */
#define OSP_MAP_CALLID          "%{Acct-Session-Id}"        /* Call-ID, RFC 2866 */
#define OSP_MAP_ISCALLINGURI    "yes"                       /* Calling number type, uri */
#define OSP_MAP_CALLING         "%{Calling-Station-Id}"     /* Calling number, RFC 2865 */
#define OSP_MAP_ISCALLEDURI     "yes"                       /* Called number type, uri */
#define OSP_MAP_CALLED          "%{Called-Station-Id}"      /* Called number, RFC 2865 */
#define OSP_MAP_SRCDEV          NULL                        /* Source device */
#define OSP_MAP_SOURCE          "%{NAS-IP-Address}"         /* Source, RFC 2865 */
#define OSP_MAP_DESTINATION     NULL                        /* Destination */
#define OSP_MAP_DESTDEV         NULL                        /* Destination device */
#define OSP_MAP_DESTCOUNT       NULL                        /* Destination count */
#define OSP_MAP_TIMEFORMAT      "0"                         /* Time string format, integer string */
#define OSP_MAP_START           "%{Acct-Session-Start-Time}"/* Call start time, FreeRADIUS internal */
#define OSP_MAP_ALERT           NULL                        /* Call alert time */
#define OSP_MAP_CONNECT         NULL                        /* Call connect time */
#define OSP_MAP_END             NULL                        /* Call end time */
#define OSP_MAP_DURATION        "%{Acct-Session-Time}"      /* Call duration, RFC 2866 */
#define OSP_MAP_PDDUNIT         "0"                         /* PDD unit, second */
#define OSP_MAP_PDD             NULL                        /* Post dial delay */
#define OSP_MAP_RELEASE         NULL                        /* Release source */
#define OSP_MAP_CAUSE           "%{Acct-Terminate-Cause}"   /* Release cause, RFC 2866 */
#define OSP_MAP_CONFID          NULL                        /* Conference ID */
#define OSP_MAP_SLOST           NULL                        /* Lost send packets */
#define OSP_MAP_SLOSTFRACT      NULL                        /* Lost send packet fraction */
#define OSP_MAP_RLOST           NULL                        /* Lost receive packets */
#define OSP_MAP_RLOSTFRACT      NULL                        /* Lost receive packet fraction */

/*
 * OSP log level
 */
typedef enum {
    OSP_LOG_SHORT = 0,  /* Log short message */
    OSP_LOG_LONG        /* Log long message */
} osp_loglevel_t;

/*
 * OSP mapping item level
 */
typedef enum {
    OSP_ITEM_MUSTDEF = 0,   /* Mapping item must be defined */
    OSP_ITEM_DEFINED        /* Mapping item may be defined */
} osp_itemlevel_t;

/*
 * OSP time string types
 */
typedef enum {
    OSP_TIMESTR_T = 0,  /* time_t, integer string */
    OSP_TIMESTR_C,      /* ctime, WWW MMM DD HH:MM:SS YYYY */
    OSP_TIMESTR_ACME,   /* ACME, HH:MM:SS.MMM ZON MMM DD YYYY */
    OSP_TIMESTR_MAX     /* Number of time string types */
} osp_timestr_t;

/*
 * Time zone strings
 */
#define OSP_TZ_UTC  "UTC"   /* Universal Time, Coordinated */
#define OSP_TZ_GMT  "GMT"   /* Greenwich Mean Time */
#define OSP_TZ_EST  "EST"   /* Eastern Standard Time */
#define OSP_TZ_EDT  "EDT"   /* Eastern Daylight Time */
#define OSP_TZ_CST  "CST"   /* Central Standard Time */
#define OSP_TZ_CDT  "CDT"   /* Central Daylight Time */
#define OSP_TZ_MST  "MST"   /* Mountain Standard Time */
#define OSP_TZ_MDT  "MDT"   /* Mountain Daylight Time */
#define OSP_TZ_PST  "PST"   /* Pacific Standard Time */
#define OSP_TZ_PDT  "PDT"   /* Pacific Daylight Time */
#define OSP_TZ_HST  "HST"   /* Hawaii-Aleutian Standard Time */
#define OSP_TZ_AKST "AKST"  /* Alaska Standard Time */
#define OSP_TZ_AKDT "AKDT"  /* Alaska Daylight Time */

/*
 * Time zone time offset
 */
#define OSP_TOFF_UTC  0             /* Universal Time, Coordinated */
#define OSP_TOFF_GMT  OSP_TOFF_UTC  /* Universal Time, Coordinated */
#define OSP_TOFF_EST  (-5*60*60)    /* Eastern Standard Time */
#define OSP_TOFF_EDT  (-4*60*60)    /* Eastern Daylight Time */
#define OSP_TOFF_CST  (-6*60*60)    /* Central Standard Time */
#define OSP_TOFF_CDT  (-5*60*60)    /* Central Daylight Time */
#define OSP_TOFF_MST  (-7*60*60)    /* Mountain Standard Time */
#define OSP_TOFF_MDT  (-6*60*60)    /* Mountain Daylight Time */
#define OSP_TOFF_PST  (-8*60*60)    /* Pacific Standard Time */
#define OSP_TOFF_PDT  (-7*60*60)    /* Pacific Daylight Time */
#define OSP_TOFF_HST  (-10*60*60)   /* Hawaii-Aleutian Standard Time */
#define OSP_TOFF_AKST (-9*60*60)    /* Alaska Standard Time */
#define OSP_TOFF_AKDT (-8*60*60)    /* Alaska Daylight Time */

/*
 * Post dial delay unit
 */
typedef enum {
    OSP_TIMEUNIT_S = 0, /* Second */
    OSP_TIMEUNIT_MS,    /* Millisecond */
    OSP_TIMEUNIT_MAX
} osp_timeunit_t;

int OSP_TIMEUNIT_SCALE[OSP_TIMEUNIT_MAX] = { 1, 1000 };

/*
 * OSP release source
 */
typedef enum {
    OSP_RELEASE_UNDEF = 0,  /* Unknown */
    OSP_RELEASE_SRC,        /* Source releases the call */
    OSP_RELEASE_DEST,       /* Destination releases the call */
    OSP_RELEASE_MAX
} osp_release_t;

/*
 * OSPTK release source
 */
#define OSP_TK_RELSRC   0
#define OSP_TK_RELDST   1

/*
 * OSP module running parameter structure
 */
typedef struct {
    int loglevel;
} osp_running_t;

/*
 * OSP module provider parameter structure.
 */
typedef struct {
    int accelerate;             /* Hardware accelerate flag */
    int sps;                    /* Number of service points */
    char* spuris[OSP_MAX_SPS];  /* Service point URIs */
    int spweights[OSP_MAX_SPS]; /* Service point weights */
    char* privatekey;           /* Private key file name */
    char* localcert;            /* Local cert file name */
    int cas;                    /* Number of cacerts */
    char* cacerts[OSP_MAX_CAS]; /* Cacert file names */
    int ssllifetime;            /* SSL life time */
    int maxconn;                /* Max number of HTTP connections */
    int persistence;            /* Persistence */
    int retrydelay;             /* Retry delay */
    int retrylimit;             /* Times of retry */
    int timeout;                /* Timeout */
    uint32_t deviceip;          /* NAS IP address */
    int deviceport;             /* NAS port */
    OSPTPROVHANDLE handle;      /* OSP provider handle */
} osp_provider_t;

/*
 * OSP module mapping parameter structure.
 */
typedef struct {
    char* transid;      /* Transaction ID */
    char* callid;       /* Call-ID */
    int iscallinguri;   /* If calling number uri */
    char* calling;      /* Calling number */
    int iscalleduri;    /* If called number uri */
    char* called;       /* Called number */
    char* srcdev;       /* Source device */
    char* source;       /* Source */
    char* destination;  /* Destination */
    char* destdev;      /* Destination device */
    char* destcount;    /* Destination count */
    int timeformat;     /* Time string format */
    char* start;        /* Call start time */
    char* alert;        /* Call alert time */
    char* connect;      /* Call connect time */
    char* end;          /* Call end time */
    char* duration;     /* Call duration */
    int pddunit;        /* Post dial delay unit */
    char* pdd;          /* Post dial delay */
    char* release;      /* Release source */
    char* cause;        /* Release cause */
    char* confid;       /* Conference ID */
    char* slost;        /* Lost send packages */
    char* slostfract;   /* Lost send packages fraction */
    char* rlost;        /* Lost receive packages */
    char* rlostfract;   /* Lost receive packages fraction */
} osp_mapping_t;

/*
 * OSP module instance data structure.
 */
typedef struct {
    osp_running_t running;      /* OSP module running parameters */
    osp_provider_t provider;    /* OSP provider parameters */
    osp_mapping_t mapping;      /* OSP mapping parameters */
} rlm_osp_t;

/*
 * Usage base information structure.
 */
typedef struct {
    OSPTUINT64 transid;                 /* Transaction ID */
    char callid[OSP_STRBUF_SIZE];       /* Call-ID */
    char calling[OSP_STRBUF_SIZE];      /* Calling number */
    char called[OSP_STRBUF_SIZE];       /* Called number */
    char srcdev[OSP_STRBUF_SIZE];       /* Source device */
    char source[OSP_STRBUF_SIZE];       /* Source */
    char destination[OSP_STRBUF_SIZE];  /* Destination */
    char destdev[OSP_STRBUF_SIZE];      /* Destination device */
    int destcount;                      /* Destination count */
    int cause;                          /* Release code */
} osp_usagebase_t;

/*
 * Usage information structure.
 */
typedef struct {
    time_t start;                   /* Call start time */
    time_t alert;                   /* Call alert time */
    time_t connect;                 /* Call connect time */
    time_t end;                     /* Call end time */
    time_t duration;                /* Length of call */
    int ispddpresent;               /* Is PDD Info present */
    int pdd;                        /* Post Dial Delay */
    int release;                    /* EP that released the call */
    char confid[OSP_STRBUF_SIZE];   /* Conference ID */
    int slost;                      /* Packets not received by peer */
    int slostfract;                 /* Fraction of packets not received by peer */
    int rlost;                      /* Packets not received that were expected */
    int rlostfract;                 /* Fraction of packets expected but not received */
} osp_usageinfo_t;

/*
 * A mapping of configuration file names to internal variables.
 *
 *   Note that the string is dynamically allocated, so it MUST
 *   be freed.  When the configuration file parse re-reads the string,
 *   it free's the old one, and strdup's the new one, placing the pointer
 *   to the strdup'd string into 'config.string'.  This gets around
 *   buffer over-flows.
 */
static const CONF_PARSER running_config[] = {
    /*
     * OSP module running parameters
     */
    { "loglevel", PW_TYPE_INTEGER, offsetof(rlm_osp_t, running.loglevel), NULL, OSP_DEF_LOGLEVEL },
    /*
     * End
     */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

static const CONF_PARSER provider_config[] = {
    /*
     * OSP provider parameters
     *
     *   All service points, weights and cacerts must be listed to allow config
     *   parser to read them.
     */
    { "accelerate", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, provider.accelerate), NULL, OSP_DEF_HWACCE },
    { "spuri1", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[0]), NULL, OSP_DEF_SPURI },
    { "spuri2", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[1]), NULL, NULL },
    { "spuri3", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[2]), NULL, NULL },
    { "spuri4", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[3]), NULL, NULL },
    { "spuri5", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[4]), NULL, NULL },
    { "spuri6", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[5]), NULL, NULL },
    { "spuri7", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[6]), NULL, NULL },
    { "spuri8", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[7]), NULL, NULL },
    { "spweight1", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[0]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight2", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[1]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight3", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[2]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight4", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[3]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight5", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[4]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight6", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[5]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight7", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[6]), NULL, OSP_DEF_SPWEIGHT },
    { "spweight8", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[7]), NULL, OSP_DEF_SPWEIGHT },
    { "privatekey", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.privatekey), NULL, OSP_DEF_PRIVATEKEY },
    { "localcert", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.localcert), NULL, OSP_DEF_LOCALCERT },
    { "cacert0", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[0]), NULL, OSP_DEF_CACERT },
    { "cacert1", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[1]), NULL, NULL },
    { "cacert2", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[2]), NULL, NULL },
    { "cacert3", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[3]), NULL, NULL },
    { "ssllifetime", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.ssllifetime), NULL, OSP_DEF_SSLLIFETIME },
    { "maxconnections", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.maxconn), NULL, OSP_DEF_MAXCONN },
    { "persistence", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.persistence), NULL, OSP_DEF_PERSISTENCE },
    { "retrydelay", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.retrydelay), NULL, OSP_DEF_RETRYDELAY },
    { "retrylimit", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.retrylimit), NULL, OSP_DEF_RETRYLIMIT },
    { "timeout", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.timeout), NULL, OSP_DEF_TIMEOUT },
    { "deviceip", PW_TYPE_IPADDR, offsetof(rlm_osp_t, provider.deviceip), NULL, OSP_DEF_DEVICEIP },
    { "deviceport", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.deviceport), NULL, OSP_DEF_DEVICEPORT },
    /*
     * End
     */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

static const CONF_PARSER mapping_config[] = {
    /*
     * RADIUS OSP mapping parameters
     */
    { "transactionid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transid), NULL, OSP_MAP_TRANSID },
    { "callid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callid), NULL, OSP_MAP_CALLID },
    { "iscallinguri", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.iscallinguri), NULL, OSP_MAP_ISCALLINGURI},
    { "callingnumber", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calling), NULL, OSP_MAP_CALLING },
    { "iscalleduri", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.iscalleduri), NULL, OSP_MAP_ISCALLEDURI},
    { "callednumber", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.called), NULL, OSP_MAP_CALLED },
    { "sourcedevice", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcdev), NULL, OSP_MAP_SRCDEV},
    { "source", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.source), NULL, OSP_MAP_SOURCE },
    { "destination", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destination), NULL, OSP_MAP_DESTINATION },
    { "destinationdevice", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destdev), NULL, OSP_MAP_DESTDEV },
    { "destinationcount", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destcount), NULL, OSP_MAP_DESTCOUNT },
    { "timeformat", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.timeformat), NULL, OSP_MAP_TIMEFORMAT },
    { "starttime", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.start), NULL, OSP_MAP_START },
    { "alerttime", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.alert), NULL, OSP_MAP_ALERT },
    { "connecttime", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.connect), NULL, OSP_MAP_CONNECT },
    { "endtime", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.end), NULL, OSP_MAP_END },
    { "duration", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.duration), NULL, OSP_MAP_DURATION },
    { "postdialdelayunit", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.pddunit), NULL, OSP_MAP_PDDUNIT },
    { "postdialdelay", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.pdd), NULL, OSP_MAP_PDD },
    { "releasesource", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.release), NULL, OSP_MAP_RELEASE },
    { "releasecause", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.cause), NULL, OSP_MAP_CAUSE },
    { "confid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.confid), NULL, OSP_MAP_CONFID },
    { "sendlost", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.slost), NULL, OSP_MAP_SLOST },
    { "sendlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.slostfract), NULL, OSP_MAP_SLOSTFRACT },
    { "receivelost", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.rlost), NULL, OSP_MAP_RLOST },
    { "receivelostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.rlostfract), NULL, OSP_MAP_RLOSTFRACT },
    /*
     * End
     */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

static const CONF_PARSER module_config[] = {
    /*
     * OSP running parameters
     */
    { "running", PW_TYPE_SUBSECTION, 0, NULL, (const void*)running_config },
    /*
     * OSP provider parameters
     */
    { "provider", PW_TYPE_SUBSECTION, 0, NULL, (const void*)provider_config },
    /*
     * RADIUS OSP mapping parameters
     */
    { "mapping", PW_TYPE_SUBSECTION, 0, NULL, (const void*)mapping_config },
    /*
     * End
     */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

/*
 * Internal function prototype
 */
static int osp_check_string(char* string);
static int osp_check_running(osp_running_t* running);
static int osp_check_provider(osp_provider_t* provider);
static int osp_check_mapping(osp_mapping_t* mapping);
static int osp_check_mapitem(char* item, osp_itemlevel_t level);
static int osp_create_provider(osp_provider_t* provider);
static int osp_get_termcause(rlm_osp_t* data, REQUEST* request, int* cause);
static int osp_get_usagebase(rlm_osp_t* data, REQUEST* request, osp_usagebase_t* base);
static void osp_format_device(char* device, char* buffer, int buffersize);
static int osp_get_username(char* uri, char* buffer, int buffersize);
static int osp_get_usageinfo(osp_mapping_t* mapping, REQUEST* request, int usagetype, osp_usageinfo_t* info);
static time_t osp_format_time(char* timestr, osp_timestr_t format);
static int osp_cal_timeoffset(char* tzone, long int* toffset);
static int osp_cal_elapsed(struct tm* dt, long int toffset, time_t* elapsed);

/*
 * Do any per-module initialization that is separate to each
 * configured instance of the module.  e.g. set up connections
 * to external databases, read configuration files, set up
 * dictionary entries, etc.
 *
 * If configuration information is given in the config section
 * that must be referenced in later calls, store a handle to it
 * in instance otherwise put a null pointer there.
 *
 * param conf Configuration section
 * param instance Instance data
 * return 0 success, -1 failure
 */
static int osp_instantiate(
    CONF_SECTION* conf,
    void** instance)
{
    rlm_osp_t* data;

    DEBUG("rlm_osp: osp_instantiate start");

    /*
     * Set up a storage area for instance data
     */
    data = rad_malloc(sizeof(*data));
    if (!data) {
        radlog(L_ERR, "rlm_osp: Failed to allocate memory for instance data.");
        return -1;
    }
    memset(data, 0, sizeof(*data));

    /*
     * If the configuration parameters can't be parsed, then fail.
     */
    if (cf_section_parse(conf, data, module_config) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to parse configuration parameters.");
        free(data);
        return -1;
    }

    /*
     * If any running parameter is wrong, then fail.
     */
    if (osp_check_running(&data->running) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to check running parameters.");
        free(data);
        return -1;
    }

    /*
     * If any provider parameter is wrong, then fail.
     */
    if (osp_check_provider(&data->provider) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to check provider parameters.");
        free(data);
        return -1;
    }

    /*
     * If any mapping parameter is wrong, then fail.
     */
    if (osp_check_mapping(&data->mapping) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to check mapping parameters.");
        free(data);
        return -1;
    }

    /*
     * If failed to create the provider, then fail.
     */
    if (osp_create_provider(&data->provider) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to create provider handle.");
        free(data);
        return -1;
    }

    *instance = data;

    DEBUG("rlm_osp: osp_instantiate success");

    return 0;
}

/*
 * Check empty string
 *
 * param string String to be checked
 * return 0 empty, 1 with contents
 */
static int osp_check_string(
    char* string)
{
    return ((string != NULL) && (*string != '\0'));
}

/*
 * Check OSP module running parameters.
 *
 * param running Running parameters
 * return 0 success, -1 failure
 */
static int osp_check_running(
    osp_running_t* running)
{
    DEBUG("rlm_osp: osp_check_running start");

    /*
     * Check log level
     */
    switch (running->loglevel) {
    case OSP_LOG_SHORT:
    case OSP_LOG_LONG:
        break;
    default:
        running->loglevel = OSP_LOG_LONG;
        break;
    }
    DEBUG("rlm_osp: loglevel = '%d'", running->loglevel);

    DEBUG("rlm_osp: osp_check_running success");

    return 0;
}

/*
 * Check OSP provider parameters.
 *
 * param provider Provider parameters
 * return 0 success, -1 failure
 */
static int osp_check_provider(
    osp_provider_t* provider)
{
    int i;

    DEBUG("rlm_osp: osp_check_provider start");

    /*
     * Calculate number of service points
     */
    provider->sps = 0;
    for (i = 0; i < OSP_MAX_SPS; i++) {
        if (osp_check_string(provider->spuris[i])) {
            /*
             * If any service point weight is wrong, then fail.
             */
            if (provider->spweights[i] <= 0) {
                radlog(L_ERR,
                    "rlm_osp: 'weight' must be larger than 0, not '%d'.",
                    provider->spweights[i]);
                return -1;
            } else {
                provider->sps++;
            }
        } else {
            break;
        }
    }

    /*
     * If number of service points is wrong, then fail.
     */
    if (provider->sps == 0) {
        radlog(L_ERR, "rlm_osp: 'spuri1' must be defined.");
        return -1;
    }
    DEBUG("rlm_osp: sps = '%d'", provider->sps);
    for (i = 0; i < provider->sps; i++) {
        /* Has checked string NULL */
        DEBUG("rlm_osp: spuri%d = '%s'", i + 1, provider->spuris[i]);
    }
    for (i = 0; i < provider->sps; i++) {
        DEBUG("rlm_osp: spweight%d = '%d'", i + 1, provider->spweights[i]);
    }

    /*
     * If privatekey is undefined, then fail.
     */
    if (!osp_check_string(provider->privatekey)) {
        radlog(L_ERR, "rlm_osp: 'privatekey' must be defined.");
        return -1;
    }
    /* Has checked string NULL */
    DEBUG("rlm_osp: privatekey = '%s'", provider->privatekey);

    /*
     * If localcert is undefined, then fail.
     */
    if (!osp_check_string(provider->localcert)) {
        radlog(L_ERR, "rlm_osp: 'localcert' must be defined.");
        return -1;
    }
    /* Has checked string NULL */
    DEBUG("rlm_osp: locacert = '%s'", provider->localcert);

    /*
     * Calculate number of cacerts
     */
    provider->cas = 0;
    for (i = 0; i < OSP_MAX_CAS; i++) {
        if (osp_check_string(provider->cacerts[i]))  {
            provider->cas++;
        } else {
            break;
        }
    }

    /*
     * If number of cacerts is wrong, then fail.
     */
    if (provider->cas == 0) {
        radlog(L_ERR, "rlm_osp: 'cacert0' must be defined.");
        return -1;
    }
    DEBUG("rlm_osp: cas = '%d'", provider->cas);

    for (i = 0; i < provider->cas; i++) {
        /* Has checked string NULL */
        DEBUG("rlm_osp: cacert%d = '%s'", i, provider->cacerts[i]);
    }

    /*
     * If SSL life time is wrong, then fail.
     */
    if (provider->ssllifetime <= 0) {
        radlog(L_ERR,
            "rlm_osp: 'ssllifetime' must be larger than 0, not '%d'.",
            provider->ssllifetime);
        return -1;
    }
    DEBUG("rlm_osp: ssllifetime = '%d'", provider->ssllifetime);

    /*
     * If persistence is wrong, then fail.
     */
    if (provider->persistence <= 0) {
        radlog(L_ERR,
            "rlm_osp: 'persistence' must be larger than 0, not '%d'.",
            provider->persistence);
        return -1;
    }
    DEBUG("rlm_osp: persistence = '%d'", provider->persistence);

    /*
     * If max number of connections is wrong, then fail.
     */
    if ((provider->maxconn < OSP_MIN_MAXCONN) || (provider->maxconn > OSP_MAX_MAXCONN)) {
        radlog(L_ERR,
            "rlm_osp: 'maxconnections' must be an integer from '%d' to '%d', not '%d'.",
            OSP_MIN_MAXCONN,
            OSP_MAX_MAXCONN,
            provider->maxconn);
        return -1;
    }
    DEBUG("rlm_osp: maxconnections = '%d'", provider->maxconn);

    /*
     * If retry delay is wrong, then fail.
     */
    if ((provider->retrydelay < OSP_MIN_RETRYDELAY) || (provider->retrydelay > OSP_MAX_RETRYDELAY)) {
        radlog(L_ERR,
            "rlm_osp: 'retrydelay' must be an integer from '%d' to '%d', not '%d'.",
            OSP_MIN_RETRYDELAY,
            OSP_MAX_RETRYDELAY,
            provider->retrydelay);
        return -1;
    }
    DEBUG("rlm_osp: retrydelay = '%d'", provider->retrydelay);

    /*
     * If times of retry is wrong, then fail.
     */
    if ((provider->retrylimit < OSP_MIN_RETRYLIMIT) || (provider->retrylimit > OSP_MAX_RETRYLIMIT)) {
        radlog(L_ERR,
            "rlm_osp: 'retrylimit' must be an integer from '%d' to '%d', not '%d'.",
            OSP_MIN_RETRYLIMIT,
            OSP_MAX_RETRYLIMIT,
            provider->retrylimit);
        return -1;
    }
    DEBUG("rlm_osp: retrylimit = '%d'", provider->retrylimit);

    /*
     * If timeout is wrong, then fail.
     */
    if ((provider->timeout < OSP_MIN_TIMEOUT) || (provider->timeout > OSP_MAX_TIMEOUT)) {
        radlog(L_ERR,
            "rlm_osp: 'timeout' must be an integer from '%d' to '%d', not '%d'.",
            OSP_MIN_TIMEOUT,
            OSP_MAX_TIMEOUT,
            provider->timeout);
        return -1;
    }
    DEBUG("rlm_osp: timeout = '%d'", provider->timeout);

    DEBUG("rlm_osp: osp_check_provider success");

    return 0;
}

/*
 * Check RADIUS OSP mapping parameters.
 *
 * param mapping Mapping parameters
 * return 0 success, -1 failure
 */
static int osp_check_mapping(
    osp_mapping_t* mapping)
{
    DEBUG("rlm_osp: osp_check_mapping start");

    /*
     * If transaction ID is incorrect, then fail.
     */
    DEBUG("rlm_osp: check transactionid mapping");
    if (osp_check_mapitem(mapping->transid, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'transactionid'.");
        return -1;
    }
    if (osp_check_string(mapping->transid)) {
        DEBUG("rlm_osp: transactionid = '%s'", mapping->transid);
    } else {
        DEBUG("rlm_osp: transactionid = 'NULL'");
    }

    /*
     * If Call-ID is undefined, then fail.
     */
    DEBUG("rlm_osp: check callid mapping");
    if (osp_check_mapitem(mapping->callid, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'callid' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: callid = '%s'", mapping->callid);

    /*
     * Nothing to check for iscallinguri
     */
    DEBUG("rlm_osp: iscallinguri = '%d'", mapping->iscallinguri);

    /*
     * If calling number is incorrect, then fail.
     */
    DEBUG("rlm_osp: check callingnumber mapping");
    if (osp_check_mapitem(mapping->calling, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'callingnumber'.");
        return -1;
    }
    if (osp_check_string(mapping->calling)) {
        DEBUG("rlm_osp: callingnumber = '%s'", mapping->calling);
    } else {
        DEBUG("rlm_osp: callingnumber = 'NULL'");
    }

    /*
     * Nothing to check for iscallieduri
     */
    DEBUG("rlm_osp: iscalleduri = '%d'", mapping->iscalleduri);

    /*
     * If called number is undefined, then fail.
     */
    DEBUG("rlm_osp: check callednumber mapping");
    if (osp_check_mapitem(mapping->called, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'callednumber' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: callednumber = '%s'", mapping->called);

    /*
     * If source device is undefined, then fail.
     */
    DEBUG("rlm_osp: check sourcedevice mapping");
    if (osp_check_mapitem(mapping->srcdev, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'sourcedevice' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: sourcedevice = '%s'", mapping->srcdev);

    /*
     * If source is incorrect, then fail.
     */
    DEBUG("rlm_osp: check source mapping");
    if (osp_check_mapitem(mapping->source, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'source'.");
        return -1;
    }
    if (osp_check_string(mapping->source)) {
        DEBUG("rlm_osp: source = '%s'", mapping->source);
    } else {
        DEBUG("rlm_osp: source = 'NULL'");
    }

    /*
     * If destination is undefined, then fail.
     */
    DEBUG("rlm_osp: check destination mapping");
    if (osp_check_mapitem(mapping->destination, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'destination' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: destination = '%s'", mapping->destination);

    /*
     * If destination device is incorrect, then fail.
     */
    DEBUG("rlm_osp: check destinationdevice mapping");
    if (osp_check_mapitem(mapping->destdev, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'destinationdevice'.");
        return -1;
    }
    if (osp_check_string(mapping->destdev)) {
        DEBUG("rlm_osp: destinationdevice = '%s'", mapping->destdev);
    } else {
        DEBUG("rlm_osp: destinationdevice = 'NULL'");
    }

    /*
     * If destination count is incorrect, then fail.
     */
    DEBUG("rlm_osp: check destinationcount mapping");
    if (osp_check_mapitem(mapping->destcount, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'destinationcount'.");
        return -1;
    }
    if (osp_check_string(mapping->destcount)) {
        DEBUG("rlm_osp: destinationcount = '%s'", mapping->destcount);
    } else {
        DEBUG("rlm_osp: destinationcount = 'NULL'");
    }

    /*
     * If time string format is wrong, then fail.
     */
    if ((mapping->timeformat < OSP_TIMESTR_T) || (mapping->timeformat >= OSP_TIMESTR_MAX)) {
        radlog(L_ERR,
            "rlm_osp: 'timeformat' must be an integer from '%d' to '%d', not '%d'.",
            OSP_TIMESTR_T,
            OSP_TIMESTR_MAX - 1,
            mapping->timeformat);
        return -1;
    }
    DEBUG("rlm_osp: timeformat = '%d'", mapping->timeformat);

    /*
     * If call start time is undefined, then fail.
     */
    DEBUG("rlm_osp: check starttime mapping");
    if (osp_check_mapitem(mapping->start, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'starttime' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: starttime = '%s'", mapping->start);

    /*
     * If call alert time is incorrect, then fail.
     */
    DEBUG("rlm_osp: check alerttime mapping");
    if (osp_check_mapitem(mapping->alert, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'alerttime'.");
        return -1;
    }
    if (osp_check_string(mapping->alert)) {
        DEBUG("rlm_osp: alerttime = '%s'", mapping->alert);
    } else {
        DEBUG("rlm_osp: alerttime = 'NULL'");
    }

    /*
     * If call connect time is incorrect, then fail.
     */
    DEBUG("rlm_osp: check connecttime mapping");
    if (osp_check_mapitem(mapping->connect, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'connecttime'.");
        return -1;
    }
    if (osp_check_string(mapping->connect)) {
        DEBUG("rlm_osp: connecttime = '%s'", mapping->connect);
    } else {
        DEBUG("rlm_osp: connecttime = 'NULL'");
    }

    /*
     * If call end time is undefined, then fail.
     */
    DEBUG("rlm_osp: check endtime mapping");
    if (osp_check_mapitem(mapping->end, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'endtime' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: endtime = '%s'", mapping->end);

    /*
     * If call duration is incorrect, then fail.
     */
    DEBUG("rlm_osp: check duration mapping");
    if (osp_check_mapitem(mapping->duration, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'duration'.");
        return -1;
    }
    if (osp_check_string(mapping->duration)) {
        DEBUG("rlm_osp: duration = '%s'", mapping->duration);
    } else {
        DEBUG("rlm_osp: duration = 'NULL'");
    }

    /*
     * If pdd unit is wrong, then fail.
     */
    if ((mapping->pddunit < OSP_TIMEUNIT_S) || (mapping->pddunit >= OSP_TIMEUNIT_MAX)) {
        radlog(L_ERR,
            "rlm_osp: 'postdialdelayunit' must be an integer from '%d' to '%d', not '%d'.",
            OSP_TIMEUNIT_S,
            OSP_TIMEUNIT_MAX - 1,
            mapping->pddunit);
        return -1;
    }
    DEBUG("rlm_osp: postdialdelayunit = '%d'", mapping->pddunit);

    /*
     * If pdd is incorrect, then fail.
     */
    DEBUG("rlm_osp: check postdialdelay mapping");
    if (osp_check_mapitem(mapping->pdd, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'postdialdelay'.");
        return -1;
    }
    if (osp_check_string(mapping->pdd)) {
        DEBUG("rlm_osp: postdialdelay = '%s'", mapping->pdd);
    } else {
        DEBUG("rlm_osp: postdialdelay = 'NULL'");
    }

    /*
     * If release source is incorrect, then fail.
     */
    DEBUG("rlm_osp: check releasesource mapping");
    if (osp_check_mapitem(mapping->release, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'releasesource'.");
        return -1;
    }
    if (osp_check_string(mapping->release)) {
        DEBUG("rlm_osp: releasesource = '%s'", mapping->release);
    } else {
        DEBUG("rlm_osp: releasesource = 'NULL'");
    }

    /*
     * If release cause is undefined, then fail.
     */
    DEBUG("rlm_osp: check releasecause mapping");
    if (osp_check_mapitem(mapping->cause, OSP_ITEM_MUSTDEF) < 0) {
        radlog(L_ERR, "rlm_osp: 'releasecause' must be defined properly.");
        return -1;
    }
    /* For must define mapping item, has checked string NULL */
    DEBUG("rlm_osp: releasecause = '%s'", mapping->cause);

    /*
     * If conference ID is incorrect, then fail.
     */
    DEBUG("rlm_osp: check conferenceid mapping");
    if (osp_check_mapitem(mapping->confid, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'conferenceid'.");
        return -1;
    }
    if (osp_check_string(mapping->confid)) {
        DEBUG("rlm_osp: conferenceid = '%s'", mapping->confid);
    } else {
        DEBUG("rlm_osp: conferenceid = 'NULL'");
    }

    /*
     * If lost send packets is incorrect, then fail.
     */
    DEBUG("rlm_osp: check sendlost mapping");
    if (osp_check_mapitem(mapping->slost, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'sendlost'.");
        return -1;
    }
    if (osp_check_string(mapping->slost)) {
        DEBUG("rlm_osp: sendlost = '%s'", mapping->slost);
    } else {
        DEBUG("rlm_osp: sendlost = 'NULL'");
    }

    /*
     * If lost send packet fraction is incorrect, then fail.
     */
    DEBUG("rlm_osp: check sendlostfract mapping");
    if (osp_check_mapitem(mapping->slostfract, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'sendlostfract'.");
        return -1;
    }
    if (osp_check_string(mapping->slostfract)) {
        DEBUG("rlm_osp: sendlostfract = '%s'", mapping->slostfract);
    } else {
        DEBUG("rlm_osp: sendlostfract = 'NULL'");
    }

    /*
     * If lost receive packets is incorrect, then fail.
     */
    DEBUG("rlm_osp: check receivelost mapping");
    if (osp_check_mapitem(mapping->rlost, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'receivelost'.");
        return -1;
    }
    if (osp_check_string(mapping->rlost)) {
        DEBUG("rlm_osp: receivelost = '%s'", mapping->rlost);
    } else {
        DEBUG("rlm_osp: receivelost = 'NULL'");
    }

    /*
     * If lost receive packet fraction is incorrect, then fail.
     */
    DEBUG("rlm_osp: check receivelostfract mapping");
    if (osp_check_mapitem(mapping->rlostfract, OSP_ITEM_DEFINED) < 0) {
        radlog(L_ERR, "rlm_osp: Incorrect 'receivelostfract'.");
        return -1;
    }
    if (osp_check_string(mapping->rlostfract)) {
        DEBUG("rlm_osp: receivelostfract = '%s'", mapping->rlostfract);
    } else {
        DEBUG("rlm_osp: receivelostfract = 'NULL'");
    }

    DEBUG("rlm_osp: osp_check_mapping success");

    return 0;
}

/*
 * Check RADIUS OSP mapping item.
 *
 * param item Mapping item
 * param level Mapping item level
 * return 0 success, -1 failure
 */
static int osp_check_mapitem (
    char* item,
    osp_itemlevel_t level)
{
    int last;

    DEBUG("rlm_osp: osp_check_mapitem start");

    if (!osp_check_string(item)) {
        if (level == OSP_ITEM_MUSTDEF) {
            radlog(L_ERR, "rlm_osp: Failed to check mapping item.");
            return -1;
        } else {
            DEBUG("rlm_osp: osp_check_mapitem success");
            return 0;
        }
    }

    if (*item != '%') {
        radlog(L_ERR,
            "rlm_osp: Failed to check mapping item '%s'.",
            item);
        return -1;
    }

    last = strlen(item) - 1;

    if ((item[1] != '{') && (last != 1)) {
        radlog(L_ERR,
            "rlm_osp: Failed to check mapping item '%s'.",
            item);
        return -1;
    }

    if (((item[1] == '{') && (item[last] != '}')) ||
        ((item[1] != '{') && (item[last] == '}')))
    {
        radlog(L_ERR,
            "rlm_osp: Failed to check mapping item '%s'.",
            item);
        return -1;
    }

   DEBUG("rlm_osp: osp_check_mapitem success");

    return 0;
}

/*
 * Create a provider handle.
 *
 * param provider Provider parameters
 * return 0 success, -1 failure
 */
static int osp_create_provider(
    osp_provider_t* provider)
{
    int i, j, error, result;
    unsigned long spweights[OSP_MAX_SPS];
    OSPTPRIVATEKEY privatekey;
    OSPT_CERT localcert;
    OSPT_CERT cacerts[OSP_MAX_CAS];
    const OSPT_CERT* pcacerts[OSP_MAX_CAS];

    DEBUG("rlm_osp: osp_create_provider start");

    /*
     * Initialize OSP
     */
    error = OSPPInit(provider->accelerate);
    if (error != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "Failed to initalize OSP, error '%d'.",
            error);
        return -1;
    }

    /*
     * Copy service point weights to a temp buffer to avoid compile warning
     */
    for (i = 0; i < provider->sps; i++) {
        spweights[i] = provider->spweights[i];
    }

    /*
     * Load private key
     */
    error = OSPPUtilLoadPEMPrivateKey((unsigned char*)provider->privatekey, &privatekey);
    if (error != OSPC_ERR_NO_ERROR) {
        /* Has checked string NULL by osp_check_provider */
        radlog(L_ERR,
            "rlm_osp: Failed to load privatekey '%s', error '%d'.",
            provider->privatekey,
            error);
        OSPPCleanup();
        return -1;
    }

    /*
     * Load local cert
     */
    error = OSPPUtilLoadPEMCert((unsigned char*)provider->localcert, &localcert);
    if (error != OSPC_ERR_NO_ERROR) {
        /* Has checked string NULL by osp_check_provider */
        radlog(L_ERR,
            "rlm_osp: Failed to load localcert '%s', error '%d'.",
            provider->localcert,
            error);
        if (privatekey.PrivateKeyData != NULL) {
            free(privatekey.PrivateKeyData);
        }
        OSPPCleanup();
        return -1;
    }

    /*
     * Load cacerts
     */
    for (i = 0; i < provider->cas; i++) {
        error = OSPPUtilLoadPEMCert((unsigned char*)provider->cacerts[i], &cacerts[i]);
        if (error != OSPC_ERR_NO_ERROR) {
            /* Has checked string NULL by osp_check_provider */
            radlog(L_ERR,
                "rlm_osp: Failed to load cacert '%s', error '%d'.",
                provider->cacerts[i],
                error);
            for (j = 0; j < i; j++) {
                if (cacerts[j].CertData != NULL) {
                    free(cacerts[j].CertData);
                }
            }
            if (localcert.CertData != NULL) {
                free(localcert.CertData);
            }
            if (privatekey.PrivateKeyData != NULL) {
                free(privatekey.PrivateKeyData);
            }
            OSPPCleanup();
            return -1;
        }
        pcacerts[i] = &cacerts[i];
    }

    /*
     * Create a provider handle
     */
    error = OSPPProviderNew(
        provider->sps,                  /* Number of service points */
        (const char**)provider->spuris, /* Service point URIs */
        spweights,                      /* Service point weights */
        OSP_DEF_AUDITURL,               /* Audit URL */
        &privatekey,                    /* Private key */
        &localcert,                     /* Local cert */
        provider->cas,                  /* Number of cacerts */
        pcacerts,                       /* Cacerts */
        OSP_DEF_VALIDATION,             /* Token Validation mode */
        provider->ssllifetime,          /* SSL life time */
        provider->maxconn,              /* Max number of connections */
        provider->persistence,          /* Persistence */
        provider->retrydelay,           /* Retry delay */
        provider->retrylimit,           /* Times of retry */
        provider->timeout,              /* Timeout */
        OSP_DEF_CUSTOMERID,             /* Customer ID */
        OSP_DEF_DEVICEID,               /* Device ID */
        &provider->handle);             /* Provider handle */
    if (error != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "rlm_osp: Failed to create provider, error '%d'.",
            error);
        OSPPCleanup();
        result = -1;
    } else {
        DEBUG("rlm_osp: osp_create_provider success");
        result = 0;
    }

    /*
     * Release temp key buffers
     */
    for (i = 0; i < provider->cas; i++) {
        if (cacerts[i].CertData != NULL) {
            free(cacerts[i].CertData);
        }
    }
    if (localcert.CertData != NULL) {
        free(localcert.CertData);
    }
    if (privatekey.PrivateKeyData != NULL) {
        free(privatekey.PrivateKeyData);
    }

    return result;
}

/*
 * Write accounting information to this modules database.
 *
 * param instance Instance data
 * param request Accounting request
 * return RLM_MODULE_OK success, RLM_MODULE_NOOP do nothing, RLM_MODULE_FAIL failure
 */
static int osp_accounting(
    void* instance,
    REQUEST* request)
{
    VALUE_PAIR* vp;
    rlm_osp_t* data = (rlm_osp_t*)instance;
    osp_running_t* running = &data->running;
    osp_provider_t* provider = &data->provider;
    OSPTTRANHANDLE transaction;
    int cause;
    osp_usagebase_t base;
    osp_usageinfo_t info;
    char buffer[OSP_LOGBUF_SIZE];
    const int MAX_RETRIES = 5;
    OSPE_ROLE role;
    int i, error;

    DEBUG("rlm_osp: osp_accounting start");

    if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) == NULL) {
        DEBUG("rlm_osp: Failed to get accounting status type.");
        return RLM_MODULE_NOOP;
    }

    switch (vp->vp_integer) {
    case PW_STATUS_START:
        /*
         * Get release cause
         */
        cause = 0;

        role = OSPC_ROLE_RADSRCSTART;

        break;
    case PW_STATUS_STOP:
        /*
         * Get release cause
         */
        if (osp_get_termcause(data, request, &cause) < 0) {
            /*
             * Note: it should not return RLM_MODULE_FAIL in case requests from others come in.
             */
            return RLM_MODULE_NOOP;
        }

        role = OSPC_ROLE_RADSRCSTOP;

        break;
    case PW_STATUS_ALIVE: /* Interim-Update */
        /*
         * Get release cause
         */
        if (osp_get_termcause(data, request, &cause) < 0) {
            /*
             * Note: it should not return RLM_MODULE_FAIL in case requests from others come in.
             */
            return RLM_MODULE_NOOP;
        }

        role = OSPC_ROLE_RADSRCINTERIM;

        break;
    default:
        DEBUG("rlm_osp: Nothing to do for request type '%d'.", vp->vp_integer);
        return RLM_MODULE_NOOP;
    }

    /*
     * Get usage base information
     */
    if (osp_get_usagebase(data, request, &base) < 0) {
        switch (running->loglevel) {
        case OSP_LOG_SHORT:
            radlog(L_INFO, "rlm_osp: Failed to get usage base info.");
            break;
        case OSP_LOG_LONG:
        default:
            radius_xlat(buffer, sizeof(buffer), "%Z", request, NULL);
            /* Do not have to check string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to get usage base info from '%s'.",
                buffer);
            break;
        }
        /*
         * Note: it should not return RLM_MODULE_FAIL in case requests from others come in.
         */
        return RLM_MODULE_NOOP;
    }

    /*
     * Get usage info
     */
    if (osp_get_usageinfo(&data->mapping, request, vp->vp_integer, &info) < 0) {
        switch (running->loglevel) {
        case OSP_LOG_SHORT:
            radlog(L_INFO, "rlm_osp: Failed to get usage info.");
            break;
        case OSP_LOG_LONG:
        default:
            radius_xlat(buffer, sizeof(buffer), "%Z", request, NULL);
            /* Do not have to check string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to get usage info from '%s'.",
                buffer);
            break;
        }
        /*
         * Note: it should not return RLM_MODULE_FAIL in case requests from others come in.
         */
        return RLM_MODULE_NOOP;
    }

    /*
     * Create a transaction handle
     */
    error = OSPPTransactionNew(provider->handle, &transaction);
    if (error != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "rlm_osp: Failed to create transaction, error '%d'.",
            error);
        return RLM_MODULE_FAIL;
    }

    /*
     * Build usage report from scratch
     */
    error = OSPPTransactionBuildUsageFromScratch(
        transaction,            /* Transaction handle */
        base.transid,           /* Transaction ID */
        role,                   /* Usage type */
        base.source,            /* Source */
        base.destination,       /* Destination */
        base.srcdev,            /* Source device */
        base.destdev,           /* Destination device */
        base.calling,           /* Calling number */
        OSPC_NFORMAT_E164,      /* Calling number format */
        base.called,            /* Called number */
        OSPC_NFORMAT_E164,      /* Called number format */
        strlen(base.callid),    /* Call ID length */
        base.callid,            /* Call ID */
        0,                      /* Previous attempt failure reason */
        NULL,                   /* Max size of detail log */
        NULL);                  /* Detail log buffer */
    if (error != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "rlm_osp: Failed to build usage report, error '%d'.",
            error);
        OSPPTransactionDelete(transaction);
        return RLM_MODULE_FAIL;
    }

    /*
     * Set release code
     */
    OSPPTransactionRecordFailure(
        transaction,    /* Transaction handle */
        cause);         /* Release reason */

    /*
     * Send OSP UsageInd message to OSP server
     */
    for (i = 1; i <= MAX_RETRIES; i++) {
        error = OSPPTransactionReportUsage(
            transaction,        /* Transaction handle */
            info.duration,      /* Call duration */
            info.start,         /* Call start time */
            info.end,           /* Call end time */
            info.alert,         /* Call alert time */
            info.connect,       /* Call connect time */
            info.ispddpresent,  /* If PDD info present */
            info.pdd,           /* Post dial delay */
            info.release,       /* Who released the call */
            info.confid,        /* Conference ID */
            info.slost,         /* Packets not received by peer */
            info.slostfract,    /* Fraction of packets not received by peer */
            info.rlost,         /* Packets not received that were expected */
            info.rlostfract,    /* Fraction of packets expected but not received */
            NULL,               /* Max size of detail log */
            NULL);              /* Detail log */
        if (error != OSPC_ERR_NO_ERROR) {
            radlog(L_INFO,
                "rlm_osp: Failed to report usage, attempt '%d', error '%d'.",
                i,
                error);
        } else {
            break;
        }
    }

    /*
     * Delete transaction handle
     */
    OSPPTransactionDelete(transaction);

    if (i > MAX_RETRIES) {
        radlog(L_ERR, "rlm_osp: Failed to report usage.");
        return RLM_MODULE_FAIL;
    } else {
        DEBUG("rlm_osp: osp_accounting success");
        return RLM_MODULE_OK;
    }
}

/*
 * Get termination cause from accounting request
 *
 * param data Instance data
 * param request Accounting request
 * param cause Termination cause
 * return 0 success, -1 failure
 */
static int osp_get_termcause(
    rlm_osp_t* data,
    REQUEST* request,
    int* cause)
{
    char buffer[OSP_STRBUF_SIZE];
    osp_mapping_t* mapping = &data->mapping;

    DEBUG("rlm_osp: osp_get_termcause start");

    /*
     * Get release cause
     */
    if (osp_check_string(mapping->cause)) {
        radius_xlat(buffer, sizeof(buffer), mapping->cause, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_ERR,
                "rlm_osp: Failed to parse '%s' in request for release cause.",
                mapping->cause);
            return -1;
        } else {
            *cause = atoi(buffer);
        }
    } else {
        radlog(L_ERR, "rlm_osp: 'releasecause' mapping undefined.");
        return -1;
    }
    DEBUG("rlm_osp: releasecause = '%d'", *cause);

    DEBUG("rlm_osp: osp_get_termcause success");

    return 0;
}

/*
 * Get usage base from accounting request
 *
 * param data Instance data
 * param request Accounting request
 * param base OSP usage base
 * return 0 success, -1 failure
 */
static int osp_get_usagebase(
    rlm_osp_t* data,
    REQUEST* request,
    osp_usagebase_t* base)
{
    int size;
    char buffer[OSP_STRBUF_SIZE];
    osp_provider_t* provider = &data->provider;
    osp_mapping_t* mapping = &data->mapping;
    struct in_addr ip;

    DEBUG("rlm_osp: osp_get_usagebase start");

    /*
     * Get transaction ID
     */
    if (osp_check_string(mapping->transid)) {
        radius_xlat(buffer, sizeof(buffer), mapping->transid, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to parse '%s' in request for transsaction ID.",
                mapping->transid);
            base->transid = 0;
        } else {
            base->transid = atol(buffer);
        }
    } else {
        DEBUG("rlm_osp: 'transactionid' mapping undefined.");
        base->transid = 0;
    }
    DEBUG("rlm_osp: Transaction ID = '%llu'", base->transid);

    /*
     * Get Call-ID
     */
    if (osp_check_string(mapping->callid)) {
        radius_xlat(base->callid, sizeof(base->callid), mapping->callid, request, NULL);
        if (base->callid[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_ERR,
                "rlm_osp: Failed to parse '%s' in request for Call-ID.",
                mapping->callid);
            return -1;
        }
    } else {
        radlog(L_ERR, "rlm_osp: 'callid' mapping undefined.");
        return -1;
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: CALL-ID = '%s'", base->callid);

    /*
     * Get calling number
     */
    if (osp_check_string(mapping->calling)) {
        radius_xlat(buffer, sizeof(buffer), mapping->calling, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to parse '%s' in request for calling number.",
                mapping->calling);
            base->calling[0] = '\0';
        } else if (mapping->iscallinguri) {
            if (osp_get_username(buffer, base->calling, sizeof(base->calling)) < 0) {
                /* Do not have to check string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to get calling number from URI '%s'.",
                    buffer);
                base->calling[0] = '\0';
            }
        } else {
            size = sizeof(base->calling) - 1;
            snprintf(base->calling, size, "%s", buffer);
            base->calling[size] = '\0';
        }
    } else {
        radlog(L_ERR, "rlm_osp: 'callingnumber' mapping undefined.");
        base->calling[0] = '\0';
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: Calling Number = '%s'", base->calling);

    /*
     * Get called number
     */
    if (osp_check_string(mapping->called)) {
        radius_xlat(buffer, sizeof(buffer), mapping->called, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_ERR,
                "rlm_osp: Failed to parse '%s' in request for callied number.",
                mapping->called);
            return -1;
        } else if (mapping->iscalleduri) {
            if (osp_get_username(buffer, base->called, sizeof(base->called)) < 0) {
                /* Do not have to check string NULL */
                radlog(L_ERR,
                    "rlm_osp: Failed to get called number from URI '%s'.",
                    buffer);
                return -1;
            } else if (!osp_check_string(base->called)) {
                /*
                 * Called number must be reported
                 */
                radlog(L_ERR, "rlm_osp: Empty called number.");
                return -1;
            }
        } else {
            size = sizeof(base->called) - 1;
            snprintf(base->called, size, "%s", buffer);
            base->called[size] = '\0';
        }
    } else {
        radlog(L_ERR, "rlm_osp: 'callednumber' mapping undefined.");
        return -1;
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: Called Number = '%s'", base->called);

    /*
     * Get source device
     */
    if (osp_check_string(mapping->srcdev)) {
        radius_xlat(buffer, sizeof(buffer), mapping->srcdev, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_ERR,
                "rlm_osp: Failed to parse '%s' in request for source device.",
                mapping->srcdev);
            return -1;
        } else {
            osp_format_device(buffer, base->srcdev, sizeof(base->srcdev));
        }
    } else {
        radlog(L_ERR, "rlm_osp: 'sourcedevice' mapping undefined.");
        return -1;
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: Source Device = '%s'", base->srcdev);

    /*
     * Get source
     */
    if (osp_check_string(mapping->source)) {
        radius_xlat(buffer, sizeof(buffer), mapping->source, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to parse '%s' in request for source address.",
                mapping->source);
            ip.s_addr = provider->deviceip;
            inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
            osp_format_device(buffer, base->source, sizeof(base->source));
        } else {
            osp_format_device(buffer, base->source, sizeof(base->source));
        }
    } else {
        DEBUG("rlm_osp: 'source' mapping undefined.");
        ip.s_addr = provider->deviceip;
        inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
        osp_format_device(buffer, base->source, sizeof(base->source));
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: Source Address = '%s'", base->source);

    /*
     * Get destination
     */
    if (osp_check_string(mapping->destination)) {
        radius_xlat(buffer, sizeof(buffer), mapping->destination, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_ERR,
                "rlm_osp: Failed to parse '%s' in request for destination address.",
                mapping->destination);
            return -1;
        } else {
            osp_format_device(buffer, base->destination, sizeof(base->destination));
        }
    } else {
        radlog(L_ERR, "rlm_osp: 'destination' mapping undefined.");
        return -1;
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: Destination Address = '%s'", base->destination);

    /*
     * Get destination device
     */
    if (osp_check_string(mapping->destdev)) {
        radius_xlat(buffer, sizeof(buffer), mapping->destdev, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to parse '%s' in request for destination device.",
                mapping->destdev);
            base->destdev[0] = '\0';
        } else {
            osp_format_device(buffer, base->destdev, sizeof(base->destdev));
        }
    } else {
        DEBUG("rlm_osp: 'destinationdevice' mapping undefined.");
        base->destdev[0] = '\0';
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: Destination Device = '%s'", base->destdev);

    /*
     * Get destination count
     */
    if (osp_check_string(mapping->destcount)) {
        radius_xlat(buffer, sizeof(buffer), mapping->destcount, request, NULL);
        if (buffer[0] == '\0') {
            /* Has checked string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to parse '%s' in request for destination count.",
                mapping->destcount);
            base->destcount = OSP_DEF_DESTCOUNT;
        } else {
            base->destcount = atoi(buffer);
        }
    } else {
        DEBUG("rlm_osp: 'destinationcount' mapping undefined.");
        base->destcount = OSP_DEF_DESTCOUNT;
    }
    DEBUG("rlm_osp: Destination Count = '%d'", base->destcount);

    DEBUG("rlm_osp: osp_get_usagebase success");

    return 0;
}

/*
 * Format device IP or domain name
 *
 * param device Device IP or domain name
 * param buffer Buffer
 * param buffersize Size of buffer
 * return
 */
static void osp_format_device(
    char* device,
    char* buffer,
    int buffersize)
{
    struct in_addr inp;
    int size;
    char tmpbuf[OSP_STRBUF_SIZE];
    char* tmpptr;

    DEBUG("rlm_osp: osp_format_device start");

    size = sizeof(tmpbuf) - 1;
    strncpy(tmpbuf, device, size);
    tmpbuf[size] = '\0';

    if((tmpptr = strchr(tmpbuf, ':')) != NULL) {
        *tmpptr = '\0';
        tmpptr++;
    }

    size = buffersize - 1;
    if (inet_aton(tmpbuf, &inp) != 0) {
        if (tmpptr != NULL) {
            snprintf(buffer, size, "[%s]:%s", tmpbuf, tmpptr);
        } else {
            snprintf(buffer, size, "[%s]", tmpbuf);
        }
    } else {
        snprintf(buffer, size, "%s", device);
    }
    buffer[size] = '\0';

    DEBUG("rlm_osp: device = '%s'", buffer);

    DEBUG("rlm_osp: osp_format_device success");
}

/*
 * Get username from uri
 *
 * SIP-URI = "sip:" [ userinfo ] hostport
 *           uri-parameters [ headers ]
 * userinfo = ( user / telephone-subscriber ) [ ":" password ] "@"
 *
 * param uri Caller/callee URI
 * param buffer Username buffer
 * param buffersize Username buffer size
 * return 0 success, -1 failure
 */
static int osp_get_username(
    char* uri,
    char* buffer,
    int buffersize)
{
    char* start;
    char* end;
    char* tmp;
    int size;

    DEBUG("rlm_osp: osp_get_username start");

    if ((start = strstr(uri, "sip:")) == NULL) {
        if (osp_check_string(uri)) {
            radlog(L_ERR,
                "rlm_osp: URI '%s' format incorrect, without 'sip:'.",
                uri);
        } else {
            radlog(L_ERR, "rlm_osp: URI format incorrect");
        }
        return -1;
    } else {
        start += 4;
    }

    if ((end = strchr(start, '@')) == NULL) {
        *buffer = '\0';
    } else {
        if (((tmp = strchr(start, ':')) != NULL) && (tmp < end )) {
            end = tmp;
        }

        size = end - start;
        if (buffersize <= size) {
            size = buffersize - 1;
        }

        memcpy(buffer, start, size);
        buffer[size] = '\0';
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: username = '%s'", buffer);

    DEBUG("rlm_osp: osp_get_username success");

    return 0;
}

/*
 * Get usage info from accounting request
 *
 * param mapping RADIUS OSP mapping
 * param request Accounting request
 * param usagetype RADIUS record type
 * param info OSP usage information
 * return 0 success, -1 failure
 */
static int osp_get_usageinfo(
    osp_mapping_t* mapping,
    REQUEST* request,
    int usagetype,
    osp_usageinfo_t* info)
{
    char buffer[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_get_usageinfo start");

    /*
     * Get call start time
     */
    if ((usagetype == PW_STATUS_START) || (usagetype == PW_STATUS_STOP) || (usagetype == PW_STATUS_ALIVE)) { 
        if (osp_check_string(mapping->start)) {
            radius_xlat(buffer, sizeof(buffer), mapping->start, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_ERR,
                    "rlm_osp: Failed to parse '%s' in request for start time.",
                    mapping->start);
                return -1;
            } else {
                info->start = osp_format_time(buffer, mapping->timeformat);
            }
        } else {
            radlog(L_ERR, "rlm_osp: 'starttime' mapping undefined.");
            return -1;
        }
    } else {
        radlog(L_ERR, "rlm_osp: do not parse 'starttime'.");
        info->start = 0;
    }
    DEBUG("rlm_osp: starttime = '%lu'", info->start);

    /*
     * Get call alert time
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->alert)) {
            radius_xlat(buffer, sizeof(buffer), mapping->alert, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for alert time.",
                    mapping->alert);
                info->alert = 0;
            } else {
                info->alert = osp_format_time(buffer, mapping->timeformat);
            }
        } else {
            DEBUG("rlm_osp: 'alerttime' mapping undefined.");
            info->alert = 0;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'alerttime'.");
        info->alert = 0;
    }
    DEBUG("rlm_osp: alerttime = '%lu'", info->alert);

    /*
     * Get call connect time
     */
    if ((usagetype == PW_STATUS_START) || (usagetype == PW_STATUS_STOP)) {
        if (osp_check_string(mapping->connect)) {
            radius_xlat(buffer, sizeof(buffer), mapping->connect, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for connect time.",
                    mapping->connect);
                info->connect = 0;
            } else {
                info->connect = osp_format_time(buffer, mapping->timeformat);
            }
        } else {
            DEBUG("rlm_osp: 'connecttime' mapping undefined.");
            info->connect = 0;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'connecttime'.");
        info->connect = 0;
    }
    DEBUG("rlm_osp: connecttime = '%lu'", info->connect);

    /*
     * Get call end time
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->end)) {
            radius_xlat(buffer, sizeof(buffer), mapping->end, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_ERR,
                    "rlm_osp: Failed to parse '%s' in request for end time.",
                    mapping->end);
                return -1;
            } else {
                info->end = osp_format_time(buffer, mapping->timeformat);
            }
        } else {
            radlog(L_ERR, "rlm_osp: 'endtime' mapping undefined.");
            return -1;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'endtime'.");
        info->end = 0;
    }
    DEBUG("rlm_osp: endtime = '%lu'", info->end);

    /*
     * Get call duration
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->duration)) {
            radius_xlat(buffer, sizeof(buffer), mapping->duration, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for duration.",
                    mapping->duration);
                info->duration = difftime(info->start, info->end);
            } else {
                info->duration = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'duration' mapping undefined.");
            info->duration = difftime(info->start, info->end);
        }
    } else {
        DEBUG("rlm_osp: do not parse 'duration'.");
        info->duration = 0;
    }
    DEBUG("rlm_osp: duration = '%lu'", info->duration);

    /*
     * Get post dial delay
     */
    if ((usagetype == PW_STATUS_START) || (usagetype == PW_STATUS_STOP)) {
        if (osp_check_string(mapping->pdd)) {
            radius_xlat(buffer, sizeof(buffer), mapping->pdd, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for post dial delay.",
                    mapping->pdd);
                info->ispddpresent = 0;
                info->pdd = 0;
            } else {
                info->ispddpresent = 1;
                info->pdd = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'postdialdelay' mapping undefined.");
            info->ispddpresent = 0;
            info->pdd = 0;
        }
        info->pdd /= OSP_TIMEUNIT_SCALE[mapping->pddunit];
    } else {
        DEBUG("rlm_osp: do not parse 'postdialdelay'.");
        info->ispddpresent = 0;
        info->pdd = 0;
    }
    DEBUG("rlm_osp: ispddpresent = '%d'", info->ispddpresent);
    DEBUG("rlm_osp: postdialdelay = '%d'", info->pdd);

    /*
     * Get release source
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->release)) {
            radius_xlat(buffer, sizeof(buffer), mapping->release, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for release source.",
                    mapping->release);
                info->release = OSP_TK_RELSRC;
            } else {
                switch (atoi(buffer)) {
                case OSP_RELEASE_DEST:
                    info->release = OSP_TK_RELDST;
                    break;
                case OSP_RELEASE_UNDEF:
                case OSP_RELEASE_SRC:
                default:
                    info->release = OSP_TK_RELSRC;
                    break;
                }
            }
        } else {
            DEBUG("rlm_osp: 'releasesource' mapping undefined.");
            info->release = OSP_TK_RELSRC;
        }
    } else if (usagetype == PW_STATUS_START) {
        DEBUG("rlm_osp: do not parse 'releasesource'.");
        info->release = OSP_TK_RELSRC;
    } else { /* PW_STATUS_ALIVE */
        DEBUG("rlm_osp: do not parse 'releasesource'.");
        info->release = OSP_TK_RELDST;
    }
    DEBUG("rlm_osp: releasesource = '%d'", info->release);

    /*
     * Get conference ID
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->confid)) {
            radius_xlat(info->confid, sizeof(info->confid), mapping->confid, request, NULL);
            if (info->confid[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for conference ID.",
                    mapping->confid);
            }
        } else {
            DEBUG("rlm_osp: 'conferenceid' mapping undefined.");
            info->confid[0] = '\0';
        }
    } else {
        DEBUG("rlm_osp: do not parse 'conferenceid'.");
        info->confid[0] = '\0';
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: conferenceid = '%s'", info->confid);

    /*
     * Get lost send packets
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->slost)) {
            radius_xlat(buffer, sizeof(buffer), mapping->slost, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for lost send packets.",
                    mapping->slost);
                info->slost = OSP_DEF_SLOST;
            } else {
                info->slost = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'sendlost' mapping undefined.");
            info->slost = OSP_DEF_SLOST;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'sendlost'.");
        info->slost = OSP_DEF_SLOST;
    }
    DEBUG("rlm_osp: sendlost = '%d'", info->slost);

    /*
     * Get lost send packet fraction
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->slostfract)) {
            radius_xlat(buffer, sizeof(buffer), mapping->slostfract, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for lost send packet fraction.",
                    mapping->slostfract);
                info->slostfract = OSP_DEF_SLOSTFRACT;
            } else {
                info->slostfract = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'sendlostfract' mapping undefined.");
            info->slostfract = OSP_DEF_SLOSTFRACT;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'sendlostfract'.");
        info->slostfract = OSP_DEF_SLOSTFRACT;
    }
    DEBUG("rlm_osp: sendlostfract = '%d'", info->slostfract);

    /*
     * Get lost receive packets
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->rlost)) {
            radius_xlat(buffer, sizeof(buffer), mapping->rlost, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for lost receive packets.",
                    mapping->rlost);
                info->rlost = OSP_DEF_SLOST;
            } else {
                info->rlost = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'receivelost' mapping undefined.");
            info->rlost = OSP_DEF_SLOST;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'receivelost'.");
        info->rlost = OSP_DEF_SLOST;
    }
    DEBUG("rlm_osp: receivelost = '%d'", info->rlost);

    /*
     * Get lost receive packet fraction
     */
    if (usagetype == PW_STATUS_STOP) {
        if (osp_check_string(mapping->rlostfract)) {
            radius_xlat(buffer, sizeof(buffer), mapping->rlostfract, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for lost receive packet fraction.",
                    mapping->rlostfract);
                info->rlostfract = OSP_DEF_SLOSTFRACT;
            } else {
                info->rlostfract = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'receivelostfraction' mapping undefined.");
            info->rlostfract = OSP_DEF_SLOSTFRACT;
        }
    } else {
        DEBUG("rlm_osp: do not parse 'receivelostfraction'.");
        info->rlostfract = OSP_DEF_SLOSTFRACT;
    }
    DEBUG("rlm_osp: receivelostfract = '%d'", info->rlostfract);

    DEBUG("rlm_osp: osp_get_usageinfo success");

    return 0;
}

/*
 * Format time from time string
 *
 * param timestr Time string
 * param format Time string format
 * return Time value
 */
static time_t osp_format_time(
    char* timestr,
    osp_timestr_t format)
{
    struct tm dt;
    char buffer[OSP_STRBUF_SIZE];
    int size;
    char* tzone;
    long int toffset;
    time_t tvalue = 0;

    DEBUG("rlm_osp: osp_format_time start");

    switch (format) {
    case OSP_TIMESTR_T:
        tvalue = atol(timestr);
        break;
    case OSP_TIMESTR_C:
        /*
        * WWW MMM DD hh:mm:ss YYYY, assume UTC
        */
        strptime(timestr, "%a %b %d %T %Y", &dt);

        tzone = NULL;
        osp_cal_timeoffset(tzone, &toffset);

        osp_cal_elapsed(&dt, toffset, &tvalue);
        break;
    case OSP_TIMESTR_ACME:
        /*
        * hh:mm:ss.kkk ZON MMM DD YYYY
        */
        size = sizeof(buffer) - 1;
        snprintf(buffer, size, "%s", timestr);
        buffer[size] = '\0';

        size = sizeof(buffer) - 1 - 8;
        snprintf(buffer + 8, size, "%s", timestr + 16);
        buffer[size + 8] = '\0';

        strptime(buffer, "%T %b %d %Y", &dt);

        size = sizeof(buffer) - 1;
        snprintf(buffer, size, "%s", timestr + 13);
        buffer[3] = '\0';

        osp_cal_timeoffset(buffer, &toffset);

        osp_cal_elapsed(&dt, toffset, &tvalue);
        break;
    case OSP_TIMESTR_MAX:
    default:
        break;
    }
    DEBUG("rlm_osp: time = '%lu'", tvalue);

    DEBUG("rlm_osp: osp_format_time success");

    return tvalue;
}

/*
 * Calculate time offset to GMT beased on time zone in USA
 *
 * param tzone Time zone
 * param toffset Time offset in seconds
 * return 0 success, -1 failure
 */
static int osp_cal_timeoffset(
    char* tzone,
    long int* toffset)
{
    int ret = 0;

    DEBUG("rlm_osp: osp_get_timeoffset start");

    if (!osp_check_string(tzone)) {
        *toffset = OSP_TOFF_UTC;
    } else if (!strcmp(tzone, OSP_TZ_UTC)) {
        *toffset = OSP_TOFF_UTC;
    } else if (!strcmp(tzone, OSP_TZ_GMT)) {
        *toffset = OSP_TOFF_GMT;
    } else if (!strcmp(tzone, OSP_TZ_EST)) {
        *toffset = OSP_TOFF_EST;
    } else if (!strcmp(tzone, OSP_TZ_EDT)) {
        *toffset = OSP_TOFF_EDT;
    } else if (!strcmp(tzone, OSP_TZ_CST)) {
        *toffset = OSP_TOFF_CST;
    } else if (!strcmp(tzone, OSP_TZ_CDT)) {
        *toffset = OSP_TOFF_CDT;
    } else if (!strcmp(tzone, OSP_TZ_MST)) {
        *toffset = OSP_TOFF_MST;
    } else if (!strcmp(tzone, OSP_TZ_MDT)) {
        *toffset = OSP_TOFF_MDT;
    } else if (!strcmp(tzone, OSP_TZ_PST)) {
        *toffset = OSP_TOFF_PST;
    } else if (!strcmp(tzone, OSP_TZ_PDT)) {
        *toffset = OSP_TOFF_PDT;
    } else if (!strcmp(tzone, OSP_TZ_HST)) {
        *toffset = OSP_TOFF_HST;
    } else if (!strcmp(tzone, OSP_TZ_AKST)) {
        *toffset = OSP_TOFF_AKST;
    } else if (!strcmp(tzone, OSP_TZ_AKDT)) {
        *toffset = OSP_TOFF_AKDT;
    } else {
        /* Has checked string NULL */
        radlog(L_INFO,
            "rlm_osp: Failed to calcaulte time offset for time zone '%s'.",
            tzone);
        *toffset = OSP_TOFF_UTC;
        ret = -1;
    }
    DEBUG("rlm_osp: toffset = '%ld'", *toffset);

    DEBUG("rlm_osp: osp_get_timeoffset success");

    return ret;
}

/*
 * Calculate seconds elapsed
 *
 * param dt Breaken down time
 * param toffset Time offset in seconds
 * param elapsed Seconds elapsed
 * return 0 success, -1 failure
 */
static int osp_cal_elapsed(
    struct tm* dt,
    long int toffset,
    time_t* elapsed)
{
    int DaysAtMonth[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    time_t days;

    DEBUG("rlm_osp: osp_cal_elapsed start");

    if ((dt->tm_mon < 0) || (dt->tm_mon > 11)) {
        radlog(L_ERR, "rlm_osp: Failed to calculate elapsed seconds.");
        *elapsed = 0;
        return -1;
    }

    dt->tm_year += 1900;
    days = (dt->tm_year * 365) + (dt->tm_year / 4) - (dt->tm_year / 100) + (dt->tm_year / 400) + DaysAtMonth[dt->tm_mon] + dt->tm_mday;
    if ((((dt->tm_year % 4) == 0) && (!((dt->tm_year % 100) == 0) || ((dt->tm_year % 400) == 0))) &&
        (dt->tm_mon < 2))
    {
        days--;
    }
    days -= 719528;

    *elapsed = ((days * 86400) + (dt->tm_hour * 3600) + (dt->tm_min * 60) + dt->tm_sec - toffset);

    DEBUG("rlm_osp: osp_cal_elapsed success");

    return 0;
}

/*
 * Only free memory we allocated.  The strings allocated via
 * cf_section_parse() do not need to be freed.
 *
 * param instance Instace data
 * return 0 success
 */
static int osp_detach(
    void* instance)
{
    rlm_osp_t* data = (rlm_osp_t*)instance;
    osp_provider_t* provider = &data->provider;

    DEBUG("rlm_osp: osp_detach start");

    /*
     * Delete provider handle
     */
    OSPPProviderDelete(provider->handle, 0);

    /*
     * Cleanup OSP
     */
    OSPPCleanup();

    /*
     * Release instance data
     */
    free(instance);

    DEBUG("rlm_osp: osp_detach success");

    return 0;
}

/*
 * The module name should be the only globally exported symbol.
 * That is, everything else should be 'static'.
 *
 * If the module needs to temporarily modify it's instantiation
 * data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 * The server will then take care of ensuring that the module
 * is single-threaded.
 */
module_t rlm_osp = {
    RLM_MODULE_INIT,
    "osp",
    RLM_TYPE_THREAD_SAFE,   /* type */
    osp_instantiate,        /* instantiation */
    osp_detach,             /* detach */
    {
        NULL,               /* authentication */
        NULL,               /* authorization */
        NULL,               /* preaccounting */
        osp_accounting,     /* accounting */
        NULL,               /* checksimul */
        NULL,               /* pre-proxy */
        NULL,               /* post-proxy */
        NULL                /* post-auth */
    },
};

