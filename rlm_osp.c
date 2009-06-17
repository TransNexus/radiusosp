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

/*
 * Note: TURE/FALSE are defined in <freeradius-devel/radiusd.h>
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "osp/osp.h"
#include "osp/osputils.h"
#include "osp/ospb64.h"

/*
 * OSP module constants.
 */
#define OSP_STRBUF_SIZE     256
#define OSP_KEYBUF_SIZE     1024
#define OSP_LOGBUF_SIZE     1024

#define OSP_LOGLEVEL_DEF    "1"                         /* Mapping default log level, long */
#define OSP_HWACCE_DEF      "no"                        /* Mapping default hardware accelerate flag */
#define OSP_SECURITY_DEF    "no"                        /* Mapping default security flag */
#define OSP_SPS_MAX         4                           /* OSP max number of service points */
#define OSP_SPURI_DEF       "http://osptestserver.transnexus.com:1080/osp"  /* OSP default service point URI */
#define OSP_SPWEIGHT_DEF    "1000"                      /* Mapping default service point weight */
#define OSP_AUDITURL_DEF    "http://localhost:1234"     /* OSP default Audit URL */
#define OSP_PRIVATEKEY_DEF  "${raddbdir}/pkey.pem"      /* OSP default private key file */
#define OSP_LOCALCERT_DEF   "${raddbdir}/localcert.pem" /* OSP default localcert file */
#define OSP_CAS_MAX         4                           /* OSP max number of cacert files */
#define OSP_CACERT_DEF      "${raddbdir}/cacert_0.pem"  /* OSP default cacert file */
#define OSP_VALIDATION_DEF  1                           /* OSP default token validation, locally */
#define OSP_SSLLIFETIME_DEF "300"                       /* Mapping default SSL life time in seconds */
#define OSP_MAXCONN_DEF     "20"                        /* Mapping default max number of connections */
#define OSP_MAXCONN_MIN     1                           /* OSP min max number of connections */
#define OSP_MAXCONN_MAX     1000                        /* OSP max max number of connections */
#define OSP_PERSISTENCE_DEF "60000"                     /* Mapping default HTTP persistence in ms*/
#define OSP_RETRYDELAY_DEF  "0"                         /* Mapping default retry delay */
#define OSP_RETRYDELAY_MIN  0                           /* OSP min retry delay */
#define OSP_RETRYDELAY_MAX  10                          /* OSP max retry delay */
#define OSP_RETRYLIMIT_DEF  "2"                         /* Mapping default retry times */
#define OSP_RETRYLIMIT_MIN  0                           /* OSP min retry times */
#define OSP_RETRYLIMIT_MAX  100                         /* OSP max retry times */
#define OSP_TIMEOUT_DEF     "10000"                     /* Mapping default timeout */
#define OSP_TIMEOUT_MIN     200                         /* OSP min timeout in ms */
#define OSP_TIMEOUT_MAX     60000                       /* OSP max timeout in ms */
#define OSP_CUSTOMERID_DEF  ""                          /* OSP default customer ID */
#define OSP_DEVICEID_DEF    ""                          /* OSP default device ID */
#define OSP_DEVICEIP_DEF    "localhost"                 /* Mapping default device IP */
#define OSP_DEVICEPORT_DEF  "5060"                      /* Mapping default device port */
#define OSP_IP_DEF          0                           /* OSP default IP */
#define OSP_PORT_DEF        0                           /* OSP default port */
#define OSP_DESTCOUNT_DEF   0                           /* OSP default destination count, unset */
#define OSP_CAUSE_DEF       0                           /* OSP default termination cause */
#define OSP_TIME_DEF        0                           /* OSP default time value */
#define OSP_STATSINT_DEF    ((int)-1)                   /* OSP default statistics, integer */
#define OSP_STATSFLOAT_DEF  ((float)-1.0)               /* OSP default statistics, float */
#define OSP_INDEX_MAX       4                           /* OSP max timeout in ms */

/*
 * Default RADIUS OSP mapping
 */
#define OSP_MAP_TRANSID         NULL                        /* Transaction ID */
#define OSP_MAP_CALLID          "%{Acct-Session-Id}"        /* Call-ID, RFC 2866 */
#define OSP_MAP_ISCALLINGURI    "yes"                       /* Calling number type, uri */
#define OSP_MAP_CALLING         "%{Calling-Station-Id}"     /* Calling number, RFC 2865 */
#define OSP_MAP_ISCALLEDURI     "yes"                       /* Called number type, uri */
#define OSP_MAP_CALLED          "%{Called-Station-Id}"      /* Called number, RFC 2865 */
#define OSP_MAP_ASSERTEDID      NULL                        /* P-Asserted-Identity */
#define OSP_MAP_SRCDEV          NULL                        /* Source device */
#define OSP_MAP_SOURCE          "%{NAS-IP-Address}"         /* Source, RFC 2865 */
#define OSP_MAP_DESTINATION     NULL                        /* Destination */
#define OSP_MAP_DESTDEV         NULL                        /* Destination device */
#define OSP_MAP_DESTCOUNT       NULL                        /* Destination count */
#define OSP_MAP_NETWORKID       NULL                        /* Network ID */
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
#define OSP_MAP_DESTPROTO       NULL                        /* Destination protocol */
#define OSP_MAP_SESSIONID       NULL                        /* Session ID */
#define OSP_MAP_CODEC           NULL                        /* Codec */
#define OSP_MAP_CONFID          NULL                        /* Conference ID */
#define OSP_MAP_STATS           NULL                        /* Statistics */
#define OSP_MAP_REPORTER        "0"                         /* Statistics reporter, proxy */
#define OSP_MAP_PROXYROLE       "2"                         /* Proxy role, media stream through, active */
#define OSP_MAP_SCALE           "4"                         /* Scale, 1 */
#define OSP_MAP_CUSTOMINFO      NULL                        /* User-defined info */

/*
 * OSP log level
 */
typedef enum {
    OSP_LOG_SHORT = 0,  /* Log short message */
    OSP_LOG_LONG        /* Log long message */
} osp_loglevel_t;

/*
 * OSP mapping define level
 */
typedef enum {
    OSP_DEF_MUST = 0,   /* Mapping must be defined */
    OSP_DEF_MAY         /* Mapping may be defined */
} osp_deflevel_t;

/*
 * OSP time string types
 */
typedef enum {
    OSP_TIMESTR_MIN = 0,
    OSP_TIMESTR_T = OSP_TIMESTR_MIN,    /* time_t, integer string */
    OSP_TIMESTR_C,                      /* ctime, WWW MMM DD HH:MM:SS YYYY */
    OSP_TIMESTR_ACME,                   /* ACME, HH:MM:SS.MMM ZON MMM DD YYYY */
    OSP_TIMESTR_MAX = OSP_TIMESTR_ACME,
    OSP_TIMESTR_NUMBER
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
    OSP_TIMEUNIT_MIN = 0,
    OSP_TIMEUNIT_S = OSP_TIMEUNIT_MIN,  /* Second */
    OSP_TIMEUNIT_MS,                    /* Millisecond */
    OSP_TIMEUNIT_MAX = OSP_TIMEUNIT_MS,
    OSP_TIMEUNIT_NUMBER
} osp_timeunit_t;

int OSP_TIMEUNIT_SCALE[OSP_TIMEUNIT_NUMBER] = { 1, 1000 };

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
 * Gerenal scale 
 */
typedef enum {
    OSP_SCALE_MIN = 0,
    OSP_SCALE_00001 = OSP_SCALE_MIN,    /* 0.0001 */
    OSP_SCALE_0001,                     /* 0.001 */
    OSP_SCALE_001,                      /* 0.01 */
    OSP_SCALE_01,                       /* 0.1 */
    OSP_SCALE_1,                        /* 1 */
    OSP_SCALE_10,                       /* 10 */
    OSP_SCALE_100,                      /* 100 */
    OSP_SCALE_1000,                     /* 1000 */
    OSP_SCALE_10000,                    /* 10000 */
    OSP_SCALE_MAX = OSP_SCALE_10000,
    OSP_SCALE_NUMBER
} osp_scale_t;

float OSP_SCALE_TABLE[OSP_SCALE_NUMBER] = { 0.0001, 0.001, 0.01, 0.1, 1, 10, 100, 1000, 10000 };

/*
 * Statistics related types
 */
typedef enum {
    OSP_RCV_MIN = 0,
    OSP_RCV_PROXY = OSP_RCV_MIN,    /* Statistics for media stream to proxy. Normally, RTP */
    OSP_RCV_PEER,                   /* Statistics for media stream to calling/called party. Normally, RTCP */
    OSP_RCV_MAX = OSP_RCV_PEER,
    OSP_RCV_NUMBER
} osp_receiver_t;

typedef enum {
    OSP_FLOW_MIN = 0,
    OSP_FLOW_DOWN = OSP_FLOW_MIN,   /* Statistics for downstream. */
    OSP_FLOW_UP,                    /* Statistics for upstream. */
    OSP_FLOW_MAX = OSP_FLOW_UP,
    OSP_FLOW_NUMBER
} osp_flow_t;

typedef struct {
    char* pack; /* Packets lost in packets mapping */
    char* fract;/* Packets lost in fraction mapping */
} osp_packmap_t;

typedef struct {
    int pack;   /* Packets lost in packets */
    int fract;  /* Packets lost in fraction */
} osp_pack_t;

typedef struct {
    char* samp; /* Samples mapping */
    char* min;  /* Minimum mapping */
    char* max;  /* Maximum mapping */
    char* mean; /* Mean mapping */
    char* var;  /* Variance mapping */
} osp_metricsmap_t;

typedef struct {
    int samp;   /* Samples */
    int min;    /* Minimum */
    int max;    /* Maximum */
    int mean;   /* Mean */
    float var;  /* Variance */
} osp_metrics_t;

typedef struct {
    osp_packmap_t lost;     /* Packets lost mapping */
    osp_metricsmap_t jitter;/* Jitter mapping */
    osp_metricsmap_t delay; /* Delay mapping */
    char* octets;           /* Octets received mapping */
    char* packets;          /* Packets received mapping */
    char* rfactor;          /* RFactor mapping */
    char* mos;              /* MOS mapping */
} osp_statsgroupmap_t;

typedef struct {
    osp_pack_t lost;        /* Packets lost */
    osp_metrics_t jitter;   /* Jitter */
    osp_metrics_t delay;    /* Delay */
    int octets;             /* Octets recieved */
    int packets;            /* Packets received */
    float rfactor;          /* RFactor */
    float mos;              /* MOS */
} osp_statsgroup_t;

typedef enum {
    OSP_REPORTER_MIN = 0,
    OSP_REPORTER_PROXY = OSP_REPORTER_MIN,  /* Proxy */
    OSP_REPORTER_CALLING,                   /* Calling party */
    OSP_REPORTER_CALLED,                    /* Called party */
    OSP_REPORTER_MAX = OSP_REPORTER_CALLED,
    OSP_REPORTER_NUMBER
} osp_reporter_t;

typedef enum {
    OSP_PROXYROLE_MIN = 0,
    OSP_PROXYROLE_BYPASS = OSP_PROXYROLE_MIN, /* Media bypass*/
    OSP_PROXYROLE_PASSIVE,                    /* Media through, passive */
    OSP_PROXYROLE_ACTIVE,                     /* Media through, active */
    OSP_PROXYROLE_MAX = OSP_PROXYROLE_ACTIVE,
    OSP_PROXYROLE_NUMBER
} osp_proxyrole_t;

typedef struct {
    int reporter;                                               /* Statistics reporter */
    int proxyrole;                                              /* The role proxy plays */
    int rfactorscale;                                           /* R-Factor scale index */
    int mosscale;                                               /* MOS scale index */
    osp_packmap_t slost;                                        /* Lost send mapping */
    osp_packmap_t rlost;                                        /* Lost receive mapping */
    osp_statsgroupmap_t group[OSP_RCV_NUMBER][OSP_FLOW_NUMBER]; /* Statistics group mapping */
} osp_statsmap_t;

typedef struct {
    osp_pack_t slost;                                           /* Packets lost */
    osp_pack_t rlost;                                           /* Packets lost */
    osp_statsgroup_t group[OSP_RCV_NUMBER][OSP_FLOW_NUMBER];    /* Statistics group */
} osp_stats_t;

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
    int security;               /* Security flag */
    int sps;                    /* Number of service points */
    char* spuris[OSP_SPS_MAX];  /* Service point URIs */
    int spweights[OSP_SPS_MAX]; /* Service point weights */
    char* privatekey;           /* Private key file name */
    char* localcert;            /* Local cert file name */
    int cas;                    /* Number of cacerts */
    char* cacerts[OSP_CAS_MAX]; /* Cacert file names */
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
    char* transid;                  /* Transaction ID */
    char* callid;                   /* Call-ID */
    int iscallinguri;               /* If calling number uri */
    char* calling;                  /* Calling number */
    int iscalleduri;                /* If called number uri */
    char* called;                   /* Called number */
    char* assertedid;               /* P-Asserted-Identity */
    char* srcdev;                   /* Source device */
    char* source;                   /* Source */
    char* destination;              /* Destination */
    char* destdev;                  /* Destination device */
    char* destcount;                /* Destination count */
    char* snid;                     /* Source network ID */
    char* dnid;                     /* Destination network ID */
    int timeformat;                 /* Time string format */
    char* start;                    /* Call start time */
    char* alert;                    /* Call alert time */
    char* connect;                  /* Call connect time */
    char* end;                      /* Call end time */
    char* duration;                 /* Call duration */
    int pddunit;                    /* Post dial delay unit */
    char* pdd;                      /* Post dial delay */
    char* release;                  /* Release source */
    char* cause;                    /* Release cause */
    char* destprot;                 /* Destination protocol */
    char* insessionid;              /* Inbound Call-ID */
    char* outsessionid;             /* Outbound Call-ID */
    char* forcodec;                 /* Forward codec */
    char* revcodec;                 /* Reverse codec */
    char* confid;                   /* Conference ID */
    osp_statsmap_t stats;           /* Statistics */
    char* custinfo[OSP_INDEX_MAX];  /* Custom info */
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
 * Usage information structure.
 */
typedef struct {
    OSPTUINT64 transid;                             /* Transaction ID */
    char callid[OSP_STRBUF_SIZE];                   /* Call-ID */
    char calling[OSP_STRBUF_SIZE];                  /* Calling number */
    char called[OSP_STRBUF_SIZE];                   /* Called number */
    char assertedid[OSP_STRBUF_SIZE];               /* P-Asserted-Identity */
    char srcdev[OSP_STRBUF_SIZE];                   /* Source device */
    char source[OSP_STRBUF_SIZE];                   /* Source */
    char destination[OSP_STRBUF_SIZE];              /* Destination */
    char destdev[OSP_STRBUF_SIZE];                  /* Destination device */
    int destcount;                                  /* Destination count */
    char snid[OSP_STRBUF_SIZE];                     /* Source network ID */
    char dnid[OSP_STRBUF_SIZE];                     /* Destination network ID */
    time_t start;                                   /* Call start time */
    time_t alert;                                   /* Call alert time */
    time_t connect;                                 /* Call connect time */
    time_t end;                                     /* Call end time */
    time_t duration;                                /* Length of call */
    int pdd;                                        /* Post Dial Delay */
    int release;                                    /* EP that released the call */
    OSPE_TERM_CAUSE causetype;                      /* Release reason type */
    int cause;                                      /* Release reason */
    OSPE_DEST_PROTOCOL destprot;                    /* Destination protocol */
    char insessionid[OSP_STRBUF_SIZE];              /* Inbound Call-ID */
    char outsessionid[OSP_STRBUF_SIZE];             /* Outbound Call-ID */
    char forcodec[OSP_STRBUF_SIZE];                 /* Forward codec */
    char revcodec[OSP_STRBUF_SIZE];                 /* Reverse codec */
    char confid[OSP_STRBUF_SIZE];                   /* Conference ID */
    osp_stats_t stats;                              /* Statistics */
    char custinfo[OSP_INDEX_MAX][OSP_STRBUF_SIZE];  /* Conference ID */
} osp_usage_t;

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
    /* OSP module running parameters */
    { "loglevel", PW_TYPE_INTEGER, offsetof(rlm_osp_t, running.loglevel), NULL, OSP_LOGLEVEL_DEF },
    /* End */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

static const CONF_PARSER provider_config[] = {
    /*
     * OSP provider parameters
     *
     *   All service points, weights and cacerts must be listed to allow config
     *   parser to read them.
     */
    { "accelerate", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, provider.accelerate), NULL, OSP_HWACCE_DEF },
    { "security", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, provider.security), NULL, OSP_SECURITY_DEF },
    { "spuri1", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[0]), NULL, OSP_SPURI_DEF },
    { "spuri2", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[1]), NULL, NULL },
    { "spuri3", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[2]), NULL, NULL },
    { "spuri4", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[3]), NULL, NULL },
    { "spweight1", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[0]), NULL, OSP_SPWEIGHT_DEF },
    { "spweight2", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[1]), NULL, OSP_SPWEIGHT_DEF },
    { "spweight3", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[2]), NULL, OSP_SPWEIGHT_DEF },
    { "spweight4", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[3]), NULL, OSP_SPWEIGHT_DEF },
    { "privatekey", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.privatekey), NULL, OSP_PRIVATEKEY_DEF },
    { "localcert", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.localcert), NULL, OSP_LOCALCERT_DEF },
    { "cacert0", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[0]), NULL, OSP_CACERT_DEF },
    { "cacert1", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[1]), NULL, NULL },
    { "cacert2", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[2]), NULL, NULL },
    { "cacert3", PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[3]), NULL, NULL },
    { "ssllifetime", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.ssllifetime), NULL, OSP_SSLLIFETIME_DEF },
    { "maxconnections", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.maxconn), NULL, OSP_MAXCONN_DEF },
    { "persistence", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.persistence), NULL, OSP_PERSISTENCE_DEF },
    { "retrydelay", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.retrydelay), NULL, OSP_RETRYDELAY_DEF },
    { "retrylimit", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.retrylimit), NULL, OSP_RETRYLIMIT_DEF },
    { "timeout", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.timeout), NULL, OSP_TIMEOUT_DEF },
    { "deviceip", PW_TYPE_IPADDR, offsetof(rlm_osp_t, provider.deviceip), NULL, OSP_DEVICEIP_DEF },
    { "deviceport", PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.deviceport), NULL, OSP_DEVICEPORT_DEF },
    /* End */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

static const CONF_PARSER mapping_config[] = {

    #define mSMAP   mapping.stats
    #define mGMAP   mapping.stats.group

    /* 
     * RADIUS OSP mapping parameters
     *
     *   All custom info must be listed to allow config parser to read them.
     */
    { "transactionid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transid), NULL, OSP_MAP_TRANSID },
    { "callid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callid), NULL, OSP_MAP_CALLID },
    { "iscallinguri", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.iscallinguri), NULL, OSP_MAP_ISCALLINGURI},
    { "callingnumber", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calling), NULL, OSP_MAP_CALLING },
    { "iscalleduri", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.iscalleduri), NULL, OSP_MAP_ISCALLEDURI},
    { "callednumber", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.called), NULL, OSP_MAP_CALLED },
    { "assertedid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.assertedid), NULL, OSP_MAP_ASSERTEDID },
    { "sourcedevice", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcdev), NULL, OSP_MAP_SRCDEV},
    { "source", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.source), NULL, OSP_MAP_SOURCE },
    { "destination", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destination), NULL, OSP_MAP_DESTINATION },
    { "destinationdevice", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destdev), NULL, OSP_MAP_DESTDEV },
    { "destinationcount", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destcount), NULL, OSP_MAP_DESTCOUNT },
    { "sourcenetworkid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.snid), NULL, OSP_MAP_NETWORKID },
    { "destinationnetworkid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.dnid), NULL, OSP_MAP_NETWORKID },
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
    { "destinationprotocol", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destprot), NULL, OSP_MAP_DESTPROTO },
    { "inboundsessionid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.insessionid), NULL, OSP_MAP_SESSIONID },
    { "outboundsessionid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.outsessionid), NULL, OSP_MAP_SESSIONID },
    { "forwardcodec", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.forcodec), NULL, OSP_MAP_CODEC},
    { "reversecodec", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.revcodec), NULL, OSP_MAP_CODEC},
    { "conferenceid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.confid), NULL, OSP_MAP_CONFID },
    /* Statistics mapping */
    { "statisticsreporter", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.reporter), NULL, OSP_MAP_REPORTER},
    { "proxyrole", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.proxyrole), NULL, OSP_MAP_PROXYROLE},
    { "rfactorscaleindex", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.rfactorscale), NULL, OSP_MAP_SCALE},
    { "mosscaleindex", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.mosscale), NULL, OSP_MAP_SCALE},
    { "sendlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.slost.pack), NULL, OSP_MAP_STATS },
    { "sendlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.slost.fract), NULL, OSP_MAP_STATS },
    { "receivelostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rlost.pack), NULL, OSP_MAP_STATS },
    { "receivelostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rlost.fract), NULL, OSP_MAP_STATS },
    /* Statistics group mapping start */
    /* Lost */
    { "toproxydownstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].lost.pack), NULL, OSP_MAP_STATS },
    { "toproxydownstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].lost.fract), NULL, OSP_MAP_STATS },
    { "toproxyupstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].lost.pack), NULL, OSP_MAP_STATS },
    { "toproxyupstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].lost.fract), NULL, OSP_MAP_STATS },
    { "topeerdownstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].lost.pack), NULL, OSP_MAP_STATS },
    { "topeerdownstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].lost.fract), NULL, OSP_MAP_STATS },
    { "topeerupstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].lost.pack), NULL, OSP_MAP_STATS },
    { "topeerupstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].lost.fract), NULL, OSP_MAP_STATS },
    /* Jitter */
    { "toproxydownstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].jitter.samp), NULL, OSP_MAP_STATS },
    { "toproxydownstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].jitter.min), NULL, OSP_MAP_STATS },
    { "toproxydownstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].jitter.max), NULL, OSP_MAP_STATS },
    { "toproxydownstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].jitter.mean), NULL, OSP_MAP_STATS },
    { "toproxydownstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].jitter.var), NULL, OSP_MAP_STATS },
    { "toproxyupstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].jitter.samp), NULL, OSP_MAP_STATS },
    { "toproxyupstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].jitter.min), NULL, OSP_MAP_STATS },
    { "toproxyupstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].jitter.max), NULL, OSP_MAP_STATS },
    { "toproxyupstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].jitter.mean), NULL, OSP_MAP_STATS },
    { "toproxyupstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].jitter.var), NULL, OSP_MAP_STATS },
    { "topeerdownstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].jitter.samp), NULL, OSP_MAP_STATS },
    { "topeerdownstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].jitter.min), NULL, OSP_MAP_STATS },
    { "topeerdownstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].jitter.max), NULL, OSP_MAP_STATS },
    { "topeerdownstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].jitter.mean), NULL, OSP_MAP_STATS },
    { "topeerdownstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].jitter.var), NULL, OSP_MAP_STATS },
    { "topeerupstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].jitter.samp), NULL, OSP_MAP_STATS },
    { "topeerupstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].jitter.min), NULL, OSP_MAP_STATS },
    { "topeerupstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].jitter.max), NULL, OSP_MAP_STATS },
    { "topeerupstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].jitter.mean), NULL, OSP_MAP_STATS },
    { "topeerupstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].jitter.var), NULL, OSP_MAP_STATS },
    /* Delay */
    { "toproxydownstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].delay.samp), NULL, OSP_MAP_STATS },
    { "toproxydownstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].delay.min), NULL, OSP_MAP_STATS },
    { "toproxydownstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].delay.max), NULL, OSP_MAP_STATS },
    { "toproxydownstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].delay.mean), NULL, OSP_MAP_STATS },
    { "toproxydownstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].delay.var), NULL, OSP_MAP_STATS },
    { "toproxyupstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].delay.samp), NULL, OSP_MAP_STATS },
    { "toproxyupstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].delay.min), NULL, OSP_MAP_STATS },
    { "toproxyupstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].delay.max), NULL, OSP_MAP_STATS },
    { "toproxyupstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].delay.mean), NULL, OSP_MAP_STATS },
    { "toproxyupstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].delay.var), NULL, OSP_MAP_STATS },
    { "topeerdownstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].delay.samp), NULL, OSP_MAP_STATS },
    { "topeerdownstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].delay.min), NULL, OSP_MAP_STATS },
    { "topeerdownstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].delay.max), NULL, OSP_MAP_STATS },
    { "topeerdownstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].delay.mean), NULL, OSP_MAP_STATS },
    { "topeerdownstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].delay.var), NULL, OSP_MAP_STATS },
    { "topeerupstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].delay.samp), NULL, OSP_MAP_STATS },
    { "topeerupstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].delay.min), NULL, OSP_MAP_STATS },
    { "topeerupstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].delay.max), NULL, OSP_MAP_STATS },
    { "topeerupstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].delay.mean), NULL, OSP_MAP_STATS },
    { "topeerupstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].delay.var), NULL, OSP_MAP_STATS },
    /* Octets */
    { "toproxydownstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].octets), NULL, OSP_MAP_STATS },
    { "toproxyupstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].octets), NULL, OSP_MAP_STATS },
    { "topeerdownstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].octets), NULL, OSP_MAP_STATS },
    { "topeerupstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].octets), NULL, OSP_MAP_STATS },
    /* Packets */
    { "toproxydownstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].packets), NULL, OSP_MAP_STATS },
    { "toproxyupstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].packets), NULL, OSP_MAP_STATS },
    { "topeerdownstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].packets), NULL, OSP_MAP_STATS },
    { "topeerupstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].packets), NULL, OSP_MAP_STATS },
    /* RFactor */
    { "toproxydownstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].rfactor), NULL, OSP_MAP_STATS },
    { "toproxyupstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].rfactor), NULL, OSP_MAP_STATS },
    { "topeerdownstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].rfactor), NULL, OSP_MAP_STATS },
    { "topeerupstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].rfactor), NULL, OSP_MAP_STATS },
    /* MOS */
    { "toproxydownstreammos", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_DOWN].mos), NULL, OSP_MAP_STATS },
    { "toproxyupstreammos", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PROXY][OSP_FLOW_UP].mos), NULL, OSP_MAP_STATS },
    { "topeerdownstreammos", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_DOWN].mos), NULL, OSP_MAP_STATS },
    { "topeerupstreammos", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mGMAP[OSP_RCV_PEER][OSP_FLOW_UP].mos), NULL, OSP_MAP_STATS },
    /* Statistics group mapping end */
    { "custominfo1", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[0]), NULL, OSP_MAP_CUSTOMINFO },
    { "custominfo2", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[1]), NULL, OSP_MAP_CUSTOMINFO },
    { "custominfo3", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[2]), NULL, OSP_MAP_CUSTOMINFO },
    { "custominfo4", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[3]), NULL, OSP_MAP_CUSTOMINFO },
    /* End */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

static const CONF_PARSER module_config[] = {
    /* OSP running parameters */
    { "running", PW_TYPE_SUBSECTION, 0, NULL, (const void*)running_config },
    /* OSP provider parameters */
    { "provider", PW_TYPE_SUBSECTION, 0, NULL, (const void*)provider_config },
    /* RADIUS OSP mapping parameters */
    { "mapping", PW_TYPE_SUBSECTION, 0, NULL, (const void*)mapping_config },
    /* End */
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};

/*
 * Internal function prototype
 */
static int osp_check_running(osp_running_t* running);
static int osp_check_provider(osp_provider_t* provider);
static int osp_check_mapping(osp_mapping_t* mapping);
static int osp_check_statsmap(osp_statsmap_t* stats);
static int osp_check_itemmap(char* item, osp_deflevel_t level);
static int osp_create_provider(osp_provider_t* provider);
static void osp_report_statsinfo(OSPTTRANHANDLE transaction, osp_statsmap_t* mapping, osp_stats_t* stats);
static int osp_get_usageinfo(rlm_osp_t* data, REQUEST* request, int type, osp_usage_t* usage);
static int osp_get_statsinfo(osp_statsmap_t* mapping, REQUEST* request, int type, osp_stats_t* stats);
static void osp_create_device(uint32_t ip, int prot, char* buffer, int buffersize);
static void osp_format_device(char* device, char* buffer, int buffersize);
static int osp_get_username(char* uri, char* buffer, int buffersize);
static OSPE_DEST_PROTOCOL osp_parse_protocol(char* protocol);
static OSPE_TERM_CAUSE osp_get_causetype(OSPE_DEST_PROTOCOL protocol);
static time_t osp_format_time(char* timestr, osp_timestr_t format);
static int osp_cal_timeoffset(char* tzone, long int* toffset);
static int osp_cal_elapsed(struct tm* dt, long int toffset, time_t* elapsed);

/*
 * Macros
 */
/*
 * Check empty string
 *
 * param _str String to be checked
 */
#define OSP_CHECK_STRING(_str)  ((_str != NULL) && (_str[0] != '\0'))

/*
 * Check value min
 *
 * param _name Varaible name
 * param _val Variable value
 * param _min Min value
 */
#define OSP_CHECK_MIN(_name, _val, _min) { \
    if (_val <= _min) { \
        radlog(L_ERR, "rlm_osp: '%s' must be larger than '%d', not '%d'.", _name, _min - 1, _val); \
        return -1; \
    } \
    DEBUG("rlm_osp: '%s' = '%d'", _name, _val); \
}

/*
 * Check value range
 *
 * param _name Varaible name
 * param _val Variable value
 * param _min Min value
 * param _max Max value
 */
#define OSP_CHECK_RANGE(_name, _val, _min, _max) { \
    if ((_val < _min) || (_val > _max)) { \
        radlog(L_ERR, "rlm_osp: '%s' must be an integer from '%d' to '%d', not '%d'.", _name, _min, _max, _val); \
        return -1; \
    } \
    DEBUG("rlm_osp: '%s' = '%d'", _name, _val); \
}

/*
 * Check item mapping
 *
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 */
#define OSP_CHECK_ITEMMAP(_name, _lev, _map) { \
    DEBUG("rlm_osp: check '%s' mapping", _name); \
    if (osp_check_itemmap(_map, _lev) < 0) { \
        radlog(L_ERR, "rlm_osp: Incorrect '%s' mapping '%s'.", _name, _map); \
        return -1; \
    } \
    if (OSP_CHECK_STRING(_map)) { \
        DEBUG("rlm_osp: '%s' = '%s'", _name, _map); \
    } else { \
        /* Undefined may be defined item */ \
        DEBUG("rlm_osp: '%s' = 'NULL'", _name); \
    } \
}

/*
 * Get long long
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _def Item default value
 * param _buf Buffer
 * param _val Item value
 */
#define OSP_GET_LONGLONG(_req, _flag, _name, _lev, _map, _def, _buf, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val = _def; \
                } \
            } else { \
               _val = atoll(_buf); \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                _val = _def; \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        _val = _def; \
    } \
    DEBUG("rlm_osp: '%s' = '%llu'", _name, _val); \
}

/*
 * Get called/calling number
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _uri If an URI
 * param _buf Buffer
 * param _size Size
 * param _val Item value
 */
#define OSP_GET_NUMBER(_req, _flag, _name, _lev, _map, _uri, _buf, _size, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val[0] = '\0'; \
                } \
            } else if (_uri) { \
                if (osp_get_username(_buf, _val, sizeof(_val)) < 0) { \
                    /* Do not have to check string NULL */ \
                    if (_lev == OSP_DEF_MUST) { \
                        radlog(L_ERR, "rlm_osp: Failed to get '%s' from URI '%s'.", _name,  _buf); \
                        return -1; \
                    } else { \
                        radlog(L_INFO, "rlm_osp: Failed to get '%s' from URI '%s'.", _name,  _buf); \
                        _val[0] = '\0'; \
                    } \
                } else if ((_lev == OSP_DEF_MUST) && !OSP_CHECK_STRING(_val)) { \
                    /* Number must be reported */ \
                    radlog(L_ERR, "rlm_osp: Empty number."); \
                    return -1; \
                } \
            } else { \
                _size = sizeof(_val) - 1; \
                snprintf(_val, _size, "%s", _buf); \
                _val[_size] = '\0'; \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                _val[0] = '\0'; \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        _val[0] = '\0'; \
    } \
    /* Do not have to check string NULL */ \
    DEBUG("rlm_osp: '%s' = '%s'", _name, _val); \
}

/*
 * Get IP address
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _ip Default IP address
 * param _port Default prot
 * param _buf Buffer
 * param _val Item value
 */
#define OSP_GET_IP(_req, _flag, _name, _lev, _map, _ip, _port, _buf, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    osp_create_device(_ip, _port, _val, sizeof(_val)); \
                } \
            } else { \
                osp_format_device(_buf, _val, sizeof(_val)); \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                osp_create_device(_ip, _port, _val, sizeof(_val)); \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        osp_create_device(_ip, _port, _val, sizeof(_val)); \
    } \
    /* Do not have to check string NULL */ \
    DEBUG("rlm_osp: '%s' = '%s'", _name, _val); \
}

/*
 * Get string
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _val Item string
 */
#define OSP_GET_STRING(_req, _flag, _name, _lev, _map, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_val, sizeof(_val), _map, _req, NULL); \
            if (_val[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                   radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                   return -1; \
                } else { \
                   radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                } \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                _val[0] = '\0'; \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        _val[0] = '\0'; \
    } \
    /* Do not have to check string NULL */ \
    DEBUG("rlm_osp: '%s' = '%s'", _name, _val); \
}

/*
 * Get integer
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _def Item default value
 * param _buf Buffer
 * param _val Item value
 */
#define OSP_GET_INTEGER(_req, _flag, _name, _lev, _map, _def, _buf, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val = _def; \
                } \
            } else { \
                _val = atoi(_buf); \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                _val = _def; \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        _val = _def; \
    } \
    DEBUG("rlm_osp: '%s' = '%d'", _name, _val); \
}

/*
 * Get float
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _sca Item scale index
 * param _def Item default value
 * param _buf Buffer
 * param _val Item value
 */
#define OSP_GET_FLOAT(_req, _flag, _name, _lev, _map, _sca, _def, _buf, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val = _def; \
                } \
            } else { \
                _val = (float)atoi(_buf) * OSP_SCALE_TABLE[_sca]; \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                _val = _def; \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        _val = _def; \
    } \
    DEBUG("rlm_osp: '%s' = '%.4f'", _name, _val); \
}

/*
 * Get time
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Time name
 * param _lev Must or may be defined
 * param _map Time mapping string
 * param _type Time format
 * param _def Time default value
 * param _buf Buffer
 * param _val Time value
 */
#define OSP_GET_TIME(_req, _flag, _name, _lev, _map, _type, _def, _buf, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    radlog(L_INFO, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val = _def; \
                } \
            } else { \
                _val = osp_format_time(_buf, _type); \
            } \
        } else { \
            if (_lev == OSP_DEF_MUST) { \
                radlog(L_ERR, "rlm_osp: '%s' mapping undefined.", _name); \
                return -1; \
            } else { \
                DEBUG("rlm_osp: '%s' mapping undefined.", _name); \
                _val = 0; \
            } \
        } \
    } else { \
        DEBUG("rlm_osp: do not parse '%s'.", _name); \
        _val = 0; \
    } \
    DEBUG("rlm_osp: '%s' = '%lu'", _name, _val); \
}

/* OSP default certificates */
const char* B64PKey = "MIIBOgIBAAJBAK8t5l+PUbTC4lvwlNxV5lpl+2dwSZGW46dowTe6y133XyVEwNiiRma2YNk3xKs/TJ3Wl9Wpns2SYEAJsFfSTukCAwEAAQJAPz13vCm2GmZ8Zyp74usTxLCqSJZNyMRLHQWBM0g44Iuy4wE3vpi7Wq+xYuSOH2mu4OddnxswCP4QhaXVQavTAQIhAOBVCKXtppEw9UaOBL4vW0Ed/6EA/1D8hDW6St0h7EXJAiEAx+iRmZKhJD6VT84dtX5ZYNVk3j3dAcIOovpzUj9a0CECIEduTCapmZQ5xqAEsLXuVlxRtQgLTUD4ZxDElPn8x0MhAiBE2HlcND0+qDbvtwJQQOUzDgqg5xk3w8capboVdzAlQQIhAMC+lDL7+gDYkNAft5Mu+NObJmQs4Cr+DkDFsKqoxqrm";
const char* B64LCert = "MIIBeTCCASMCEHqkOHVRRWr+1COq3CR/xsowDQYJKoZIhvcNAQEEBQAwOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMB4XDTA1MDYyMzAwMjkxOFoXDTA2MDYyNDAwMjkxOFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvLeZfj1G0wuJb8JTcVeZaZftncEmRluOnaME3ustd918lRMDYokZmtmDZN8SrP0yd1pfVqZ7NkmBACbBX0k7pAgMBAAEwDQYJKoZIhvcNAQEEBQADQQDnV8QNFVVJx/+7IselU0wsepqMurivXZzuxOmTEmTVDzCJx1xhA8jd3vGAj7XDIYiPub1PV23eY5a2ARJuw5w9";
const char* B64CACert = "MIIBYDCCAQoCAQEwDQYJKoZIhvcNAQEEBQAwOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMB4XDTAyMDIwNDE4MjU1MloXDTEyMDIwMzE4MjU1MlowOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPGeGwV41EIhX0jEDFLRXQhDEr50OUQPq+f55VwQd0TQNts06BP29+UiNdRW3c3IRHdZcJdC1Cg68ME9cgeq0h8CAwEAATANBgkqhkiG9w0BAQQFAANBAGkzBSj1EnnmUxbaiG1N4xjIuLAWydun7o3bFk2tV8dBIhnuh445obYyk1EnQ27kI7eACCILBZqi2MHDOIMnoN0=";

/* Media stream receiver strings */
char* rcv_str[OSP_RCV_NUMBER] = { "toproxy", "topeer" };

/* Media stream flow stings */
char* flow_str[OSP_FLOW_NUMBER] = { "downstream", "upstream" };

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

    /* Set up a storage area for instance data */
    data = rad_malloc(sizeof(*data));
    if (!data) {
        radlog(L_ERR, "rlm_osp: Failed to allocate memory for instance data.");
        return -1;
    }
    memset(data, 0, sizeof(*data));

    /* If the configuration parameters can't be parsed, then fail. */
    if (cf_section_parse(conf, data, module_config) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to parse configuration parameters.");
        free(data);
        return -1;
    }

    /* If any running parameter is wrong, then fail. */
    if (osp_check_running(&data->running) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to check running parameters.");
        free(data);
        return -1;
    }

    /* If any provider parameter is wrong, then fail. */
    if (osp_check_provider(&data->provider) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to check provider parameters.");
        free(data);
        return -1;
    }

    /* If any mapping parameter is wrong, then fail. */
    if (osp_check_mapping(&data->mapping) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to check mapping parameters.");
        free(data);
        return -1;
    }

    /* If failed to create the provider, then fail. */
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
 * Check OSP module running parameters.
 *
 * param running Running parameters
 * return 0 success, -1 failure
 */
static int osp_check_running(
    osp_running_t* running)
{
    DEBUG("rlm_osp: osp_check_running start");

    /* Check log level */
    switch (running->loglevel) {
    case OSP_LOG_SHORT:
    case OSP_LOG_LONG:
        break;
    default:
        running->loglevel = OSP_LOG_LONG;
        break;
    }
    DEBUG("rlm_osp: 'loglevel' = '%d'", running->loglevel);

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
    struct in_addr ip;
    char buffer[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_check_provider start");

    /* Calculate number of service points */
    provider->sps = 0;
    for (i = 0; i < OSP_SPS_MAX; i++) {
        if (OSP_CHECK_STRING(provider->spuris[i])) {
            /* If any service point weight is wrong, then fail. */
            if (provider->spweights[i] <= 0) {
                radlog(L_ERR,
                    "rlm_osp: 'spweight%d' must be larger than 0, not '%d'.", 
                    i + 1, 
                    provider->spweights[i]);
                return -1;
            }
            provider->sps++;
        } else {
            break;
        }
    }

    /* If number of service points is wrong, then fail. */
    if (provider->sps == 0) {
        radlog(L_ERR, "rlm_osp: 'spuri1' must be defined.");
        return -1;
    }
    DEBUG("rlm_osp: 'sps' = '%d'", provider->sps);

    for (i = 0; i < provider->sps; i++) {
        /* Has checked string NULL */
        DEBUG("rlm_osp: 'spuri%d' = '%s'", i + 1, provider->spuris[i]);
    }

    for (i = 0; i < provider->sps; i++) {
        DEBUG("rlm_osp: 'spweight%d' = '%d'", i + 1, provider->spweights[i]);
    }

    /* If security flag is set, check certificate file names. Otherwise, use default certificates */
    if (provider->security) {
        /* If privatekey is undefined, then fail. */
        if (!OSP_CHECK_STRING(provider->privatekey)) {
            radlog(L_ERR, "rlm_osp: 'privatekey' must be defined.");
            return -1;
        }
        /* Has checked string NULL */
        DEBUG("rlm_osp: 'privatekey' = '%s'", provider->privatekey);

        /* If localcert is undefined, then fail. */
        if (!OSP_CHECK_STRING(provider->localcert)) {
            radlog(L_ERR, "rlm_osp: 'localcert' must be defined.");
            return -1;
        }
        /* Has checked string NULL */
        DEBUG("rlm_osp: 'locacert' = '%s'", provider->localcert);

        /* Calculate number of cacerts */
        provider->cas = 0;
        for (i = 0; i < OSP_CAS_MAX; i++) {
            if (OSP_CHECK_STRING(provider->cacerts[i]))  {
                provider->cas++;
            } else {
                break;
            }
        }

        /* If number of cacerts is wrong, then fail. */
        if (provider->cas == 0) {
            radlog(L_ERR, "rlm_osp: 'cacert0' must be defined.");
            return -1;
        }
        DEBUG("rlm_osp: 'cas' = '%d'", provider->cas);

        for (i = 0; i < provider->cas; i++) {
            /* Has checked string NULL */
            DEBUG("rlm_osp: 'cacert%d' = '%s'", i, provider->cacerts[i]);
        }
    }

    /* If SSL life time is wrong, then fail. */
    OSP_CHECK_MIN("ssllifetime", provider->ssllifetime, 0);

    /* If max number of connections is wrong, then fail. */
    OSP_CHECK_RANGE("maxconnections", provider->maxconn, OSP_MAXCONN_MIN, OSP_MAXCONN_MAX);

    /* If persistence is wrong, then fail. */
    OSP_CHECK_MIN("persistence", provider->persistence, 0);

    /* If retry delay is wrong, then fail. */
    OSP_CHECK_RANGE("retrydelay", provider->retrydelay, OSP_RETRYDELAY_MIN, OSP_RETRYDELAY_MAX);

    /* If times of retry is wrong, then fail. */
    OSP_CHECK_RANGE("retrylimit", provider->retrylimit, OSP_RETRYLIMIT_MIN, OSP_RETRYLIMIT_MAX);

    /* If timeout is wrong, then fail. */
    OSP_CHECK_RANGE("timeout", provider->timeout, OSP_TIMEOUT_MIN, OSP_TIMEOUT_MAX);

    /* Nothing to check for deviceip */
    ip.s_addr = provider->deviceip;
    inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
    DEBUG("rlm_osp: 'deviceip' = '%s'", buffer);

    /* Nothing to check for deviceport */
    DEBUG("rlm_osp: 'deviceport' = '%d'", provider->deviceport);

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
    int i;
    char buffer[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_check_mapping start");

    /* If transaction ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("transactionid", OSP_DEF_MAY, mapping->transid);

    /* If Call-ID is undefined, then fail. */
    OSP_CHECK_ITEMMAP("callid", OSP_DEF_MUST, mapping->callid);

    /* Nothing to check for iscallinguri */
    DEBUG("rlm_osp: 'iscallinguri' = '%d'", mapping->iscallinguri);

    /* If calling number is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("callingnumber", OSP_DEF_MAY, mapping->calling);

    /* Nothing to check for iscallieduri */
    DEBUG("rlm_osp: 'iscalleduri' = '%d'", mapping->iscalleduri);

    /* If called number is undefined, then fail. */
    OSP_CHECK_ITEMMAP("callednumber", OSP_DEF_MUST, mapping->called);

    /* If asserted ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("assertedid", OSP_DEF_MAY, mapping->assertedid);

    /* If source device is undefined, then fail. */
    OSP_CHECK_ITEMMAP("sourcedevice", OSP_DEF_MUST, mapping->srcdev);

    /* If source is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("source", OSP_DEF_MAY, mapping->source);

    /* If destination is undefined, then fail. */
    OSP_CHECK_ITEMMAP("destination", OSP_DEF_MUST, mapping->destination);

    /* If destination device is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("destinationdevice", OSP_DEF_MAY, mapping->destdev);

    /* If destination count is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("destinationcount", OSP_DEF_MAY, mapping->destcount);

    /* If source network ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("sourcenetworkid", OSP_DEF_MAY, mapping->snid);

    /* If destination network ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("destinationnetworkid", OSP_DEF_MAY, mapping->dnid);

    /* If time string format is wrong, then fail. */
    OSP_CHECK_RANGE("timeformat", mapping->timeformat, OSP_TIMESTR_MIN, OSP_TIMESTR_MAX);

    /* If call start time is undefined, then fail. */
    OSP_CHECK_ITEMMAP("starttime", OSP_DEF_MUST, mapping->start);

    /* If call alert time is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("alerttime", OSP_DEF_MAY, mapping->alert);

    /* If call connect time is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("connecttime", OSP_DEF_MAY, mapping->connect);

    /* If call end time is undefined, then fail. */
    OSP_CHECK_ITEMMAP("endtime", OSP_DEF_MUST, mapping->end);

    /* If call duration is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("duration", OSP_DEF_MAY, mapping->duration);

    /* If pdd unit is wrong, then fail. */
    OSP_CHECK_RANGE("postdialdelayunit", mapping->pddunit, OSP_TIMEUNIT_MIN, OSP_TIMEUNIT_MAX);

    /* If pdd is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("postdialdelay", OSP_DEF_MAY, mapping->pdd);

    /* If release source is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("releasesource", OSP_DEF_MAY, mapping->release);

    /* If release cause is undefined, then fail. */
    OSP_CHECK_ITEMMAP("releasecause", OSP_DEF_MUST, mapping->cause);

    /* If destination protocol is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("destinationprotocol", OSP_DEF_MAY, mapping->destprot);

    /* If inbound session ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("inboundsessionid", OSP_DEF_MAY, mapping->insessionid);

    /* If outbound session ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("outboundsessionid", OSP_DEF_MAY, mapping->outsessionid);

    /* If forward codec is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("forwardcodec", OSP_DEF_MAY, mapping->forcodec);

    /* If reverse codec is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("reversecodec", OSP_DEF_MAY, mapping->revcodec);

    /* If conference ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("conferenceid", OSP_DEF_MAY, mapping->confid);

    /* If statistcs are incorrect, then fail. */
    if (osp_check_statsmap(&mapping->stats) != 0) {
        return -1;
    }

    /* If user-defined info are incorrect, then fail. */
    for (i = 0; i < OSP_INDEX_MAX; i++) {
        snprintf(buffer, sizeof(buffer), "custominfo%d", i + 1);
        OSP_CHECK_ITEMMAP(buffer, OSP_DEF_MAY, mapping->custinfo[i]);
    }

    DEBUG("rlm_osp: osp_check_mapping success");

    return 0;
}

/*
 * Check statistics mapping parameters.
 *
 * param stats Mapping parameters
 * return 0 success, -1 failure
 */
static int osp_check_statsmap(
    osp_statsmap_t* stats)
{
    osp_receiver_t receiver;
    osp_flow_t flow;
    char name[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_check_statsmap start");

    /* If statistics reporter is wrong, then fail. */
    OSP_CHECK_RANGE("statisticsreporter", stats->reporter, OSP_REPORTER_MIN, OSP_REPORTER_MAX);

    /* If proxy role is wrong, then fail. */
    OSP_CHECK_RANGE("proxyrole", stats->proxyrole, OSP_PROXYROLE_MIN, OSP_PROXYROLE_MAX);

    /* If R-Factor scale index is wrong, then fail. */
    OSP_CHECK_RANGE("rfactorscaleindex", stats->rfactorscale, OSP_SCALE_MIN, OSP_SCALE_MAX);

    /* If MOS scale index is wrong, then fail. */
    OSP_CHECK_RANGE("mosscaleindex", stats->mosscale, OSP_SCALE_MIN, OSP_SCALE_MAX);

    /* If lost send packets is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("sendlostpackets", OSP_DEF_MAY, stats->slost.pack);

    /* If lost send packet fraction is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("sendlostfraction", OSP_DEF_MAY, stats->slost.fract);

    /* If lost receive packets is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("receivelostpackets", OSP_DEF_MAY, stats->rlost.pack);

    /* If lost receive packet fraction is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("receivelostfraction", OSP_DEF_MAY, stats->rlost.fract);

    for (receiver = OSP_RCV_PROXY; receiver < OSP_RCV_NUMBER; receiver++) {
        for (flow = OSP_FLOW_DOWN; flow < OSP_FLOW_NUMBER; flow++) {

            #define mGRP                (stats->group[receiver][flow])
            #define mSTR(_name, _var)   snprintf(_name, sizeof(_name), "%s%s%s", rcv_str[receiver], flow_str[flow], _var)

            /* If packets lost packets is incorrect, then fail. */
            mSTR(name, "lostpackets");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.lost.pack);

            /* If packets lost fraction is incorrect, then fail. */
            mSTR(name, "lostfraction");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.lost.fract);

            /* If jitter samples is incorrect, then fail. */
            mSTR(name, "jittersamples");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.jitter.samp);

            /* If jitter minimum is incorrect, then fail. */
            mSTR(name, "jitterminimum");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.jitter.min);

            /* If jitter maximum is incorrect, then fail. */
            mSTR(name, "jittermaximum");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.jitter.max);

            /* If jitter mean is incorrect, then fail. */
            mSTR(name, "jittermean");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.jitter.mean);

            /* If jitter variance is incorrect, then fail. */
            mSTR(name, "jittervariance");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.jitter.var);

            /* If delay samples is incorrect, then fail. */
            mSTR(name, "delaysamples");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.delay.samp);

            /* If delay minimum is incorrect, then fail. */
            mSTR(name, "delayminimum");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.delay.min);

            /* If delay maximum is incorrect, then fail. */
            mSTR(name, "delaymaximum");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.delay.max);

            /* If delay mean is incorrect, then fail. */
            mSTR(name, "delaymean");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.delay.mean);

            /* If delay variance is incorrect, then fail. */
            mSTR(name, "delayvariance");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.delay.var);

            /* If octets is incorrect, then fail. */
            mSTR(name, "octets");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.octets);

            /* If packets is incorrect, then fail. */
            mSTR(name, "packets");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.packets);

            /* If rfactor is incorrect, then fail. */
            mSTR(name, "rfactor");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.rfactor);

            /* If mos is incorrect, then fail. */
            mSTR(name, "mos");
            OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGRP.mos);
        }
    }

    DEBUG("rlm_osp: osp_check_statsmap success");

    return 0;
}

/*
 * Check RADIUS OSP item mapping.
 *
 * param item Mapping item
 * param level Mapping item level
 * return 0 success, -1 failure
 */
static int osp_check_itemmap (
    char* item,
    osp_deflevel_t level)
{
    int last;

    DEBUG("rlm_osp: osp_check_itemmap start");

    if (!OSP_CHECK_STRING(item)) {
        if (level == OSP_DEF_MUST) {
            radlog(L_ERR, "rlm_osp: Failed to check mapping item.");
            return -1;
        } else {
            DEBUG("rlm_osp: osp_check_itemmap success");
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

    DEBUG("rlm_osp: osp_check_itemmap success");

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
    int i, error, result = -1;
    unsigned long spweights[OSP_SPS_MAX];
    OSPTPRIVATEKEY privatekey;
    OSPT_CERT localcert;
    OSPT_CERT cacerts[OSP_CAS_MAX];
    const OSPT_CERT* pcacerts[OSP_CAS_MAX];
    unsigned char privatekeydata[OSP_KEYBUF_SIZE];
    unsigned char localcertdata[OSP_KEYBUF_SIZE];
    unsigned char cacertdata[OSP_KEYBUF_SIZE];

    DEBUG("rlm_osp: osp_create_provider start");

    /* Initialize OSP */
    if ((error = OSPPInit(provider->accelerate)) != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "Failed to initalize OSP, error '%d'.",
            error);
        return -1;
    }

    /* Copy service point weights to a temp buffer to avoid compile warning */
    for (i = 0; i < provider->sps; i++) {
        spweights[i] = provider->spweights[i];
    }

    if (provider->security) {
        privatekey.PrivateKeyData = NULL;
        privatekey.PrivateKeyLength = 0;

        localcert.CertData = NULL;
        localcert.CertDataLength = 0;

        for (i = 0; i < provider->cas; i++) {
            cacerts[i].CertData = NULL;
            cacerts[i].CertDataLength = 0;
        }

        if ((error = OSPPUtilLoadPEMPrivateKey((unsigned char*)provider->privatekey, &privatekey)) != OSPC_ERR_NO_ERROR) {
            /* Has checked string NULL by osp_check_provider */
            radlog(L_ERR,
                "rlm_osp: Failed to load privatekey '%s', error '%d'.",
                provider->privatekey,
                error);
        } else if ((error = OSPPUtilLoadPEMCert((unsigned char*)provider->localcert, &localcert)) != OSPC_ERR_NO_ERROR) {
            /* Has checked string NULL by osp_check_provider */
            radlog(L_ERR,
                "rlm_osp: Failed to load localcert '%s', error '%d'.",
                provider->localcert,
                error);
        } else {
            for (i = 0; i < provider->cas; i++) {
                if ((error = OSPPUtilLoadPEMCert((unsigned char*)provider->cacerts[i], &cacerts[i])) != OSPC_ERR_NO_ERROR) {
                    cacerts[i].CertData = NULL;
                    /* Has checked string NULL by osp_check_provider */
                    radlog(L_ERR,
                        "rlm_osp: Failed to load cacert '%s', error '%d'.",
                        provider->cacerts[i],
                        error);
                    break;
                } else {
                    pcacerts[i] = &cacerts[i];
                }
            }
        }
    } else {
        privatekey.PrivateKeyData = privatekeydata;
        privatekey.PrivateKeyLength = sizeof(privatekeydata);

        localcert.CertData = localcertdata;
        localcert.CertDataLength = sizeof(localcertdata);

        provider->cas = 1;
        cacerts[0].CertData = cacertdata;
        cacerts[0].CertDataLength = sizeof(cacertdata);
        pcacerts[0] = &cacerts[0];

        if ((error = OSPPBase64Decode(B64PKey, strlen(B64PKey), privatekey.PrivateKeyData, &privatekey.PrivateKeyLength)) != OSPC_ERR_NO_ERROR) {
            radlog(L_ERR,
                "rlm_osp: Failed to decode private key, error '%d'.",
                error);
        } else if ((error = OSPPBase64Decode(B64LCert, strlen(B64LCert), localcert.CertData, &localcert.CertDataLength)) != OSPC_ERR_NO_ERROR) {
            radlog(L_ERR,
                "rlm_osp: Failed to decode loca cert, error '%d'.",
                error);
        } else if ((error = OSPPBase64Decode(B64CACert, strlen(B64CACert), cacerts[0].CertData, &cacerts[0].CertDataLength)) != OSPC_ERR_NO_ERROR) {
            radlog(L_ERR,
                "rlm_osp: Failed to decode cacert, error '%d'.",
                error);
        }
    }

    if (error == OSPC_ERR_NO_ERROR) {
        /* Create a provider handle */
        error = OSPPProviderNew(
            provider->sps,                  /* Number of service points */
            (const char**)provider->spuris, /* Service point URIs */
            spweights,                      /* Service point weights */
            OSP_AUDITURL_DEF,               /* Audit URL */
            &privatekey,                    /* Private key */
            &localcert,                     /* Local cert */
            provider->cas,                  /* Number of cacerts */
            pcacerts,                       /* Cacerts */
            OSP_VALIDATION_DEF,             /* Token Validation mode */
            provider->ssllifetime,          /* SSL life time */
            provider->maxconn,              /* Max number of connections */
            provider->persistence,          /* Persistence */
            provider->retrydelay,           /* Retry delay */
            provider->retrylimit,           /* Times of retry */
            provider->timeout,              /* Timeout */
            OSP_CUSTOMERID_DEF,             /* Customer ID */
            OSP_DEVICEID_DEF,               /* Device ID */
            &provider->handle);             /* Provider handle */
        if (error != OSPC_ERR_NO_ERROR) {
            radlog(L_ERR,
                "rlm_osp: Failed to create provider, error '%d'.",
                error);
            OSPPCleanup();
        } else {
            DEBUG("rlm_osp: osp_create_provider success");
            result = 0;
        }
    } else {
        OSPPCleanup();
    }

    if (provider->security) {
        /* Release temp key buffers */
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
    osp_mapping_t* mapping = &data->mapping;
    OSPTTRANHANDLE transaction;
    OSPE_ROLE role;
    OSPT_CALL_ID* sessionid;
    osp_usage_t usage;
    const int MAX_RETRIES = 5;
    char buffer[OSP_LOGBUF_SIZE];
    int i, error;

    if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) == NULL) {
        DEBUG("rlm_osp: Failed to get accounting status type.");
        return RLM_MODULE_NOOP;
    }

    switch (vp->vp_integer) {
    case PW_STATUS_START:
        role = OSPC_ROLE_RADSRCSTART;
        break;
    case PW_STATUS_STOP:
        role = OSPC_ROLE_RADSRCSTOP;
        break;
    case PW_STATUS_ALIVE:   /* Interim-Update */
        role = OSPC_ROLE_RADSRCINTERIM;
        break;
    default:
        DEBUG("rlm_osp: Nothing to do for request type '%d'.", vp->vp_integer);
        return RLM_MODULE_NOOP;
    }

    /* Get usage information */
    if (osp_get_usageinfo(data, request, vp->vp_integer, &usage) < 0) {
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
        /* Note: it should not return RLM_MODULE_FAIL in case requests from others come in. */
        return RLM_MODULE_NOOP;
    }

    /* Create a transaction handle */
    error = OSPPTransactionNew(provider->handle, &transaction);
    if (error != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "rlm_osp: Failed to create transaction, error '%d'.",
            error);
        return RLM_MODULE_FAIL;
    }

    /* Build usage report from scratch */
    error = OSPPTransactionBuildUsageFromScratch(
        transaction,            /* Transaction handle */
        usage.transid,          /* Transaction ID */
        role,                   /* Usage type */
        usage.source,           /* Source */
        usage.destination,      /* Destination */
        usage.srcdev,           /* Source device */
        usage.destdev,          /* Destination device */
        usage.calling,          /* Calling number */
        OSPC_NFORMAT_E164,      /* Calling number format */
        usage.called,           /* Called number */
        OSPC_NFORMAT_E164,      /* Called number format */
        strlen(usage.callid),   /* Call ID length */
        usage.callid,           /* Call ID */
        OSP_CAUSE_DEF,          /* Previous attempt failure reason */
        NULL,                   /* Max size of detail log */
        NULL);                  /* Detail log buffer */
    if (error != OSPC_ERR_NO_ERROR) {
        radlog(L_ERR,
            "rlm_osp: Failed to build usage report, error '%d'.",
            error);
        OSPPTransactionDelete(transaction);
        return RLM_MODULE_FAIL;
    }

    /* Report destination count */
    if (usage.destcount != OSP_DESTCOUNT_DEF) {
        OSPPTransactionSetDestinationCount(
            transaction,
            usage.destcount);
    }

    /* Report source network ID */
    OSPPTransactionSetSrcNetworkId(
        transaction,
        usage.snid);

    /* Report destination network ID */
    OSPPTransactionSetDestNetworkId(
        transaction,
        usage.dnid);

    /* Report asserted ID */
    OSPPTransactionSetAssertedId(
        transaction,        /* Transaction handle */
        usage.assertedid);  /* Asserted ID */

    /* Report user-defined info */
    for (i = 0; i < OSP_INDEX_MAX; i++) {
        if (OSP_CHECK_STRING(usage.custinfo[i])) {
            OSPPTransactionSetCustomInfo(
                transaction,        /* Transaction handle */
                i,                  /* Index */
                usage.custinfo[i]); /* User-defined info */
        }
    }

    /* Report release code */
    OSPPTransactionSetTermCause(
        transaction,        /* Transaction handle */
        usage.causetype,    /* Release reason type */
        usage.cause,        /* Release reason */
        NULL);              /* Description */

    /* Report destination protocol */
    OSPPTransactionSetDestProtocol(
        transaction,        /* Transaction handle */
        usage.destprot);    /* Destination protocol */

    /* Report inbound session ID */
    if (usage.insessionid[0] != '\0') {
        sessionid = OSPPCallIdNew(strlen(usage.insessionid), (const unsigned char *)usage.insessionid);
        if (sessionid != NULL) {
            OSPPTransactionSetSessionId(
                transaction,        /* Transaction handle */
                OSPC_CLEG_INBOUND,  /* Inbound */
                sessionid);         /* Inbound session ID */
            OSPPCallIdDelete(&sessionid);
        }
    }

    /* Report outbound session ID */
    if (usage.outsessionid[0] != '\0') {
        sessionid = OSPPCallIdNew(strlen(usage.outsessionid), (const unsigned char *)usage.outsessionid);
        if (sessionid != NULL) {
            OSPPTransactionSetSessionId(
                transaction,        /* Transaction handle */
                OSPC_CLEG_OUTBOUND, /* Outbound */
                sessionid);         /* Outbound session ID */
            OSPPCallIdDelete(&sessionid);
        }
    }

    /* Report forward codec */
    OSPPTransactionSetForwardCodec(
        transaction,        /* Transaction handle */
        usage.forcodec);    /* Forward codec */

    /* Report reverse codec */
    OSPPTransactionSetReverseCodec(
        transaction,        /* Transaction handle */
        usage.revcodec);    /* Reverse codec */

    /* Report statistics */
    osp_report_statsinfo(transaction, &mapping->stats, &usage.stats);

    /* Send OSP UsageInd message to OSP server */
    for (i = 1; i <= MAX_RETRIES; i++) {
        error = OSPPTransactionReportUsage(
            transaction,                    /* Transaction handle */
            usage.duration,                 /* Call duration */
            usage.start,                    /* Call start time */
            usage.end,                      /* Call end time */
            usage.alert,                    /* Call alert time */
            usage.connect,                  /* Call connect time */
            (usage.pdd != OSP_STATSINT_DEF),/* If PDD info present */
            usage.pdd,                      /* Post dial delay */
            usage.release,                  /* Who released the call */
            usage.confid,                   /* Conference ID */
            usage.stats.slost.pack,         /* Packets not received by peer */
            usage.stats.slost.fract,        /* Fraction of packets not received by peer */
            usage.stats.rlost.pack,         /* Packets not received that were expected */
            usage.stats.rlost.fract,        /* Fraction of packets expected but not received */
            NULL,                           /* Max size of detail log */
            NULL);                          /* Detail log */
        if (error != OSPC_ERR_NO_ERROR) {
            radlog(L_INFO,
                "rlm_osp: Failed to report usage, attempt '%d', error '%d'.",
                i,
                error);
        } else {
            break;
        }
    }

    /* Delete transaction handle */
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
 * Report statistics info
 *
 * param transaction Transaction handle
 * param mapping Statistics mapping (for reproter & proxyrole)
 * param stats Statistics info
 * return
 */
static void osp_report_statsinfo(
    OSPTTRANHANDLE transaction,
    osp_statsmap_t* mapping,
    osp_stats_t* stats)
{
    osp_receiver_t receiver;
    osp_flow_t flow;
    OSPE_STATS_RANGE range;
    OSPE_STATS_FLOW direction;

    for (receiver = OSP_RCV_PROXY; receiver < OSP_RCV_NUMBER; receiver++) {
        switch (receiver) {
        case OSP_RCV_PEER:
            if (mapping->proxyrole == OSP_PROXYROLE_ACTIVE) {
                range = OSPC_SRANGE_PROXYPEER;
            } else {
                range = OSPC_SRANGE_PEERPEER;
            }
            break;
        case OSP_RCV_PROXY:
        default:
            range = OSPC_SRANGE_PEERPROXY;
            break;
        }

        for (flow = OSP_FLOW_DOWN; flow < OSP_FLOW_NUMBER; flow++) {
            if (flow == OSP_FLOW_DOWN) {
                direction = OSPC_SFLOW_DOWNSTREAM;
            } else {
                direction = OSPC_SFLOW_UPSTREAM;
            }

            #define mVAR    (stats->group[receiver][flow])

            /* Report packets lost */
            if ((mVAR.lost.pack != OSP_STATSINT_DEF) || (mVAR.lost.fract != OSP_STATSINT_DEF)) {
                OSPPTransactionSetLost(
                    transaction,        /* Transaction handle */
                    range,              /* Range */
                    direction,          /* Flow direction */
                    mVAR.lost.pack,     /* Packets lost packets */
                    mVAR.lost.fract);   /* Packets lost fraction */
            }

            /* Report jitter */
            if ((mVAR.jitter.samp != OSP_STATSINT_DEF) ||
                (mVAR.jitter.min != OSP_STATSINT_DEF) ||
                (mVAR.jitter.max != OSP_STATSINT_DEF) ||
                (mVAR.jitter.mean != OSP_STATSINT_DEF) ||
                (mVAR.jitter.var != OSP_STATSFLOAT_DEF))
            {
                OSPPTransactionSetJitter(
                    transaction,        /* Transaction handle */
                    range,              /* Range */
                    direction,          /* Flow direction */
                    mVAR.jitter.samp,   /* Jitter samples */
                    mVAR.jitter.min,    /* Jitter minimum */
                    mVAR.jitter.max,    /* Jitter maximum */
                    mVAR.jitter.mean,   /* Jitter mean */
                    mVAR.jitter.var);   /* Jitter variance */
            }

            /* Report delay */
            if ((mVAR.delay.samp != OSP_STATSINT_DEF) ||
                (mVAR.delay.min != OSP_STATSINT_DEF) ||
                (mVAR.delay.max != OSP_STATSINT_DEF) ||
                (mVAR.delay.mean != OSP_STATSINT_DEF) ||
                (mVAR.delay.var != OSP_STATSFLOAT_DEF))
            {
                OSPPTransactionSetDelay(
                    transaction,        /* Transaction handle */
                    range,              /* Range */
                    direction,          /* Flow direction */
                    mVAR.delay.samp,    /* Delay samples */
                    mVAR.delay.min,     /* Delay minimum */
                    mVAR.delay.max,     /* Delay maximum */
                    mVAR.delay.mean,    /* Delay mean */
                    mVAR.delay.var);    /* Delay variance */
            }

            /* Report octets */
            if (mVAR.octets != OSP_STATSINT_DEF) {
                OSPPTransactionSetOctets(
                    transaction,    /* Transaction handle */
                    range,          /* Range */
                    direction,      /* Flow direction */
                    mVAR.octets);   /* Octets */
            }

            /* Report packets */
            if (mVAR.packets != OSP_STATSINT_DEF) {
                OSPPTransactionSetPackets(
                    transaction,    /* Transaction handle */
                    range,          /* Range */
                    direction,      /* Flow direction */
                    mVAR.packets);  /* Packets */
            }

            /* Report rfactor */
            if (mVAR.rfactor != OSP_STATSFLOAT_DEF) {
                OSPPTransactionSetRFactor(
                    transaction,    /* Transaction handle */
                    range,          /* Range */
                    direction,      /* Flow direction */
                    mVAR.rfactor);  /* R-Factor */
            }

            /* Report mos */
            if (mVAR.mos != OSP_STATSFLOAT_DEF) {
                OSPPTransactionSetMOS(
                    transaction,    /* Transaction handle */
                    range,          /* Range */
                    direction,      /* Flow direction */
                    mVAR.mos);      /* MOS */
            }
        }
    }
}

/*
 * Get usage from accounting request
 *
 * param data Instance data
 * param request Accounting request
 * param type RADIUS record type
 * param usage OSP usage info
 * return 0 success, -1 failure
 */
static int osp_get_usageinfo(
    rlm_osp_t* data,
    REQUEST* request,
    int type,
    osp_usage_t* usage)
{
    osp_provider_t* provider = &data->provider;
    osp_mapping_t* mapping = &data->mapping;
    char buffer[OSP_STRBUF_SIZE];
    int parse, size, i;

    DEBUG("rlm_osp: osp_get_usageinfo start");

    /* Get transaction ID */
    OSP_GET_LONGLONG(request, TRUE, "transactionid", OSP_DEF_MAY, mapping->transid, 0, buffer, usage->transid);

    /* Get Call-ID */
    OSP_GET_STRING(request, TRUE, "callid", OSP_DEF_MUST, mapping->callid, usage->callid);

    /* Get calling number */
    OSP_GET_NUMBER(request, TRUE, "callingnumber", OSP_DEF_MAY, mapping->calling, mapping->iscallinguri, buffer, size, usage->calling);

    /* Get called number */
    OSP_GET_NUMBER(request, TRUE, "callednumber", OSP_DEF_MUST, mapping->called, mapping->iscalleduri, buffer, size, usage->called);

    /* Get asserted ID */
    OSP_GET_STRING(request, TRUE, "assertedid", OSP_DEF_MAY, mapping->assertedid, usage->assertedid);

    /* Get source device */
    OSP_GET_IP(request, TRUE, "sourcedevice", OSP_DEF_MUST, mapping->srcdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev);

    /* Get source */
    OSP_GET_IP(request, TRUE, "source", OSP_DEF_MAY, mapping->source, provider->deviceip, provider->deviceport, buffer, usage->source);

    /* Get destination */
    OSP_GET_IP(request, TRUE, "destination", OSP_DEF_MUST, mapping->destination, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination);

    /* Get destination device */
    OSP_GET_IP(request, TRUE, "destinationdevice", OSP_DEF_MAY, mapping->destdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destdev);

    /* Get destination count */
    OSP_GET_INTEGER(request, TRUE, "destinationcount", OSP_DEF_MAY, mapping->destcount, OSP_DESTCOUNT_DEF, buffer, usage->destcount);

    /* Get source network ID */
    OSP_GET_STRING(request, TRUE, "sourcenetworkid", OSP_DEF_MAY, mapping->snid, usage->snid);

    /* Get destination network ID */
    OSP_GET_STRING(request, TRUE, "destinationnetworkid", OSP_DEF_MAY, mapping->dnid, usage->dnid);

    /* Get call start time */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_TIME(request, parse, "starttime", OSP_DEF_MUST, mapping->start, mapping->timeformat, OSP_TIME_DEF, buffer, usage->start);

    /* Get call alert time */
    parse = (type == PW_STATUS_STOP);
    OSP_GET_TIME(request, parse, "alerttime", OSP_DEF_MAY, mapping->alert, mapping->timeformat, OSP_TIME_DEF, buffer, usage->alert);

    /* Get call connect time */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
    OSP_GET_TIME(request, parse, "connecttime", OSP_DEF_MAY, mapping->connect, mapping->timeformat, OSP_TIME_DEF, buffer, usage->connect);

    /* Get call end time */
    parse = (type == PW_STATUS_STOP);
    OSP_GET_TIME(request, parse, "endtime", OSP_DEF_MUST, mapping->end, mapping->timeformat, OSP_TIME_DEF, buffer, usage->end);

    /* Get call duration */
    if (type == PW_STATUS_STOP) {
        if (OSP_CHECK_STRING(mapping->duration)) {
            radius_xlat(buffer, sizeof(buffer), mapping->duration, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for 'duration'.",
                    mapping->duration);
                usage->duration = difftime(usage->start, usage->end);
            } else {
                usage->duration = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: 'duration' mapping undefined.");
            usage->duration = difftime(usage->start, usage->end);
        }
    } else {
        DEBUG("rlm_osp: do not parse 'duration'.");
        usage->duration = 0;
    }
    DEBUG("rlm_osp: 'duration' = '%lu'", usage->duration);

    /* Get post dial delay */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
    OSP_GET_INTEGER(request, parse, "postdialdelay", OSP_DEF_MAY, mapping->pdd, OSP_STATSINT_DEF, buffer, usage->pdd);
    if (usage->pdd != OSP_STATSINT_DEF) {
        usage->pdd /= OSP_TIMEUNIT_SCALE[mapping->pddunit];
    }
    DEBUG("rlm_osp: Post dial delay = '%d'", usage->pdd);

    /* Get release source */
    if (type == PW_STATUS_STOP) {
        if (OSP_CHECK_STRING(mapping->release)) {
            radius_xlat(buffer, sizeof(buffer), mapping->release, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                radlog(L_INFO,
                    "rlm_osp: Failed to parse '%s' in request for 'releasesource'.",
                    mapping->release);
                usage->release = OSP_TK_RELSRC;
            } else {
                switch (atoi(buffer)) {
                case OSP_RELEASE_DEST:
                    usage->release = OSP_TK_RELDST;
                    break;
                case OSP_RELEASE_UNDEF:
                case OSP_RELEASE_SRC:
                default:
                    usage->release = OSP_TK_RELSRC;
                    break;
                }
            }
        } else {
            DEBUG("rlm_osp: 'releasesource' mapping undefined.");
            usage->release = OSP_TK_RELSRC;
        }
    } else if (type == PW_STATUS_START) {
        DEBUG("rlm_osp: do not parse 'releasesource'.");
        usage->release = OSP_TK_RELSRC;
    } else {   /* PW_STATUS_ALIVE */
        DEBUG("rlm_osp: do not parse 'releasesource'.");
        usage->release = OSP_TK_RELDST;
    }
    DEBUG("rlm_osp: 'releasesource' = '%d'", usage->release);

    /* Get release cause */
    parse = ((type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_INTEGER(request, parse, "releasecause", OSP_DEF_MUST, mapping->cause, OSP_CAUSE_DEF, buffer, usage->cause);

    /* Get destination protocol */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, "destinationprotocol", OSP_DEF_MAY, mapping->destprot, buffer);
    usage->destprot = osp_parse_protocol(buffer);
    DEBUG("rlm_osp: Destination protocol type = '%d'", usage->destprot);

    /* Get release reason type */
    usage->causetype = osp_get_causetype(usage->destprot);
    DEBUG("rlm_osp: Termination cause type = '%d'", usage->causetype);

    /* Get inbound session ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, "inboundsessionid", OSP_DEF_MAY, mapping->insessionid, usage->insessionid);

    /* Get outbound session ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, "outboundsessionid", OSP_DEF_MAY, mapping->outsessionid, usage->outsessionid);

    /* Get forward codec */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
    OSP_GET_STRING(request, parse, "forwardcodec", OSP_DEF_MAY, mapping->forcodec, usage->forcodec);

    /* Get reverse codec */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
    OSP_GET_STRING(request, parse, "reversecodec", OSP_DEF_MAY, mapping->revcodec, usage->revcodec);

    /* Get conference ID */
    parse = (type == PW_STATUS_STOP);
    OSP_GET_STRING(request, parse, "conferenceid",  OSP_DEF_MAY, mapping->confid, usage->confid);

    /* Get inbound delay */
    osp_get_statsinfo(&data->mapping.stats, request, type, &usage->stats);

    /* Get user-defined info */
    for (i = 0; i < OSP_INDEX_MAX; i++) {
        snprintf(buffer, sizeof(buffer), "custominfo%d", i + 1);
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
        OSP_GET_STRING(request, parse, buffer, OSP_DEF_MAY, mapping->custinfo[i], usage->custinfo[i]);
    }

    DEBUG("rlm_osp: osp_get_usageinfo success");

    return 0;
}

/*
 * Get statistcs from accounting request
 *
 * param data Instance data
 * param request Accounting request
 * param type RADIUS record type
 * param stats OSP statistcs info
 * return 0 success, -1 failure
 */
static int osp_get_statsinfo(
    osp_statsmap_t* mapping,
    REQUEST* request,
    int type,
    osp_stats_t* stats)
{
    int parse;
    osp_receiver_t receiver;
    osp_flow_t flow;
    char name[OSP_STRBUF_SIZE];
    char buffer[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_get_statsinfo start");

    /* If parse statistics */
    parse = (type == PW_STATUS_STOP);

    /* Get lost send packets */
    OSP_GET_INTEGER(request, parse, "sendlostpackets", OSP_DEF_MAY, mapping->slost.pack, OSP_STATSINT_DEF, buffer, stats->slost.pack);

    /* Get lost send packet fraction */
    OSP_GET_INTEGER(request, parse, "sendlostfraction", OSP_DEF_MAY, mapping->slost.fract, OSP_STATSINT_DEF, buffer, stats->slost.fract);

    /* Get lost receive packets */
    OSP_GET_INTEGER(request, parse, "receivelostpackets", OSP_DEF_MAY, mapping->rlost.pack, OSP_STATSINT_DEF, buffer, stats->rlost.pack);

    /* Get lost receive packet fraction */
    OSP_GET_INTEGER(request, parse, "receivelostfraction", OSP_DEF_MAY, mapping->rlost.fract, OSP_STATSINT_DEF, buffer, stats->rlost.fract);

    for (receiver = OSP_RCV_PROXY; receiver < OSP_RCV_NUMBER; receiver++) {
        for (flow = OSP_FLOW_DOWN; flow < OSP_FLOW_NUMBER; flow++) {

            #define mMAP                (mapping->group[receiver][flow])
            #define mVAR                (stats->group[receiver][flow])
            #define mSTR(_name, _var)   snprintf(_name, sizeof(_name), "%s%s%s", rcv_str[receiver], flow_str[flow], _var)

            /* Get packets lost packets */
            mSTR(name, "lostpackets");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.lost.pack, OSP_STATSINT_DEF, buffer, mVAR.lost.pack);

            /* Get packets lost fraction */
            mSTR(name, "lostfraction");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.lost.fract, OSP_STATSINT_DEF, buffer, mVAR.lost.fract);

            /* Get jitter samples */
            mSTR(name, "jittersamples");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.jitter.samp, OSP_STATSINT_DEF, buffer, mVAR.jitter.samp);

            /* Get jitter minimim */
            mSTR(name, "jitterminimum");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.jitter.min, OSP_STATSINT_DEF, buffer, mVAR.jitter.min);

            /* Get jitter maximum */
            mSTR(name, "jittermaximum");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.jitter.max, OSP_STATSINT_DEF, buffer, mVAR.jitter.max);

            /* Get jitter mean */
            mSTR(name, "jittermean");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.jitter.mean, OSP_STATSINT_DEF, buffer, mVAR.jitter.mean);

            /* Get jitter variance */
            mSTR(name, "jittervariance");
            OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mMAP.jitter.var, OSP_SCALE_1, OSP_STATSFLOAT_DEF, buffer, mVAR.jitter.var);

            /* Get delay samples */
            mSTR(name, "delaysamples");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.delay.samp, OSP_STATSINT_DEF, buffer, mVAR.delay.samp);

            /* Get delay minimim */
            mSTR(name, "delayminimum");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.delay.min, OSP_STATSINT_DEF, buffer, mVAR.delay.min);

            /* Get delay maximum */
            mSTR(name, "delaymaximum");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.delay.max, OSP_STATSINT_DEF, buffer, mVAR.delay.max);

            /* Get delay mean */
            mSTR(name, "delaymean");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.delay.mean, OSP_STATSINT_DEF, buffer, mVAR.delay.mean);

            /* Get delay variance */
            mSTR(name, "delayvariance");
            OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mMAP.delay.var, OSP_SCALE_1, OSP_STATSFLOAT_DEF, buffer, mVAR.delay.var);

            /* Get octets */
            mSTR(name, "octets");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.octets, OSP_STATSINT_DEF, buffer, mVAR.octets);

            /* Get packets */
            mSTR(name, "packets");
            OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mMAP.packets, OSP_STATSINT_DEF, buffer, mVAR.packets);

            /* Get rfactor is */
            mSTR(name, "rfactor");
            OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mMAP.rfactor, mapping->rfactorscale, OSP_STATSFLOAT_DEF, buffer, mVAR.rfactor);

            /* Get mos */
            mSTR(name, "mos");
            OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mMAP.mos, mapping->mosscale, OSP_STATSFLOAT_DEF, buffer, mVAR.mos);
        }
    }

    DEBUG("rlm_osp: osp_get_statsinfo success");

    return 0;
}

/*
 * Create device IP with port
 *
 * param ip Device IP address
 * param port Device port
 * param buffer Buffer
 * param buffersize Size of buffer
 * return
 */
static void osp_create_device(
    uint32_t ip,
    int port,
    char* buffer,
    int buffersize)
{
    struct in_addr inp;
    char tmpbuf[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_create_device start");

    if (ip == OSP_IP_DEF) {
        buffer[0] = '\0';
    } else {
        inp.s_addr = ip;
        inet_ntop(AF_INET, &inp, tmpbuf, sizeof(tmpbuf));
    
        if (port == OSP_PORT_DEF) {
            snprintf(buffer, buffersize, "[%s]", tmpbuf);
        } else {
            snprintf(buffer, buffersize, "[%s]:%d", tmpbuf, port);
        }
    }
    DEBUG("rlm_osp: Device = '%s'", buffer);

    DEBUG("rlm_osp: osp_create_device success");
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

    DEBUG("rlm_osp: Device = '%s'", buffer);

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
        if (OSP_CHECK_STRING(uri)) {
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
        /* Check if there is a password */
        if (((tmp = strchr(start, ':')) != NULL) && (tmp < end )) {
            end = tmp;
        }

        /* Check if there is user part parameter, such as npdi */
        if (((tmp = strchr(start, ';')) != NULL) && (tmp < end )) {
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
    DEBUG("rlm_osp: URI username = '%s'", buffer);

    DEBUG("rlm_osp: osp_get_username success");

    return 0;
}

/*
 * Parse protocol from string
 *
 * param protocol Protocol string
 * return Protocol
 */
static OSPE_DEST_PROTOCOL osp_parse_protocol(
    char* protocol)
{
    OSPE_DEST_PROTOCOL type = OSPC_DPROT_UNKNOWN;

    DEBUG("rlm_osp: osp_parse_protocol start");

    if (OSP_CHECK_STRING(protocol)) {
        /* Comparing ignore case, Solaris does not support strcasestr */
        if (strstr(protocol, "H323") || strstr(protocol, "h323")) {
            type = OSPC_DPROT_Q931;
        } else if (strstr(protocol, "SIP") || strstr(protocol, "sip") || strstr(protocol, "Sip")) {
            type = OSPC_DPROT_SIP;
        }
    }
    DEBUG("rlm_osp: Protocol type = '%d'", type);

    DEBUG("rlm_osp: osp_parse_protocol success");

    return type;
}

/*
 * Get termination cause type from destination protocol
 *
 * param protocol Destination protocol
 * return Termination cause type
 */
static OSPE_TERM_CAUSE osp_get_causetype(
    OSPE_DEST_PROTOCOL protocol)
{
    OSPE_TERM_CAUSE type;

    DEBUG("rlm_osp: osp_get_causetype start");

    switch (protocol) {
    case OSPC_DPROT_SIP:
        type = OSPC_TCAUSE_SIP;
        break;
    case OSPC_DPROT_LRQ:
    case OSPC_DPROT_Q931:
        type = OSPC_TCAUSE_H323;
        break;
    case OSPC_DPROT_XMPP:
        type = OSPC_TCAUSE_XMPP;
        break;
    default:
        type = OSPC_TCAUSE_Q850;
        break;
    }
    DEBUG("rlm_osp: Cause type = '%d'", type);

    DEBUG("rlm_osp: osp_get_causetype success");

    return type;
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
        /* WWW MMM DD hh:mm:ss YYYY, assume UTC */
        tzone = NULL;
        if (osp_cal_timeoffset(tzone, &toffset) == 0) {
            strptime(timestr, "%a %b %d %T %Y", &dt);
            osp_cal_elapsed(&dt, toffset, &tvalue);
        }
        break;
    case OSP_TIMESTR_ACME:
        /* hh:mm:ss.kkk ZON MMM DD YYYY */
        size = sizeof(buffer) - 1;
        snprintf(buffer, size, "%s", timestr + 13);
        buffer[3] = '\0';

        if (osp_cal_timeoffset(buffer, &toffset) == 0) {
            size = sizeof(buffer) - 1;
            snprintf(buffer, size, "%s", timestr);
            buffer[size] = '\0';

            size = sizeof(buffer) - 1 - 8;
            snprintf(buffer + 8, size, "%s", timestr + 16);
            buffer[size + 8] = '\0';

            strptime(buffer, "%T %b %d %Y", &dt);

            osp_cal_elapsed(&dt, toffset, &tvalue);
        }
        break;
    default:
        break;
    }
    DEBUG("rlm_osp: Time = '%lu'", tvalue);

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

    if (!OSP_CHECK_STRING(tzone)) {
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
    DEBUG("rlm_osp: Time offset = '%ld'", *toffset);

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

    /* Delete provider handle */
    OSPPProviderDelete(provider->handle, 0);

    /* Cleanup OSP */
    OSPPCleanup();

    /* Release instance data */
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

