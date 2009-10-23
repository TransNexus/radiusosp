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

/* Module configurations */
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
#define OSP_DEVICEIP_DEF    "localhost"                 /* Mapping default device IP */
#define OSP_DEVICEPORT_DEF  "5060"                      /* Mapping default device port */
#define OSP_CUSTOMERID_DEF  ""                          /* OSP default customer ID */
#define OSP_DEVICEID_DEF    ""                          /* OSP default device ID */
/* VSA configurations */
#define OSP_IP_DEF          0                           /* OSP default IP */
#define OSP_PORT_DEF        0                           /* OSP default port */
#define OSP_DESTCOUNT_DEF   0                           /* OSP default destination count, unset */
#define OSP_CAUSE_DEF       0                           /* OSP default termination cause */
#define OSP_TIME_DEF        0                           /* OSP default time value */
#define OSP_STATSINT_DEF    ((int)-1)                   /* OSP default statistics, integer */
#define OSP_STATSFLOAT_DEF  ((float)-1.0)               /* OSP default statistics, float */
#define OSP_SUBNET_MAX      4                           /* OSP max number of subnets in a subnet list */
#define OSP_NETMASK_DEF     0xFFFFFFFF                  /* OSP default subnet mask */
#define OSP_NET_DELIMITER   "/"                         /* OSP delimiter string for subnet (ip/mask) */
#define OSP_LIST_DELIMITER  ",; "                       /* OSP delimiter string for subnet list */
#define OSP_CUSTOMINFO_MAX  4                           /* OSP max number of custom info */

/*
 * Default RADIUS OSP mapping
 */
#define OSP_MAP_REPORTSTART     "yes"                       /* Report RADIUS Start records */
#define OSP_MAP_REPORTINTERIM   "yes"                       /* Report RADIUS Interim-Update records */
#define OSP_MAP_REPORTSTOP      "yes"                       /* Report RADIUS Stop records */
#define OSP_MAP_CLIENTTYPE      "0"                         /* RADIUS client type, undefined */
#define OSP_MAP_NETLIST         NULL                        /* Subnet list */
#define OSP_MAP_ORIGIN          NULL                        /* Call origin */
#define OSP_MAP_TRANSID         NULL                        /* Transaction ID */
#define OSP_MAP_CALLID          "%{Acct-Session-Id}"        /* Call-ID, RFC 2866 */
#define OSP_MAP_NUMFORMAT       "0"                         /* Calling/called number format, E.164 */
#define OSP_MAP_CALLING         "%{Calling-Station-Id}"     /* Calling number, RFC 2865 */
#define OSP_MAP_CALLED          "%{Called-Station-Id}"      /* Called number, RFC 2865 */
#define OSP_MAP_ASSERTEDID      NULL                        /* P-Asserted-Identity */
#define OSP_MAP_SOURCE          "%{NAS-IP-Address}"         /* Source, RFC 2865 */
#define OSP_MAP_PROXY           "%{NAS-IP-Address}"         /* Proxy, RFC 2865 */
#define OSP_MAP_SRCDEV          NULL                        /* Source device */
#define OSP_MAP_DESTINATION     NULL                        /* Destination */
#define OSP_MAP_DESTDEV         NULL                        /* Destination device */
#define OSP_MAP_DESTCOUNT       NULL                        /* Destination count */
#define OSP_MAP_NETWORKID       NULL                        /* Network ID */
#define OSP_MAP_DIVUSER         NULL                        /* Diversion user */
#define OSP_MAP_DIVHOST         NULL                        /* Diversion host */
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
#define OSP_MAP_REPORTSTATS     "yes"                       /* Report statistics */
#define OSP_MAP_STATS           NULL                        /* Statistics */
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
 * Subnet
 */
typedef struct {
    uint32_t ip;    /* Subnet IP */
    uint32_t mask;  /* Subnet mask */
} osp_subnet_t;

/*
 * Subnet list
 */
typedef struct {
    int number;                             /* Number of subnets */
    osp_subnet_t subnet[OSP_SUBNET_MAX];    /* Subnets */
} osp_netlist_t;

/*
 * RADIUS client types
 */
typedef enum {
    OSP_CLIENT_MIN = 0,
    OSP_CLIENT_UNDEF = OSP_CLIENT_MIN,  /* Undefined */
    OSP_CLIENT_ACME,                    /* Acme */
    OSP_CLIENT_NEXTONE,                 /* NexTone */
    OSP_CLIENT_CISCO,                   /* Cisco */
    OSP_CLIENT_MAX = OSP_CLIENT_CISCO,
    OSP_CLIENT_NUMBER
} osp_client_t;

/*
 * Cisco h323-call-origin value strings
 */
#define OSP_CISCOCALL_INIT  "originate" /* Call originate, outbound */
#define OSP_CISCOCALL_TERM  "answer"    /* Call answer, inbound */

/*
 * Call origin types
 */
typedef enum {
    OSP_ORIGIN_INIT = 0,    /* Initiating, outbound */
    OSP_ORIGIN_TERM         /* Terminating, inbound */
} osp_origin_t;

/*
 * Normal string buffer type
 */
typedef char    osp_string_t[OSP_STRBUF_SIZE];

/*
 * Calling/called number format types
 */
typedef enum {
    OSP_CALLNUM_MIN = 0,
    OSP_CALLNUM_E164 = OSP_CALLNUM_MIN, /* E.164 */
    OSP_CALLNUM_URI,                    /* URI */
    OSP_CALLNUM_CISCO,                  /* Cisco, ton:0~7,npi:0~15,pi:0~3,si:0~3,#:E.164 */
    OSP_CALLNUM_MAX = OSP_CALLNUM_CISCO,
    OSP_CALLNUM_NUMBER
} osp_callnum_t;

/*
 * Integer string format types
 */
typedef enum {
    OSP_INTSTR_MIN = 0,
    OSP_INTSTR_DEC = OSP_INTSTR_MIN,    /* Decimal */
    OSP_INTSTR_HEX,                     /* Hex */
    OSP_INTSTR_MAX = OSP_INTSTR_HEX,
    OSP_INTSTR_NUMBER
} osp_intstr_t;

/*
 * OSP time string types
 */
typedef enum {
    OSP_TIMESTR_MIN = 0,
    OSP_TIMESTR_T = OSP_TIMESTR_MIN,    /* time_t, integer string */
    OSP_TIMESTR_C,                      /* ctime, WWW MMM DD HH:MM:SS YYYY */
    OSP_TIMESTR_ACME,                   /* Acme, HH:MM:SS.MMM ZON MMM DD YYYY */
    OSP_TIMESTR_NTP ,                   /* NTP, HH:MM:SS.MMM ZON WWW MMM DD YYYY */
    OSP_TIMESTR_CISCO ,                 /* NTP, {'*'|'.'}HH:MM:SS.MMM ZON WWW MMM DD YYYY */
    OSP_TIMESTR_MAX = OSP_TIMESTR_CISCO,
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
 * Time unit
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
 * OSP Toolkit release source
 */
#define OSP_TK_RELSRC   0
#define OSP_TK_RELDST   1

/*
 * OSP release source
 */
typedef enum {
    OSP_RELEASE_UNDEF = 0,  /* Unknown */
    OSP_RELEASE_SRC,        /* Source releases the call */
    OSP_RELEASE_DEST,       /* Destination releases the call */
} osp_release_t;

/*
 * Cisco release source
 */
typedef enum {
    OSP_CISCOREL_UNDEF = 0,
    OSP_CISCOREL_CALLINGPSTN,
    OSP_CISCOREL_CALLINGVOIP,
    OSP_CISCOREL_CALLEDPSTN,
    OSP_CISCOREL_CALLEDVOIP,
    OSP_CISCOREL_INTPOST,
    OSP_CISCOREL_INTVOIP,
    OSP_CISCOREL_INTAPPL,
    OSP_CISCOREL_INTAAA,
    OSP_CISCOREL_CONSOLE,
    OSP_CISCOREL_EXTRADIUS,
    OSP_CISCOREL_EXTAPPL,
    OSP_CISCOREL_EXTAGENT
} osp_ciscorelease_t;

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
    OSP_GROUP_MIN = 0,
    OSP_GROUP_RTP = OSP_GROUP_MIN,  /* Statistics for media stream to proxy. Normally, RTP */
    OSP_GROUP_RTCP,                 /* Statistics for media stream to calling/called party. Normally, RTCP */
    OSP_GROUP_MAX = OSP_GROUP_RTCP,
    OSP_GROUP_NUMBER
} osp_group_t;

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
    char* moscq;            /* MOS-CQ mapping */
    char* moslq;            /* MOS-LQ mapping */
} osp_statsgroupmap_t;

typedef struct {
    osp_pack_t lost;        /* Packets lost */
    osp_metrics_t jitter;   /* Jitter */
    osp_metrics_t delay;    /* Delay */
    int octets;             /* Octets recieved */
    int packets;            /* Packets received */
    float rfactor;          /* RFactor */
    float moscq;            /* MOS-CQ */
    float moslq;            /* MOS-LQ */
} osp_statsgroup_t;

typedef struct {
    int reportstats;                                                /* If to report statistics */
    int rfactorscale;                                               /* R-Factor scale index */
    int mosscale;                                                   /* MOS scale index */
    osp_packmap_t slost;                                            /* Lost send mapping */
    osp_packmap_t rlost;                                            /* Lost receive mapping */
    osp_statsgroupmap_t group[OSP_GROUP_NUMBER][OSP_FLOW_NUMBER];   /* Statistics group mapping */
} osp_statsmap_t;

typedef struct {
    osp_pack_t slost;                                           /* Packets lost */
    osp_pack_t rlost;                                           /* Packets lost */
    osp_statsgroup_t group[OSP_GROUP_NUMBER][OSP_FLOW_NUMBER];  /* Statistics group */
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
    uint32_t deviceip;          /* OSP reporting IP address */
    int deviceport;             /* OSP reporting IP port */
    OSPTPROVHANDLE handle;      /* OSP provider handle */
} osp_provider_t;

/*
 * OSP module mapping parameter structure.
 */
typedef struct {
    int reportstart;                    /* If to report RADIUS Start records */
    int reportstop;                     /* If to report RADIUS Stop records */
    int reportinterim;                  /* If to report RADIUS Interim-Update records */
    int clienttype;                     /* RADIUS client type */
    char* ignoreddeststr;               /* Ignored destination subnet list string */
    osp_netlist_t ignoreddestlist;      /* Ignored destination subnet list */
    char* origin;                       /* Call origin */
    char* transid;                      /* Transaction ID */
    char* callid;                       /* Call-ID */
    int callingformat;                  /* Calling number format */
    char* calling;                      /* Calling number */
    int calledformat;                   /* Called number format */
    char* called;                       /* Called number */
    char* assertedid;                   /* P-Asserted-Identity */
    char* source;                       /* Source */
    char* proxy;                        /* Proxy, only for call leg type records */
    char* srcdev;                       /* Source device */
    char* destination;                  /* Destination */
    char* destdev;                      /* Destination device */
    char* destcount;                    /* Destination count */
    char* snid;                         /* Source network ID */
    char* dnid;                         /* Destination network ID */
    char* divuser;                      /* Diversion user */
    char* divhost;                      /* Diversion host */
    int timeformat;                     /* Time string format */
    char* start;                        /* Call start time */
    char* alert;                        /* Call alert time */
    char* connect;                      /* Call connect time */
    char* end;                          /* Call end time */
    char* duration;                     /* Call duration */
    int pddunit;                        /* Post dial delay unit */
    char* pdd;                          /* Post dial delay */
    char* release;                      /* Release source */
    char* cause;                        /* Release cause */
    char* destprot;                     /* Destination protocol */
    char* insessionid;                  /* Inbound Call-ID */
    char* outsessionid;                 /* Outbound Call-ID */
    char* forcodec;                     /* Forward codec */
    char* revcodec;                     /* Reverse codec */
    char* confid;                       /* Conference ID */
    osp_statsmap_t stats;               /* Statistics */
    char* custinfo[OSP_CUSTOMINFO_MAX]; /* Custom info */
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
    int origin;                                 /* Call origin */
    OSPTUINT64 transid;                         /* Transaction ID */
    osp_string_t callid;                        /* Call-ID */
    osp_string_t calling;                       /* Calling number */
    osp_string_t called;                        /* Called number */
    osp_string_t assertedid;                    /* P-Asserted-Identity */
    osp_string_t source;                        /* Source */
    osp_string_t srcdev;                        /* Source device */
    osp_string_t destination;                   /* Destination */
    osp_string_t destdev;                       /* Destination device */
    int destcount;                              /* Destination count */
    osp_string_t snid;                          /* Source network ID */
    osp_string_t dnid;                          /* Destination network ID */
    osp_string_t divuser;                       /* Diversion user */
    osp_string_t divhost;                       /* Diversion host */
    time_t start;                               /* Call start time */
    time_t alert;                               /* Call alert time */
    time_t connect;                             /* Call connect time */
    time_t end;                                 /* Call end time */
    time_t duration;                            /* Length of call */
    int pdd;                                    /* Post Dial Delay */
    int release;                                /* EP that released the call */
    OSPE_TERM_CAUSE causetype;                  /* Release reason type */
    int cause;                                  /* Release reason */
    OSPE_DEST_PROTOCOL destprot;                /* Destination protocol */
    osp_string_t insessionid;                   /* Inbound Call-ID */
    osp_string_t outsessionid;                  /* Outbound Call-ID */
    osp_string_t forcodec;                      /* Forward codec */
    osp_string_t revcodec;                      /* Reverse codec */
    osp_string_t confid;                        /* Conference ID */
    osp_stats_t stats;                          /* Statistics */
    osp_string_t custinfo[OSP_CUSTOMINFO_MAX];  /* Conference ID */
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
    /*
     * RADIUS OSP mapping parameters
     *
     *   All custom info must be listed to allow config parser to read them.
     */
    { "reportstart", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.reportstart), NULL, OSP_MAP_REPORTSTART },
    { "reportstop", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.reportstop), NULL, OSP_MAP_REPORTSTOP },
    { "reportinterim", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.reportinterim), NULL, OSP_MAP_REPORTINTERIM },
    { "radiusclienttype", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.clienttype), NULL, OSP_MAP_CLIENTTYPE },
    { "ignoreddestinationlist", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.ignoreddeststr), NULL, OSP_MAP_NETLIST },
    { "callorigin", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.origin), NULL, OSP_MAP_ORIGIN },
    { "transactionid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transid), NULL, OSP_MAP_TRANSID },
    { "callid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callid), NULL, OSP_MAP_CALLID },
    { "callingnumberformat", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.callingformat), NULL, OSP_MAP_NUMFORMAT },
    { "callingnumber", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calling), NULL, OSP_MAP_CALLING },
    { "callednumberformat", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.calledformat), NULL, OSP_MAP_NUMFORMAT },
    { "callednumber", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.called), NULL, OSP_MAP_CALLED },
    { "assertedid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.assertedid), NULL, OSP_MAP_ASSERTEDID },
    { "source", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.source), NULL, OSP_MAP_SOURCE },
    { "proxy", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.proxy), NULL, OSP_MAP_PROXY },
    { "sourcedevice", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcdev), NULL, OSP_MAP_SRCDEV },
    { "destination", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destination), NULL, OSP_MAP_DESTINATION },
    { "destinationdevice", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destdev), NULL, OSP_MAP_DESTDEV },
    { "destinationcount", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destcount), NULL, OSP_MAP_DESTCOUNT },
    { "sourcenetworkid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.snid), NULL, OSP_MAP_NETWORKID },
    { "destinationnetworkid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.dnid), NULL, OSP_MAP_NETWORKID },
    { "diversionuser", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.divuser), NULL, OSP_MAP_DIVUSER },
    { "diversionhost", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.divhost), NULL, OSP_MAP_DIVHOST },
    { "timestringformat", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.timeformat), NULL, OSP_MAP_TIMEFORMAT },
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
    { "forwardcodec", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.forcodec), NULL, OSP_MAP_CODEC },
    { "reversecodec", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.revcodec), NULL, OSP_MAP_CODEC },
    { "conferenceid", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.confid), NULL, OSP_MAP_CONFID },
    /* Statistics mapping */
#define mSMAP   mapping.stats
    { "reportstatistics", PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mSMAP.reportstats), NULL, OSP_MAP_REPORTSTATS },
    { "rfactorscaleindex", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.rfactorscale), NULL, OSP_MAP_SCALE },
    { "mosscaleindex", PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.mosscale), NULL, OSP_MAP_SCALE },
    { "sendlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.slost.pack), NULL, OSP_MAP_STATS },
    { "sendlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.slost.fract), NULL, OSP_MAP_STATS },
    { "receivelostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rlost.pack), NULL, OSP_MAP_STATS },
    { "receivelostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rlost.fract), NULL, OSP_MAP_STATS },
#undef mSMAP
    /* Statistics group mapping start */
#define mSGMAP  mapping.stats.group
    /* Lost */
    { "rtpdownstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].lost.pack), NULL, OSP_MAP_STATS },
    { "rtpdownstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].lost.fract), NULL, OSP_MAP_STATS },
    { "rtpupstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].lost.pack), NULL, OSP_MAP_STATS },
    { "rtpupstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].lost.fract), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].lost.pack), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].lost.fract), NULL, OSP_MAP_STATS },
    { "rtcpupstreamlostpackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].lost.pack), NULL, OSP_MAP_STATS },
    { "rtcpupstreamlostfraction", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].lost.fract), NULL, OSP_MAP_STATS },
    /* Jitter */
    { "rtpdownstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].jitter.samp), NULL, OSP_MAP_STATS },
    { "rtpdownstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].jitter.min), NULL, OSP_MAP_STATS },
    { "rtpdownstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].jitter.max), NULL, OSP_MAP_STATS },
    { "rtpdownstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].jitter.mean), NULL, OSP_MAP_STATS },
    { "rtpdownstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].jitter.var), NULL, OSP_MAP_STATS },
    { "rtpupstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].jitter.samp), NULL, OSP_MAP_STATS },
    { "rtpupstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].jitter.min), NULL, OSP_MAP_STATS },
    { "rtpupstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].jitter.max), NULL, OSP_MAP_STATS },
    { "rtpupstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].jitter.mean), NULL, OSP_MAP_STATS },
    { "rtpupstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].jitter.var), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].jitter.samp), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].jitter.min), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].jitter.max), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].jitter.mean), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].jitter.var), NULL, OSP_MAP_STATS },
    { "rtcpupstreamjittersamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].jitter.samp), NULL, OSP_MAP_STATS },
    { "rtcpupstreamjitterminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].jitter.min), NULL, OSP_MAP_STATS },
    { "rtcpupstreamjittermaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].jitter.max), NULL, OSP_MAP_STATS },
    { "rtcpupstreamjittermean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].jitter.mean), NULL, OSP_MAP_STATS },
    { "rtcpupstreamjittervariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].jitter.var), NULL, OSP_MAP_STATS },
    /* Delay */
    { "rtpdownstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].delay.samp), NULL, OSP_MAP_STATS },
    { "rtpdownstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].delay.min), NULL, OSP_MAP_STATS },
    { "rtpdownstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].delay.max), NULL, OSP_MAP_STATS },
    { "rtpdownstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].delay.mean), NULL, OSP_MAP_STATS },
    { "rtpdownstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].delay.var), NULL, OSP_MAP_STATS },
    { "rtpupstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].delay.samp), NULL, OSP_MAP_STATS },
    { "rtpupstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].delay.min), NULL, OSP_MAP_STATS },
    { "rtpupstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].delay.max), NULL, OSP_MAP_STATS },
    { "rtpupstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].delay.mean), NULL, OSP_MAP_STATS },
    { "rtpupstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].delay.var), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].delay.samp), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].delay.min), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].delay.max), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].delay.mean), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].delay.var), NULL, OSP_MAP_STATS },
    { "rtcpupstreamdelaysamples", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].delay.samp), NULL, OSP_MAP_STATS },
    { "rtcpupstreamdelayminimum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].delay.min), NULL, OSP_MAP_STATS },
    { "rtcpupstreamdelaymaximum", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].delay.max), NULL, OSP_MAP_STATS },
    { "rtcpupstreamdelaymean", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].delay.mean), NULL, OSP_MAP_STATS },
    { "rtcpupstreamdelayvariance", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].delay.var), NULL, OSP_MAP_STATS },
    /* Octets */
    { "rtpdownstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].octets), NULL, OSP_MAP_STATS },
    { "rtpupstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].octets), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].octets), NULL, OSP_MAP_STATS },
    { "rtcpupstreamoctets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].octets), NULL, OSP_MAP_STATS },
    /* Packets */
    { "rtpdownstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].packets), NULL, OSP_MAP_STATS },
    { "rtpupstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].packets), NULL, OSP_MAP_STATS },
    { "rtcpdownstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].packets), NULL, OSP_MAP_STATS },
    { "rtcpupstreampackets", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].packets), NULL, OSP_MAP_STATS },
    /* RFactor */
    { "rtpdownstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].rfactor), NULL, OSP_MAP_STATS },
    { "rtpupstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].rfactor), NULL, OSP_MAP_STATS },
    { "rtcpdownstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].rfactor), NULL, OSP_MAP_STATS },
    { "rtcpupstreamrfactor", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].rfactor), NULL, OSP_MAP_STATS },
    /* MOS */
    { "rtpdownstreammoscq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].moscq), NULL, OSP_MAP_STATS },
    { "rtpupstreammoscq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].moscq), NULL, OSP_MAP_STATS },
    { "rtcpdownstreammoscq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].moscq), NULL, OSP_MAP_STATS },
    { "rtcpupstreammoscq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].moscq), NULL, OSP_MAP_STATS },
    { "rtpdownstreammoslq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_DOWN].moslq), NULL, OSP_MAP_STATS },
    { "rtpupstreammoslq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTP][OSP_FLOW_UP].moslq), NULL, OSP_MAP_STATS },
    { "rtcpdownstreammoslq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_DOWN].moslq), NULL, OSP_MAP_STATS },
    { "rtcpupstreammoslq", PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSGMAP[OSP_GROUP_RTCP][OSP_FLOW_UP].moslq), NULL, OSP_MAP_STATS },
#undef mSGMAP
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
static int osp_parse_netlist(char* liststr, osp_netlist_t* list);
static int osp_check_statsmap(osp_statsmap_t* stats);
static int osp_check_itemmap(char* item, osp_deflevel_t level);
static int osp_create_provider(osp_provider_t* provider);
static void osp_report_statsinfo(OSPTTRANHANDLE transaction, osp_statsmap_t* mapping, osp_stats_t* stats);
static int osp_get_usageinfo(rlm_osp_t* data, REQUEST* request, int type, osp_usage_t* usage);
static int osp_match_subnet(osp_netlist_t* list, uint32_t ip);
static int osp_get_statsinfo(osp_mapping_t* mapping, REQUEST* request, int type, osp_usage_t* usage);
static void osp_create_device(uint32_t ip, int prot, char* buffer, int buffersize);
static void osp_format_device(char* device, char* buffer, int buffersize);
static int osp_get_uriuser(char* uri, char* buffer, int buffersize);
static int osp_get_urihost(char* uri, char* buffer, int buffersize);
static OSPE_DEST_PROTOCOL osp_parse_protocol(osp_mapping_t* mapping, char* protocol);
static OSPE_TERM_CAUSE osp_get_causetype(osp_mapping_t* mapping, OSPE_DEST_PROTOCOL protocol);
static time_t osp_format_time(char* timestamp, osp_timestr_t format);
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
        if (OSP_CHECK_STRING(_map)) { \
            radlog(L_ERR, "rlm_osp: Incorrect '%s' mapping '%s'.", _name, _map); \
        } else { \
            radlog(L_ERR, "rlm_osp: Incorrect '%s' mapping 'NULL'.", _name); \
        } \
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
 * param _type Calling/called number format
 * param _buf Buffer
 * param _ptr Temporary pointer
 * param _size Size
 * param _val Item value
 */
#define OSP_GET_CALLNUM(_req, _flag, _name, _lev, _map, _type, _buf, _ptr, _size, _val) { \
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
            } else  { \
                _ptr = _buf; \
                switch (_type) { \
                case OSP_CALLNUM_URI: \
                    if (osp_get_uriuser(_buf, _val, sizeof(_val)) < 0) { \
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
                    break; \
                case OSP_CALLNUM_CISCO: \
                    if ((_ptr = strstr(_buf, "#:")) != NULL) { \
                        _ptr += 2; \
                    } else { \
                        _ptr = _buf; \
                    } \
                case OSP_CALLNUM_E164: \
                default: \
                    _size = sizeof(_val) - 1; \
                    snprintf(_val, _size, "%s", _ptr); \
                    _val[_size] = '\0'; \
                    break; \
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
 * Get URI hostport
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
#define OSP_GET_URIHOST(_req, _flag, _name, _lev, _map, _ip, _port, _buf, _val) { \
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
                    osp_create_device(_ip, _port, _val, sizeof(_val)); \
                } \
            } else { \
                if (osp_get_urihost(_val, _buf, sizeof(_buf)) < 0) { \
                    /* Do not have to check string NULL */ \
                    if (_lev == OSP_DEF_MUST) { \
                        radlog(L_ERR, "rlm_osp: Failed to get '%s' from URI '%s'.", _name,  _buf); \
                        return -1; \
                    } else { \
                        radlog(L_INFO, "rlm_osp: Failed to get '%s' from URI '%s'.", _name,  _buf); \
                        osp_create_device(_ip, _port, _val, sizeof(_val)); \
                    } \
                } else  { \
                    if (OSP_CHECK_STRING(_buf)) { \
                        osp_format_device(_buf, _val, sizeof(_val)); \
                    } else { \
                        if (_lev == OSP_DEF_MUST) { \
                            /* Hostport must be reported */ \
                            radlog(L_ERR, "rlm_osp: Empty hostport."); \
                            return -1; \
                        } else { \
                            DEBUG("rlm_osp: Empty hostport."); \
                            osp_create_device(_ip, _port, _val, sizeof(_val)); \
                        } \
                    } \
                } \
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
 * param _fmt Integer string format
 * param _def Item default value
 * param _buf Buffer
 * param _val Item value
 */
#define OSP_GET_INTEGER(_req, _flag, _name, _lev, _map, _fmt, _def, _buf, _val) { \
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
                if (_fmt == OSP_INTSTR_HEX) { \
                    sscanf(_buf, "%x", &_val); \
                } else { \
                    _val = atoi(_buf); \
                } \
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

/* Media stream group strings */
char* group_str[OSP_GROUP_NUMBER] = { "rtp", "rtcp" };

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

    /* Nothing to check for reportstart */
    DEBUG("rlm_osp: 'reportstart' = '%d'", mapping->reportstart);

    /* Nothing to check for reportstop */
    DEBUG("rlm_osp: 'reportstop' = '%d'", mapping->reportstop);

    /* Nothing to check for reportinterim */
    DEBUG("rlm_osp: 'reportinterim' = '%d'", mapping->reportinterim);

    /* If ignored destination subnet list string is incorrect, then fail. */
    DEBUG("rlm_osp: parse 'ignoreddestinationlist'"); \
    if (osp_parse_netlist(mapping->ignoreddeststr, &mapping->ignoreddestlist) < 0) {
        return -1;
    }

    /* If RADIUS client type is wrong, then fail. */
    OSP_CHECK_RANGE("radiusclienttype", mapping->clienttype, OSP_CLIENT_MIN, OSP_CLIENT_MAX);

    /* If call origin is undefined for NexTone and Cisco, then fail. */
    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        OSP_CHECK_ITEMMAP("callorigin", OSP_DEF_MUST, mapping->origin);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }

    /* If transaction ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("transactionid", OSP_DEF_MAY, mapping->transid);

    /* If Call-ID is undefined, then fail. */
    OSP_CHECK_ITEMMAP("callid", OSP_DEF_MUST, mapping->callid);

    /* If calling number format is incorrect, then fail. */
    OSP_CHECK_RANGE("callingnumberformat", mapping->callingformat, OSP_CALLNUM_MIN, OSP_CALLNUM_MAX);

    /* If calling number is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("callingnumber", OSP_DEF_MAY, mapping->calling);

    /* If called number format is incorrect, then fail. */
    OSP_CHECK_RANGE("callednumberformat", mapping->calledformat, OSP_CALLNUM_MIN, OSP_CALLNUM_MAX);

    /* If called number is undefined, then fail. */
    OSP_CHECK_ITEMMAP("callednumber", OSP_DEF_MUST, mapping->called);

    /* If asserted ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("assertedid", OSP_DEF_MAY, mapping->assertedid);

    /* If source is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("source", OSP_DEF_MAY, mapping->source);

    /* If proxy is undefined for NexTone and Cisco, then fail. */
    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        OSP_CHECK_ITEMMAP("proxy", OSP_DEF_MUST, mapping->proxy);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }

    /* If source device is undefined, then fail. */
    OSP_CHECK_ITEMMAP("sourcedevice", OSP_DEF_MUST, mapping->srcdev);

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

    /* If diversion user is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("diversionuser", OSP_DEF_MAY, mapping->divuser);

    /* If diversion host is incorrect, then fail. */
    OSP_CHECK_ITEMMAP("diversionhost", OSP_DEF_MAY, mapping->divhost);

    /* If time string format is wrong, then fail. */
    OSP_CHECK_RANGE("timestringformat", mapping->timeformat, OSP_TIMESTR_MIN, OSP_TIMESTR_MAX);

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
    if (osp_check_statsmap(&mapping->stats) < 0) {
        return -1;
    }

    /* If user-defined info are incorrect, then fail. */
    for (i = 0; i < OSP_CUSTOMINFO_MAX; i++) {
        snprintf(buffer, sizeof(buffer), "custominfo%d", i + 1);
        OSP_CHECK_ITEMMAP(buffer, OSP_DEF_MAY, mapping->custinfo[i]);
    }

    DEBUG("rlm_osp: osp_check_mapping success");

    return 0;
}

/*
 * Parse subnet list.
 *
 * param liststr Subnet list string
 * param list Subnet list
 * return 0 success, -1 failure
 */
static int osp_parse_netlist(
    char* liststr,
    osp_netlist_t* list)
{
    char listbuf[OSP_STRBUF_SIZE];
    char buffer[OSP_STRBUF_SIZE];
    struct in_addr ip;
    char* subnet;
    char* tmplist;
    char* ipstr;
    char* tmpnet;
    int i;

    DEBUG("rlm_osp: osp_parse_netlist start");

    if (liststr) {
        strncpy(listbuf, liststr, OSP_STRBUF_SIZE);
        for (i = 0, subnet = strtok_r(listbuf, OSP_LIST_DELIMITER, &tmplist);
            (i < OSP_SUBNET_MAX) && subnet;
            i++, subnet = strtok_r(NULL, OSP_LIST_DELIMITER, &tmplist))
        {
            if (((ipstr = strtok_r(subnet, OSP_NET_DELIMITER, &tmpnet)) == NULL) || (inet_pton(AF_INET, ipstr, &ip) != 1)) {
                radlog(L_INFO,
                    "rlm_osp: Failed to parse IP address from '%s'.",
                    subnet);
                break;
            } else {
                list->subnet[i].ip = ip.s_addr;
                inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
                DEBUG("rlm_osp: subnet[%d] ip = '%s'", i, buffer);

                if (((ipstr = strtok_r(NULL, OSP_NET_DELIMITER, &tmpnet)) == NULL) || (inet_pton(AF_INET, ipstr, &ip) != 1)) {
                    ip.s_addr = OSP_NETMASK_DEF;
                }
                list->subnet[i].mask = ip.s_addr;
                inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
                DEBUG("rlm_osp: subnet[%d] mask = '%s'", i, buffer);
            }
        }
        list->number = i;
    } else {
        list->number = 0;
    }

    DEBUG("rlm_osp: osp_parse_netlist success");

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
    osp_group_t group;
    osp_flow_t flow;
    char name[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_check_statsmap start");

    /* Nothing to check for reportstatistics */
    DEBUG("rlm_osp: 'reportstatistics' = '%d'", stats->reportstats);

    if (stats->reportstats) {
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

        for (group = OSP_GROUP_RTP; group < OSP_GROUP_NUMBER; group++) {
            for (flow = OSP_FLOW_DOWN; flow < OSP_FLOW_NUMBER; flow++) {
#define mGMAP               (stats->group[group][flow])
#define mGSTR(_name, _var)  snprintf(_name, sizeof(_name), "%s%s%s", group_str[group], flow_str[flow], _var)
                /* If packets lost packets is incorrect, then fail. */
                mGSTR(name, "lostpackets");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.lost.pack);

                /* If packets lost fraction is incorrect, then fail. */
                mGSTR(name, "lostfraction");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.lost.fract);

                /* If jitter samples is incorrect, then fail. */
                mGSTR(name, "jittersamples");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.jitter.samp);

                /* If jitter minimum is incorrect, then fail. */
                mGSTR(name, "jitterminimum");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.jitter.min);

                /* If jitter maximum is incorrect, then fail. */
                mGSTR(name, "jittermaximum");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.jitter.max);

                /* If jitter mean is incorrect, then fail. */
                mGSTR(name, "jittermean");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.jitter.mean);

                /* If jitter variance is incorrect, then fail. */
                mGSTR(name, "jittervariance");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.jitter.var);

                /* If delay samples is incorrect, then fail. */
                mGSTR(name, "delaysamples");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.delay.samp);

                /* If delay minimum is incorrect, then fail. */
                mGSTR(name, "delayminimum");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.delay.min);

                /* If delay maximum is incorrect, then fail. */
                mGSTR(name, "delaymaximum");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.delay.max);

                /* If delay mean is incorrect, then fail. */
                mGSTR(name, "delaymean");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.delay.mean);

                /* If delay variance is incorrect, then fail. */
                mGSTR(name, "delayvariance");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.delay.var);

                /* If octets is incorrect, then fail. */
                mGSTR(name, "octets");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.octets);

                /* If packets is incorrect, then fail. */
                mGSTR(name, "packets");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.packets);

                /* If rfactor is incorrect, then fail. */
                mGSTR(name, "rfactor");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.rfactor);

                /* If moscq is incorrect, then fail. */
                mGSTR(name, "moscq");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.moscq);

                /* If moslq is incorrect, then fail. */
                mGSTR(name, "moslq");
                OSP_CHECK_ITEMMAP(name, OSP_DEF_MAY, mGMAP.moslq);
#undef mGMAP
#undef mGSTR
            }
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
        if (mapping->reportstart) {
            role = OSPC_ROLE_RADSRCSTART;
            break;
        } else {
            DEBUG("rlm_osp: Nothing to do for Start request.");
            return RLM_MODULE_NOOP;
        }
    case PW_STATUS_STOP:
        if (mapping->reportstop) {
            role = OSPC_ROLE_RADSRCSTOP;
            break;
        } else {
            DEBUG("rlm_osp: Nothing to do for Stop request.");
            return RLM_MODULE_NOOP;
        }
    case PW_STATUS_ALIVE:   /* Interim-Update */
        if (mapping->reportinterim) {
            role = OSPC_ROLE_RADSRCINTERIM;
            break;
        } else {
            DEBUG("rlm_osp: Nothing to do for Interim-Update request.");
            return RLM_MODULE_NOOP;
        }
    default:
        DEBUG("rlm_osp: Nothing to do for request type '%d'.", vp->vp_integer);
        return RLM_MODULE_NOOP;
    }

    /* Get usage information */
    error = osp_get_usageinfo(data, request, vp->vp_integer, &usage);
    if (error < 0) {
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
        /* Note: it should not return RLM_MODULE_FAIL in case requests from others. */
        return RLM_MODULE_NOOP;
    } else if (error == 1) {
        switch (running->loglevel) {
        case OSP_LOG_SHORT:
            radlog(L_INFO, "rlm_osp: ignore record for destination.");
            break;
        case OSP_LOG_LONG:
        default:
            radius_xlat(buffer, sizeof(buffer), "%Z", request, NULL);
            /* Do not have to check string NULL */
            radlog(L_INFO,
                "rlm_osp: ignore record '%s' for destination.",
                buffer);
            break;
        }
        /* Note: it should not return RLM_MODULE_FAIL. */
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

    /* Report diversion */
    OSPPTransactionSetDiversion(
        transaction,
        usage.divuser,
        usage.divhost);

    /* Report asserted ID */
    OSPPTransactionSetAssertedId(
        transaction,        /* Transaction handle */
        usage.assertedid);  /* Asserted ID */

    /* Report user-defined info */
    for (i = 0; i < OSP_CUSTOMINFO_MAX; i++) {
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
 * param mapping Statistic mapping
 * param stats Statistics info
 * return
 */
static void osp_report_statsinfo(
    OSPTTRANHANDLE transaction,
    osp_statsmap_t* mapping,
    osp_stats_t* stats)
{
    osp_group_t group;
    osp_flow_t flow;
    OSPE_STATS_METRIC metric;
    OSPE_STATS_FLOW direction;

    DEBUG("rlm_osp: osp_report_statsinfo start");

    if (mapping->reportstats) {
        for (group = OSP_GROUP_RTP; group < OSP_GROUP_NUMBER; group++) {
            if (group == OSP_GROUP_RTCP) {
                metric = OSPC_SMETRIC_RTCP;
            } else {
                metric = OSPC_SMETRIC_RTP;
            }

            for (flow = OSP_FLOW_DOWN; flow < OSP_FLOW_NUMBER; flow++) {
                if (flow == OSP_FLOW_UP) {
                    direction = OSPC_SFLOW_UPSTREAM;
                } else {
                    direction = OSPC_SFLOW_DOWNSTREAM;
                }

#define mGVAR   (stats->group[group][flow])
                /* Report packets lost */
                if ((mGVAR.lost.pack != OSP_STATSINT_DEF) || (mGVAR.lost.fract != OSP_STATSINT_DEF)) {
                    OSPPTransactionSetLost(
                        transaction,        /* Transaction handle */
                        metric,             /* Metric */
                        direction,          /* Flow direction */
                        mGVAR.lost.pack,     /* Packets lost packets */
                        mGVAR.lost.fract);   /* Packets lost fraction */
                }

                /* Report jitter */
                if ((mGVAR.jitter.samp != OSP_STATSINT_DEF) ||
                    (mGVAR.jitter.min != OSP_STATSINT_DEF) ||
                    (mGVAR.jitter.max != OSP_STATSINT_DEF) ||
                    (mGVAR.jitter.mean != OSP_STATSINT_DEF) ||
                    (mGVAR.jitter.var != OSP_STATSFLOAT_DEF))
                {
                    OSPPTransactionSetJitter(
                        transaction,        /* Transaction handle */
                        metric,             /* Metric */
                        direction,          /* Flow direction */
                        mGVAR.jitter.samp,   /* Jitter samples */
                        mGVAR.jitter.min,    /* Jitter minimum */
                        mGVAR.jitter.max,    /* Jitter maximum */
                        mGVAR.jitter.mean,   /* Jitter mean */
                        mGVAR.jitter.var);   /* Jitter variance */
                }

                /* Report delay */
                if ((mGVAR.delay.samp != OSP_STATSINT_DEF) ||
                    (mGVAR.delay.min != OSP_STATSINT_DEF) ||
                    (mGVAR.delay.max != OSP_STATSINT_DEF) ||
                    (mGVAR.delay.mean != OSP_STATSINT_DEF) ||
                    (mGVAR.delay.var != OSP_STATSFLOAT_DEF))
                {
                    OSPPTransactionSetDelay(
                        transaction,        /* Transaction handle */
                        metric,             /* Metric */
                        direction,          /* Flow direction */
                        mGVAR.delay.samp,    /* Delay samples */
                        mGVAR.delay.min,     /* Delay minimum */
                        mGVAR.delay.max,     /* Delay maximum */
                        mGVAR.delay.mean,    /* Delay mean */
                        mGVAR.delay.var);    /* Delay variance */
                }

                /* Report octets */
                if (mGVAR.octets != OSP_STATSINT_DEF) {
                    OSPPTransactionSetOctets(
                        transaction,    /* Transaction handle */
                        metric,         /* Metric */
                        direction,      /* Flow direction */
                        mGVAR.octets);   /* Octets */
                }

                /* Report packets */
                if (mGVAR.packets != OSP_STATSINT_DEF) {
                    OSPPTransactionSetPackets(
                        transaction,    /* Transaction handle */
                        metric,         /* Metric */
                        direction,      /* Flow direction */
                        mGVAR.packets);  /* Packets */
                }

                /* Report rfactor */
                if (mGVAR.rfactor != OSP_STATSFLOAT_DEF) {
                    OSPPTransactionSetRFactor(
                        transaction,    /* Transaction handle */
                        metric,         /* Metric */
                        direction,      /* Flow direction */
                        mGVAR.rfactor);  /* R-Factor */
                }

                /* Report moscq */
                if (mGVAR.moscq != OSP_STATSFLOAT_DEF) {
                    OSPPTransactionSetMOSCQ(
                        transaction,    /* Transaction handle */
                        metric,         /* Metric */
                        direction,      /* Flow direction */
                        mGVAR.moscq);    /* MOS-CQ */
                }

                /* Report moslq */
                if (mGVAR.moslq != OSP_STATSFLOAT_DEF) {
                    OSPPTransactionSetMOSLQ(
                        transaction,    /* Transaction handle */
                        metric,         /* Metric */
                        direction,      /* Flow direction */
                        mGVAR.moslq);    /* MOS-LQ */
                }
#undef mGVAR
            }
        }
    }

    DEBUG("rlm_osp: osp_report_statsinfo success");
}

/*
 * Get usage from accounting request
 *
 * param data Instance data
 * param request Accounting request
 * param type RADIUS record type
 * param usage OSP usage info
 * return 0 success, 1 ignore for destination, -1 failure
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
    char* ptr;
    int parse, size, i;
    osp_intstr_t format;
    int release;
    struct in_addr dest;

    DEBUG("rlm_osp: osp_get_usageinfo start");

    /* Get call origin */
    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        OSP_GET_STRING(request, TRUE, "callorigin", OSP_DEF_MUST, mapping->origin, buffer);
        if (!strcmp(buffer, OSP_CISCOCALL_INIT)) {
            usage->origin = OSP_ORIGIN_INIT;
        } else {
            usage->origin = OSP_ORIGIN_TERM;
        }
        DEBUG("rlm_osp: Call origin type = '%d'", usage->origin);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }

    /* Get transaction ID */
    OSP_GET_LONGLONG(request, TRUE, "transactionid", OSP_DEF_MAY, mapping->transid, 0, buffer, usage->transid);

    /* Get Call-ID */
    OSP_GET_STRING(request, TRUE, "callid", OSP_DEF_MUST, mapping->callid, usage->callid);

    /* Get calling number */
    OSP_GET_CALLNUM(request, TRUE, "callingnumber", OSP_DEF_MAY, mapping->calling, mapping->callingformat, buffer, ptr, size, usage->calling);

    /* Get called number */
    OSP_GET_CALLNUM(request, TRUE, "callednumber", OSP_DEF_MUST, mapping->called, mapping->calledformat, buffer, ptr, size, usage->called);

    /* Get asserted ID */
    OSP_GET_STRING(request, TRUE, "assertedid", OSP_DEF_MAY, mapping->assertedid, usage->assertedid);

    /* Get source */
    OSP_GET_IP(request, TRUE, "source", OSP_DEF_MAY, mapping->source, provider->deviceip, provider->deviceport, buffer, usage->source);

    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        if (usage->origin == OSP_ORIGIN_INIT) {
            /* Get proxy/source device */
            OSP_GET_IP(request, TRUE, "proxy", OSP_DEF_MUST, mapping->proxy, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev);

            /* Get destination */
            OSP_GET_IP(request, TRUE, "destination", OSP_DEF_MUST, mapping->destination, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination);
        } else {
            /* Get source device */
            OSP_GET_IP(request, TRUE, "sourcedevice", OSP_DEF_MUST, mapping->srcdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev);

            /* Get proxy/destination */
            OSP_GET_IP(request, TRUE, "proxy", OSP_DEF_MUST, mapping->proxy, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination);
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        /* Get source device */
        OSP_GET_IP(request, TRUE, "sourcedevice", OSP_DEF_MUST, mapping->srcdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev);

        /* Get destination */
        OSP_GET_IP(request, TRUE, "destination", OSP_DEF_MUST, mapping->destination, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination);

        break;
    }

    /* Check if the record is for a destination should be ignored */
    if (inet_pton(AF_INET, usage->destination, &dest) == 1) {
        if (osp_match_subnet(&mapping->ignoreddestlist, dest.s_addr) == 0) {
            DEBUG("rlm_osp: ignore record for destination '%s'.", usage->destination);
            return 1;
        }
    }

    /* Get destination device */
    OSP_GET_IP(request, TRUE, "destinationdevice", OSP_DEF_MAY, mapping->destdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destdev);

    /* Get destination count */
    OSP_GET_INTEGER(request, TRUE, "destinationcount", OSP_DEF_MAY, mapping->destcount, OSP_INTSTR_DEC, OSP_DESTCOUNT_DEF, buffer, usage->destcount);

    /* Get source network ID */
    OSP_GET_STRING(request, TRUE, "sourcenetworkid", OSP_DEF_MAY, mapping->snid, usage->snid);

    /* Get destination network ID */
    OSP_GET_STRING(request, TRUE, "destinationnetworkid", OSP_DEF_MAY, mapping->dnid, usage->dnid);

    /* Get diversion user */
    OSP_GET_CALLNUM(request, TRUE, "diversionuser", OSP_DEF_MAY, mapping->divuser, TRUE, buffer, ptr, size, usage->divuser);

    /* Get diversion host */
    OSP_GET_URIHOST(request, TRUE, "diversionhost", OSP_DEF_MAY, mapping->divhost, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->divhost);

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
    OSP_GET_INTEGER(request, parse, "postdialdelay", OSP_DEF_MAY, mapping->pdd, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, usage->pdd);
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
                release = atoi(buffer);
                switch (mapping->clienttype) {
                case OSP_CLIENT_NEXTONE:
                case OSP_CLIENT_CISCO:
                    switch (release) {
                    case OSP_CISCOREL_CALLEDPSTN:
                    case OSP_CISCOREL_CALLEDVOIP:
                        usage->release = OSP_TK_RELDST;
                        break;
                    case OSP_CISCOREL_CALLINGPSTN:
                    case OSP_CISCOREL_CALLINGVOIP:
                    case OSP_CISCOREL_INTPOST:
                    case OSP_CISCOREL_INTVOIP:
                    case OSP_CISCOREL_INTAPPL:
                    case OSP_CISCOREL_INTAAA:
                    case OSP_CISCOREL_CONSOLE:
                    case OSP_CISCOREL_EXTRADIUS:
                    case OSP_CISCOREL_EXTAPPL:
                    case OSP_CISCOREL_EXTAGENT:
                    default:
                        usage->release = OSP_TK_RELSRC;
                        break;
                    }
                    break;
                case OSP_CLIENT_UNDEF:
                case OSP_CLIENT_ACME:
                default:
                    switch (release) {
                    case OSP_RELEASE_DEST:
                        usage->release = OSP_TK_RELDST;
                        break;
                    case OSP_RELEASE_UNDEF:
                    case OSP_RELEASE_SRC:
                    default:
                        usage->release = OSP_TK_RELSRC;
                        break;
                    }
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
    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        format = OSP_INTSTR_HEX;
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        format = OSP_INTSTR_DEC;
        break;
    }
    OSP_GET_INTEGER(request, parse, "releasecause", OSP_DEF_MUST, mapping->cause, format, OSP_CAUSE_DEF, buffer, usage->cause);

    /* Get destination protocol */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, "destinationprotocol", OSP_DEF_MAY, mapping->destprot, buffer);
    usage->destprot = osp_parse_protocol(mapping, buffer);
    DEBUG("rlm_osp: Destination protocol type = '%d'", usage->destprot);

    /* Get release reason type */
    usage->causetype = osp_get_causetype(mapping, usage->destprot);
    DEBUG("rlm_osp: Termination cause type = '%d'", usage->causetype);

    /* Get inbound session ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    switch (mapping->clienttype) {
    case OSP_CLIENT_CISCO:
        if (usage->origin == OSP_ORIGIN_INIT) {
            parse = FALSE;
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_NEXTONE:
    default:
        break;
    }
    OSP_GET_STRING(request, parse, "inboundsessionid", OSP_DEF_MAY, mapping->insessionid, usage->insessionid);

    /* Get outbound session ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        if (usage->origin == OSP_ORIGIN_TERM) {
            parse = FALSE;
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }
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

    /* Get statistics */
    osp_get_statsinfo(mapping, request, type, usage);

    /* Get user-defined info */
    for (i = 0; i < OSP_CUSTOMINFO_MAX; i++) {
        snprintf(buffer, sizeof(buffer), "custominfo%d", i + 1);
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
        OSP_GET_STRING(request, parse, buffer, OSP_DEF_MAY, mapping->custinfo[i], usage->custinfo[i]);
    }

    DEBUG("rlm_osp: osp_get_usageinfo success");

    return 0;
}

/*
 * Match IP in subnet list
 *
 * param list Subnet list
 * param ip IP address
 * return 0 success, -1 failure
 */
static int osp_match_subnet(
    osp_netlist_t* list,
    uint32_t ip)
{
    int i;

    DEBUG("rlm_osp: osp_match_subnet start");

    for (i = 0; i < list->number; i++) {
        if (!((list->subnet[i].ip & list->subnet[i].mask) ^ (ip & list->subnet[i].mask))) {
            break;
        }
    }
    if (i >= list->number) {
        DEBUG("rlm_osp: osp_match_subnet failed");
        return -1;
    }

    DEBUG("rlm_osp: osp_match_subnet success");

    return 0;
}

/*
 * Get statistcs from accounting request
 *
 * param mapping Mapping parameters
 * param request Accounting request
 * param type RADIUS record type
 * param usage OSP usage info
 * return 0 success, -1 failure
 */
static int osp_get_statsinfo(
    osp_mapping_t* mapping,
    REQUEST* request,
    int type,
    osp_usage_t* usage)
{
    osp_statsmap_t* map = &mapping->stats;
    osp_stats_t* var = &usage->stats;
    int parse, parseleg;
    osp_group_t group;
    osp_flow_t flow;
    char name[OSP_STRBUF_SIZE];
    char buffer[OSP_STRBUF_SIZE];

    DEBUG("rlm_osp: osp_get_statsinfo start");

    if (map->reportstats) {
        /* If parse statistics */
        parse = (type == PW_STATUS_STOP);

        /* Get lost send packets */
        OSP_GET_INTEGER(request, parse, "sendlostpackets", OSP_DEF_MAY, map->slost.pack, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->slost.pack);

        /* Get lost send packet fraction */
        OSP_GET_INTEGER(request, parse, "sendlostfraction", OSP_DEF_MAY, map->slost.fract, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->slost.fract);

        /* Get lost receive packets */
        OSP_GET_INTEGER(request, parse, "receivelostpackets", OSP_DEF_MAY, map->rlost.pack, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rlost.pack);

        /* Get lost receive packet fraction */
        OSP_GET_INTEGER(request, parse, "receivelostfraction", OSP_DEF_MAY, map->rlost.fract, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rlost.fract);

        for (group = OSP_GROUP_RTP; group < OSP_GROUP_NUMBER; group++) {
            for (flow = OSP_FLOW_DOWN; flow < OSP_FLOW_NUMBER; flow++) {
#define mGMAP               (map->group[group][flow])
#define mGVAR               (var->group[group][flow])
#define mGSTR(_name, _var)  snprintf(_name, sizeof(_name), "%s%s%s", group_str[group], flow_str[flow], _var)
                /* Get packets lost packets */
                mGSTR(name, "lostpackets");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.lost.pack, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.lost.pack);

                /* Get packets lost fraction */
                mGSTR(name, "lostfraction");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.lost.fract, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.lost.fract);

                /* Get jitter samples */
                mGSTR(name, "jittersamples");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.jitter.samp, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.jitter.samp);

                /* Get jitter minimim */
                mGSTR(name, "jitterminimum");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.jitter.min, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.jitter.min);

                /* Get jitter maximum */
                mGSTR(name, "jittermaximum");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.jitter.max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.jitter.max);

                /* Get jitter mean */
                mGSTR(name, "jittermean");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.jitter.mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.jitter.mean);

                /* Get jitter variance */
                mGSTR(name, "jittervariance");
                OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mGMAP.jitter.var, OSP_SCALE_1, OSP_STATSFLOAT_DEF, buffer, mGVAR.jitter.var);

                /* Get delay samples */
                mGSTR(name, "delaysamples");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.delay.samp, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.delay.samp);

                /* Get delay minimim */
                mGSTR(name, "delayminimum");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.delay.min, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.delay.min);

                /* Get delay maximum */
                mGSTR(name, "delaymaximum");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.delay.max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.delay.max);

                /* Get delay mean */
                mGSTR(name, "delaymean");
                OSP_GET_INTEGER(request, parse, name, OSP_DEF_MAY, mGMAP.delay.mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.delay.mean);

                /* Get delay variance */
                mGSTR(name, "delayvariance");
                OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mGMAP.delay.var, OSP_SCALE_1, OSP_STATSFLOAT_DEF, buffer, mGVAR.delay.var);

                parseleg = parse;
                switch (mapping->clienttype) {
                case OSP_CLIENT_CISCO:
                    if ((group == OSP_GROUP_RTP) &&
                        (((usage->origin == OSP_ORIGIN_INIT) && (flow == OSP_FLOW_DOWN)) ||
                        ((usage->origin == OSP_ORIGIN_TERM) && (flow == OSP_FLOW_UP))))
                    {
                        parseleg = FALSE;
                    }
                    break;
                case OSP_CLIENT_UNDEF:
                case OSP_CLIENT_ACME:
                case OSP_CLIENT_NEXTONE:
                default:
                    break;
                }

                /* Get octets */
                mGSTR(name, "octets");
                OSP_GET_INTEGER(request, parseleg, name, OSP_DEF_MAY, mGMAP.octets, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.octets);

                /* Get packets */
                mGSTR(name, "packets");
                OSP_GET_INTEGER(request, parseleg, name, OSP_DEF_MAY, mGMAP.packets, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, mGVAR.packets);

                /* Get rfactor is */
                mGSTR(name, "rfactor");
                OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mGMAP.rfactor, map->rfactorscale, OSP_STATSFLOAT_DEF, buffer, mGVAR.rfactor);

                /* Get moscq */
                mGSTR(name, "moscq");
                OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mGMAP.moscq, map->mosscale, OSP_STATSFLOAT_DEF, buffer, mGVAR.moscq);

                /* Get moslq */
                mGSTR(name, "moslq");
                OSP_GET_FLOAT(request, parse, name, OSP_DEF_MAY, mGMAP.moslq, map->mosscale, OSP_STATSFLOAT_DEF, buffer, mGVAR.moslq);
#undef mGMAP
#undef mGVAR
#undef mGSTR
            }
        }
    } else {
        /* Do not report statistics. slost and rlost must be set to default. */
        var->slost.pack = OSP_STATSINT_DEF;
        var->slost.fract = OSP_STATSINT_DEF;
        var->rlost.pack = OSP_STATSINT_DEF;
        var->rlost.fract = OSP_STATSINT_DEF;
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
    if (inet_pton(AF_INET, tmpbuf, &inp) == 1) {
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
 * Get userinfo from uri
 *
 * SIP-URI = "sip:" [ userinfo ] hostport uri-parameters [ headers ]
 * userinfo = ( user / telephone-subscriber ) [ ":" password ] "@"
 * hostport = host [ ":" port ]
 *
 * param uri Caller/callee URI
 * param buffer Userinfo buffer
 * param buffersize Userinfo buffer size
 * return 0 success, -1 failure
 */
static int osp_get_uriuser(
    char* uri,
    char* buffer,
    int buffersize)
{
    char* start;
    char* end;
    char* tmp;
    int size;

    DEBUG("rlm_osp: osp_get_uriuser start");

    if ((start = strstr(uri, "sip:")) == NULL) {
        if (OSP_CHECK_STRING(uri)) {
            radlog(L_ERR,
                "rlm_osp: URI '%s' format incorrect, without 'sip:'.",
                uri);
        } else {
            radlog(L_ERR, "rlm_osp: URI format incorrect.");
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
    DEBUG("rlm_osp: URI userinfo = '%s'", buffer);

    DEBUG("rlm_osp: osp_get_uriuser success");

    return 0;
}

/*
 * Get hostport from uri
 *
 * SIP-URI = "sip:" [ userinfo ] hostport uri-parameters [ headers ]
 * userinfo = ( user / telephone-subscriber ) [ ":" password ] "@"
 * hostport = host [ ":" port ]
 *
 * param uri Caller/callee URI
 * param buffer Hostport buffer
 * param buffersize Hostport buffer size
 * return 0 success, -1 failure
 */
static int osp_get_urihost(
    char* uri,
    char* buffer,
    int buffersize)
{
    char* start;
    char* end;
    char* tmp;
    int size;

    DEBUG("rlm_osp: osp_get_urihost start");

    if ((start = strstr(uri, "sip:")) == NULL) {
        if (OSP_CHECK_STRING(uri)) {
            radlog(L_ERR,
                "rlm_osp: URI '%s' format incorrect, without 'sip:'.",
                uri);
        } else {
            radlog(L_ERR, "rlm_osp: URI format incorrect.");
        }
        return -1;
    } else {
        start += 4;

        if (((tmp = strchr(start, '@')) != NULL) && (start < tmp)) {
            start = tmp + 1;
        }
    }

    if ((end = strpbrk(start, ";?>")) == NULL) {
        *buffer = '\0';
    } else {
        size = end - start;
        if (buffersize <= size) {
            size = buffersize - 1;
        }

        memcpy(buffer, start, size);
        buffer[size] = '\0';
    }
    /* Do not have to check string NULL */
    DEBUG("rlm_osp: URI hostport = '%s'", buffer);

    DEBUG("rlm_osp: osp_get_urihost success");

    return 0;
}

/*
 * Parse protocol from string
 *
 * param mapping Mapping parameters
 * param protocol Protocol string
 * return Protocol
 */
static OSPE_DEST_PROTOCOL osp_parse_protocol(
    osp_mapping_t* mapping,
    char* protocol)
{
    OSPE_DEST_PROTOCOL type = OSPC_DPROT_UNKNOWN;

    DEBUG("rlm_osp: osp_parse_protocol start");

    if (OSP_CHECK_STRING(protocol)) {
        /* Comparing ignore case, Solaris does not support strcasestr */
        if (strstr(protocol, "SIP") || strstr(protocol, "Sip") || strstr(protocol, "sip")) {
            type = OSPC_DPROT_SIP;
        } else {
            switch (mapping->clienttype) {
            case OSP_CLIENT_NEXTONE:
            case OSP_CLIENT_CISCO:
                if (strstr(protocol, "CISCO") || strstr(protocol, "Cisco") || strstr(protocol, "cisco")) {
                    type = OSPC_DPROT_Q931;
                }
                break;
            case OSP_CLIENT_UNDEF:
            case OSP_CLIENT_ACME:
            default:
                if (strstr(protocol, "H323") || strstr(protocol, "h323")) {
                    type = OSPC_DPROT_Q931;
                }
                break;
            }
        }
    }
    DEBUG("rlm_osp: Protocol type = '%d'", type);

    DEBUG("rlm_osp: osp_parse_protocol success");

    return type;
}

/*
 * Get termination cause type from destination protocol
 *
 * param mapping Mapping parameters
 * param protocol Destination protocol
 * return Termination cause type
 */
static OSPE_TERM_CAUSE osp_get_causetype(
    osp_mapping_t* mapping,
    OSPE_DEST_PROTOCOL protocol)
{
    OSPE_TERM_CAUSE type;

    DEBUG("rlm_osp: osp_get_causetype start");

    switch (mapping->clienttype) {
    case OSP_CLIENT_NEXTONE:
    case OSP_CLIENT_CISCO:
        type = OSPC_TCAUSE_H323;
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
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
    char* timestamp,
    osp_timestr_t format)
{
    struct tm dt;
    char* timestr = timestamp;
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
        /* WWW MMM DD hh:mm:ss YYYY, assume UTC, length 24 bytes */
        if (strlen(timestr) == 24) {
            tzone = NULL;
            if (osp_cal_timeoffset(tzone, &toffset) == 0) {
                strptime(timestr, "%a %b %d %T %Y", &dt);
                osp_cal_elapsed(&dt, toffset, &tvalue);
            }
        }
        break;
    case OSP_TIMESTR_ACME:
        /* hh:mm:ss.kkk ZON MMM DD YYYY, length 28 bytes */
        if (strlen(timestr) == 28) {
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
        }
        break;
    case OSP_TIMESTR_CISCO:
        if (timestr[0] == '*' || timestr[0] == '.') {
            /* A timestamp that is preceded by an asterisk (*) or a
               dot (.) might not be accurate. An asterisk (*) means
               that after a gateway reboot, the gateway clock was not
               manually set and the gateway has not synchronized with
               an NTP server yet. A dot (.) means the gateway NTP has
               lost synchronization with an NTP server. */
            timestr++;
        }
    case OSP_TIMESTR_NTP:
        /* hh:mm:ss.kkk ZON WWW MMM DD YYYY, length 32 bytes */
        if (strlen(timestr) == 32) {
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

                strptime(buffer, "%T %a %b %d %Y", &dt);

                osp_cal_elapsed(&dt, toffset, &tvalue);
            }
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

