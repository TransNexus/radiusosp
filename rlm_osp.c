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
 * OSP module version
 */
#define OSP_MODULE_VERSION_MAJOR    2
#define OSP_MODULE_VERSION_MINOR    0
#define OSP_MODULE_VERSION_BUGFIX   2

/*
 * OSP module buffer size constants.
 */
#define OSP_TZNAME_SIZE     16
#define OSP_STRBUF_SIZE     256
#define OSP_KEYBUF_SIZE     1024
#define OSP_LOGBUF_SIZE     1024

/* Module configurations */
#define OSP_LOGLEVEL_DEF    "1"                         /* Mapping default log level, long */
#define OSP_TZFILE_DEF      "${raddbdir}/timezone.conf" /* Time zone configuration file */
#define OSP_TZ_DELIMITER    " \t"                       /* Time zone item delimiter */
#define OSP_TZ_COMMENT      '#'                         /* Time zone file comment */
#define OSP_TZ_MAX          512                         /* Max number of time zones */
#define OSP_TZ_CACHE        8                           /* Time zone cache size */
#define OSP_HWACCE_DEF      "no"                        /* Mapping default hardware accelerate flag */
#define OSP_SECURITY_DEF    "no"                        /* Mapping default security flag */
#define OSP_SPNUM_MAX       4                           /* OSP max number of service points */
#define OSP_SPURI_DEF       "http://osptestserver.transnexus.com:5045/osp"  /* OSP default service point URI */
#define OSP_SPWEIGHT_DEF    "1000"                      /* Mapping default service point weight */
#define OSP_AUDITURL_DEF    "http://localhost:1234"     /* OSP default Audit URL */
#define OSP_PRIVATEKEY_DEF  "${raddbdir}/pkey.pem"      /* OSP default private key file */
#define OSP_LOCALCERT_DEF   "${raddbdir}/localcert.pem" /* OSP default localcert file */
#define OSP_CANUM_MAX       4                           /* OSP max number of cacert files */
#define OSP_CACERT_DEF      "${raddbdir}/cacert_0.pem"  /* OSP default cacert file */
#define OSP_VALIDATION_DEF  1                           /* OSP default token validation, locally */
#define OSP_SSLLIFETIME_DEF "300"                       /* Mapping default SSL life time in seconds */
#define OSP_SSLLIFETIME_MIN 0                           /* OSP min SSL life time */
#define OSP_MAXCONN_DEF     "20"                        /* Mapping default max number of connections */
#define OSP_MAXCONN_MIN     1                           /* OSP min max number of connections */
#define OSP_MAXCONN_MAX     1000                        /* OSP max max number of connections */
#define OSP_PERSISTENCE_DEF "60"                        /* Mapping default HTTP persistence in seconds */
#define OSP_PERSISTENCE_MIN 0                           /* OSP min HTTP persistence */
#define OSP_RETRYDELAY_DEF  "0"                         /* Mapping default retry delay */
#define OSP_RETRYDELAY_MIN  0                           /* OSP min retry delay */
#define OSP_RETRYDELAY_MAX  10                          /* OSP max retry delay */
#define OSP_RETRYLIMIT_DEF  "2"                         /* Mapping default retry times */
#define OSP_RETRYLIMIT_MIN  0                           /* OSP min retry times */
#define OSP_RETRYLIMIT_MAX  100                         /* OSP max retry times */
#define OSP_TIMEOUT_DEF     "10000"                     /* Mapping default timeout */
#define OSP_TIMEOUT_MIN     200                         /* OSP min timeout in milliseconds */
#define OSP_TIMEOUT_MAX     60000                       /* OSP max timeout in milliseconds */
#define OSP_DEVICEIP_DEF    "localhost"                 /* Mapping default device IP */
#define OSP_DEVICEPORT_DEF  "5060"                      /* Mapping default device port */
#define OSP_CUSTOMERID_DEF  ""                          /* OSP default customer ID */
#define OSP_DEVICEID_DEF    ""                          /* OSP default device ID */
/* VSA configurations */
#define OSP_IP_DEF          0                           /* OSP default IP */
#define OSP_PORT_DEF        0                           /* OSP default port */
#define OSP_DESTCOUNT_DEF   0                           /* OSP default destination count, unknown */
#define OSP_CAUSE_DEF       0                           /* OSP default termination cause */
#define OSP_CAUSE_UNKNOWN   -1                          /* OSP unknown termination cause */
#define OSP_TIME_DEF        0                           /* OSP default time value */
#define OSP_STATSINT_DEF    ((int)-1)                   /* OSP default statistics, integer */
#define OSP_STATSFLOAT_DEF  ((float)-1.0)               /* OSP default statistics, float */
#define OSP_SUBNET_MAX      4                           /* OSP max number of subnets in a subnet list */
#define OSP_NETMASK_DEF     0xFFFFFFFF                  /* OSP default subnet mask */
#define OSP_NET_DELIMITER   "/"                         /* OSP delimiter string for subnet (ip/mask) */
#define OSP_LIST_DELIMITER  ",; "                       /* OSP delimiter string for subnet list */
#define OSP_CUSTOMINFO_MAX  8                           /* OSP max number of custom info */

/*
 * Default RADIUS OSP mapping
 */
#define OSP_MAP_NULL            "NULL"                          /* Empty map */
#define OSP_MAP_IDITEM          NULL                            /* RADIUS record identity VSA name */
#define OSP_MAP_IDVALUE         NULL                            /* RADIUS record identity VSA value */
#define OSP_MAP_REPORT          "yes"                           /* Report Stop, Start or Interim-Update RADIUS records */
#define OSP_MAP_CLIENTTYPE      "0"                             /* RADIUS client type, undefined */
#define OSP_MAP_NETLIST         NULL                            /* Subnet list */
#define OSP_MAP_SUBTYPE         NULL                            /* Sub status type */
#define OSP_MAP_DIRECTION       NULL                            /* Call direction */
#define OSP_MAP_IGNORERAD       "no"                            /* Ingore inbound or outbound RADIUS records */
#define OSP_MAP_TRANSID         NULL                            /* Transaction ID */
#define OSP_MAP_CALLID          "%{Acct-Session-Id}"            /* Call-ID, RFC 2866 */
#define OSP_MAP_NUMFORMAT       "0"                             /* Calling/called number format, E.164 */
#define OSP_MAP_CALLING         "%{Calling-Station-Id}"         /* Calling number, RFC 2865 */
#define OSP_MAP_CALLED          "%{Called-Station-Id}"          /* Called number, RFC 2865 */
#define OSP_MAP_PARSETRANSFER   "yes"                           /* Parse transfer VSAs in RADIUS records */
#define OSP_MAP_TRANSFERCALLING NULL                            /* Transfer calling number */
#define OSP_MAP_TRANSFERCALLED  NULL                            /* Transfer called called number */
#define OSP_MAP_TRANSFERRET     NULL                            /* Transfer result */
#define OSP_MAP_TRANSFERID      NULL                            /* Transfer ID */
#define OSP_MAP_ANSWERIND       NULL                            /* Answer indicator */
#define OSP_MAP_ASSERTEDID      NULL                            /* P-Asserted-Identity */
#define OSP_MAP_RPID            NULL                            /* Remote-Party-ID */
#define OSP_MAP_SOURCE          "%{NAS-IP-Address}"             /* Source, RFC 2865 */
#define OSP_MAP_PROXY           NULL                            /* Proxy */
#define OSP_MAP_SRCDEV          NULL                            /* Source device */
#define OSP_MAP_DESTINATION     NULL                            /* Destination */
#define OSP_MAP_DESTDEV         NULL                            /* Destination device */
#define OSP_MAP_DESTCOUNT       NULL                            /* Destination count */
#define OSP_MAP_DEVICE          NULL                            /* General device */
#define OSP_MAP_NETWORKID       NULL                            /* Network ID */
#define OSP_MAP_DIVUSER         NULL                            /* Diversion user */
#define OSP_MAP_DIVHOST         NULL                            /* Diversion host */
#define OSP_MAP_TIMEFORMAT      "0"                             /* Time string format, integer string */
#define OSP_MAP_START           "%{Acct-Session-Start-Time}"    /* Call start time, FreeRADIUS internal */
#define OSP_MAP_ALERT           NULL                            /* Call alert time */
#define OSP_MAP_CONNECT         NULL                            /* Call connect time */
#define OSP_MAP_END             NULL                            /* Call end time */
#define OSP_MAP_DURATION        "%{Acct-Session-Time}"          /* Call duration, RFC 2866 */
#define OSP_MAP_PDDUNIT         "1"                             /* PDD unit, millisecond */
#define OSP_MAP_PDD             NULL                            /* Post dial delay */
#define OSP_MAP_RELEASE         NULL                            /* Release source */
#define OSP_MAP_CAUSE           NULL                            /* Release cause per protocol */
#define OSP_MAP_Q850CAUSE       "%{Acct-Terminate-Cause}"       /* Release cause, RFC 2866 */
#define OSP_MAP_PROTOCOL        NULL                            /* Signaling protocol */
#define OSP_MAP_SESSIONID       NULL                            /* Session ID */
#define OSP_MAP_CODEC           NULL                            /* Codec */
#define OSP_MAP_CONFID          NULL                            /* Conference ID */
#define OSP_MAP_CUSTOMINFO      NULL                            /* User-defined info */
#define OSP_MAP_REALM           NULL                            /* Realm */
#define OSP_MAP_CALLPARTYINFO   NULL                            /* Call party info */
#define OSP_MAP_STATS           NULL                            /* Statistics */
#define OSP_MAP_SCALE           "4"                             /* Scale, 1 */

/* OSP module name */
#define OSP_STR_OSP             "osp"

/* OSP module running parameter names */
#define OSP_STR_RUNNING         "running"
#define OSP_STR_LOGLEVEL        "loglevel"
#define OSP_STR_TZFILE          "timezonefile"

/* OSP provider parameter names */
#define OSP_STR_PROVIDER        "provider"
#define OSP_STR_ACCELERATE      "accelerate"
#define OSP_STR_SECURITY        "security"
#define OSP_STR_SPNUM           "spnumber"
#define OSP_STR_SPURI           "spuri"
#define OSP_STR_SPURI1          "spuri1"
#define OSP_STR_SPURI2          "spuri2"
#define OSP_STR_SPURI3          "spuri3"
#define OSP_STR_SPURI4          "spuri4"
#define OSP_STR_SPWEIGHT        "spweight"
#define OSP_STR_SPWEIGHT1       "spweight1"
#define OSP_STR_SPWEIGHT2       "spweight2"
#define OSP_STR_SPWEIGHT3       "spweight3"
#define OSP_STR_SPWEIGHT4       "spweight4"
#define OSP_STR_PRIVATEKEY      "privatekey"
#define OSP_STR_LOCALCERT       "localcert"
#define OSP_STR_CANUM           "canumber"
#define OSP_STR_CACERT          "cacert"
#define OSP_STR_CACERT0         "cacert0"
#define OSP_STR_CACERT1         "cacert1"
#define OSP_STR_CACERT2         "cacert2"
#define OSP_STR_CACERT3         "cacert3"
#define OSP_STR_SSLLIFETIME     "ssllifetime"
#define OSP_STR_MAXCONN         "maxconnections"
#define OSP_STR_PERSISTENCE     "persistence"
#define OSP_STR_RETRYDELAY      "retrydelay"
#define OSP_STR_RETRYLIMIT      "retrylimit"
#define OSP_STR_TIMEOUT         "timeout"
#define OSP_STR_DEVICEIP        "deviceip"
#define OSP_STR_DEVICEPORT      "deviceport"

/* RADIUS OSP mapping parameter names */
#define OSP_STR_MAPPING             "mapping"
#define OSP_STR_IDITEM              "identityitem"
#define OSP_STR_IDVALUE             "identityvalue"
#define OSP_STR_REPORTSTART         "reportstart"
#define OSP_STR_REPORTSTOP          "reportstop"
#define OSP_STR_REPORTINTERIM       "reportinterim"
#define OSP_STR_CLIENTTYPE          "clienttype"
#define OSP_STR_SUBTYPE             "substatustype"
#define OSP_STR_IGNOREDDESTLIST     "ignoreddestinationlist"
#define OSP_STR_DIRECTION           "calldirection"
#define OSP_STR_IGNOREIN            "ignoreinbound"
#define OSP_STR_IGNOREOUT           "ignoreoutbound"
#define OSP_STR_TRANSACTIONID       "transactionid"
#define OSP_STR_CALLID              "callid"
#define OSP_STR_CALLINGFORMAT       "callingnumberformat"
#define OSP_STR_CALLEDFORMAT        "callednumberformat"
#define OSP_STR_CALLINGNUMBER       "callingnumber"
#define OSP_STR_CALLEDNUMBER        "callednumber"
#define OSP_STR_PARSETRANSFER       "parsetransfer"
#define OSP_STR_TRANSFERCALLINGNUM  "transfercallingnumber"
#define OSP_STR_TRANSFERCALLEDNUM   "transfercallednumber"
#define OSP_STR_TRANSFERRET         "transferresult"
#define OSP_STR_TRANSFERID          "transferid"
#define OSP_STR_ASSERTEDID          "assertedid"
#define OSP_STR_RPID                "remotepartyid"
#define OSP_STR_SOURCE              "source"
#define OSP_STR_PROXY               "proxy"
#define OSP_STR_SRCDEVICE           "sourcedevice"
#define OSP_STR_DESTINATION         "destination"
#define OSP_STR_DESTDEVICE          "destinationdevice"
#define OSP_STR_DESTCOUNT           "destinationcount"
#define OSP_STR_ACCESSDEVICE        "accessdevice"
#define OSP_STR_ROUTEDEVICE         "routedevice"
#define OSP_STR_SRCNETWORKID        "sourcenetworkid"
#define OSP_STR_DESTNETWORKID       "destinationnetworkid"
#define OSP_STR_DIVERSIONUSER       "diversionuser"
#define OSP_STR_DIVERSIONHOST       "diversionhost"
#define OSP_STR_TIMEFORMAT          "timestringformat"
#define OSP_STR_STARTTIME           "starttime"
#define OSP_STR_ALERTTIME           "alerttime"
#define OSP_STR_CONNECTTIME         "connecttime"
#define OSP_STR_ENDTIME             "endtime"
#define OSP_STR_DURATION            "duration"
#define OSP_STR_PDDUNIT             "postdialdelayunit"
#define OSP_STR_PDD                 "postdialdelay"
#define OSP_STR_RELEASE             "releasesource"
#define OSP_STR_Q850CAUSE           "q850releasecause"
#define OSP_STR_SIPCAUSE            "sipreleasecause"
#define OSP_STR_PROTOCOL            "signalingprotocol"
#define OSP_STR_SRCPROTOCOL         "sourceprotocol"
#define OSP_STR_DESTPROTOCOL        "destinationprotocol"
#define OSP_STR_SRCSESSIONID        "sourcesessionid"
#define OSP_STR_DESTSESSIONID       "destinationsessionid"
#define OSP_STR_CORRSESSIONID       "correlationsessionid"
#define OSP_STR_ACCESSCALLID        "accesscallid"
#define OSP_STR_ROUTECALLID         "routecallid"
#define OSP_STR_LOCALCALLID         "localcallid"
#define OSP_STR_REMOTECALLID        "remotecallid"
#define OSP_STR_SRCCODEC            "sourcecodec"
#define OSP_STR_DESTCODEC           "destinationcodec"
#define OSP_STR_CONFID              "conferenceid"
#define OSP_STR_CUSTOMINFO          "custominfo"
#define OSP_STR_CUSTOMINFO1         "custominfo1"
#define OSP_STR_CUSTOMINFO2         "custominfo2"
#define OSP_STR_CUSTOMINFO3         "custominfo3"
#define OSP_STR_CUSTOMINFO4         "custominfo4"
#define OSP_STR_CUSTOMINFO5         "custominfo5"
#define OSP_STR_CUSTOMINFO6         "custominfo6"
#define OSP_STR_CUSTOMINFO7         "custominfo7"
#define OSP_STR_CUSTOMINFO8         "custominfo8"
#define OSP_STR_SRCREALM            "sourcerealm"
#define OSP_STR_DESTREALM           "destinationrealm"
#define OSP_STR_OTHERPARTY          "otherpartyinfo"
#define OSP_STR_CALLINGUSERNAME     "callingpartyusername"
#define OSP_STR_CALLINGUSERID       "callingpartyuserid"
#define OSP_STR_CALLINGUSERGROUP    "callingpartyusergroup"
#define OSP_STR_CALLEDUSERNAME      "calledpartyusername"
#define OSP_STR_CALLEDUSERID        "calledpartyuserid"
#define OSP_STR_CALLEDUSERGROUP     "calledpartyusergroup"

/* Statistics parameter names */
#define OSP_STR_REPORTSTATS            "reportstatistics"
#define OSP_STR_SLOSTPACKETS           "sendlostpackets"
#define OSP_STR_SLOSTFRACTION          "sendlostfraction"
#define OSP_STR_RLOSTPACKETS           "receivelostpackets"
#define OSP_STR_RLOSTFRACTION          "receivelostfraction"
#define OSP_STR_RTPSRCREPOCTETS        "rtpsourcetoreporteroctets"
#define OSP_STR_RTPDESTREPOCTETS       "rtpdestinationtoreporteroctets"
#define OSP_STR_RTPSRCREPPACKETS       "rtpsourcetoreporterpackets"
#define OSP_STR_RTPDESTREPPACKETS      "rtpdestinationtoreporterpackets"
#define OSP_STR_RTPSRCREPLOST          "rtpsourcetoreporterlost"
#define OSP_STR_RTPDESTREPLOST         "rtpdestinationtoreporterlost"
#define OSP_STR_RTPSRCREPJITTERMEAN    "rtpsourcetoreporterjittermean"
#define OSP_STR_RTPDESTREPJITTERMEAN   "rtpdestinationtoreporterjittermean"
#define OSP_STR_RTPSRCREPJITTERMAX     "rtpsourcetoreporterjittermax"
#define OSP_STR_RTPDESTREPJITTERMAX    "rtpdestinationtoreporterjittermax"
#define OSP_STR_RTCPSRCDESTLOST        "rtcpsourcetodestinationlost"
#define OSP_STR_RTCPDESTSRCLOST        "rtcpdestinationtosourcelost"
#define OSP_STR_RTCPSRCDESTJITTERMEAN  "rtcpsourcetodestinationjittermean"
#define OSP_STR_RTCPDESTSRCJITTERMEAN  "rtcpdestinationtosourcejittermean"
#define OSP_STR_RTCPSRCDESTJITTERMAX   "rtcpsourcetodestinationjittermax"
#define OSP_STR_RTCPDESTSRCJITTERMAX   "rtcpdestinationtosourcejittermax"
#define OSP_STR_RTCPSRCRTDELAYMEAN     "rtcpsourceroundtripdelaymean"
#define OSP_STR_RTCPDESTRTDELAYMEAN    "rtcpdestinationroundtripdelaymean"
#define OSP_STR_RTCPSRCRTDELAYMAX      "rtcpsourceroundtripdelaymax"
#define OSP_STR_RTCPDESTRTDELAYMAX     "rtcpdestinationroundtripdelaymax"
#define OSP_STR_RFACTORSCALE           "rfactorscaleindex"
#define OSP_STR_SRCREPRFACTOR          "sourcetoreporterrfactor"
#define OSP_STR_DESTREPRFACTOR         "destinationtoreporterrfactor"
#define OSP_STR_MOSSCALE               "mosscaleindex"
#define OSP_STR_SRCREPMOS              "sourcetoreportermos"
#define OSP_STR_DESTREPMOS             "destinationtoreportermos"

/*
 * OSP log level
 */
typedef enum {
    OSP_LOG_SHORT = 0,  /* Log short message */
    OSP_LOG_LONG        /* Log long message */
} osp_loglevel_e;

/*
 * OSP mapping define level
 */
typedef enum {
    OSP_DEF_MUST = 0,   /* Mapping must be defined */
    OSP_DEF_MAY         /* Mapping may be defined */
} osp_deflevel_e;

/*
 * General scale
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
} osp_scale_e;

static const float OSP_SCALE_TABLE[OSP_SCALE_NUMBER] = { 0.0001, 0.001, 0.01, 0.1, 1, 10, 100, 1000, 10000 };

/*
 * Time unit
 */
typedef enum {
    OSP_TIMEUNIT_MIN = 0,
    OSP_TIMEUNIT_S = OSP_TIMEUNIT_MIN,  /* Second */
    OSP_TIMEUNIT_MS,                    /* Millisecond */
    OSP_TIMEUNIT_MAX = OSP_TIMEUNIT_MS,
    OSP_TIMEUNIT_NUMBER
} osp_timeunit_e;

static const int OSP_TIMEUNIT_SCALE[OSP_TIMEUNIT_NUMBER] = { 1000, 1 };

/*
 * Integer string format types
 */
typedef enum {
    OSP_INTSTR_MIN = 0,
    OSP_INTSTR_DEC = OSP_INTSTR_MIN,    /* Decimal */
    OSP_INTSTR_HEX,                     /* Hex */
    OSP_INTSTR_MAX = OSP_INTSTR_HEX,
    OSP_INTSTR_NUMBER
} osp_intstr_e;

/*
 * RADIUS client types
 */
typedef enum {
    OSP_CLIENT_MIN = 0,
    OSP_CLIENT_UNDEF = OSP_CLIENT_MIN,  /* Undefined */
    OSP_CLIENT_ACME,                    /* Acme */
    OSP_CLIENT_GENBANDS3,               /* GENBAND S3 */
    OSP_CLIENT_CISCO,                   /* Cisco */
    OSP_CLIENT_BROADWORKS,              /* BroadWorks */
    OSP_CLIENT_MAX = OSP_CLIENT_BROADWORKS,
    OSP_CLIENT_NUMBER
} osp_client_e;

/*
 * OSP time string types
 */
typedef enum {
    OSP_TIMESTR_MIN = 0,
    OSP_TIMESTR_T = OSP_TIMESTR_MIN,    /* time_t, integer string */
    OSP_TIMESTR_C,                      /* ctime, WWW MMM DD hh:mm:ss YYYY */
    OSP_TIMESTR_ACME,                   /* Acme, hh:mm:ss.kkk ZON MMM DD YYYY */
    OSP_TIMESTR_NTP,                    /* NTP, hh:mm:ss.kkk ZON WWW MMM DD YYYY */
    OSP_TIMESTR_CISCO,                  /* NTP, {'*'|'.'}hh:mm:ss.kkk ZON WWW MMM DD YYYY */
    OSP_TIMESTR_BW,                     /* BroadWorks, YYYYMMDDhhmmss.kkk */
    OSP_TIMESTR_MAX = OSP_TIMESTR_BW,
    OSP_TIMESTR_NUMBER
} osp_timestr_e;

/*
 * Calling/called number format types
 */
typedef enum {
    OSP_CALLNUM_MIN = 0,
    OSP_CALLNUM_E164 = OSP_CALLNUM_MIN, /* E.164 */
    OSP_CALLNUM_SIPURI,                 /* SIP URI */
    OSP_CALLNUM_E164SIPURI,             /* E.164 or SIP URI */
    OSP_CALLNUM_CISCO,                  /* Cisco, ton:0~7,npi:0~15,pi:0~3,si:0~3,#:E.164 */
    OSP_CALLNUM_MAX = OSP_CALLNUM_CISCO,
    OSP_CALLNUM_NUMBER
} osp_callnum_e;

/*
 * Cisco h323-call-origin value strings
 */
#define OSP_CISCOCALL_IN    "answer"    /* Call answer, inbound */
#define OSP_CISCOCALL_OUT   "originate" /* Call originate, outbound */

/*
 * BroadWorks BWAS-Direction value strings
 */
#define OSP_BWCALL_IN   "Originating"   /* Call originating, inbound */
#define OSP_BWCALL_OUT  "Terminating"   /* Call termianting, outbound */

/*
 * Call direction types
 */
typedef enum {
    OSP_DIRECTION_IN = 0,   /* Inbound */
    OSP_DIRECTION_OUT,      /* Outbound */
} osp_direction_e;

/* 
 * Acme release source 
 */
typedef enum {
    OSP_ACMEREL_UNDEF = 0,  /* Unknown */
    OSP_ACMEREL_SRC,        /* Source releases the call */
    OSP_ACMEREL_DEST,       /* Destination releases the call */
    OSP_ACMEREL_INT,        /* Internal releases the call */
} osp_acmerelease_e;

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
} osp_ciscorelease_e;

/*
 * BroadWorks release source
 */
#define OSP_BWREL_NONE      "none"
#define OSP_BWREL_LOCAL     "local"
#define OSP_BWREL_REMOTE    "remote"

/*
 * BroadWorks sub status type
 */
#define OSP_BWTYPE_START    "Start"         /* Start */
#define OSP_BWTYPE_END      "End"           /* End */
#define OSP_BWTYPE_DURATION "Long Diration" /* Long Duration */
#define OSP_BWTYPE_NORMAL   "Normal"        /* Normal */
#define OSP_BWTYPE_INTERIM  "Interim"       /* Interim */
#define OSP_BWTYPE_FAILOVER "Failover"      /* Failover */

/*
 * BroadWorks special device names
 */
#define OSP_BWDEV_GROUP         "Group"
#define OSP_BWDEV_ENTERPRISE    "Enterprise"
#define OSP_BWDEV_UNCONFIRMED   "unconfirmed"
#define OSP_BWDEV_UNAVAILABLE   "unavailable"

/*
 * BroadWorks transfer results
 */
#define OSP_BWTRANSFERRET_FAILURE   "Failure"
#define OSP_BWTRANSFERRET_SUCCESS   "Success"

/*
 * Normal string buffer type
 */
typedef char    osp_string_t[OSP_STRBUF_SIZE];

/*
 * Time zone
 */
typedef struct {
    char name[OSP_TZNAME_SIZE];
    int offset;
} osp_timezone_t;

/*
 * OSP module running parameter structure
 */
typedef struct {
    int loglevel;
    char* tzfile;
    int tzlist_size;
    osp_timezone_t tzlist[OSP_TZ_MAX];
} osp_running_t;

/*
 * OSP module provider parameter structure.
 */
typedef struct {
    int accelerate;                 /* Hardware accelerate flag */
    int security;                   /* Security flag */
    int spnumber;                   /* Number of service points */
    char* spuris[OSP_SPNUM_MAX];    /* Service point URIs */
    int spweights[OSP_SPNUM_MAX];   /* Service point weights */
    char* privatekey;               /* Private key file name */
    char* localcert;                /* Local cert file name */
    int canumber;                   /* Number of cacerts */
    char* cacerts[OSP_CANUM_MAX];   /* Cacert file names */
    int ssllifetime;                /* SSL life time */
    int maxconn;                    /* Max number of HTTP connections */
    int persistence;                /* Persistence */
    int retrydelay;                 /* Retry delay */
    int retrylimit;                 /* Times of retry */
    int timeout;                    /* Timeout */
    uint32_t deviceip;              /* OSP reporting IP address */
    int deviceport;                 /* OSP reporting IP port */
    OSPTPROVHANDLE handle;          /* OSP provider handle */
} osp_provider_t;

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

typedef struct {
    char* pack;     /* Packets lost in packets mapping */
    char* fract;    /* Packets lost in fraction mapping */
} osp_packmap_t;

typedef struct {
    int reportstats;                    /* If to report statistics */
    osp_packmap_t slost;                /* Lost send mapping */
    osp_packmap_t rlost;                /* Lost receive mapping */
    char* rtp_src_rep_octets;           /* RTP source-to-reporter octets */
    char* rtp_dest_rep_octets;          /* RTP destination-to-reporter octets */
    char* rtp_src_rep_packets;          /* RTP source-to-reporter packets */
    char* rtp_dest_rep_packets;         /* RTP destination-to-reporter packets */
    char* rtp_src_rep_lost;             /* RTP source-to-reporter lost packets */
    char* rtp_dest_rep_lost;            /* RTP destination-to-reporter lost packets */
    char* rtp_src_rep_jitter_mean;      /* RTP source-to-reporter jitter mean */
    char* rtp_dest_rep_jitter_mean;     /* RTP destination-to-reporter jitter mean */
    char* rtp_src_rep_jitter_max;       /* RTP source-to-reporter jitter max */
    char* rtp_dest_rep_jitter_max;      /* RTP destination-to-reporter jitter max */
    char* rtcp_src_dest_lost;           /* RTCP source-to-destination lost packets */
    char* rtcp_dest_src_lost;           /* RTCP destination-to-source lost packets */
    char* rtcp_src_dest_jitter_mean;    /* RTCP source-to-destination jitter mean */
    char* rtcp_dest_src_jitter_mean;    /* RTCP destination-to-source jitter mean */
    char* rtcp_src_dest_jitter_max;     /* RTCP source-to-destination jitter max */
    char* rtcp_dest_src_jitter_max;     /* RTCP destination-to-source jitter max */
    char* rtcp_src_rtdelay_mean;        /* RTCP source round trip delay mean */
    char* rtcp_dest_rtdelay_mean;       /* RTCP destination round trip delay mean */
    char* rtcp_src_rtdelay_max;         /* RTCP source round trip delay max */
    char* rtcp_dest_rtdelay_max;        /* RTCP destination round trip delay max */
    int rfactorscale;                   /* R-Factor scale index */
    char* src_rep_rfactor;              /* Source-to-reporter R-Factor */
    char* dest_rep_rfactor;             /* Destination-to-reporter R-Factor */
    int mosscale;                       /* MOS scale index */
    char* src_rep_mos;                  /* Source-to-reporter MOS */
    char* dest_rep_mos;                 /* Destination-to-reporter MOS */
} osp_statsmap_t;

/*
 * OSP module mapping parameter structure.
 */
typedef struct {
    char* iditem;                       /* RADIUS record identity VSA name */
    char* idvalue;                      /* RADIUS record identity VSA value */
    int reportstart;                    /* If to report RADIUS Start records */
    int reportstop;                     /* If to report RADIUS Stop records */
    int reportinterim;                  /* If to report RADIUS Interim-Update records */
    int clienttype;                     /* RADIUS client type */
    char* subtype;                      /* Sub status type */
    char* ignoreddeststr;               /* Ignored destination subnet list string */
    osp_netlist_t ignoreddestlist;      /* Ignored destination subnet list */
    char* direction;                    /* Call direction */
    int ignorein;                       /* Ignore inbound records */
    int ignoreout;                      /* Ignore outbound records */
    char* transid;                      /* Transaction ID */
    char* callid;                       /* Call-ID */
    int callingformat;                  /* Calling number format */
    int calledformat;                   /* Called number format */
    char* calling;                      /* Calling number */
    char* called;                       /* Called number */
    int parsetransfer;                  /* If to parse transfer VSAs in RADIUS records */
    char* transfercalling;              /* Transfer calling number */
    char* transfercalled;               /* Transfer called number */
    char* transferret;                  /* Transfer result */
    char* transferid;                   /* Transfer ID */
    char* assertedid;                   /* P-Asserted-Identity */
    char* rpid;                         /* Remote-Party-ID */
    char* source;                       /* Source */
    char* proxy;                        /* Proxy, only for call leg type records */
    char* srcdev;                       /* Source device */
    char* destination;                  /* Destination */
    char* destdev;                      /* Destination device */
    char* destcount;                    /* Destination count */
    char* accessdev;                    /* Access device */
    char* routedev;                     /* Route device */
    char* srcnid;                       /* Source network ID */
    char* destnid;                      /* Destination network ID */
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
    char* q850cause;                    /* Release cause, Q850 */
    char* sipcause;                     /* Release cause, SIP */
    char* protocol;                     /* Signaling protocol */
    char* srcprotocol;                  /* Source protocol */
    char* destprotocol;                 /* Destination protocol */
    char* srcsessionid;                 /* Source sessionID */
    char* destsessionid;                /* Destination session ID */
    char* corrsessionid;                /* Correlation session ID */
    char* accesscallid;                 /* Access call ID */
    char* routecallid;                  /* Route call ID */
    char* localcallid;                  /* Local call ID */
    char* remotecallid;                 /* Remote call ID */
    char* srccodec;                     /* Source codec */
    char* destcodec;                    /* Destination codec */
    char* confid;                       /* Conference ID */
    char* custinfo[OSP_CUSTOMINFO_MAX]; /* Custom info */
    char* srcrealm;                     /* Source realm */
    char* destrealm;                    /* Destination realm */
    char* otherparty;                   /* Other party info */
    char* callingusername;              /* Calling party user name */
    char* callinguserid;                /* Calling party user ID */
    char* callingusergroup;             /* Calling party user group */
    char* calledusername;               /* Called party user name */
    char* calleduserid;                 /* Called party user ID */
    char* calledusergroup;              /* Called party user group */
    osp_statsmap_t stats;               /* Statistics */
} osp_mapping_t;

/*
 * OSP module instance data structure.
 */
typedef struct {
    osp_running_t running;      /* OSP module running parameters */
    osp_provider_t provider;    /* OSP provider parameters */
    osp_mapping_t mapping;      /* OSP mapping parameters */
} rlm_osp_t;

typedef struct {
    int pack;   /* Packets lost in packets */
    int fract;  /* Packets lost in fraction */
} osp_pack_t;

typedef struct {
    osp_pack_t slost;               /* Send packets lost */
    osp_pack_t rlost;               /* Receive packets lost */
    int rtp_src_rep_octets;         /* RTP source-to-reporter octets */
    int rtp_dest_rep_octets;        /* RTP destination-to-reporter octets */
    int rtp_src_rep_packets;        /* RTP source-to-reporter packets */
    int rtp_dest_rep_packets;       /* RTP destination-to-reporter packets */
    int rtp_src_rep_lost;           /* RTP source-to-reporter lost packets */
    int rtp_dest_rep_lost;          /* RTP destination-to-reporter lost packets */
    int rtp_src_rep_jitter_mean;    /* RTP source-to-reporter jitter mean */
    int rtp_dest_rep_jitter_mean;   /* RTP destination-to-reporter jitter mean */
    int rtp_src_rep_jitter_max;     /* RTP source-to-reporter jitter max */
    int rtp_dest_rep_jitter_max;    /* RTP destination-to-reporter jitter max */
    int rtcp_src_dest_lost;         /* RTCP source-to-destination lost packets */
    int rtcp_dest_src_lost;         /* RTCP destination-to-source lost packets */
    int rtcp_src_dest_jitter_mean;  /* RTCP source-to-destination jitter mean */
    int rtcp_dest_src_jitter_mean;  /* RTCP destination-to-source jitter mean */
    int rtcp_src_dest_jitter_max;   /* RTCP source-to-destination jitter max */
    int rtcp_dest_src_jitter_max;   /* RTCP destination-to-source jitter max */
    int rtcp_src_rtdelay_mean;      /* RTCP source round trip delay mean */
    int rtcp_dest_rtdelay_mean;     /* RTCP destination round trip delay mean */
    int rtcp_src_rtdelay_max;       /* RTCP source round trip delay max */
    int rtcp_dest_rtdelay_max;      /* RTCP destination round trip delay max */
    float src_rep_rfactor;          /* Source-to-reporter R-Factor */
    float dest_rep_rfactor;         /* Destination-to-reporter R-Factor */
    float src_rep_mos;              /* Source-to-reporter MOS */
    float dest_rep_mos;             /* Destination-to-reporter MOS */
} osp_stats_t;

/*
 * Usage information structure.
 */
typedef struct {
    osp_string_t subtype;                       /* Sub status type */
    int direction;                              /* Call direction */
    OSPTUINT64 transid;                         /* Transaction ID */
    osp_string_t callid;                        /* Call-ID */
    osp_string_t calling;                       /* Calling number */
    osp_string_t called;                        /* Called number */
    osp_string_t transferid;                    /* Transfer ID */
    OSPE_TRANSFER_STATUS transfer;              /* Transfer status */
    osp_string_t assertedid;                    /* P-Asserted-Identity */
    osp_string_t rpid;                          /* Remote-Party-ID */
    osp_string_t source;                        /* Source */
    osp_string_t srcdev;                        /* Source device */
    osp_string_t destination;                   /* Destination */
    osp_string_t destdev;                       /* Destination device */
    int destcount;                              /* Destination count */
    osp_string_t srcnid;                        /* Source network ID */
    osp_string_t destnid;                       /* Destination network ID */
    osp_string_t divuser;                       /* Diversion user */
    osp_string_t divhost;                       /* Diversion host */
    time_t start;                               /* Call start time */
    time_t alert;                               /* Call alert time */
    time_t connect;                             /* Call connect time */
    time_t end;                                 /* Call end time */
    time_t duration;                            /* Length of call */
    int pdd;                                    /* Post Dial Delay, in milliseconds */
    OSPE_RELEASE release;                       /* EP that released the call */
    int q850cause;                              /* Release reason, Q850 */
    int sipcause;                               /* Release reason, SIP */
    OSPE_PROTOCOL_NAME protocol;                /* Signaling protocol */
    OSPE_PROTOCOL_NAME srcprotocol;             /* Source protocol */
    OSPE_PROTOCOL_NAME destprotocol;            /* Destination protocol */
    osp_string_t srcsessionid;                  /* Source session ID */
    osp_string_t destsessionid;                 /* Destination session ID */
    osp_string_t corrsessionid;                 /* Correlation session ID */
    osp_string_t localcallid;                   /* Local call ID */
    osp_string_t remotecallid;                  /* Remote call ID */
    osp_string_t srccodec;                      /* Source codec */
    osp_string_t destcodec;                     /* Destination codec */
    osp_string_t confid;                        /* Conference ID */
    osp_string_t custinfo[OSP_CUSTOMINFO_MAX];  /* Custom info */
    osp_string_t srcrealm;                      /* Source realm */
    osp_string_t destrealm;                     /* Destination realm */
    osp_string_t otherparty;                    /* Other party info */
    osp_string_t callingusername;               /* Calling party user name */
    osp_string_t callinguserid;                 /* Calling party user ID */
    osp_string_t callingusergroup;              /* Calling party user group */
    osp_string_t calledusername;                /* Called party user name */
    osp_string_t calleduserid;                  /* Called party user ID */
    osp_string_t calledusergroup;               /* Called party user group */
    osp_stats_t stats;                          /* Statistics */
} osp_usage_t;

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
 * param _name Variable name
 * param _val Variable value
 * param _min Min value
 */
#define OSP_CHECK_MIN(_name, _val, _min) { \
    if (_val <= _min) { \
        radlog(L_ERR, "rlm_osp: '%s' must be larger than '%d', not '%d'.", _name, _min - 1, _val); \
        return -1; \
    } \
    DEBUG2("rlm_osp: '%s' = '%d'", _name, _val); \
}

/*
 * Check value range
 *
 * param _name Variable name
 * param _val Variable value
 * param _min Min value
 * param _max Max value
 */
#define OSP_CHECK_RANGE(_name, _val, _min, _max) { \
    if ((_val < _min) || (_val > _max)) { \
        radlog(L_ERR, "rlm_osp: '%s' must be an integer from '%d' to '%d', not '%d'.", _name, _min, _max, _val); \
        return -1; \
    } \
    DEBUG2("rlm_osp: '%s' = '%d'", _name, _val); \
}

/*
 * Check item mapping
 *
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 */
#define OSP_CHECK_ITEMMAP(_name, _lev, _map) { \
    DEBUG3("rlm_osp: check '%s' mapping", _name); \
    if (OSP_CHECK_STRING(_map) && !strcasecmp(_map, OSP_MAP_NULL)) { \
        _map = NULL; \
    } \
    if (osp_check_itemmap(_map, _lev) < 0) { \
        if (OSP_CHECK_STRING(_map)) { \
            radlog(L_ERR, "rlm_osp: Incorrect '%s' mapping '%s'.", _name, _map); \
        } else { \
            radlog(L_ERR, "rlm_osp: Incorrect '%s' mapping 'NULL'.", _name); \
        } \
        return -1; \
    } \
    if (OSP_CHECK_STRING(_map)) { \
        DEBUG2("rlm_osp: '%s' = '%s'", _name, _map); \
    } else { \
        /* Undefined may be defined item */ \
        DEBUG2("rlm_osp: '%s' = 'NULL'", _name); \
    } \
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
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        _val = _def; \
    } \
    DEBUG2("rlm_osp: '%s' = '%d'", _name, _val); \
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
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        _val = _def; \
    } \
    DEBUG2("rlm_osp: '%s' = '%llu'", _name, _val); \
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
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        _val = _def; \
    } \
    DEBUG2("rlm_osp: '%s' = '%.4f'", _name, _val); \
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
                   DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        _val[0] = '\0'; \
    } \
    /* Do not have to check string NULL */ \
    DEBUG2("rlm_osp: '%s' = '%s'", _name, _val); \
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
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val[0] = '\0'; \
                } \
            } else  { \
                _ptr = _buf; \
                switch (_type) { \
                case OSP_CALLNUM_SIPURI: \
                    if (osp_get_uriuser(_buf, _val, sizeof(_val), TRUE) < 0) { \
                        /* Do not have to check string NULL */ \
                        if (_lev == OSP_DEF_MUST) { \
                            radlog(L_ERR, "rlm_osp: Failed to get '%s' from SIP URI '%s'.", _name,  _buf); \
                            return -1; \
                        } else { \
                            radlog(L_INFO, "rlm_osp: Failed to get '%s' from SIP URI '%s'.", _name,  _buf); \
                            _val[0] = '\0'; \
                        } \
                    } else if ((_lev == OSP_DEF_MUST) && !OSP_CHECK_STRING(_val)) { \
                        /* Number must be reported */ \
                        radlog(L_ERR, "rlm_osp: Empty number."); \
                        return -1; \
                    } \
                    break; \
                case OSP_CALLNUM_E164SIPURI: \
                    if (osp_get_uriuser(_buf, _val, sizeof(_val), FALSE) < 0) { \
                        _size = sizeof(_val) - 1; \
                        snprintf(_val, _size, "%s", _ptr); \
                        _val[_size] = '\0'; \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        _val[0] = '\0'; \
    } \
    /* Do not have to check string NULL */ \
    DEBUG2("rlm_osp: '%s' = '%s'", _name, _val); \
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
 * param _port Default port
 * param _buf Buffer
 * param _val Item value
 * param _host Host of IP
 */
#define OSP_GET_IP(_req, _flag, _name, _lev, _map, _ip, _port, _buf, _val, _host) { \
    _host[0] = '\0'; \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
                    osp_create_device(_ip, _port, _val, sizeof(_val)); \
                } \
            } else { \
                osp_format_device(_buf, _val, sizeof(_val)); \
                osp_get_iphost(_buf, _host, sizeof(_host)); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        osp_create_device(_ip, _port, _val, sizeof(_val)); \
    } \
    /* Do not have to check string NULL */ \
    DEBUG2("rlm_osp: '%s' = '%s'", _name, _val); \
}

/*
 * Get hostport
 *
 * param _req FreeRADIUS request
 * param _flag Parse flag
 * param _name Item name
 * param _lev Must or may be defined
 * param _map Item mapping string
 * param _ip Default IP address
 * param _port Default port
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
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
                    osp_create_device(_ip, _port, _val, sizeof(_val)); \
                } \
            } else { \
                if (osp_get_urihost(_val, _buf, sizeof(_buf)) < 0) { \
                    /* Do not have to check string NULL */ \
                    if (_lev == OSP_DEF_MUST) { \
                        radlog(L_ERR, "rlm_osp: Failed to get '%s' from SIP URI '%s'.", _name,  _buf); \
                        return -1; \
                    } else { \
                        radlog(L_INFO, "rlm_osp: Failed to get '%s' from SIP URI '%s'.", _name,  _buf); \
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
                            DEBUG("rlm_osp: empty hostport."); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        osp_create_device(_ip, _port, _val, sizeof(_val)); \
    } \
    /* Do not have to check string NULL */ \
    DEBUG2("rlm_osp: '%s' = '%s'", _name, _val); \
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
#define OSP_GET_TIME(_req, _flag, _name, _lev, _run, _map, _type, _def, _buf, _val) { \
    if (_flag) { \
        if (OSP_CHECK_STRING(_map)) { \
            radius_xlat(_buf, sizeof(_buf), _map, _req, NULL); \
            if (_buf[0] == '\0') { \
                /* Has checked string NULL */ \
                if (_lev == OSP_DEF_MUST) { \
                    radlog(L_ERR, "rlm_osp: Failed to parse '%s' in request for '%s'.", _map, _name); \
                    return -1; \
                } else { \
                    DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", _map, _name); \
                    _val = _def; \
                } \
            } else { \
                _val = osp_format_time(_run, _buf, _type); \
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
        DEBUG2("rlm_osp: do not parse '%s'.", _name); \
        _val = 0; \
    } \
    DEBUG2("rlm_osp: '%s' = '%lu'", _name, _val); \
}

/*
 * Internal function prototype
 */
static int osp_check_running(osp_running_t* running);
static int osp_load_tzlist(osp_running_t* running);
static int osp_check_provider(osp_provider_t* provider);
static int osp_check_mapping(osp_mapping_t* mapping);
static int osp_parse_netlist(char* liststr, osp_netlist_t* list);
static int osp_check_statsmap(osp_statsmap_t* stats);
static int osp_check_itemmap(char* item, osp_deflevel_e level);
static int osp_create_provider(osp_provider_t* provider);
static void osp_report_statsinfo(OSPTTRANHANDLE transaction, osp_statsmap_t* mapping, osp_stats_t* stats);
static int osp_get_usageinfo(rlm_osp_t* data, REQUEST* request, int type, osp_usage_t* usage);
static int osp_match_subnet(osp_netlist_t* list, uint32_t ip);
static int osp_get_statsinfo(osp_mapping_t* mapping, REQUEST* request, int type, osp_usage_t* usage);
static void osp_get_iphost(char* ip, char* buffer, int buffersize);
static void osp_create_device(uint32_t ip, int port, char* buffer, int buffersize);
static void osp_format_device(char* device, char* buffer, int buffersize);
static int osp_get_uriuser(char* uri, char* buffer, int buffersize, int logflag);
static int osp_get_urihost(char* uri, char* buffer, int buffersize);
static OSPE_PROTOCOL_NAME osp_parse_protocol(osp_mapping_t* mapping, char* protocol);
static time_t osp_format_time(osp_running_t* running, char* timestamp, osp_timestr_e format);
static int osp_remove_timezone(osp_running_t* running, char* timestamp, char* buffer, int buffersize, long int* toffset);
static int osp_cal_timeoffset(osp_running_t* running, char* tzone, long int* toffset);
static int osp_cal_elapsed(struct tm* dt, long int toffset, time_t* elapsed);

/* OSP instance flag */
static int instance_count = 0;

/* OSP default certificates */
static const char* B64PKey = "MIIBOgIBAAJBAK8t5l+PUbTC4lvwlNxV5lpl+2dwSZGW46dowTe6y133XyVEwNiiRma2YNk3xKs/TJ3Wl9Wpns2SYEAJsFfSTukCAwEAAQJAPz13vCm2GmZ8Zyp74usTxLCqSJZNyMRLHQWBM0g44Iuy4wE3vpi7Wq+xYuSOH2mu4OddnxswCP4QhaXVQavTAQIhAOBVCKXtppEw9UaOBL4vW0Ed/6EA/1D8hDW6St0h7EXJAiEAx+iRmZKhJD6VT84dtX5ZYNVk3j3dAcIOovpzUj9a0CECIEduTCapmZQ5xqAEsLXuVlxRtQgLTUD4ZxDElPn8x0MhAiBE2HlcND0+qDbvtwJQQOUzDgqg5xk3w8capboVdzAlQQIhAMC+lDL7+gDYkNAft5Mu+NObJmQs4Cr+DkDFsKqoxqrm";
static const char* B64LCert = "MIIBeTCCASMCEHqkOHVRRWr+1COq3CR/xsowDQYJKoZIhvcNAQEEBQAwOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMB4XDTA1MDYyMzAwMjkxOFoXDTA2MDYyNDAwMjkxOFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvLeZfj1G0wuJb8JTcVeZaZftncEmRluOnaME3ustd918lRMDYokZmtmDZN8SrP0yd1pfVqZ7NkmBACbBX0k7pAgMBAAEwDQYJKoZIhvcNAQEEBQADQQDnV8QNFVVJx/+7IselU0wsepqMurivXZzuxOmTEmTVDzCJx1xhA8jd3vGAj7XDIYiPub1PV23eY5a2ARJuw5w9";
static const char* B64CACert = "MIIBYDCCAQoCAQEwDQYJKoZIhvcNAQEEBQAwOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMB4XDTAyMDIwNDE4MjU1MloXDTEyMDIwMzE4MjU1MlowOzElMCMGA1UEAxMcb3NwdGVzdHNlcnZlci50cmFuc25leHVzLmNvbTESMBAGA1UEChMJT1NQU2VydmVyMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPGeGwV41EIhX0jEDFLRXQhDEr50OUQPq+f55VwQd0TQNts06BP29+UiNdRW3c3IRHdZcJdC1Cg68ME9cgeq0h8CAwEAATANBgkqhkiG9w0BAQQFAANBAGkzBSj1EnnmUxbaiG1N4xjIuLAWydun7o3bFk2tV8dBIhnuh445obYyk1EnQ27kI7eACCILBZqi2MHDOIMnoN0=";

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
    { OSP_STR_LOGLEVEL, PW_TYPE_INTEGER, offsetof(rlm_osp_t, running.loglevel), NULL, OSP_LOGLEVEL_DEF },
    { OSP_STR_TZFILE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, running.tzfile), NULL, OSP_TZFILE_DEF },
    /* End */
    { NULL, -1, 0, NULL, NULL } /* end the list */
};

static const CONF_PARSER provider_config[] = {
    /*
     * OSP provider parameters
     *
     *   All service points, weights and cacerts must be listed to allow config
     *   parser to read them.
     */
    { OSP_STR_ACCELERATE, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, provider.accelerate), NULL, OSP_HWACCE_DEF },
    { OSP_STR_SECURITY, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, provider.security), NULL, OSP_SECURITY_DEF },
    { OSP_STR_SPURI1, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[0]), NULL, OSP_SPURI_DEF },
    { OSP_STR_SPURI2, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[1]), NULL, NULL },
    { OSP_STR_SPURI3, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[2]), NULL, NULL },
    { OSP_STR_SPURI4, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, provider.spuris[3]), NULL, NULL },
    { OSP_STR_SPWEIGHT1, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[0]), NULL, OSP_SPWEIGHT_DEF },
    { OSP_STR_SPWEIGHT2, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[1]), NULL, OSP_SPWEIGHT_DEF },
    { OSP_STR_SPWEIGHT3, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[2]), NULL, OSP_SPWEIGHT_DEF },
    { OSP_STR_SPWEIGHT4, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.spweights[3]), NULL, OSP_SPWEIGHT_DEF },
    { OSP_STR_PRIVATEKEY, PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.privatekey), NULL, OSP_PRIVATEKEY_DEF },
    { OSP_STR_LOCALCERT, PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.localcert), NULL, OSP_LOCALCERT_DEF },
    { OSP_STR_CACERT0, PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[0]), NULL, OSP_CACERT_DEF },
    { OSP_STR_CACERT1, PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[1]), NULL, NULL },
    { OSP_STR_CACERT2, PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[2]), NULL, NULL },
    { OSP_STR_CACERT3, PW_TYPE_FILENAME, offsetof(rlm_osp_t, provider.cacerts[3]), NULL, NULL },
    { OSP_STR_SSLLIFETIME, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.ssllifetime), NULL, OSP_SSLLIFETIME_DEF },
    { OSP_STR_MAXCONN, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.maxconn), NULL, OSP_MAXCONN_DEF },
    { OSP_STR_PERSISTENCE, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.persistence), NULL, OSP_PERSISTENCE_DEF },
    { OSP_STR_RETRYDELAY, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.retrydelay), NULL, OSP_RETRYDELAY_DEF },
    { OSP_STR_RETRYLIMIT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.retrylimit), NULL, OSP_RETRYLIMIT_DEF },
    { OSP_STR_TIMEOUT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.timeout), NULL, OSP_TIMEOUT_DEF },
    { OSP_STR_DEVICEIP, PW_TYPE_IPADDR, offsetof(rlm_osp_t, provider.deviceip), NULL, OSP_DEVICEIP_DEF },
    { OSP_STR_DEVICEPORT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, provider.deviceport), NULL, OSP_DEVICEPORT_DEF },
    /* End */
    { NULL, -1, 0, NULL, NULL } /* end the list */
};

static const CONF_PARSER mapping_config[] = {
    /*
     * RADIUS OSP mapping parameters
     *
     *   All custom info must be listed to allow config parser to read them.
     */
    { OSP_STR_IDITEM, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.iditem), NULL, OSP_MAP_IDITEM },
    { OSP_STR_IDVALUE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.idvalue), NULL, OSP_MAP_IDVALUE },
    { OSP_STR_REPORTSTART, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.reportstart), NULL, OSP_MAP_REPORT },
    { OSP_STR_REPORTSTOP, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.reportstop), NULL, OSP_MAP_REPORT },
    { OSP_STR_REPORTINTERIM, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.reportinterim), NULL, OSP_MAP_REPORT },
    { OSP_STR_CLIENTTYPE, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.clienttype), NULL, OSP_MAP_CLIENTTYPE },
    { OSP_STR_SUBTYPE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.subtype), NULL, OSP_MAP_SUBTYPE },
    { OSP_STR_IGNOREDDESTLIST, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.ignoreddeststr), NULL, OSP_MAP_NETLIST },
    { OSP_STR_DIRECTION, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.direction), NULL, OSP_MAP_DIRECTION},
    { OSP_STR_IGNOREIN, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.ignorein), NULL, OSP_MAP_IGNORERAD },
    { OSP_STR_IGNOREOUT, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.ignoreout), NULL, OSP_MAP_IGNORERAD },
    { OSP_STR_TRANSACTIONID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transid), NULL, OSP_MAP_TRANSID },
    { OSP_STR_CALLID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callid), NULL, OSP_MAP_CALLID },
    { OSP_STR_CALLINGFORMAT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.callingformat), NULL, OSP_MAP_NUMFORMAT },
    { OSP_STR_CALLEDFORMAT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.calledformat), NULL, OSP_MAP_NUMFORMAT },
    { OSP_STR_CALLINGNUMBER, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calling), NULL, OSP_MAP_CALLING },
    { OSP_STR_CALLEDNUMBER, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.called), NULL, OSP_MAP_CALLED },
    { OSP_STR_PARSETRANSFER, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mapping.parsetransfer), NULL, OSP_MAP_PARSETRANSFER },
    { OSP_STR_TRANSFERCALLINGNUM, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transfercalling), NULL, OSP_MAP_TRANSFERCALLING },
    { OSP_STR_TRANSFERCALLEDNUM, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transfercalled), NULL, OSP_MAP_TRANSFERCALLED },
    { OSP_STR_TRANSFERRET, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transferret), NULL, OSP_MAP_TRANSFERRET },
    { OSP_STR_TRANSFERID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.transferid), NULL, OSP_MAP_TRANSFERID },
    { OSP_STR_ASSERTEDID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.assertedid), NULL, OSP_MAP_ASSERTEDID },
    { OSP_STR_RPID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.rpid), NULL, OSP_MAP_RPID },
    { OSP_STR_SOURCE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.source), NULL, OSP_MAP_SOURCE },
    { OSP_STR_PROXY, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.proxy), NULL, OSP_MAP_PROXY },
    { OSP_STR_SRCDEVICE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcdev), NULL, OSP_MAP_SRCDEV },
    { OSP_STR_DESTINATION, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destination), NULL, OSP_MAP_DESTINATION },
    { OSP_STR_DESTDEVICE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destdev), NULL, OSP_MAP_DESTDEV },
    { OSP_STR_DESTCOUNT, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destcount), NULL, OSP_MAP_DESTCOUNT },
    { OSP_STR_ACCESSDEVICE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.accessdev), NULL, OSP_MAP_DEVICE },
    { OSP_STR_ROUTEDEVICE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.routedev), NULL, OSP_MAP_DEVICE },
    { OSP_STR_SRCNETWORKID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcnid), NULL, OSP_MAP_NETWORKID },
    { OSP_STR_DESTNETWORKID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destnid), NULL, OSP_MAP_NETWORKID },
    { OSP_STR_DIVERSIONUSER, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.divuser), NULL, OSP_MAP_DIVUSER },
    { OSP_STR_DIVERSIONHOST, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.divhost), NULL, OSP_MAP_DIVHOST },
    { OSP_STR_TIMEFORMAT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.timeformat), NULL, OSP_MAP_TIMEFORMAT },
    { OSP_STR_STARTTIME, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.start), NULL, OSP_MAP_START },
    { OSP_STR_ALERTTIME, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.alert), NULL, OSP_MAP_ALERT },
    { OSP_STR_CONNECTTIME, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.connect), NULL, OSP_MAP_CONNECT },
    { OSP_STR_ENDTIME, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.end), NULL, OSP_MAP_END },
    { OSP_STR_DURATION, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.duration), NULL, OSP_MAP_DURATION },
    { OSP_STR_PDDUNIT, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mapping.pddunit), NULL, OSP_MAP_PDDUNIT },
    { OSP_STR_PDD, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.pdd), NULL, OSP_MAP_PDD },
    { OSP_STR_RELEASE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.release), NULL, OSP_MAP_RELEASE },
    { OSP_STR_Q850CAUSE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.q850cause), NULL, OSP_MAP_Q850CAUSE },
    { OSP_STR_SIPCAUSE, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.sipcause), NULL, OSP_MAP_CAUSE },
    { OSP_STR_PROTOCOL, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.protocol), NULL, OSP_MAP_PROTOCOL },
    { OSP_STR_SRCPROTOCOL, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcprotocol), NULL, OSP_MAP_PROTOCOL },
    { OSP_STR_DESTPROTOCOL, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destprotocol), NULL, OSP_MAP_PROTOCOL },
    { OSP_STR_SRCSESSIONID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcsessionid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_DESTSESSIONID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destsessionid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_CORRSESSIONID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.corrsessionid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_ACCESSCALLID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.accesscallid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_ROUTECALLID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.routecallid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_LOCALCALLID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.localcallid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_REMOTECALLID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.remotecallid), NULL, OSP_MAP_SESSIONID },
    { OSP_STR_SRCCODEC, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srccodec), NULL, OSP_MAP_CODEC },
    { OSP_STR_DESTCODEC, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destcodec), NULL, OSP_MAP_CODEC },
    { OSP_STR_CONFID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.confid), NULL, OSP_MAP_CONFID },
    { OSP_STR_CUSTOMINFO1, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[0]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO2, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[1]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO3, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[2]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO4, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[3]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO5, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[4]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO6, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[5]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO7, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[6]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_CUSTOMINFO8, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.custinfo[7]), NULL, OSP_MAP_CUSTOMINFO },
    { OSP_STR_SRCREALM, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.srcrealm), NULL, OSP_MAP_REALM },
    { OSP_STR_DESTREALM, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.destrealm), NULL, OSP_MAP_REALM },
    { OSP_STR_OTHERPARTY, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.otherparty), NULL, OSP_MAP_CALLPARTYINFO },
    { OSP_STR_CALLINGUSERNAME, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callingusername), NULL, OSP_MAP_CALLPARTYINFO },
    { OSP_STR_CALLINGUSERID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callinguserid), NULL, OSP_MAP_CALLPARTYINFO },
    { OSP_STR_CALLINGUSERGROUP, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.callingusergroup), NULL, OSP_MAP_CALLPARTYINFO },
    { OSP_STR_CALLEDUSERNAME, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calledusername), NULL, OSP_MAP_CALLPARTYINFO },
    { OSP_STR_CALLEDUSERID, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calleduserid), NULL, OSP_MAP_CALLPARTYINFO },
    { OSP_STR_CALLEDUSERGROUP, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mapping.calledusergroup), NULL, OSP_MAP_CALLPARTYINFO },
    /* Statistics mapping */
#define mSMAP   mapping.stats
    { OSP_STR_REPORTSTATS, PW_TYPE_BOOLEAN, offsetof(rlm_osp_t, mSMAP.reportstats), NULL, OSP_MAP_REPORT },
    { OSP_STR_SLOSTPACKETS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.slost.pack), NULL, OSP_MAP_STATS },
    { OSP_STR_SLOSTFRACTION, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.slost.fract), NULL, OSP_MAP_STATS },
    { OSP_STR_RLOSTPACKETS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rlost.pack), NULL, OSP_MAP_STATS },
    { OSP_STR_RLOSTFRACTION, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rlost.fract), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPSRCREPOCTETS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_src_rep_octets), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPDESTREPOCTETS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_dest_rep_octets), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPSRCREPPACKETS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_src_rep_packets), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPDESTREPPACKETS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_dest_rep_packets), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPSRCREPLOST, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_src_rep_lost), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPDESTREPLOST, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_dest_rep_lost), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPSRCREPJITTERMEAN, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_src_rep_jitter_mean), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPDESTREPJITTERMEAN, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_dest_rep_jitter_mean), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPSRCREPJITTERMAX, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_src_rep_jitter_max), NULL, OSP_MAP_STATS },
    { OSP_STR_RTPDESTREPJITTERMAX, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtp_dest_rep_jitter_max), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPSRCDESTLOST, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_src_dest_lost), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPDESTSRCLOST, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_dest_src_lost), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPSRCDESTJITTERMEAN, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_src_dest_jitter_mean), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPDESTSRCJITTERMEAN, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_dest_src_jitter_mean), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPSRCDESTJITTERMAX, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_src_dest_jitter_max), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPDESTSRCJITTERMAX, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_dest_src_jitter_max), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPSRCRTDELAYMEAN, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_src_rtdelay_mean), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPDESTRTDELAYMEAN, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_dest_rtdelay_mean), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPSRCRTDELAYMAX, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_src_rtdelay_max), NULL, OSP_MAP_STATS },
    { OSP_STR_RTCPDESTRTDELAYMAX, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.rtcp_dest_rtdelay_max), NULL, OSP_MAP_STATS },
    { OSP_STR_RFACTORSCALE, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.rfactorscale), NULL, OSP_MAP_SCALE },
    { OSP_STR_SRCREPRFACTOR, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.src_rep_rfactor), NULL, OSP_MAP_STATS },
    { OSP_STR_DESTREPRFACTOR, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.dest_rep_rfactor), NULL, OSP_MAP_STATS },
    { OSP_STR_MOSSCALE, PW_TYPE_INTEGER, offsetof(rlm_osp_t, mSMAP.mosscale), NULL, OSP_MAP_SCALE },
    { OSP_STR_SRCREPMOS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.src_rep_mos), NULL, OSP_MAP_STATS },
    { OSP_STR_DESTREPMOS, PW_TYPE_STRING_PTR, offsetof(rlm_osp_t, mSMAP.dest_rep_mos), NULL, OSP_MAP_STATS },
#undef mSMAP
    /* Statistics group mapping end */
    /* End */
    { NULL, -1, 0, NULL, NULL } /* end the list */
};

static const CONF_PARSER module_config[] = {
    /* OSP running parameters */
    { OSP_STR_RUNNING, PW_TYPE_SUBSECTION, 0, NULL, (const void*)running_config },
    /* OSP provider parameters */
    { OSP_STR_PROVIDER, PW_TYPE_SUBSECTION, 0, NULL, (const void*)provider_config },
    /* RADIUS OSP mapping parameters */
    { OSP_STR_MAPPING, PW_TYPE_SUBSECTION, 0, NULL, (const void*)mapping_config },
    /* End */
    { NULL, -1, 0, NULL, NULL } /* end the list */
};

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

    DEBUG3("rlm_osp: osp_instantiate start");

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

    DEBUG3("rlm_osp: osp_instantiate success");

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
    DEBUG3("rlm_osp: osp_check_running start");

    /* Check log level */
    switch (running->loglevel) {
    case OSP_LOG_SHORT:
    case OSP_LOG_LONG:
        break;
    default:
        running->loglevel = OSP_LOG_LONG;
        break;
    }
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_LOGLEVEL, running->loglevel);

    /* If failed to load time zone configuration, then fail. */
    if (osp_load_tzlist(running) < 0) {
        radlog(L_ERR, "rlm_osp: Failed to load time zone configuration.");
        return -1;
    }

    DEBUG3("rlm_osp: osp_check_running success");

    return 0;
}

/*
 * Load time zone configuration.
 *
 * param running Running parameters
 * return 0 success, -1 failure
 */
static int osp_load_tzlist(
    osp_running_t* running)
{
    FILE* fp;
    osp_string_t buffer;
    char* start;
    char* tmp;
    char* token;
    osp_timezone_t tz;

    DEBUG3("rlm_osp: osp_load_tz start");

    if (!(fp = fopen(running->tzfile, "r"))) {
        radlog(L_ERR, "rlm_osp: Failed to open '%s'.", running->tzfile);
        return -1;
    }

    while (fgets(buffer, OSP_STRBUF_SIZE, fp)) {
        start = buffer;
        while (*start == ' ') {
            start++;
        }
        if ((tmp = strchr(start, OSP_TZ_COMMENT)) != NULL) {
            *tmp = '\0';
        }
        if ((token = strtok_r(start, OSP_TZ_DELIMITER, &tmp)) != NULL) {
            strncpy(tz.name, token, OSP_TZNAME_SIZE);
            if ((token = strtok_r(NULL, OSP_TZ_DELIMITER, &tmp)) != NULL) {
                tz.offset = atoi(token);
                if (running->tzlist_size < OSP_TZ_MAX) {
                    DEBUG2("rlm_osp: time zone '%s' offset '%d'", tz.name, tz.offset);
                    running->tzlist[running->tzlist_size++] = tz;
                } else {
                    DEBUG("rlm_osp: time zone table too big");
                    break;
                }
            } else {
                DEBUG("rlm_osp: time zone '%s' offset undefined", tz.name);
            }
        }
    }
    fclose(fp);

    DEBUG2("rlm_osp: time zone list size = '%d'", running->tzlist_size);

    DEBUG3("rlm_osp: osp_load_tz success");

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
    osp_string_t buffer;

    DEBUG3("rlm_osp: osp_check_provider start");

    /* Nothing to check for accelerate */
    if (instance_count == 0) {
        DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_ACCELERATE, provider->accelerate);
    }

    /* Nothing to check for security */
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_SECURITY, provider->security);

    /* Calculate number of service points */
    provider->spnumber = 0;
    for (i = 0; i < OSP_SPNUM_MAX; i++) {
        if (OSP_CHECK_STRING(provider->spuris[i])) {
            /* If any service point weight is wrong, then fail. */
            if (provider->spweights[i] <= 0) {
                radlog(L_ERR,
                    "rlm_osp: '%s%d' must be larger than 0, not '%d'.",
                    OSP_STR_SPWEIGHT,
                    i + 1,
                    provider->spweights[i]);
                return -1;
            }
            provider->spnumber++;
        } else {
            break;
        }
    }

    /* If number of service points is wrong, then fail. */
    if (provider->spnumber == 0) {
        radlog(L_ERR,
            "rlm_osp: '%s' must be defined.",
            OSP_STR_SPURI1);
        return -1;
    }
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_SPNUM, provider->spnumber);

    for (i = 0; i < provider->spnumber; i++) {
        /* Has checked string NULL */
        DEBUG2("rlm_osp: '%s%d' = '%s'", OSP_STR_SPURI, i + 1, provider->spuris[i]);
    }

    for (i = 0; i < provider->spnumber; i++) {
        DEBUG2("rlm_osp: '%s%d' = '%d'", OSP_STR_SPWEIGHT, i + 1, provider->spweights[i]);
    }

    /* If security flag is set, check certificate file names. Otherwise, use default certificates */
    if (provider->security) {
        /* If privatekey is undefined, then fail. */
        if (!OSP_CHECK_STRING(provider->privatekey)) {
            radlog(L_ERR,
                "rlm_osp: '%s' must be defined.",
                OSP_STR_PRIVATEKEY);
            return -1;
        }
        /* Has checked string NULL */
        DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_PRIVATEKEY, provider->privatekey);

        /* If localcert is undefined, then fail. */
        if (!OSP_CHECK_STRING(provider->localcert)) {
            radlog(L_ERR,
                "rlm_osp: '%s' must be defined.",
                OSP_STR_LOCALCERT);
            return -1;
        }
        /* Has checked string NULL */
        DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_LOCALCERT, provider->localcert);

        /* Calculate number of cacerts */
        provider->canumber = 0;
        for (i = 0; i < OSP_CANUM_MAX; i++) {
            if (OSP_CHECK_STRING(provider->cacerts[i]))  {
                provider->canumber++;
            } else {
                break;
            }
        }

        /* If number of cacerts is wrong, then fail. */
        if (provider->canumber == 0) {
            radlog(L_ERR,
                "rlm_osp: '%s' must be defined.",
                OSP_STR_CACERT0);
            return -1;
        }
        DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_CANUM, provider->canumber);

        for (i = 0; i < provider->canumber; i++) {
            /* Has checked string NULL */
            DEBUG2("rlm_osp: '%s%d' = '%s'", OSP_STR_CACERT, i, provider->cacerts[i]);
        }
    }

    /* If SSL life time is wrong, then fail. */
    OSP_CHECK_MIN(OSP_STR_SSLLIFETIME, provider->ssllifetime, OSP_SSLLIFETIME_MIN);

    /* If max number of connections is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_MAXCONN, provider->maxconn, OSP_MAXCONN_MIN, OSP_MAXCONN_MAX);

    /* If persistence is wrong, then fail. */
    OSP_CHECK_MIN(OSP_STR_PERSISTENCE, provider->persistence, OSP_PERSISTENCE_MIN);

    /* If retry delay is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_RETRYDELAY, provider->retrydelay, OSP_RETRYDELAY_MIN, OSP_RETRYDELAY_MAX);

    /* If times of retry is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_RETRYLIMIT, provider->retrylimit, OSP_RETRYLIMIT_MIN, OSP_RETRYLIMIT_MAX);

    /* If timeout is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_TIMEOUT, provider->timeout, OSP_TIMEOUT_MIN, OSP_TIMEOUT_MAX);

    /* Nothing to check for deviceip */
    ip.s_addr = provider->deviceip;
    inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_DEVICEIP, buffer);

    /* Nothing to check for deviceport */
    DEBUG2("rlm_osp: 'deviceport' = '%d'", provider->deviceport);

    DEBUG3("rlm_osp: osp_check_provider success");

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
    osp_string_t buffer;

    DEBUG3("rlm_osp: osp_check_mapping start");

    /* If identity VSA name is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_IDITEM, OSP_DEF_MAY, mapping->iditem);

    /* Nothing to check for identity VSA value */
    if (OSP_CHECK_STRING(mapping->idvalue)) {
        DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_IDVALUE, mapping->idvalue);
    } else {
        DEBUG2("rlm_osp: '%s' = 'NULL'", OSP_STR_IDVALUE);
    }

    /* Nothing to check for reportstart */
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_REPORTSTART, mapping->reportstart);

    /* Nothing to check for reportstop */
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_REPORTSTOP, mapping->reportstop);

    /* Nothing to check for reportinterim */
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_REPORTINTERIM, mapping->reportinterim);

    /* If ignored destination subnet list string is incorrect, then fail. */
    DEBUG3("rlm_osp: parse '%s'", OSP_STR_IGNOREDDESTLIST);
    if (osp_parse_netlist(mapping->ignoreddeststr, &mapping->ignoreddestlist) < 0) {
        return -1;
    }

    /* If RADIUS client type is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_CLIENTTYPE, mapping->clienttype, OSP_CLIENT_MIN, OSP_CLIENT_MAX);

    /* If sub status type is undefined for BroadWorks, then fail. */
    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        OSP_CHECK_ITEMMAP(OSP_STR_SUBTYPE, OSP_DEF_MUST, mapping->subtype);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        break;
    }

    /* If call direction is undefined for GENBAND S3, Cisco and BroadWorks, then fail. */
    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    case OSP_CLIENT_BROADWORKS:
        OSP_CHECK_ITEMMAP(OSP_STR_DIRECTION, OSP_DEF_MUST, mapping->direction);

        /* Nothing to check for ignore inbound */
        DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_IGNOREIN, mapping->ignorein);

        /* Nothing to check for ignore outbound */
        DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_IGNOREOUT, mapping->ignoreout);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }

    /* If transaction ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_TRANSACTIONID, OSP_DEF_MAY, mapping->transid);

    /* If Call-ID is undefined, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLID, OSP_DEF_MUST, mapping->callid);

    /* If calling number format is incorrect, then fail. */
    OSP_CHECK_RANGE(OSP_STR_CALLINGFORMAT, mapping->callingformat, OSP_CALLNUM_MIN, OSP_CALLNUM_MAX);

    /* If called number format is incorrect, then fail. */
    OSP_CHECK_RANGE(OSP_STR_CALLEDFORMAT, mapping->calledformat, OSP_CALLNUM_MIN, OSP_CALLNUM_MAX);

    /* If calling number is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLINGNUMBER, OSP_DEF_MAY, mapping->calling);

    /* If called number is undefined, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLEDNUMBER, OSP_DEF_MUST, mapping->called);

    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
        break;
    case OSP_CLIENT_BROADWORKS:
        /* If transfer result is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_TRANSFERRET, OSP_DEF_MAY, mapping->transferret);

        /* If transfer ID is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_TRANSFERID, OSP_DEF_MAY, mapping->transferid);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        /* Nothing to check for parsetransfer */
        DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_PARSETRANSFER, mapping->parsetransfer);
        if (mapping->parsetransfer) {
            /* If transfer calling number is incorrect, then fail. */
            OSP_CHECK_ITEMMAP(OSP_STR_TRANSFERCALLINGNUM, OSP_DEF_MAY, mapping->transfercalling);

            /* If transfer called number is incorrect, then fail. */
            OSP_CHECK_ITEMMAP(OSP_STR_TRANSFERCALLEDNUM, OSP_DEF_MAY, mapping->transfercalled);

            /* If transfer ID is incorrect, then fail. */
            OSP_CHECK_ITEMMAP(OSP_STR_TRANSFERID, OSP_DEF_MAY, mapping->transferid);
        }
        break;
    }

    /* If asserted ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_ASSERTEDID, OSP_DEF_MAY, mapping->assertedid);

    /* If RPID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_RPID, OSP_DEF_MAY, mapping->rpid);

    /* If source is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_SOURCE, OSP_DEF_MAY, mapping->source);

    /* If proxy is undefined for GENBAND S3, Cisco and BroadWorks, then fail. */
    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    case OSP_CLIENT_BROADWORKS:
        OSP_CHECK_ITEMMAP(OSP_STR_PROXY, OSP_DEF_MUST, mapping->proxy);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }

    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        /* If access device is undefined, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_ACCESSDEVICE, OSP_DEF_MUST, mapping->accessdev);

        /* If route device is undefined, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_ROUTEDEVICE, OSP_DEF_MUST, mapping->routedev);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        /* If source device is undefined, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_SRCDEVICE, OSP_DEF_MUST, mapping->srcdev);

        /* If destination is undefined, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_DESTINATION, OSP_DEF_MUST, mapping->destination);
        break;
    }

    /* If destination device is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DESTDEVICE, OSP_DEF_MAY, mapping->destdev);

    /* If destination count is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DESTCOUNT, OSP_DEF_MAY, mapping->destcount);

    /* If source network ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_SRCNETWORKID, OSP_DEF_MAY, mapping->srcnid);

    /* If destination network ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DESTNETWORKID, OSP_DEF_MAY, mapping->destnid);

    /* If diversion user is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DIVERSIONUSER, OSP_DEF_MAY, mapping->divuser);

    /* If diversion host is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DIVERSIONHOST, OSP_DEF_MAY, mapping->divhost);

    /* If time string format is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_TIMEFORMAT, mapping->timeformat, OSP_TIMESTR_MIN, OSP_TIMESTR_MAX);

    /* If call start time is undefined, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_STARTTIME, OSP_DEF_MUST, mapping->start);

    /* If call alert time is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_ALERTTIME, OSP_DEF_MAY, mapping->alert);

    /* If call connect time is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CONNECTTIME, OSP_DEF_MAY, mapping->connect);

    /* If call end time is undefined, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_ENDTIME, OSP_DEF_MUST, mapping->end);

    /* If call duration is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DURATION, OSP_DEF_MAY, mapping->duration);

    /* If pdd unit is wrong, then fail. */
    OSP_CHECK_RANGE(OSP_STR_PDDUNIT, mapping->pddunit, OSP_TIMEUNIT_MIN, OSP_TIMEUNIT_MAX);

    /* If pdd is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_PDD, OSP_DEF_MAY, mapping->pdd);

    /* If release source is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_RELEASE, OSP_DEF_MAY, mapping->release);

    /* If Q850 release cause is undefined, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_Q850CAUSE, OSP_DEF_MUST, mapping->q850cause);

    /* If SIP release cause is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_SIPCAUSE, OSP_DEF_MAY, mapping->sipcause);

    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    case OSP_CLIENT_BROADWORKS:
        /* If source protocol is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_SRCPROTOCOL, OSP_DEF_MAY, mapping->srcprotocol);

        /* If destination protocol is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_DESTPROTOCOL, OSP_DEF_MAY, mapping->destprotocol);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        /* If signaling protocol is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_PROTOCOL, OSP_DEF_MAY, mapping->protocol);
        break;
    }

    /* If source session ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_SRCSESSIONID, OSP_DEF_MAY, mapping->srcsessionid);

    /* If destination session ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DESTSESSIONID, OSP_DEF_MAY, mapping->destsessionid);

    /* If correlation session ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CORRSESSIONID, OSP_DEF_MAY, mapping->corrsessionid);

    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        /* If access call ID is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_ACCESSCALLID, OSP_DEF_MAY, mapping->accesscallid);

        /* If route call ID is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_ROUTECALLID, OSP_DEF_MAY, mapping->routecallid);

        /* If local call ID is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_LOCALCALLID, OSP_DEF_MAY, mapping->localcallid);

        /* If remote call ID is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_REMOTECALLID, OSP_DEF_MAY, mapping->remotecallid);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        break;
    }

    /* If source codec is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_SRCCODEC, OSP_DEF_MAY, mapping->srccodec);

    /* If destination codec is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DESTCODEC, OSP_DEF_MAY, mapping->destcodec);

    /* If conference ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CONFID, OSP_DEF_MAY, mapping->confid);

    /* If user-defined info are incorrect, then fail. */
    for (i = 0; i < OSP_CUSTOMINFO_MAX; i++) {
        snprintf(buffer, sizeof(buffer), "%s%d", OSP_STR_CUSTOMINFO, i + 1);
        OSP_CHECK_ITEMMAP(buffer, OSP_DEF_MAY, mapping->custinfo[i]);
    }

    /* If source realm is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_SRCREALM, OSP_DEF_MAY, mapping->srcrealm);

    /* If destination realm is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_DESTREALM, OSP_DEF_MAY, mapping->destrealm);

    /* If other party info is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_OTHERPARTY, OSP_DEF_MAY, mapping->otherparty);

    /* If calling party user name is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLINGUSERNAME, OSP_DEF_MAY, mapping->callingusername);

    /* If calling party user ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLINGUSERID, OSP_DEF_MAY, mapping->callinguserid);

    /* If calling party user group is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLINGUSERGROUP, OSP_DEF_MAY, mapping->callingusergroup);

    /* If called party user name is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLEDUSERNAME, OSP_DEF_MAY, mapping->calledusername);

    /* If called party user ID is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLEDUSERID, OSP_DEF_MAY, mapping->calleduserid);

    /* If called party user group is incorrect, then fail. */
    OSP_CHECK_ITEMMAP(OSP_STR_CALLEDUSERGROUP, OSP_DEF_MAY, mapping->calledusergroup);

    /* If statistics are incorrect, then fail. */
    if (osp_check_statsmap(&mapping->stats) < 0) {
        return -1;
    }

    DEBUG3("rlm_osp: osp_check_mapping success");

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
    osp_string_t listbuf;
    osp_string_t buffer;
    struct in_addr ip;
    char* subnet;
    char* tmplist;
    char* ipstr;
    char* tmpnet;
    int i;

    DEBUG3("rlm_osp: osp_parse_netlist start");

    if (liststr) {
        strncpy(listbuf, liststr, OSP_STRBUF_SIZE);
        for (i = 0, subnet = strtok_r(listbuf, OSP_LIST_DELIMITER, &tmplist);
            (i < OSP_SUBNET_MAX) && subnet;
            i++, subnet = strtok_r(NULL, OSP_LIST_DELIMITER, &tmplist))
        {
            if (((ipstr = strtok_r(subnet, OSP_NET_DELIMITER, &tmpnet)) == NULL) || (inet_pton(AF_INET, ipstr, &ip) != 1)) {
                DEBUG("rlm_osp: failed to parse IP address from '%s'.", subnet);
                break;
            } else {
                list->subnet[i].ip = ip.s_addr;
                inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
                DEBUG2("rlm_osp: subnet[%d] ip = '%s'", i, buffer);

                if (((ipstr = strtok_r(NULL, OSP_NET_DELIMITER, &tmpnet)) == NULL) || (inet_pton(AF_INET, ipstr, &ip) != 1)) {
                    ip.s_addr = OSP_NETMASK_DEF;
                }
                list->subnet[i].mask = ip.s_addr;
                inet_ntop(AF_INET, &ip, buffer, sizeof(buffer));
                DEBUG2("rlm_osp: subnet[%d] mask = '%s'", i, buffer);
            }
        }
        list->number = i;
    } else {
        list->number = 0;
    }

    DEBUG3("rlm_osp: osp_parse_netlist success");

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
    DEBUG3("rlm_osp: osp_check_statsmap start");

    /* Nothing to check for reportstatistics */
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_REPORTSTATS, stats->reportstats);

    if (stats->reportstats) {
        /* If lost send packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_SLOSTPACKETS, OSP_DEF_MAY, stats->slost.pack);

        /* If lost send packet fraction is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_SLOSTFRACTION, OSP_DEF_MAY, stats->slost.fract);

        /* If lost receive packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RLOSTPACKETS, OSP_DEF_MAY, stats->rlost.pack);

        /* If lost receive packet fraction is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RLOSTFRACTION, OSP_DEF_MAY, stats->rlost.fract);

        /* If RTP source-to-reporter octets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPSRCREPOCTETS, OSP_DEF_MAY, stats->rtp_src_rep_octets);

        /* If RTP destination-to-reporter octets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPDESTREPOCTETS, OSP_DEF_MAY, stats->rtp_dest_rep_octets);

        /* If RTP source-to-reporter packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPSRCREPPACKETS, OSP_DEF_MAY, stats->rtp_src_rep_packets);

        /* If RTP destination-to-reporter packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPDESTREPPACKETS, OSP_DEF_MAY, stats->rtp_dest_rep_packets);

        /* If RTP source-to-reporter lost packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPSRCREPLOST, OSP_DEF_MAY, stats->rtp_src_rep_lost);

        /* If RTP destination-to-reporter lost packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPDESTREPLOST, OSP_DEF_MAY, stats->rtp_dest_rep_lost);

        /* If RTP source-to-reporter jitter mean is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPSRCREPJITTERMEAN, OSP_DEF_MAY, stats->rtp_src_rep_jitter_mean);

        /* If RTP destination-to-reporter jitter mean is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPDESTREPJITTERMEAN, OSP_DEF_MAY, stats->rtp_dest_rep_jitter_mean);

        /* If RTP source-to-reporter jitter max is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPSRCREPJITTERMAX, OSP_DEF_MAY, stats->rtp_src_rep_jitter_max);

        /* If RTP destination-to-reporter jitter max is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTPDESTREPJITTERMAX, OSP_DEF_MAY, stats->rtp_dest_rep_jitter_max);

        /* If RTCP source-to-destination lost packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPSRCDESTLOST, OSP_DEF_MAY, stats->rtcp_src_dest_lost);

        /* If RTCP destination-to-source lost packets is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPDESTSRCLOST, OSP_DEF_MAY, stats->rtcp_dest_src_lost);

        /* If RTCP source-to-destination jitter mean is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPSRCDESTJITTERMEAN, OSP_DEF_MAY, stats->rtcp_src_dest_jitter_mean);

        /* If RTCP destination-to-source jitter mean is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPDESTSRCJITTERMEAN, OSP_DEF_MAY, stats->rtcp_dest_src_jitter_mean);

        /* If RTCP source-to-destination jitter max is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPSRCDESTJITTERMAX, OSP_DEF_MAY, stats->rtcp_src_dest_jitter_max);

        /* If RTCP destination-to-source jitter max is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPDESTSRCJITTERMAX, OSP_DEF_MAY, stats->rtcp_dest_src_jitter_max);

        /* If RTCP source round trip delay mean is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPSRCRTDELAYMEAN, OSP_DEF_MAY, stats->rtcp_src_rtdelay_mean);

        /* If RTCP destination round trip delay mean is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPDESTRTDELAYMEAN, OSP_DEF_MAY, stats->rtcp_dest_rtdelay_mean);

        /* If RTCP source round trip delay max is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPSRCRTDELAYMAX, OSP_DEF_MAY, stats->rtcp_src_rtdelay_max);

        /* If RTCP destination round trip delay max is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_RTCPDESTRTDELAYMAX, OSP_DEF_MAY, stats->rtcp_dest_rtdelay_max);

        /* If R-Factor scale index is wrong, then fail. */
        OSP_CHECK_RANGE(OSP_STR_RFACTORSCALE, stats->rfactorscale, OSP_SCALE_MIN, OSP_SCALE_MAX);

        /* If source-to-reporter R-Factor is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_SRCREPRFACTOR, OSP_DEF_MAY, stats->src_rep_rfactor);

        /* If destiantion-to-reporter R-Factor is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_DESTREPRFACTOR, OSP_DEF_MAY, stats->dest_rep_rfactor);

        /* If MOS scale index is wrong, then fail. */
        OSP_CHECK_RANGE(OSP_STR_MOSSCALE, stats->mosscale, OSP_SCALE_MIN, OSP_SCALE_MAX);

        /* If source-to-reporter MOS is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_SRCREPMOS, OSP_DEF_MAY, stats->src_rep_mos);

        /* If destination-to-reporter MOS is incorrect, then fail. */
        OSP_CHECK_ITEMMAP(OSP_STR_DESTREPMOS, OSP_DEF_MAY, stats->dest_rep_mos);
    }

    DEBUG3("rlm_osp: osp_check_statsmap success");

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
    osp_deflevel_e level)
{
    int last;

    DEBUG3("rlm_osp: osp_check_itemmap start");

    if (!OSP_CHECK_STRING(item)) {
        if (level == OSP_DEF_MUST) {
            radlog(L_ERR, "rlm_osp: Failed to check mapping item.");
            return -1;
        } else {
            DEBUG3("rlm_osp: osp_check_itemmap success");
            return 0;
        }
    }

    last = strlen(item) - 1;

    if ((*item != '%') || (item[1] != '{') || (item[last] != '}') || (last == 2)) {
        radlog(L_ERR,
            "rlm_osp: Failed to check mapping item '%s'.",
            item);
        return -1;
    }

    DEBUG3("rlm_osp: osp_check_itemmap success");

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
    unsigned long spweights[OSP_SPNUM_MAX];
    OSPTPRIVATEKEY privatekey;
    OSPT_CERT localcert;
    OSPT_CERT cacerts[OSP_CANUM_MAX];
    const OSPT_CERT* pcacerts[OSP_CANUM_MAX];
    unsigned char privatekeydata[OSP_KEYBUF_SIZE];
    unsigned char localcertdata[OSP_KEYBUF_SIZE];
    unsigned char cacertdata[OSP_KEYBUF_SIZE];

    DEBUG3("rlm_osp: osp_create_provider start");

    /* Initialize OSP */
    if (instance_count == 0) {
        if ((error = OSPPInit(provider->accelerate)) != OSPC_ERR_NO_ERROR) {
            radlog(L_ERR,
                "Failed to initialize OSP, error '%d'.",
                error);
            return -1;
        }
    }

    /* Copy service point weights to a temporary buffer to avoid compile warning */
    for (i = 0; i < provider->spnumber; i++) {
        spweights[i] = provider->spweights[i];
    }

    if (provider->security) {
        privatekey.PrivateKeyData = NULL;
        privatekey.PrivateKeyLength = 0;

        localcert.CertData = NULL;
        localcert.CertDataLength = 0;

        for (i = 0; i < provider->canumber; i++) {
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
            for (i = 0; i < provider->canumber; i++) {
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

        provider->canumber = 1;
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
            provider->spnumber,             /* Number of service points */
            (const char**)provider->spuris, /* Service point URIs */
            spweights,                      /* Service point weights */
            OSP_AUDITURL_DEF,               /* Audit URL */
            &privatekey,                    /* Private key */
            &localcert,                     /* Local cert */
            provider->canumber,             /* Number of cacerts */
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
        } else {
            DEBUG3("rlm_osp: osp_create_provider success");
            instance_count++;
            result = 0;
        }
    }

    if (error != OSPC_ERR_NO_ERROR) {
        if (instance_count == 0) {
            OSPPCleanup();
        }
    }

    if (provider->security) {
        /* Release temporary key buffers */
        for (i = 0; i < provider->canumber; i++) {
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
    int type;
    rlm_osp_t* data = (rlm_osp_t*)instance;
    osp_running_t* running = &data->running;
    osp_provider_t* provider = &data->provider;
    osp_mapping_t* mapping = &data->mapping;
    OSPTTRANHANDLE transaction;
    OSPE_ROLE_STATE rolestate;
    OSPE_ROLE_VENDOR rolevendor;
    OSPT_CALL_ID* sessionid;
    osp_usage_t usage;
    const int MAX_RETRIES = 5;
    char buffer[OSP_LOGBUF_SIZE];
    int i, error;

    DEBUG3("rlm_osp: osp_accounting start");

    if (OSP_CHECK_STRING(mapping->iditem)) {
        OSP_GET_STRING(request, TRUE, OSP_STR_IDITEM, OSP_DEF_MAY, mapping->iditem, buffer);
        if ((buffer[0] == '\0') ||
            (OSP_CHECK_STRING(mapping->idvalue) && strcasecmp(mapping->idvalue, buffer)))
        {
            DEBUG2("rlm_osp: nothing to do for this request.");
            return RLM_MODULE_NOOP;
        }
    }

    if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) == NULL) {
        DEBUG("rlm_osp: failed to get accounting status type.");
        return RLM_MODULE_NOOP;
    }

    type = vp->vp_integer;
    switch (type) {
    case PW_STATUS_START:
        rolestate = OSPC_RSTATE_START;
        if (!mapping->reportstart) {
            DEBUG2("rlm_osp: nothing to do for Start request.");
            return RLM_MODULE_NOOP;
        }
        break;
    case PW_STATUS_STOP:
        rolestate = OSPC_RSTATE_STOP;
        if (!mapping->reportstop) {
            DEBUG2("rlm_osp: nothing to do for Stop request.");
            return RLM_MODULE_NOOP;
        }
        break;
    case PW_STATUS_ALIVE:   /* Interim-Update */
        rolestate = OSPC_RSTATE_INTERIM;
        if (!mapping->reportinterim) {
            DEBUG2("rlm_osp: nothing to do for Interim-Update request.");
            return RLM_MODULE_NOOP;
        }
        break;
    default:
        DEBUG2("rlm_osp: nothing to do for request type '%d'.", type);
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
            radlog(L_INFO, "rlm_osp: Inore record.");
            break;
        case OSP_LOG_LONG:
        default:
            radius_xlat(buffer, sizeof(buffer), "%Z", request, NULL);
            /* Do not have to check string NULL */
            radlog(L_INFO,
                "rlm_osp: ignore record '%s'.",
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
        OSPC_ROLE_SOURCE,       /* Usage type */
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

    switch (mapping->clienttype) {
    case OSP_CLIENT_ACME:
        rolevendor = OSPC_RVENDOR_ACME;
        break;
    case OSP_CLIENT_GENBANDS3:
        if (usage.direction == OSP_DIRECTION_IN) {
            switch (type) {
            case PW_STATUS_START:
                rolestate = OSPC_RSTATE_START1;
                break;
            case PW_STATUS_ALIVE:   /* Interim-Update */
                rolestate = OSPC_RSTATE_INTERIM1;
                break;
            case PW_STATUS_STOP:
            default:
                rolestate = OSPC_RSTATE_STOP1;
                break;
            }
        } else {
            switch (type) {
            case PW_STATUS_START:
                rolestate = OSPC_RSTATE_START2;
                break;
            case PW_STATUS_ALIVE:   /* Interim-Update */
                rolestate = OSPC_RSTATE_INTERIM2;
                break;
            case PW_STATUS_STOP:
            default:
                rolestate = OSPC_RSTATE_STOP2;
                break;
            }
        }
        rolevendor = OSPC_RVENDOR_GENBANDS3;
        break;
    case OSP_CLIENT_BROADWORKS:
        if (usage.direction == OSP_DIRECTION_IN) {
            switch (type) {
            case PW_STATUS_START:
                rolestate = OSPC_RSTATE_START1;
                break;
            case PW_STATUS_ALIVE:   /* Interim-Update */
                rolestate = OSPC_RSTATE_INTERIM1;
                break;
            case PW_STATUS_STOP:
            default:
                rolestate = OSPC_RSTATE_STOP1;
                break;
            }
        } else {
            switch (type) {
            case PW_STATUS_START:
                rolestate = OSPC_RSTATE_START2;
                break;
            case PW_STATUS_ALIVE:   /* Interim-Update */
                rolestate = OSPC_RSTATE_INTERIM2;
                break;
            case PW_STATUS_STOP:
            default:
                rolestate = OSPC_RSTATE_STOP2;
                break;
            }
        }
        rolevendor = OSPC_RVENDOR_BROADWORKS;
        break;
    default:
        rolevendor = OSPC_RVENDOR_UNDEFINED;
        break;
    }

    /* Report role info */
    OSPPTransactionSetRoleInfo(
        transaction,
        rolestate,
        OSPC_RFORMAT_RADIUS,
        rolevendor);

    /* Report destination count */
    if (usage.destcount != OSP_DESTCOUNT_DEF) {
        OSPPTransactionSetDestinationCount(
            transaction,
            usage.destcount);
    }

    /* Report source network ID */
    OSPPTransactionSetSrcNetworkId(
        transaction,
        usage.srcnid);

    /* Report destination network ID */
    OSPPTransactionSetDestNetworkId(
        transaction,
        usage.destnid);

    /* Report diversion */
    OSPPTransactionSetDiversion(
        transaction,
        usage.divuser,
        usage.divhost);

    /* Report asserted ID */
    OSPPTransactionSetAssertedId(
        transaction,        /* Transaction handle */
        OSPC_NFORMAT_E164,  /* Format */
        usage.assertedid);  /* Asserted ID */

    /* Report RPID */
    OSPPTransactionSetRemotePartyId(
        transaction,        /* Transaction handle */
        OSPC_NFORMAT_E164,  /* Format */
        usage.rpid);        /* RPID */

    /* Report user-defined info */
    for (i = 0; i < OSP_CUSTOMINFO_MAX; i++) {
        if (OSP_CHECK_STRING(usage.custinfo[i])) {
            OSPPTransactionSetCustomInfo(
                transaction,        /* Transaction handle */
                i,                  /* Index */
                usage.custinfo[i]); /* User-defined info */
        }
    }

    /* Report source realm */
    OSPPTransactionSetSrcRealm(
        transaction,        /* Transaction handle */
        usage.srcrealm);    /* Source realm */

    /* Report destination realm */
    OSPPTransactionSetDestRealm(
        transaction,        /* Transaction handle */
        usage.destrealm);   /* Destination realm */

    /* Report calling party info */
    OSPPTransactionSetCallPartyInfo(
        transaction,                /* Transaction handle */
        OSPC_CPARTY_SOURCE,         /* Calling party */
        usage.callingusername,      /* Calling party user name */
        usage.callinguserid,        /* Calling party user ID */
        usage.callingusergroup);    /* Calling party user group */

    /* Report called party info */
    OSPPTransactionSetCallPartyInfo(
        transaction,                /* Transaction handle */
        OSPC_CPARTY_DESTINATION,    /* Called party */
        usage.calledusername,       /* Called party user name */
        usage.calleduserid,         /* Called party user ID */
        usage.calledusergroup);     /* Called party user group */

    /* Report Q850 release code */
    if (usage.q850cause != OSP_CAUSE_UNKNOWN) {
        OSPPTransactionSetTermCause(
            transaction,        /* Transaction handle */
            OSPC_TCAUSE_Q850,   /* Q850 */
            usage.q850cause,    /* Release reason */
            NULL);              /* Description */
    }

    /* Report SIP release code */
    if (usage.sipcause != OSP_CAUSE_UNKNOWN) {
        OSPPTransactionSetTermCause(
            transaction,        /* Transaction handle */
            OSPC_TCAUSE_SIP,    /* SIP */
            usage.sipcause,     /* Release reason */
            NULL);              /* Description */
    }

    /* Report signaling protocol */
    OSPPTransactionSetProtocol(
        transaction,        /* Transaction handle */
        OSPC_PROTTYPE_NA,   /* Protocol type */
        usage.protocol);    /* Protocol name */

    /* Report source protocol */
    OSPPTransactionSetProtocol(
        transaction,            /* Transaction handle */
        OSPC_PROTTYPE_SOURCE,   /* Protocol type */
        usage.srcprotocol);     /* Protocol name */

    /* Report destination protocol */
    OSPPTransactionSetProtocol(
        transaction,                /* Transaction handle */
        OSPC_PROTTYPE_DESTINATION,  /* Protocol type */
        usage.destprotocol);        /* Protocol name */

    /* Report source session ID */
    if (usage.srcsessionid[0] != '\0') {
        sessionid = OSPPCallIdNew(strlen(usage.srcsessionid), (const unsigned char *)usage.srcsessionid);
        if (sessionid != NULL) {
            OSPPTransactionSetSessionId(
                transaction,            /* Transaction handle */
                OSPC_SESSIONID_SOURCE,  /* Source */
                sessionid);             /* Source session ID */
            OSPPCallIdDelete(&sessionid);
        }
    }

    /* Report destination session ID */
    if (usage.destsessionid[0] != '\0') {
        sessionid = OSPPCallIdNew(strlen(usage.destsessionid), (const unsigned char *)usage.destsessionid);
        if (sessionid != NULL) {
            OSPPTransactionSetSessionId(
                transaction,                /* Transaction handle */
                OSPC_SESSIONID_DESTINATION, /* Destiantion */
                sessionid);                 /* Destination session ID */
            OSPPCallIdDelete(&sessionid);
        }
    }

    /* Report correlation session ID */
    if (usage.corrsessionid[0] != '\0') {
        sessionid = OSPPCallIdNew(strlen(usage.corrsessionid), (const unsigned char *)usage.corrsessionid);
        if (sessionid != NULL) {
            OSPPTransactionSetSessionId(
                transaction,                /* Transaction handle */
                OSPC_SESSIONID_CORRELATION, /* Correlation */
                sessionid);                 /* Correlation session ID */
            OSPPCallIdDelete(&sessionid);
        }
    }

    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        /* Report local call ID */
        if (usage.localcallid[0] != '\0') {
            sessionid = OSPPCallIdNew(strlen(usage.localcallid), (const unsigned char *)usage.localcallid);
            if (sessionid != NULL) {
                OSPPTransactionSetSessionId(
                    transaction,                /* Transaction handle */
                    OSPC_SESSIONID_LOCAL,       /* Local */
                    sessionid);                 /* Local session ID */
                OSPPCallIdDelete(&sessionid);
            }
        }
    
        /* Report remote call ID */
        if (usage.remotecallid[0] != '\0') {
            sessionid = OSPPCallIdNew(strlen(usage.remotecallid), (const unsigned char *)usage.remotecallid);
            if (sessionid != NULL) {
                OSPPTransactionSetSessionId(
                    transaction,                /* Transaction handle */
                    OSPC_SESSIONID_REMOTE,      /* Remote */
                    sessionid);                 /* Remote session ID */
                OSPPCallIdDelete(&sessionid);
            }
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        break;
    }

    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
        break;
    case OSP_CLIENT_BROADWORKS:
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        /* Report transfer ID */
        OSPPTransactionSetTransferId(
            transaction,        /* Transaction handle */
            usage.transferid);  /* Transfer ID */

        /* Report transfer status */
        OSPPTransactionSetTransferStatus(
            transaction,        /* Transaction handle */
            usage.transfer);    /* Transfer status */
        break;
    }

    /* Report source codec */
    OSPPTransactionSetCodec(
        transaction,        /* Transaction handle */
        OSPC_CODEC_SOURCE,  /* Source */
        usage.srccodec);    /* Source codec */

    /* Report destination codec */
    OSPPTransactionSetCodec(
        transaction,            /* Transaction handle */
        OSPC_CODEC_DESTINATION, /* Destination */
        usage.destcodec);       /* Destination codec */

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
        DEBUG3("rlm_osp: osp_accounting success");
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
    DEBUG3("rlm_osp: osp_report_statsinfo start");

    if (mapping->reportstats) {
        /* Report RTP source-to-reporter octets */
        if (stats->rtp_src_rep_octets != OSP_STATSINT_DEF) {
            OSPPTransactionSetOctets(
                transaction,                /* Transaction handle */
                OSPC_SMETRIC_RTP,           /* Metric */
                OSPC_SDIR_SRCREP,           /* Direction */
                stats->rtp_src_rep_octets); /* Octets */
        }

        /* Report RTP destiantion-to-reporter octets */
        if (stats->rtp_dest_rep_octets != OSP_STATSINT_DEF) {
            OSPPTransactionSetOctets(
                transaction,                    /* Transaction handle */
                OSPC_SMETRIC_RTP,               /* Metric */
                OSPC_SDIR_DESTREP,              /* Direction */
                stats->rtp_dest_rep_octets);    /* Octets */
        }

        /* Report RTP source-to-reporter packets */
        if (stats->rtp_src_rep_packets != OSP_STATSINT_DEF) {
            OSPPTransactionSetPackets(
                transaction,                    /* Transaction handle */
                OSPC_SMETRIC_RTP,               /* Metric */
                OSPC_SDIR_SRCREP,               /* Direction */
                stats->rtp_src_rep_packets);    /* Packets */
        }

        /* Report RTP destination-to-reporter packets */
        if (stats->rtp_dest_rep_packets != OSP_STATSINT_DEF) {
            OSPPTransactionSetPackets(
                transaction,                    /* Transaction handle */
                OSPC_SMETRIC_RTP,               /* Metric */
                OSPC_SDIR_DESTREP,              /* Direction */
                stats->rtp_dest_rep_packets);   /* Packets */
        }

        /* Report RTP source-to-reporter lost packets */
        if (stats->rtp_src_rep_lost != OSP_STATSINT_DEF) {
            OSPPTransactionSetLost(
                transaction,                /* Transaction handle */
                OSPC_SMETRIC_RTP,           /* Metric */
                OSPC_SDIR_SRCREP,           /* Direction */
                stats->rtp_src_rep_lost,    /* Packets lost packets */
                OSP_STATSINT_DEF);          /* Packets lost fraction */
        }

        /* Report RTP destination-to-reporter lost packets */
        if (stats->rtp_dest_rep_lost != OSP_STATSINT_DEF) {
            OSPPTransactionSetLost(
                transaction,                /* Transaction handle */
                OSPC_SMETRIC_RTP,           /* Metric */
                OSPC_SDIR_DESTREP,          /* Direction */
                stats->rtp_dest_rep_lost,   /* Packets lost packets */
                OSP_STATSINT_DEF);          /* Packets lost fraction */
        }

        /* Report RTP source-to-reporter jitter mean and max */
        if ((stats->rtp_src_rep_jitter_mean != OSP_STATSINT_DEF) ||
            (stats->rtp_src_rep_jitter_max != OSP_STATSINT_DEF))
        {
            OSPPTransactionSetJitter(
                transaction,                    /* Transaction handle */
                OSPC_SMETRIC_RTP,               /* Metric */
                OSPC_SDIR_SRCREP,               /* Direction */
                OSP_STATSINT_DEF,               /* Jitter samples */
                OSP_STATSINT_DEF,               /* Jitter minimum */
                stats->rtp_src_rep_jitter_max,  /* Jitter maximum */
                stats->rtp_src_rep_jitter_mean, /* Jitter mean */
                OSP_STATSFLOAT_DEF);            /* Jitter variance */
        }

        /* Report RTP destination-to-reporter jitter mean and max */
        if ((stats->rtp_dest_rep_jitter_mean != OSP_STATSINT_DEF) ||
            (stats->rtp_dest_rep_jitter_max != OSP_STATSINT_DEF))
        {
            OSPPTransactionSetJitter(
                transaction,                        /* Transaction handle */
                OSPC_SMETRIC_RTP,                   /* Metric */
                OSPC_SDIR_DESTREP,                  /* Direction */
                OSP_STATSINT_DEF,                   /* Jitter samples */
                OSP_STATSINT_DEF,                   /* Jitter minimum */
                stats->rtp_dest_rep_jitter_max,     /* Jitter maximum */
                stats->rtp_dest_rep_jitter_mean,    /* Jitter mean */
                OSP_STATSFLOAT_DEF);                /* Jitter variance */
        }

        /* Report RTCP source-to-destination lost packets */
        if (stats->rtcp_src_dest_lost != OSP_STATSINT_DEF) {
            OSPPTransactionSetLost(
                transaction,                /* Transaction handle */
                OSPC_SMETRIC_RTCP,          /* Metric */
                OSPC_SDIR_SRCDEST,          /* Direction */
                stats->rtcp_src_dest_lost,  /* Packets lost packets */
                OSP_STATSINT_DEF);          /* Packets lost fraction */
        }

        /* Report RTCP destination-to-source lost packets */
        if (stats->rtcp_dest_src_lost != OSP_STATSINT_DEF) {
            OSPPTransactionSetLost(
                transaction,                /* Transaction handle */
                OSPC_SMETRIC_RTCP,          /* Metric */
                OSPC_SDIR_DESTSRC,          /* Direction */
                stats->rtcp_dest_src_lost,  /* Packets lost packets */
                OSP_STATSINT_DEF);          /* Packets lost fraction */
        }


        /* Report RTCP source-to-destination jitter mean and max */
        if ((stats->rtcp_src_dest_jitter_mean != OSP_STATSINT_DEF) ||
            (stats->rtcp_src_dest_jitter_max != OSP_STATSINT_DEF))
        {
            OSPPTransactionSetJitter(
                transaction,                        /* Transaction handle */
                OSPC_SMETRIC_RTCP,                  /* Metric */
                OSPC_SDIR_SRCDEST,                  /* Direction */
                OSP_STATSINT_DEF,                   /* Jitter samples */
                OSP_STATSINT_DEF,                   /* Jitter minimum */
                stats->rtcp_src_dest_jitter_max,    /* Jitter maximum */
                stats->rtcp_src_dest_jitter_mean,   /* Jitter mean */
                OSP_STATSFLOAT_DEF);                /* Jitter variance */
        }

        /* Report RTCP destination-to-source jitter mean and max */
        if ((stats->rtcp_dest_src_jitter_mean != OSP_STATSINT_DEF) ||
            (stats->rtcp_dest_src_jitter_max != OSP_STATSINT_DEF))
        {
            OSPPTransactionSetJitter(
                transaction,                        /* Transaction handle */
                OSPC_SMETRIC_RTCP,                  /* Metric */
                OSPC_SDIR_DESTSRC,                  /* Direction */
                OSP_STATSINT_DEF,                   /* Jitter samples */
                OSP_STATSINT_DEF,                   /* Jitter minimum */
                stats->rtcp_dest_src_jitter_max,    /* Jitter maximum */
                stats->rtcp_dest_src_jitter_mean,   /* Jitter mean */
                OSP_STATSFLOAT_DEF);                /* Jitter variance */
        }

        /* Report RTCP source round trip delay */
        if ((stats->rtcp_src_rtdelay_mean != OSP_STATSINT_DEF) ||
            (stats->rtcp_src_rtdelay_max != OSP_STATSINT_DEF))
        {
            OSPPTransactionSetRTDelay(
                transaction,                    /* Transaction handle */
                OSPC_SMETRIC_RTCP,              /* Metric */
                OSPC_SLEG_SOURCE,               /* Session leg */
                OSP_STATSINT_DEF,               /* Round trip delay samples */
                OSP_STATSINT_DEF,               /* Round trip delay minimum */
                stats->rtcp_src_rtdelay_max,    /* Round trip delay maximum */
                stats->rtcp_src_rtdelay_mean,   /* Round trip delay mean */
                OSP_STATSFLOAT_DEF);            /* Round trip delay variance */
        }

        /* Report RTCP destination round trip delay */
        if ((stats->rtcp_dest_rtdelay_mean != OSP_STATSINT_DEF) ||
            (stats->rtcp_dest_rtdelay_max != OSP_STATSINT_DEF))
        {
            OSPPTransactionSetRTDelay(
                transaction,                    /* Transaction handle */
                OSPC_SMETRIC_RTCP,              /* Metric */
                OSPC_SLEG_DESTINATION,          /* Session leg */
                OSP_STATSINT_DEF,               /* Round trip delay samples */
                OSP_STATSINT_DEF,               /* Round trip delay minimum */
                stats->rtcp_dest_rtdelay_max,   /* Round trip delay maximum */
                stats->rtcp_dest_rtdelay_mean,  /* Round trip delay mean */
                OSP_STATSFLOAT_DEF);            /* Round trip delay variance */
        }

        /* Report source-to_reporter R-Factor */
        if (stats->src_rep_rfactor != OSP_STATSFLOAT_DEF) {
            OSPPTransactionSetRFactor(
                transaction,                /* Transaction handle */
                OSPC_SDIR_SRCREP,           /* Direction */
                stats->src_rep_rfactor);    /* R-Factor */
        }

        /* Report destination-to_reporter R-Factor */
        if (stats->dest_rep_rfactor != OSP_STATSFLOAT_DEF) {
            OSPPTransactionSetRFactor(
                transaction,                /* Transaction handle */
                OSPC_SDIR_DESTREP,          /* Direction */
                stats->dest_rep_rfactor);   /* R-Factor */
        }

        /* Report source-to_reporter MOS */
        if (stats->src_rep_mos != OSP_STATSFLOAT_DEF) {
            OSPPTransactionSetMOSLQ(
                transaction,            /* Transaction handle */
                OSPC_SDIR_SRCREP,       /* Direction */
                stats->src_rep_mos);    /* MOS */
        }

        /* Report destination-to_reporter MOS */
        if (stats->dest_rep_mos != OSP_STATSFLOAT_DEF) {
            OSPPTransactionSetMOSLQ(
                transaction,            /* Transaction handle */
                OSPC_SDIR_DESTREP,      /* Direction */
                stats->dest_rep_mos);   /* MOS */
        }
    }

    DEBUG3("rlm_osp: osp_report_statsinfo success");
}

/*
 * Get usage from accounting request
 *
 * param data Instance data
 * param request Accounting request
 * param type RADIUS record type
 * param usage OSP usage info
 * return 0 success, 1 ignore record, -1 failure
 */
static int osp_get_usageinfo(
    rlm_osp_t* data,
    REQUEST* request,
    int type,
    osp_usage_t* usage)
{
    osp_running_t* running = &data->running;
    osp_provider_t* provider = &data->provider;
    osp_mapping_t* mapping = &data->mapping;
    osp_string_t buffer;
    osp_string_t tmphost;
    osp_string_t desthost;
    osp_string_t proxy;
    char* ptr;
    char* transferflagname = "transferflag";
    char* transferflagmap = "%{Acme-Primary-Routing-Number}";
    int transferred, parse, size, i;
    osp_intstr_e format;
    int release;
    struct in_addr dest;

    DEBUG3("rlm_osp: osp_get_usageinfo start");

    memset(usage, 0, sizeof(*usage));
    usage->transfer = OSPC_TSTATUS_UNKNOWN;

    /* Get call direction */
    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
        OSP_GET_STRING(request, TRUE, OSP_STR_DIRECTION, OSP_DEF_MUST, mapping->direction, buffer);
        if (!strcasecmp(buffer, OSP_CISCOCALL_IN)) {
            usage->direction = OSP_DIRECTION_IN;
        } else {
            usage->direction = OSP_DIRECTION_OUT;
        }
        DEBUG2("rlm_osp: call direction = '%d'", usage->direction);

        if (((usage->direction == OSP_DIRECTION_IN) && (mapping->ignorein)) ||
            ((usage->direction == OSP_DIRECTION_OUT) && (mapping->ignoreout)))
        {
            DEBUG2("rlm_osp: ignore '%s' record.", buffer);
            return 1;
        }
        break;
    case OSP_CLIENT_BROADWORKS:
        OSP_GET_STRING(request, TRUE, OSP_STR_SUBTYPE, OSP_DEF_MUST, mapping->subtype, usage->subtype);
        DEBUG2("rlm_osp: sub status type = '%s'", usage->subtype);

        if (!strcasecmp(usage->subtype, OSP_BWTYPE_START) || 
            !strcasecmp(usage->subtype, OSP_BWTYPE_END) || 
            !strcasecmp(usage->subtype, OSP_BWTYPE_FAILOVER))
        {
            DEBUG2("rlm_osp: ignore sub status type '%s' record.", usage->subtype);
            return 1;
        }

        OSP_GET_STRING(request, TRUE, OSP_STR_DIRECTION, OSP_DEF_MUST, mapping->direction, buffer);
        if (!strcasecmp(buffer, OSP_BWCALL_IN)) {
            usage->direction = OSP_DIRECTION_IN;
        } else {
            usage->direction = OSP_DIRECTION_OUT;
        }
        DEBUG2("rlm_osp: call direction = '%d'", usage->direction);

        if (((usage->direction == OSP_DIRECTION_IN) && (mapping->ignorein)) ||
            ((usage->direction == OSP_DIRECTION_OUT) && (mapping->ignoreout)))
        {
            DEBUG2("rlm_osp: ignore '%s' record.", buffer);
            return 1;
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        break;
    }

    /* Get transaction ID */
    OSP_GET_LONGLONG(request, TRUE, OSP_STR_TRANSACTIONID, OSP_DEF_MAY, mapping->transid, 0, buffer, usage->transid);

    /* Get Call-ID */
    OSP_GET_STRING(request, TRUE, OSP_STR_CALLID, OSP_DEF_MUST, mapping->callid, usage->callid);

    transferred = FALSE;
    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
        break;
    case OSP_CLIENT_BROADWORKS:
        /* Get transfer result */
        OSP_GET_STRING(request, TRUE, OSP_STR_TRANSFERRET, OSP_DEF_MAY, mapping->transferret, buffer);
        if (OSP_CHECK_STRING(buffer) && !strcasecmp(buffer, OSP_BWTRANSFERRET_SUCCESS)) {
            if (usage->direction == OSP_DIRECTION_IN) {
                usage->transfer = OSPC_TSTATUS_TRANSFERTO;
            } else {
                usage->transfer = OSPC_TSTATUS_TRANSFERFROM;
            }

            /* Get transfer ID */
            OSP_GET_STRING(request, TRUE, OSP_STR_TRANSFERID, OSP_DEF_MAY, mapping->transferid, usage->transferid);
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        if (mapping->parsetransfer) {
            switch (type) {
            case PW_STATUS_START:
                /* This is a special case that Acme transferred call leg Start RADIUS record does not have Acme-Primary-Routing-Number */
                OSP_GET_STRING(request, TRUE, transferflagname, OSP_DEF_MAY, transferflagmap, buffer);
                if (!OSP_CHECK_STRING(buffer)) {
                    transferred = TRUE;
                }
                break;
            case PW_STATUS_STOP:
                /* Get transfer ID */
                OSP_GET_STRING(request, TRUE, OSP_STR_TRANSFERID, OSP_DEF_MAY, mapping->transferid, usage->transferid);
                if (OSP_CHECK_STRING(usage->transferid)) {
                    transferred = TRUE;
                    usage->transfer = OSPC_TSTATUS_TRANSFERTO;
                }
                break;
            case PW_STATUS_ALIVE:
            default:
                break;
            }
        }
        break;
    }
    if (transferred) {
        /* Get calling number */
        OSP_GET_CALLNUM(request, TRUE, OSP_STR_TRANSFERCALLINGNUM, OSP_DEF_MAY, mapping->transfercalling, mapping->callingformat, buffer, ptr, size, usage->calling);

        /* Get called number */
        OSP_GET_CALLNUM(request, TRUE, OSP_STR_TRANSFERCALLEDNUM, OSP_DEF_MUST, mapping->transfercalled, mapping->calledformat, buffer, ptr, size, usage->called);
    } else {
        /* Get calling number */
        OSP_GET_CALLNUM(request, TRUE, OSP_STR_CALLINGNUMBER, OSP_DEF_MAY, mapping->calling, mapping->callingformat, buffer, ptr, size, usage->calling);

        /* Get called number */
        OSP_GET_CALLNUM(request, TRUE, OSP_STR_CALLEDNUMBER, OSP_DEF_MUST, mapping->called, mapping->calledformat, buffer, ptr, size, usage->called);
    }

    /* Get asserted ID */
    OSP_GET_CALLNUM(request, TRUE, OSP_STR_ASSERTEDID, OSP_DEF_MAY, mapping->assertedid, OSPC_NFORMAT_URL, buffer, ptr, size, usage->assertedid);

    /* Get RPID */
    OSP_GET_CALLNUM(request, TRUE, OSP_STR_RPID, OSP_DEF_MAY, mapping->rpid, OSPC_NFORMAT_URL, buffer, ptr, size, usage->rpid);

    /* Get source */
    OSP_GET_IP(request, TRUE, OSP_STR_SOURCE, OSP_DEF_MAY, mapping->source, provider->deviceip, provider->deviceport, buffer, usage->source, tmphost);

    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
        if (usage->direction == OSP_DIRECTION_IN) {
            /* Get source device */
            OSP_GET_IP(request, TRUE, OSP_STR_SRCDEVICE, OSP_DEF_MUST, mapping->srcdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev, tmphost);

            /* Get proxy/destination */
            OSP_GET_IP(request, TRUE, OSP_STR_PROXY, OSP_DEF_MUST, mapping->proxy, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination, desthost);
        } else {
            /* Get proxy/source device */
            OSP_GET_IP(request, TRUE, OSP_STR_PROXY, OSP_DEF_MUST, mapping->proxy, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev, tmphost);

            /* Get destination */
            OSP_GET_IP(request, TRUE, OSP_STR_DESTINATION, OSP_DEF_MUST, mapping->destination, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination, desthost);
        }
        break;
    case OSP_CLIENT_BROADWORKS:
        /* Get proxy */
        OSP_GET_IP(request, TRUE, OSP_STR_PROXY, OSP_DEF_MUST, mapping->proxy, OSP_IP_DEF, OSP_PORT_DEF, buffer, proxy, tmphost);

        if (usage->direction == OSP_DIRECTION_IN) {
            /* Get access device/source */
            /* Special case, BWAS-Access-Device-Address may not be reported */
            OSP_GET_IP(request, TRUE, OSP_STR_ACCESSDEVICE, OSP_DEF_MAY, mapping->accessdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev, tmphost);

            /* Get route device/destination */
            /* Special case, BWAS-Route may not be reported */
            OSP_GET_IP(request, TRUE, OSP_STR_ROUTEDEVICE, OSP_DEF_MAY, mapping->routedev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination, desthost);
            switch (type) {
            case PW_STATUS_STOP:
            case PW_STATUS_ALIVE:
                if (!strcasecmp(usage->destination, OSP_BWDEV_GROUP) || !strcasecmp(usage->destination, OSP_BWDEV_ENTERPRISE)) {
                    strncpy(usage->destination, proxy, sizeof(usage->destination));
                } 
                break;
            case PW_STATUS_START:
                if (usage->destination[0] == '\0') {
                    strncpy(usage->destination, proxy, sizeof(usage->destination));
                }
                break;
            default:
                break;
            }
        } else {
            /* Get route device/source*/
            OSP_GET_IP(request, TRUE, OSP_STR_ROUTEDEVICE, OSP_DEF_MUST, mapping->routedev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev, desthost);
            switch (type) {
            case PW_STATUS_START:
            case PW_STATUS_STOP:
            case PW_STATUS_ALIVE:
                if (!strcasecmp(usage->srcdev, OSP_BWDEV_GROUP) || !strcasecmp(usage->srcdev, OSP_BWDEV_ENTERPRISE)) {
                    strncpy(usage->srcdev, proxy, sizeof(usage->srcdev));
                } 
                break;
            default:
                break;
            }

            /* Get access device/destination */
            /* Special case, BWAS-Access-Device-Address may not be reported */
            OSP_GET_IP(request, TRUE, OSP_STR_ACCESSDEVICE, OSP_DEF_MAY, mapping->accessdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination, tmphost);
            switch (type) {
            case PW_STATUS_START:
            case PW_STATUS_STOP:
            case PW_STATUS_ALIVE:
                if (usage->destination[0] == '\0') {
                    strncpy(usage->destination, proxy, sizeof(usage->destination));
                } 
                break;
            default:
                break;
            }
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        /* Get source device */
        OSP_GET_IP(request, TRUE, OSP_STR_SRCDEVICE, OSP_DEF_MUST, mapping->srcdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->srcdev, tmphost);

        /* Get destination */
        OSP_GET_IP(request, TRUE, OSP_STR_DESTINATION, OSP_DEF_MUST, mapping->destination, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destination, desthost);

        break;
    }

    /* Check if the record is for a destination should be ignored */
    if (inet_pton(AF_INET, desthost, &dest) == 1) {
        if (osp_match_subnet(&mapping->ignoreddestlist, dest.s_addr) == 0) {
            DEBUG2("rlm_osp: ignore record for destination '%s'.", usage->destination);
            return 1;
        }
    }

    /* Get destination device */
    OSP_GET_IP(request, TRUE, OSP_STR_DESTDEVICE, OSP_DEF_MAY, mapping->destdev, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->destdev, tmphost);

    /* Get destination count */
    OSP_GET_INTEGER(request, TRUE, OSP_STR_DESTCOUNT, OSP_DEF_MAY, mapping->destcount, OSP_INTSTR_DEC, OSP_DESTCOUNT_DEF, buffer, usage->destcount);

    /* Get source network ID */
    OSP_GET_STRING(request, TRUE, OSP_STR_SRCNETWORKID, OSP_DEF_MAY, mapping->srcnid, usage->srcnid);

    /* Get destination network ID */
    OSP_GET_STRING(request, TRUE, OSP_STR_DESTNETWORKID, OSP_DEF_MAY, mapping->destnid, usage->destnid);

    /* Get diversion user */
    OSP_GET_CALLNUM(request, TRUE, OSP_STR_DIVERSIONUSER, OSP_DEF_MAY, mapping->divuser, TRUE, buffer, ptr, size, usage->divuser);

    /* Get diversion host */
    OSP_GET_URIHOST(request, TRUE, OSP_STR_DIVERSIONHOST, OSP_DEF_MAY, mapping->divhost, OSP_IP_DEF, OSP_PORT_DEF, buffer, usage->divhost);

    /* Get call start time */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_TIME(request, parse, OSP_STR_STARTTIME, OSP_DEF_MUST, running, mapping->start, mapping->timeformat, OSP_TIME_DEF, buffer, usage->start);

    /* Get call alert time */
    parse = (type == PW_STATUS_STOP);
    OSP_GET_TIME(request, parse, OSP_STR_ALERTTIME, OSP_DEF_MAY, running, mapping->alert, mapping->timeformat, OSP_TIME_DEF, buffer, usage->alert);

    /* Get call connect time */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
    OSP_GET_TIME(request, parse, OSP_STR_CONNECTTIME, OSP_DEF_MAY, running, mapping->connect, mapping->timeformat, OSP_TIME_DEF, buffer, usage->connect);

    /* Get call end time */
    parse = (type == PW_STATUS_STOP);
    OSP_GET_TIME(request, parse, OSP_STR_ENDTIME, OSP_DEF_MUST, running, mapping->end, mapping->timeformat, OSP_TIME_DEF, buffer, usage->end);

    if (type == PW_STATUS_STOP) {
        /* Get call duration */
        if (OSP_CHECK_STRING(mapping->duration)) {
            radius_xlat(buffer, sizeof(buffer), mapping->duration, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", mapping->duration, OSP_STR_DURATION);
                if (usage->connect != OSP_TIME_DEF) {
                    usage->duration = difftime(usage->end, usage->connect);
                } else {
                    switch (mapping->clienttype) {
                    case OSP_CLIENT_BROADWORKS:
                        /* This is a special case that BroadWorks does not report connect time for failed call attempt */
                        usage->duration = 0;
                        break;
                    case OSP_CLIENT_UNDEF:
                    case OSP_CLIENT_ACME:
                    case OSP_CLIENT_GENBANDS3:
                    case OSP_CLIENT_CISCO:
                    default:
                        usage->duration = difftime(usage->end, usage->start);
                        break;
                    }
                }
            } else {
                usage->duration = atoi(buffer);
            }
        } else {
            DEBUG("rlm_osp: '%s' mapping undefined.", OSP_STR_DURATION);
            if (usage->connect != OSP_TIME_DEF) {
                usage->duration = difftime(usage->end, usage->connect);
            } else {
                switch (mapping->clienttype) {
                case OSP_CLIENT_BROADWORKS:
                    /* This is a special case that BroadWorks does not report connect time for failed call attempt */
                    usage->duration = 0;
                    break;
                case OSP_CLIENT_UNDEF:
                case OSP_CLIENT_ACME:
                case OSP_CLIENT_GENBANDS3:
                case OSP_CLIENT_CISCO:
                default:
                    usage->duration = difftime(usage->end, usage->start);
                    break;
                }
            }
        }
    } else {
        DEBUG2("rlm_osp: do not parse '%s'.", OSP_STR_DURATION);
        usage->duration = 0;
    }
    DEBUG2("rlm_osp: '%s' = '%lu'", OSP_STR_DURATION, usage->duration);

    /* Get post dial delay */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
    OSP_GET_INTEGER(request, parse, OSP_STR_PDD, OSP_DEF_MAY, mapping->pdd, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, usage->pdd);
    if (usage->pdd != OSP_STATSINT_DEF) {
        usage->pdd *= OSP_TIMEUNIT_SCALE[mapping->pddunit];
    }
    DEBUG2("rlm_osp: post dial delay = '%d'", usage->pdd);

    /* Get release source */
    if (type == PW_STATUS_START) {
        DEBUG2("rlm_osp: do not parse '%s'.", OSP_STR_RELEASE);
        usage->release = OSPC_RELEASE_UNKNOWN;
    } else if (type == PW_STATUS_STOP) {
        if (OSP_CHECK_STRING(mapping->release)) {
            radius_xlat(buffer, sizeof(buffer), mapping->release, request, NULL);
            if (buffer[0] == '\0') {
                /* Has checked string NULL */
                DEBUG("rlm_osp: failed to parse '%s' in request for '%s'.", mapping->release, OSP_STR_RELEASE);
                usage->release = OSPC_RELEASE_UNKNOWN;
            } else {
                switch (mapping->clienttype) {
                case OSP_CLIENT_GENBANDS3:
                case OSP_CLIENT_CISCO:
                    release = atoi(buffer);
                    switch (release) {
                    case OSP_CISCOREL_CALLEDPSTN:
                    case OSP_CISCOREL_CALLEDVOIP:
                        usage->release = OSPC_RELEASE_DESTINATION;
                        break;
                    case OSP_CISCOREL_CALLINGPSTN:
                    case OSP_CISCOREL_CALLINGVOIP:
                        usage->release = OSPC_RELEASE_SOURCE;
                        break;
                    case OSP_CISCOREL_INTPOST:
                    case OSP_CISCOREL_INTVOIP:
                    case OSP_CISCOREL_INTAPPL:
                    case OSP_CISCOREL_INTAAA:
                        usage->release = OSPC_RELEASE_INTERNAL;
                        break;
                    case OSP_CISCOREL_CONSOLE:
                    case OSP_CISCOREL_EXTRADIUS:
                    case OSP_CISCOREL_EXTAPPL:
                    case OSP_CISCOREL_EXTAGENT:
                    default:
                        usage->release = OSPC_RELEASE_EXTERNAL;
                        break;
                    }
                    break;
                case OSP_CLIENT_BROADWORKS:
                    if (!strcasecmp(buffer, OSP_BWREL_LOCAL)) {
                        if (usage->direction == OSP_DIRECTION_IN) {
                            usage->release = OSPC_RELEASE_SOURCE;
                        } else {
                            usage->release = OSPC_RELEASE_DESTINATION;
                        }
                    } else if (!strcasecmp(buffer, OSP_BWREL_REMOTE)) {
                        if (usage->direction == OSP_DIRECTION_IN) {
                            usage->release = OSPC_RELEASE_DESTINATION;
                        } else {
                            usage->release = OSPC_RELEASE_SOURCE;
                        }
                    } else {
                        usage->release = OSPC_RELEASE_UNKNOWN;
                    }
                    break;
                case OSP_CLIENT_UNDEF:
                case OSP_CLIENT_ACME:
                default:
                    release = atoi(buffer);
                    switch (release) {
                    case OSP_ACMEREL_SRC:
                        usage->release = OSPC_RELEASE_SOURCE;
                        break;
                    case OSP_ACMEREL_DEST:
                        usage->release = OSPC_RELEASE_DESTINATION;
                        break;
                    case OSP_ACMEREL_INT:
                        usage->release = OSPC_RELEASE_INTERNAL;
                        break;
                    case OSP_ACMEREL_UNDEF:
                    default:
                        usage->release = OSPC_RELEASE_UNKNOWN;
                        break;
                    }
                    break;
                }
            }
        } else {
            DEBUG("rlm_osp: '%s' mapping undefined.", OSP_STR_RELEASE);
            usage->release = OSPC_RELEASE_UNKNOWN;
        }
    } else {    /* PW_STATUS_ALIVE */
        DEBUG2("rlm_osp: do not parse '%s'.", OSP_STR_RELEASE);
        switch (mapping->clienttype) {
        case OSP_CLIENT_GENBANDS3:
        case OSP_CLIENT_CISCO:
        case OSP_CLIENT_BROADWORKS:
            usage->release = OSPC_RELEASE_UNKNOWN;
            break;
        case OSP_CLIENT_UNDEF:
        case OSP_CLIENT_ACME:
        default:
            usage->release = OSPC_RELEASE_DESTINATION;
            break;
        }
    }
    DEBUG2("rlm_osp: '%s' = '%d'", OSP_STR_RELEASE, usage->release);

    /* Get release causes */
    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
        parse = ((type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
        format = OSP_INTSTR_HEX;
        break;
    case OSP_CLIENT_BROADWORKS:
        parse = (type == PW_STATUS_STOP);
        format = OSP_INTSTR_DEC;
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        parse = ((type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
        format = OSP_INTSTR_DEC;
        break;
    }
    OSP_GET_INTEGER(request, parse, OSP_STR_Q850CAUSE, OSP_DEF_MUST, mapping->q850cause, format, OSP_CAUSE_UNKNOWN, buffer, usage->q850cause);
    OSP_GET_INTEGER(request, parse, OSP_STR_SIPCAUSE, OSP_DEF_MAY, mapping->sipcause, format, OSP_CAUSE_UNKNOWN, buffer, usage->sipcause);

    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    switch (mapping->clienttype) {
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    case OSP_CLIENT_BROADWORKS:
        usage->protocol = OSPC_PROTNAME_UNKNOWN;

        if (usage->direction == OSP_DIRECTION_IN) {
            /* Get source protocol */
            parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
            OSP_GET_STRING(request, parse, OSP_STR_SRCPROTOCOL, OSP_DEF_MAY, mapping->srcprotocol, buffer);
            usage->srcprotocol = osp_parse_protocol(mapping, buffer);

            usage->destprotocol = OSPC_PROTNAME_UNKNOWN;
        } else {
            usage->srcprotocol = OSPC_PROTNAME_UNKNOWN;

            /* Get destination protocol */
            parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
            OSP_GET_STRING(request, parse, OSP_STR_DESTPROTOCOL, OSP_DEF_MAY, mapping->destprotocol, buffer);
            usage->destprotocol = osp_parse_protocol(mapping, buffer);
        }

        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    default:
        /* Get signaling protocol */
        OSP_GET_STRING(request, parse, OSP_STR_PROTOCOL, OSP_DEF_MAY, mapping->protocol, buffer);
        usage->protocol = osp_parse_protocol(mapping, buffer);

        usage->srcprotocol = OSPC_PROTNAME_UNKNOWN;
        usage->destprotocol = OSPC_PROTNAME_UNKNOWN;

        break;
    }

    /* Get source/destination session ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    switch (mapping->clienttype) {
    case OSP_CLIENT_CISCO:
        if (usage->direction == OSP_DIRECTION_IN) {
            OSP_GET_STRING(request, parse, OSP_STR_SRCSESSIONID, OSP_DEF_MAY, mapping->srcsessionid, usage->srcsessionid);
        } else {
            OSP_GET_STRING(request, parse, OSP_STR_DESTSESSIONID, OSP_DEF_MAY, mapping->destsessionid, usage->destsessionid);
        }
        break;
    case OSP_CLIENT_BROADWORKS:
        if (usage->direction == OSP_DIRECTION_IN) {
            OSP_GET_STRING(request, parse, OSP_STR_ACCESSCALLID, OSP_DEF_MAY, mapping->accesscallid, usage->srcsessionid);
            OSP_GET_STRING(request, parse, OSP_STR_ROUTECALLID, OSP_DEF_MAY, mapping->routecallid, usage->destsessionid);
        } else {
            OSP_GET_STRING(request, parse, OSP_STR_ROUTECALLID, OSP_DEF_MAY, mapping->routecallid, usage->srcsessionid);
            OSP_GET_STRING(request, parse, OSP_STR_ACCESSCALLID, OSP_DEF_MAY, mapping->accesscallid, usage->destsessionid);
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    default:
        OSP_GET_STRING(request, parse, OSP_STR_SRCSESSIONID, OSP_DEF_MAY, mapping->srcsessionid, usage->srcsessionid);
        OSP_GET_STRING(request, parse, OSP_STR_DESTSESSIONID, OSP_DEF_MAY, mapping->destsessionid, usage->destsessionid);
        break;
    }

    /* Get correlation session ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, OSP_STR_CORRSESSIONID, OSP_DEF_MAY, mapping->corrsessionid, usage->corrsessionid);

    /* Get local/remote call ID */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        OSP_GET_STRING(request, parse, OSP_STR_LOCALCALLID, OSP_DEF_MAY, mapping->localcallid, usage->localcallid);
        OSP_GET_STRING(request, parse, OSP_STR_REMOTECALLID, OSP_DEF_MAY, mapping->remotecallid, usage->remotecallid);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        break;
    }

    /* Get source codec */
    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE)) && (usage->direction == OSP_DIRECTION_IN);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
        break;
    }
    OSP_GET_STRING(request, parse, OSP_STR_SRCCODEC, OSP_DEF_MAY, mapping->srccodec, usage->srccodec);

    /* Get destination codec */
    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE)) && (usage->direction == OSP_DIRECTION_OUT);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP));
        break;
    }
    OSP_GET_STRING(request, parse, OSP_STR_DESTCODEC, OSP_DEF_MAY, mapping->destcodec, usage->destcodec);

    /* Get conference ID */
    parse = (type == PW_STATUS_STOP);
    OSP_GET_STRING(request, parse, OSP_STR_CONFID, OSP_DEF_MAY, mapping->confid, usage->confid);

    /* Get user-defined info */
    for (i = 0; i < OSP_CUSTOMINFO_MAX; i++) {
        snprintf(buffer, sizeof(buffer), "%s%d", OSP_STR_CUSTOMINFO, i + 1);
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
        OSP_GET_STRING(request, parse, buffer, OSP_DEF_MAY, mapping->custinfo[i], usage->custinfo[i]);
    }

    /* Get source realm */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, OSP_STR_SRCREALM, OSP_DEF_MAY, mapping->srcrealm, usage->srcrealm);

    /* Get destination realm */
    parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
    OSP_GET_STRING(request, parse, OSP_STR_DESTREALM, OSP_DEF_MAY, mapping->destrealm, usage->destrealm);

    /* Get other party info */
    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        parse = ((type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE));
        OSP_GET_STRING(request, parse, OSP_STR_OTHERPARTY, OSP_DEF_MAY, mapping->otherparty, usage->otherparty);
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        break;
    }

    /* Get call party info */
    parse = (type == PW_STATUS_START) || (type == PW_STATUS_STOP) || (type == PW_STATUS_ALIVE);
    switch (mapping->clienttype) {
    case OSP_CLIENT_BROADWORKS:
        if (usage->direction == OSP_DIRECTION_IN) {
            OSP_GET_STRING(request, parse, OSP_STR_CALLINGUSERNAME, OSP_DEF_MAY, mapping->callingusername, usage->callingusername);
            OSP_GET_STRING(request, parse, OSP_STR_CALLINGUSERID, OSP_DEF_MAY, mapping->callinguserid, usage->callinguserid);
            OSP_GET_STRING(request, parse, OSP_STR_CALLINGUSERGROUP, OSP_DEF_MAY, mapping->callingusergroup, usage->callingusergroup);

            if (OSP_CHECK_STRING(usage->otherparty)) {
                strncpy(buffer, usage->otherparty, sizeof(buffer));
                if ((ptr = strchr(buffer, ' ')) != NULL) {
                    *ptr = '\0';
                    ptr++;
                    strncpy(usage->calleduserid, buffer, sizeof(usage->calleduserid));
                    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_CALLEDUSERID, usage->calleduserid);
                    strncpy(usage->calledusergroup, ptr, sizeof(usage->calledusergroup));
                    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_CALLEDUSERGROUP, usage->calledusergroup);
                } else {
                    strncpy(usage->calleduserid, buffer, sizeof(usage->calleduserid));
                    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_CALLEDUSERID, usage->calleduserid);
                }
            }
        } else if (usage->direction == OSP_DIRECTION_OUT) {
            if (OSP_CHECK_STRING(usage->otherparty)) {
                strncpy(buffer, usage->otherparty, sizeof(buffer));
                if ((ptr = strchr(buffer, ' ')) != NULL) {
                    *ptr = '\0';
                    ptr++;
                    strncpy(usage->callinguserid, buffer, sizeof(usage->callinguserid));
                    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_CALLINGUSERID, usage->callinguserid);
                    strncpy(usage->callingusergroup, ptr, sizeof(usage->callingusergroup));
                    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_CALLINGUSERGROUP, usage->callingusergroup);
                } else {
                    strncpy(usage->callinguserid, buffer, sizeof(usage->callinguserid));
                    DEBUG2("rlm_osp: '%s' = '%s'", OSP_STR_CALLINGUSERID, usage->callinguserid);
                }
            }

            OSP_GET_STRING(request, parse, OSP_STR_CALLEDUSERNAME, OSP_DEF_MAY, mapping->calledusername, usage->calledusername);
            OSP_GET_STRING(request, parse, OSP_STR_CALLEDUSERID, OSP_DEF_MAY, mapping->calleduserid, usage->calleduserid);
            OSP_GET_STRING(request, parse, OSP_STR_CALLEDUSERGROUP, OSP_DEF_MAY, mapping->calledusergroup, usage->calledusergroup);
        }
        break;
    case OSP_CLIENT_UNDEF:
    case OSP_CLIENT_ACME:
    case OSP_CLIENT_GENBANDS3:
    case OSP_CLIENT_CISCO:
    default:
        OSP_GET_STRING(request, parse, OSP_STR_CALLINGUSERNAME, OSP_DEF_MAY, mapping->callingusername, usage->callingusername);
        OSP_GET_STRING(request, parse, OSP_STR_CALLINGUSERID, OSP_DEF_MAY, mapping->callinguserid, usage->callinguserid);
        OSP_GET_STRING(request, parse, OSP_STR_CALLINGUSERGROUP, OSP_DEF_MAY, mapping->callingusergroup, usage->callingusergroup);
        OSP_GET_STRING(request, parse, OSP_STR_CALLEDUSERNAME, OSP_DEF_MAY, mapping->calledusername, usage->calledusername);
        OSP_GET_STRING(request, parse, OSP_STR_CALLEDUSERID, OSP_DEF_MAY, mapping->calleduserid, usage->calleduserid);
        OSP_GET_STRING(request, parse, OSP_STR_CALLEDUSERGROUP, OSP_DEF_MAY, mapping->calledusergroup, usage->calledusergroup);
        break;
    }

    /* Get statistics */
    osp_get_statsinfo(mapping, request, type, usage);

    DEBUG3("rlm_osp: osp_get_usageinfo success");

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

    DEBUG3("rlm_osp: osp_match_subnet start");

    for (i = 0; i < list->number; i++) {
        if (!((list->subnet[i].ip & list->subnet[i].mask) ^ (ip & list->subnet[i].mask))) {
            break;
        }
    }
    if (i >= list->number) {
        DEBUG2("rlm_osp: subnet list unmatched");
        return -1;
    }

    DEBUG3("rlm_osp: osp_match_subnet success");

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
    int parse;
    osp_string_t buffer;

    DEBUG3("rlm_osp: osp_get_statsinfo start");

    if (map->reportstats) {
        /* If parse statistics */
        parse = (type == PW_STATUS_STOP);

        /* Get lost send packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_SLOSTPACKETS, OSP_DEF_MAY, map->slost.pack, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->slost.pack);

        /* Get lost send packet fraction */
        OSP_GET_INTEGER(request, parse, OSP_STR_SLOSTFRACTION, OSP_DEF_MAY, map->slost.fract, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->slost.fract);

        /* Get lost receive packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RLOSTPACKETS, OSP_DEF_MAY, map->rlost.pack, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rlost.pack);

        /* Get lost receive packet fraction */
        OSP_GET_INTEGER(request, parse, OSP_STR_RLOSTFRACTION, OSP_DEF_MAY, map->rlost.fract, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rlost.fract);

        /* Get RTP source-to-reporter octets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPSRCREPOCTETS, OSP_DEF_MAY, map->rtp_src_rep_octets, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_src_rep_octets);

        /* Get RTP destination-to-reporter octets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPDESTREPOCTETS, OSP_DEF_MAY, map->rtp_dest_rep_octets, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_dest_rep_octets);

        /* Get RTP source-to-reporter packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPSRCREPPACKETS, OSP_DEF_MAY, map->rtp_src_rep_packets, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_src_rep_packets);

        /* Get RTP destination-to-reporter packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPDESTREPPACKETS, OSP_DEF_MAY, map->rtp_dest_rep_packets, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_dest_rep_packets);

        /* Get RTP source-to-reporter lost packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPSRCREPLOST, OSP_DEF_MAY, map->rtp_src_rep_lost, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_src_rep_lost);

        /* Get RTP destination-to-reporter lost packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPDESTREPLOST, OSP_DEF_MAY, map->rtp_dest_rep_lost, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_dest_rep_lost);

        /* Get RTP source-to-reporter jitter mean */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPSRCREPJITTERMEAN, OSP_DEF_MAY, map->rtp_src_rep_jitter_mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_src_rep_jitter_mean);

        /* Get RTP destination-to-reporter jitter mean */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPDESTREPJITTERMEAN, OSP_DEF_MAY, map->rtp_dest_rep_jitter_mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_dest_rep_jitter_mean);

        /* Get RTP source-to-reporter jitter max */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPSRCREPJITTERMAX, OSP_DEF_MAY, map->rtp_src_rep_jitter_max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_src_rep_jitter_max);

        /* Get RTP destination-to-reporter jitter max */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTPDESTREPJITTERMAX, OSP_DEF_MAY, map->rtp_dest_rep_jitter_max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtp_dest_rep_jitter_max);

        /* Get RTCP source-to-destination lost packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPSRCDESTLOST, OSP_DEF_MAY, map->rtcp_src_dest_lost, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_src_dest_lost);

        /* Get RTCP destination-to-source lost packets */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPDESTSRCLOST, OSP_DEF_MAY, map->rtcp_dest_src_lost, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_dest_src_lost);

        /* Get RTCP source-to-destination jitter mean */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPSRCDESTJITTERMEAN, OSP_DEF_MAY, map->rtcp_src_dest_jitter_mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_src_dest_jitter_mean);

        /* Get RTCP destination-to-source jitter mean */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPDESTSRCJITTERMEAN, OSP_DEF_MAY, map->rtcp_dest_src_jitter_mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_dest_src_jitter_mean);

        /* Get RTCP source-to-destination jitter max */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPSRCDESTJITTERMAX, OSP_DEF_MAY, map->rtcp_src_dest_jitter_max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_src_dest_jitter_max);

        /* Get RTCP destination-to-source jitter max */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPDESTSRCJITTERMAX, OSP_DEF_MAY, map->rtcp_dest_src_jitter_max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_dest_src_jitter_max);

        /* Get RTCP source round trip delay mean */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPSRCRTDELAYMEAN, OSP_DEF_MAY, map->rtcp_src_rtdelay_mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_src_rtdelay_mean);

        /* Get RTCP destination round trip delay mean */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPDESTRTDELAYMEAN, OSP_DEF_MAY, map->rtcp_dest_rtdelay_mean, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_dest_rtdelay_mean);

        /* Get RTCP source round trip delay max */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPSRCRTDELAYMAX, OSP_DEF_MAY, map->rtcp_src_rtdelay_max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_src_rtdelay_max);

        /* Get RTCP destination round trip delay max */
        OSP_GET_INTEGER(request, parse, OSP_STR_RTCPDESTRTDELAYMAX, OSP_DEF_MAY, map->rtcp_dest_rtdelay_max, OSP_INTSTR_DEC, OSP_STATSINT_DEF, buffer, var->rtcp_dest_rtdelay_max);

        /* Get source-to-reporter R-Factor */
        OSP_GET_FLOAT(request, parse, OSP_STR_SRCREPRFACTOR, OSP_DEF_MAY, map->src_rep_rfactor, map->rfactorscale, OSP_STATSFLOAT_DEF, buffer, var->src_rep_rfactor);

        /* Get destination-to-reporter R-Factor */
        OSP_GET_FLOAT(request, parse, OSP_STR_DESTREPRFACTOR, OSP_DEF_MAY, map->dest_rep_rfactor, map->rfactorscale, OSP_STATSFLOAT_DEF, buffer, var->dest_rep_rfactor);

        /* Get source-to-reporter MOS */
        OSP_GET_FLOAT(request, parse, OSP_STR_SRCREPMOS, OSP_DEF_MAY, map->src_rep_mos, map->mosscale, OSP_STATSFLOAT_DEF, buffer, var->src_rep_mos);

        /* Get destination-to-reporter MOS */
        OSP_GET_FLOAT(request, parse, OSP_STR_DESTREPMOS, OSP_DEF_MAY, map->dest_rep_mos, map->mosscale, OSP_STATSFLOAT_DEF, buffer, var->dest_rep_mos);
    } else {
        /* Do not report statistics. slost and rlost must be set to default. */
        var->slost.pack = OSP_STATSINT_DEF;
        var->slost.fract = OSP_STATSINT_DEF;
        var->rlost.pack = OSP_STATSINT_DEF;
        var->rlost.fract = OSP_STATSINT_DEF;
    }

    DEBUG3("rlm_osp: osp_get_statsinfo success");

    return 0;
}

/*
 * Get host of IP
 *
 * param ip IP address
 * param buffer Buffer
 * param buffersize Size of buffer
 * return
 */
static void osp_get_iphost(
    char* ip,
    char* buffer,
    int buffersize)
{
    int size;
    char* tmpptr;

    DEBUG3("rlm_osp: osp_get_iphost start");

    size = buffersize - 1;
    strncpy(buffer, ip, size);
    buffer[size] = '\0';

    if((tmpptr = strchr(buffer, ':')) != NULL) {
        *tmpptr = '\0';
    }

    DEBUG2("rlm_osp: host = '%s'", buffer);

    DEBUG3("rlm_osp: osp_get_iphost success");
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
    osp_string_t tmpbuf;

    DEBUG3("rlm_osp: osp_create_device start");

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
    DEBUG2("rlm_osp: device = '%s'", buffer);

    DEBUG3("rlm_osp: osp_create_device success");
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
    osp_string_t tmpbuf;
    char* tmpptr;

    DEBUG3("rlm_osp: osp_format_device start");

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

    DEBUG2("rlm_osp: device = '%s'", buffer);

    DEBUG3("rlm_osp: osp_format_device success");
}

/*
 * Get userinfo from uri
 *
 * SIP-URI = "sip:" [ userinfo ] hostport uri-parameters [ headers ]
 * userinfo = ( user / telephone-subscriber ) [ ":" password ] "@"
 * hostport = host [ ":" port ]
 *
 * param uri Caller/callee SIP URI
 * param buffer Userinfo buffer
 * param buffersize Userinfo buffer size
 * param logflag If to log error message
 * return 0 success, -1 failure
 */
static int osp_get_uriuser(
    char* uri,
    char* buffer,
    int buffersize,
    int logflag)
{
    char* start;
    char* end;
    char* tmp;
    int size;

    DEBUG3("rlm_osp: osp_get_uriuser start");

    if ((start = strstr(uri, "sip:")) != NULL) {
        start += 4;
        if ((end = strchr(start, '@')) == NULL) {
            /* For example, "Bob <sip:127.0.0.1:5060>;tag=123456789" */
            *buffer = '\0';
        } else {
            /* Check if there is a password or a user parameter */
            if (((tmp = strpbrk(start, ":;")) != NULL) && (tmp < end )) {
                end = tmp;
            }

            size = end - start;
            if (buffersize <= size) {
                size = buffersize - 1;
            }

            memcpy(buffer, start, size);
            buffer[size] = '\0';
        }
    } else if ((start = strstr(uri, "tel:")) != NULL) {
        start += 4;
        /* Check if there is a parameter */
        if ((end = strchr(start, ';')) != NULL) {
            size = end - start;
        } else {
            size = strlen(start);
        }

        if (buffersize <= size) {
            size = buffersize - 1;
        }

        memcpy(buffer, start, size);
        buffer[size] = '\0';
    } else {
        if (logflag) {
            if (OSP_CHECK_STRING(uri)) {
                radlog(L_ERR,
                    "rlm_osp: URI '%s' format incorrect, without 'sip:' or 'tel:'.",
                    uri);
            } else {
                radlog(L_ERR, "rlm_osp: URI format incorrect.");
            }
        }
        return -1;
    }

    /* Do not have to check string NULL */
    DEBUG2("rlm_osp: uri userinfo = '%s'", buffer);

    DEBUG3("rlm_osp: osp_get_uriuser success");

    return 0;
}

/*
 * Get hostport from uri
 *
 * SIP-URI = "sip:" [ userinfo ] hostport uri-parameters [ headers ]
 * userinfo = ( user / telephone-subscriber ) [ ":" password ] "@"
 * hostport = host [ ":" port ]
 *
 * param uri Caller/callee SIP URI
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

    DEBUG3("rlm_osp: osp_get_urihost start");

    if ((start = strstr(uri, "sip:")) == NULL) {
        if (OSP_CHECK_STRING(uri)) {
            radlog(L_ERR,
                "rlm_osp: SIP URI '%s' format incorrect, without 'sip:'.",
                uri);
        } else {
            radlog(L_ERR, "rlm_osp: SIP URI format incorrect.");
        }
        return -1;
    }

    start += 4;
    if ((tmp = strchr(start, '@')) != NULL) {
        start = tmp + 1;
    }

    /* Check if there is a parameter or a header */
    if ((end = strpbrk(start, ";?>")) == NULL) {
        size = strlen(start);
    } else {
        size = end - start;
    }

    if (buffersize <= size) {
        size = buffersize - 1;
    }

    memcpy(buffer, start, size);
    buffer[size] = '\0';

    /* Do not have to check string NULL */
    DEBUG2("rlm_osp: uri hostport = '%s'", buffer);

    DEBUG3("rlm_osp: osp_get_urihost success");

    return 0;
}

/*
 * Parse protocol from string
 *
 * param mapping Mapping parameters
 * param protocol Protocol name string
 * return Protocol
 */
static OSPE_PROTOCOL_NAME osp_parse_protocol(
    osp_mapping_t* mapping,
    char* protocol)
{
    OSPE_PROTOCOL_NAME name = OSPC_PROTNAME_UNKNOWN;

    DEBUG3("rlm_osp: osp_parse_protocol start");

    if (OSP_CHECK_STRING(protocol)) {
        /* Comparing ignore case, Solaris does not support strcasestr */
        if (strstr(protocol, "SIP") || strstr(protocol, "Sip") || strstr(protocol, "sip")) {
            name = OSPC_PROTNAME_SIP;
        } else {
            switch (mapping->clienttype) {
            case OSP_CLIENT_GENBANDS3:
                if (strstr(protocol, "H.323") || strstr(protocol, "h.323")) {
                    name = OSPC_PROTNAME_Q931;
                }
                break;
            case OSP_CLIENT_CISCO:
                if (strstr(protocol, "CISCO") || strstr(protocol, "Cisco") || strstr(protocol, "cisco")) {
                    name = OSPC_PROTNAME_Q931;
                }
                break;
            case OSP_CLIENT_UNDEF:
            case OSP_CLIENT_ACME:
            case OSP_CLIENT_BROADWORKS:
            default:
                if (strstr(protocol, "H323") || strstr(protocol, "h323")) {
                    name = OSPC_PROTNAME_Q931;
                }
                break;
            }
        }
    }
    DEBUG2("rlm_osp: protocol name = '%d'", name);

    DEBUG3("rlm_osp: osp_parse_protocol success");

    return name;
}

/*
 * Format time from time string
 *
 * param running Running parameters
 * param timestr Time string
 * param format Time string format
 * return Time value
 */
static time_t osp_format_time(
    osp_running_t* running,
    char* timestamp,
    osp_timestr_e format)
{
    struct tm dt;
    char* timestr = timestamp;
    osp_string_t buffer;
    char* tzone;
    long int toffset;
    time_t tvalue = 0;

    DEBUG3("rlm_osp: osp_format_time start");

    switch (format) {
    case OSP_TIMESTR_T:
        tvalue = atol(timestr);
        break;
    case OSP_TIMESTR_C:
        /* WWW MMM DD hh:mm:ss YYYY, assume UTC */
        tzone = NULL;
        if (osp_cal_timeoffset(running, tzone, &toffset) == 0) {
            strptime(timestr, "%a %b %d %T %Y", &dt);
            osp_cal_elapsed(&dt, toffset, &tvalue);
        }
        break;
    case OSP_TIMESTR_ACME:
        /* hh:mm:ss.kkk ZON MMM DD YYYY */
        if (osp_remove_timezone(running, timestr, buffer, sizeof(buffer), &toffset) == 0) {
            strptime(buffer, "%T %b %d %Y", &dt);
            osp_cal_elapsed(&dt, toffset, &tvalue);
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
        /* hh:mm:ss.kkk ZON WWW MMM DD YYYY */
        if (osp_remove_timezone(running, timestr, buffer, sizeof(buffer), &toffset) == 0) {
            strptime(buffer, "%T %a %b %d %Y", &dt);
            osp_cal_elapsed(&dt, toffset, &tvalue);
        }
        break;
    case OSP_TIMESTR_BW:
        /* YYYYMMDDhhmmss.kkk */
        tzone = NULL;
        if (osp_cal_timeoffset(running, tzone, &toffset) == 0) {
            strptime(timestr, "%Y%m%d%H%M%S.", &dt);
            osp_cal_elapsed(&dt, toffset, &tvalue);
        }
        break;
    default:
        break;
    }
    DEBUG2("rlm_osp: time = '%lu'", tvalue);

    DEBUG3("rlm_osp: osp_format_time success");

    return tvalue;
}

/*
 * Remove time zone substring from timestamp and calculate time zone offset
 *
 * param running Running parameters
 * param timestr Timestamp string
 * param buffer Buffer for timestamp string without time zone
 * param buffersize Buffer size
 * param toffset Time offset in seconds
 * return 0 success, -1 failure
 */
static int osp_remove_timezone(
    osp_running_t* running,
    char* timestr,
    char* buffer,
    int buffersize,
    long int* toffset)
{
    int i, size, tzlen;

    DEBUG3("rlm_osp: osp_remove_timezone start");

    size = buffersize - 1;
    snprintf(buffer, size, "%s", timestr + 13);
    buffer[size] = '\0';

    size = buffersize;
    for (i = 0; i < size; i++) {
        if ((buffer[i] == ' ') || (buffer[i] == '\0')) {
            break;
        }
    }
    buffer[i] = '\0';
    tzlen = i;

    if (osp_cal_timeoffset(running, buffer, toffset) == 0) {
        size = buffersize - 1;
        snprintf(buffer, size, "%s", timestr);
        buffer[size] = '\0';

        size = buffersize - 8 - 1;
        snprintf(buffer + 8, size, "%s", timestr + 13 + tzlen);
        buffer[size + 8] = '\0';
        DEBUG2("rlm_osp: timestr = '%s'", buffer);
        DEBUG3("rlm_osp: osp_remove_timezone success");
        return 0;
    } else {
        buffer[0] = '\0';
        /* Has checked string NULL */
        radlog(L_INFO,
            "rlm_osp: Failed to remove time zone from '%s'.",
            timestr);
        return -1;
    }
}

/*
 * Calculate time offset to GMT beased on time zone in USA
 *
 * param running Running parameters
 * param tzone Time zone
 * param toffset Time offset in seconds
 * return 0 success, -1 failure
 */
static int osp_cal_timeoffset(
    osp_running_t* running,
    char* tzone,
    long int* toffset)
{
    int i, j;
    osp_timezone_t tmp;
    int ret = 0;

    DEBUG3("rlm_osp: osp_get_timeoffset start");

    if (!OSP_CHECK_STRING(tzone)) {
        *toffset = 0;
    } else {
        for (i = 0; i < running->tzlist_size; i++) {
            if (!strcmp(tzone, running->tzlist[i].name)) {
                break;
            }
        }
        if (i >= running->tzlist_size) {
            /* Has checked string NULL */
            radlog(L_INFO,
                "rlm_osp: Failed to calculate time offset for time zone '%s'.",
                tzone);
            *toffset = 0;
            ret = -1;
        } else {
            tmp = running->tzlist[i];
            if (i > OSP_TZ_CACHE) {
                for (j = i; j > 0; j--) {
                    running->tzlist[j] = running->tzlist[j - 1];
                }
                running->tzlist[0] = tmp;
            }
            *toffset = tmp.offset * 60;
       }
    }
    DEBUG2("rlm_osp: time zine '%s' offset = '%ld'", tzone, *toffset);

    DEBUG3("rlm_osp: osp_get_timeoffset success");

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

    DEBUG3("rlm_osp: osp_cal_elapsed start");

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

    DEBUG3("rlm_osp: osp_cal_elapsed success");

    return 0;
}

/*
 * Only free memory we allocated.  The strings allocated via
 * cf_section_parse() do not need to be freed.
 *
 * param instance Instance data
 * return 0 success
 */
static int osp_detach(
    void* instance)
{
    rlm_osp_t* data = (rlm_osp_t*)instance;
    osp_provider_t* provider = &data->provider;

    DEBUG3("rlm_osp: osp_detach start");

    /* Delete provider handle */
    OSPPProviderDelete(provider->handle, 0);

    /* Release instance data */
    free(instance);

    /* Reduce instance count */
    instance_count--;

    /* Cleanup OSP */
    if (instance_count == 0) {
        OSPPCleanup();
    }

    DEBUG3("rlm_osp: osp_detach success");

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
    OSP_STR_OSP,
    RLM_TYPE_THREAD_SAFE,   /* type */
    osp_instantiate,        /* instantiation */
    osp_detach,             /* detach */
    {
        NULL,               /* authentication */
        NULL,               /* authorization */
        NULL,               /* pre-accounting */
        osp_accounting,     /* accounting */
        NULL,               /* checksimul */
        NULL,               /* pre-proxy */
        NULL,               /* post-proxy */
        NULL                /* post-auth */
    },
};

