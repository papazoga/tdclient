#ifndef TD_H
#define TD_H

#define LOG_FACILITY     LOG_DAEMON

#define debug(format,...)        if (debug_flag) fprintf(stderr, "<%s:%d> %s(): " format, __FILE__, __LINE__, __func__, ## __VA_ARGS__)
#if 0
#define error(format,...)        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), format, ## __VA_ARGS__)
#else
#define error(format,...)        fprintf(stderr, "tunneldigger-client: " format, ## __VA_ARGS__)
#endif

#define L2TP_UDP_OVERHEAD 40

#define TUNNEL_L2TP          1

/* 
 * Packet data
 */
#define P_TYPE(x)      (((unsigned char *)x)[4])
#define P_LEN(x)       (((unsigned char *)x)[5])
#define P_DATA(x)      ((char *)((unsigned char *)x + 6))

/* packet types */
#define PACKET_COOKIE     0x01
#define PACKET_PREPARE    0x02
#define PACKET_ERROR      0x03
#define PACKET_TUNNEL     0x04
#define PACKET_KEEPALIVE  0x05
#define PACKET_PMTUD      0x06
#define PACKET_PMTUD_ACK  0x07
#define PACKET_REL_ACK    0x08

#endif
