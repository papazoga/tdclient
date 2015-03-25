#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/errqueue.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "td.h"

#define LOG_FACILITY     LOG_DAEMON

#define BUFSIZE   2048

struct tunsess {
  int sockfd;
  struct sockaddr_in remote_sa;
  struct sockaddr_in local_sa;
  struct timespec last_seen;
  socklen_t remote_sl;
  socklen_t local_sl;
  int local_port;
  uint32_t remote_tunid;
  uint32_t local_tunid;
  char cookie[16];
  char *ifname;
  int pmtu;
  char outbuf[BUFSIZE];
  int outlen;
  char inbuf[BUFSIZE];
  int inlen;
  int close_flag;
};

int dont_daemonize = 0;
int debug_flag = 0;
char *uuid = NULL;
char *local_ip = "0.0.0.0";
char *ifname = "l2tp0";
char *script = NULL;
int tunnel_id = 1;
int limit_down = -1;
struct tunsess *current;

void signal_handler(int);

int parse_broker(char *s, char **hostname, char **service)
{
  char *p;
  int len = 0;
  
  /* find the separator */
  for (p=s;*p && (*p) != ':';p++)
    len++;

  /* invalid without a separator */
  if (*p == 0)
    goto error_out;

  *hostname = malloc(len);
  strncpy(*hostname, s, len);
  (*hostname)[len] = 0;
  *service = strdup(++p);
  
  return 0;
  
 error_out:
  return -1;
}

void dump_packet(char *buf, int len)
{
  int i;

  for (i=0;i<len;i++) {
    printf ("%02X", (uint8_t)buf[i]);
    if (i % 16 == 15)
      fputc ('\n', stdout);
    else
      fputc (' ', stdout);
  }

  if (i % 16 != 0)
    fputc('\n', stdout);
}

/* 
 * Subtract timespecs with carry.
 */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int nsec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
    y->tv_nsec -= 1000000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_nsec - y->tv_nsec > 1000000000) {
    int nsec = (x->tv_nsec - y->tv_nsec) / 1000000000;
    y->tv_nsec += 1000000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_nsec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_nsec = x->tv_nsec - y->tv_nsec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

/* 
 * Detect MTU using Linux error queues (not used).
 */
int detect_mtu(int sockfd)
{
  struct sockaddr_in sa;
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct sock_extended_err *e = 0;
  char cbuf[512];
  char inbuf[512];
  int res;
  int mtu = -1;

  iov.iov_base = inbuf;  /* Should be unused */
  iov.iov_len = 512;

  msg.msg_name = &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  res = recvmsg(sockfd, &msg, MSG_ERRQUEUE);

  if (res > 0)			/* not sure if this can happen */
    return -1;

  if (res < 0 && errno == EAGAIN)
    return -1;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_IP || cmsg->cmsg_type != IP_RECVERR)
      continue;

    e = (struct sock_extended_err *)CMSG_DATA(cmsg);
    if (!e || e->ee_errno != EMSGSIZE)
      continue;

    mtu = e->ee_info;
  }

  return mtu;
}

/* 
 * Detect MTU via sockopt (not used).
 */
int get_mtu_sockopt(int sockfd, int *path_mtu)
{
  socklen_t len;

  len = sizeof(*path_mtu);
  if (getsockopt(sockfd, SOL_IP, IP_MTU, path_mtu, &len) < 0) {
    debug("unable to retrieve MTU\n");
    return -1;
  }
  return 0;
}

int lookup(char *hostname, char *service, struct sockaddr_in *sa, socklen_t *sl, int flags)
{
  struct addrinfo hints;
  struct addrinfo *res = 0;
  int s;
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = flags;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  s = getaddrinfo(hostname, service, &hints, &res);

  if (res) {
    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *sl = res->ai_addrlen;
    freeaddrinfo(res);
  } else {
    *sl = 0;
  }

  return s;
}

void print_help()
{
}

struct tunsess *ts_new(char *hostname, char *service)
{
  struct tunsess *tun;
  int r;

  tun = malloc(sizeof(struct tunsess));
  if (!tun)
    return NULL;

  tun->local_tunid = 1;
  tun->close_flag = 0;

  /* look up the local address */
  if ((r = lookup(local_ip, NULL, &tun->local_sa, &tun->local_sl, AI_PASSIVE)) != 0) {
    error("unable to resolve local endpoint: %s\n", gai_strerror(r));
    return NULL;
  }

  /* look up the remote address */
  if ((r=lookup(hostname, service, &tun->remote_sa, &tun->remote_sl, 0)) != 0) {
    error("unable to perform resolution: %s\n", gai_strerror(r));
    return NULL;
  }

  return tun;
}

int ts_socket_bind_connect(struct tunsess *tun)
{
  int r;
  int optval;

  tun->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (tun->sockfd < 0)
    return -1;

  optval = IP_PMTUDISC_PROBE;
  setsockopt(tun->sockfd, SOL_IP, IP_MTU_DISCOVER, &optval, sizeof(optval));

  optval = 1;
  setsockopt(tun->sockfd, SOL_IP, IP_RECVERR, &optval, sizeof(optval));

  tun->local_sl = sizeof(tun->local_sa);

  r = bind(tun->sockfd, (struct sockaddr *)&tun->local_sa, tun->local_sl);
  if (r<0)
    return r;

  /* get the local port */
  r = getsockname(tun->sockfd, (struct sockaddr *)&tun->local_sa, &tun->local_sl);
  if (r<0)
    return r;

  r = connect(tun->sockfd, (struct sockaddr *)&tun->remote_sa, sizeof(tun->remote_sa));
  tun->local_port = ntohs(tun->local_sa.sin_port);

  return 0;
}

/* 
 * Compose a packet according to a format string.
 */
void ts_compose_packet(struct tunsess *tun, int type, char *fmt, ...)
{
  char *p = tun->outbuf;
  char *f, *s;
  unsigned char *lenp;
  va_list argp;
  int slen, len;
  uint8_t b;
  uint16_t w;
  uint32_t l;

  va_start(argp, fmt);
  
  *p++ = 0x80;
  *p++ = 0x73;
  *p++ = 0xa7;
  *p++ = 0x01;
  *p++ = type;
  lenp = p++;

  for (f=fmt;*f;f++) {
    switch (*f) {
    case 's':			/* string */
      s = va_arg(argp, char *);
      slen = strlen(s);
      *p++ = slen;
      memcpy(p, s, slen);
      p += slen;
      break;
    case 'b':			/* byte */
      b = va_arg(argp, int);
      *p++ = b;
      break;
    case 'w':			/* 16-bit word */
      w = va_arg(argp, int);
      *(uint16_t *)p = ntohs(w);
      p += 2;
      break;
    case 'l':			/* 32-bit word */
      l = va_arg(argp, int);
      *(uint32_t *)p = ntohl(l);
      p += 4;
      break;
    case 'C':			/* 8-byte cookie */
      s = va_arg(argp, char *);
      memcpy(p, s, 8);
      p += 8;
      break;
    }
  }

  tun->outlen = p - tun->outbuf;
  *lenp = tun->outlen - 6;
}

/* 
 * Verify that a received packet conforms
 * to the protocol.
 */
int ts_verify_packet(struct tunsess *tun)
{
  uint8_t *p = tun->inbuf;

  if (*p++ == 0x80 &&
      *p++ == 0x73 &&
      *p++ == 0xa7 &&
      *p++ == 0x01)
    return 1;
  else
    return 0;
}

int ts_set_mtu(struct tunsess *tun, int mtu)
{
  struct ifreq ifr;
  int r;
  debug("setting mtu of '%s' to %d\n", tun->ifname, mtu);

  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, tun->ifname);
  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_mtu = mtu;
  r = ioctl(tun->sockfd, SIOCSIFMTU, (caddr_t)&ifr);

  if (r<0)
    debug("failed: %s\n", strerror(errno));
}

int ts_send_packet(struct tunsess *tun)
{
  int r;
  int mtu;

  r = sendto(tun->sockfd,
	     tun->outbuf,
	     tun->outlen,
	     0,
	     (struct sockaddr *)&tun->remote_sa,
	     tun->remote_sl);

  if (r<0) {
    if (errno == EMSGSIZE) {
      mtu = detect_mtu(tun->sockfd);
      if (mtu != tun->pmtu)
	ts_set_mtu(tun, mtu-60);
      debug("got MTU: %d\n", mtu);	
    } else {
      debug("huh? errno==%d, '%s')\n", r, errno, strerror(errno));
    }
  }
  return r;
}

int ts_recv_packet(struct tunsess *tun)
{
  int r;
  r = recv(tun->sockfd, tun->inbuf, BUFSIZE, MSG_DONTWAIT);
  clock_gettime(CLOCK_MONOTONIC, &tun->last_seen);

  if (r < 0)
    return -1;

  tun->inlen = r;
  return 0;
}


/* 
 * Wait for an appropriate response packet for 'secs' seconds.
 * Appropriateness is checked by calling callback(), which must return
 * a non-zero value to cancel the select loop.
 *
 * Returns 0 on success, -1 on failure (timeout).
 */
int ts_packet_wait(struct tunsess *tun, int secs, int (*callback)(struct tunsess *))
{
  fd_set rfds;
  struct timespec ts_wait;
  struct timespec ts_end;
  struct timespec ts_current;
  int r;

  FD_ZERO(&rfds);
  FD_SET(tun->sockfd, &rfds);

  clock_gettime(CLOCK_MONOTONIC, &ts_end);
  ts_end.tv_sec += secs;

 do_select:
  clock_gettime(CLOCK_MONOTONIC, &ts_current);
  current = tun;

  if (timespec_subtract(&ts_wait, &ts_end, &ts_current) == 1)
    goto timed_out;

  r = pselect(tun->sockfd+1, &rfds, NULL, NULL, &ts_wait, NULL);
  if (r==1) {
    ts_recv_packet(tun);
    if (callback(tun) == 0)
      return 0;
  }

  if (!tun->close_flag)
    goto do_select;

 timed_out:
  return -1;
}

int cookie_cb(struct tunsess *tun)
{
  if (P_TYPE(tun->inbuf) == PACKET_COOKIE) {
    debug("received COOKIE 0x%16lx\n", *(uint64_t *)P_DATA(tun->inbuf));
    memcpy(tun->cookie, P_DATA(tun->inbuf), 8);
    tun->cookie[8] = 0;
    return 0;
  } else {
    return -1;
  }
}

#define COOKIE_TIMEOUT      5
#define COOKIE_RETRIES      3

int ts_get_cookie(struct tunsess *tun)
{
  int tries;
  ts_compose_packet(tun, PACKET_COOKIE, "C", "XXXXXXXX");

  for (tries=0;tries<COOKIE_RETRIES;tries++) {
    ts_send_packet(tun);
    if (ts_packet_wait(tun, COOKIE_TIMEOUT, cookie_cb) == 0)
      return 0;
  }

  return -1;
}


/* 
 * This callback responds to PMTU requests, too. It
 * returns 0 only for teardowns.
 */
int keepalive_cb(struct tunsess *tun)
{
  if (!ts_verify_packet(tun))
    return 0;
    
  switch (P_TYPE(tun->inbuf)) {
  case PACKET_KEEPALIVE:
    debug("received KEEPALIVE\n");
    break;
  case PACKET_PMTUD:
    debug("received PMTUD with size %d\n", tun->inlen);
    ts_compose_packet(tun, PACKET_PMTUD_ACK, "w", tun->inlen);
    ts_send_packet(tun);
    debug("sent PMTUD ACK\n");
    break;
  case PACKET_PMTUD_ACK:
    debug("received PMTUD ACK\n");
    break;
  case PACKET_ERROR:
    debug("received teardown request\n");
    return 0;
    break;
  default:
    debug("received unexpected packet of size %d\n", tun->inlen);
    dump_packet(tun->inbuf, tun->inlen);
  }

  return -1;
}

/* These are in seconds */
#define KEEPALIVE_INTERVAL    3
#define KEEPALIVE_TIMELIMIT   30

void ts_keepalive(struct tunsess *tun)
{
  struct timespec t;

  for (;;) {
    /* check MTU */
    ts_compose_packet(tun, PACKET_KEEPALIVE, "");
    tun->outlen = 2048;
    ts_send_packet(tun);

    if (ts_packet_wait(tun, KEEPALIVE_INTERVAL, keepalive_cb) == 0 || tun->close_flag)
      return;

    clock_gettime(CLOCK_MONOTONIC, &t);
    timespec_subtract(&t, &t, &tun->last_seen);

    debug("last seen: %d seconds ago.\n", t.tv_sec);
    if (t.tv_sec >= KEEPALIVE_TIMELIMIT) {
      error("tunnel timed out. shutting down.\n");
      return;
    }

    ts_compose_packet(tun, PACKET_KEEPALIVE, "");
    ts_send_packet(tun);
    debug("sent KEEPALIVE\n");
  }
}

#define TUNNEL_TIMEOUT      5
#define TUNNEL_RETRIES      3

int tunnel_cb(struct tunsess *tun)
{
  if (P_TYPE(tun->inbuf) == PACKET_TUNNEL) {
    tun->remote_tunid = ntohl(*(uint32_t *)P_DATA(tun->inbuf));
    debug("received TUNNEL. Remote tunnel ID is %d.\n", tun->remote_tunid);
    return 0;
  } else
    return -1;
}


int ts_close(struct tunsess *tun)
{
  ts_compose_packet(tun, PACKET_ERROR, "");
  ts_send_packet(tun);
  close(tun->sockfd);
  free(tun);
}

int ts_get_tunnel(struct tunsess *tun)
{
  int tries;
  int uuidlen = strlen(uuid);
  uint16_t *tidp;
  char *uuidp;

  ts_compose_packet(tun, PACKET_PREPARE, "Csw", tun->cookie, uuid, htons(1));

  for (tries=0;tries<TUNNEL_RETRIES;tries++) {
    ts_send_packet(tun);
    if (ts_packet_wait(tun, TUNNEL_TIMEOUT, tunnel_cb) == 0)
      return 0;
  }

  return -1;
}


int ts_create_tunnel(struct tunsess *tun)
{
  if (l2tp_create_tunnel(tun->local_tunid, tun->remote_tunid, tun->sockfd) < 0 ||
      l2tp_create_session(tun->local_tunid, 1, 1, tun->ifname) < 0)
    return -1;
  return 0;
}

int ts_delete_tunnel(struct tunsess *tun)
{
  if (l2tp_delete_session(tun->local_tunid, 1, 1, tun->ifname) < 0 ||
      l2tp_delete_tunnel(tun->local_tunid, tun->remote_tunid, tun->sockfd) < 0)
    return -1;
  return 0;
}

void signal_handler(int signum)
{
  switch(signum) {
  case SIGINT:
    current->close_flag = 1;
    break;
  }
}

int main(int argc, char **argv)
{
  int c, r;
  char *hostname, *service;
  struct tunsess *tun;
  struct sigaction sigact;
  int local_tunid;
  
  openlog("tunneldigger-client", 0, 0);

  while ((c = getopt(argc, argv, "dhfu:l:b:p:i:s:t:L:")) != EOF) {
    switch (c) {
    case 'h':			/* show help */
      print_help();
      exit(EXIT_SUCCESS);
      break;
    case 'f':			/* don't daemonize */
      dont_daemonize = 1;
      break;
    case 'd':
      debug_flag = 1;
      break;
    case 'u':			/* connection UUID */
      uuid = strdup(optarg);
      break;
    case 'l':			/* local IP address */
      local_ip = strdup(optarg);
      break;
    case 'b':			/* broker in <host>:<port> form */
      if (parse_broker(optarg, &hostname, &service) != 0) {
	fprintf(stderr, "invalid broker specification\n");
	exit(EXIT_FAILURE);
      }
      break;
    case 'i':			/* tunnel interface name */
      ifname = strdup(optarg);
      break;
    case 's':			/* hook script */
      script = strdup(optarg);
      break;
    case 't':			/* tunnel id */
      local_tunid = atoi(optarg);
      break;
    case 'L':			/* limit bandwidth down */
      limit_down = atoi(optarg);
      break;
    default:
      fprintf(stderr, "use '-h' for help\n", c);
      break;
    }
  }

  l2tp_init();

  if (!uuid) {
    printf ("the uuid is required\n");
    exit(EXIT_FAILURE);
  }

  tun = ts_new(hostname, service);
  tun->local_tunid = local_tunid;
  tun->ifname = strdup(ifname);

  /* create and bind a socket, and connect it */
  if ((r=ts_socket_bind_connect(tun)) != 0) {
    error("unable to obtain bound socket\n");
    exit(EXIT_FAILURE);
  }

  /* request a cookie */
  if ((r=ts_get_cookie(tun)) != 0) {
    error("unable to get cookie\n");
    exit(EXIT_FAILURE);
  }

  /* request a tunnel */
  if ((r=ts_get_tunnel(tun)) != 0) {
    error("unable to get tunnel\n");
    exit(EXIT_FAILURE);
  }

  /* create the tunnel */
  if (ts_create_tunnel(tun) != 0) {
    error("unable to create tunnel (is l2tp_eth loaded?)!\n");
    exit(EXIT_FAILURE);
  }

  /* handle SIGINT */
  sigact.sa_handler = signal_handler;
  sigemptyset(&sigact.sa_mask);
  if (sigaction(SIGINT, &sigact, NULL) < 0) {
    error("couldn't set signal handler\n");
  }

  /* keep the tunnel alive, and respond to PMTU discovery requests */
  ts_keepalive(tun);

  error("closing tunnel\n");

  if (ts_delete_tunnel(tun) != 0) {
    error("unable to delete tunnel!\n");
    exit(EXIT_FAILURE);
  }

  ts_close(tun);
}
