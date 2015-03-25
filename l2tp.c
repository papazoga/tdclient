#include <linux/l2tp.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/ctrl.h>
#include <netlink/utils.h>
#include <syslog.h>

#include "td.h"

static struct nl_sock *nl_sock;
static int l2tp_family;

int l2tp_init()
{
  int r;

  nl_sock = nl_socket_alloc();
  if (!nl_sock) {
    error("unable to open netlink socket!\n");
    exit(EXIT_FAILURE);
  }

  r = nl_connect(nl_sock, NETLINK_GENERIC);
  if (r<0) {
    error("unable to connect to netlink endpoint. are you root?\n");
    exit(EXIT_FAILURE);
  }

  l2tp_family = genl_ctrl_resolve(nl_sock, L2TP_GENL_NAME);
  if (l2tp_family < 0) {
    error("unable to resolve L2TP in netlink. missing modules?\n");
    exit(EXIT_FAILURE);
  }
}


int l2tp_create_tunnel(uint32_t local_tunnel_id, uint32_t remote_tunnel_id, int fd)
{
  struct nl_msg *msg = nlmsg_alloc();

  genlmsg_put(msg,		/* nl_msg */
	      NL_AUTO_PID,	/* port */
	      NL_AUTO_SEQ,	/* seq */
	      l2tp_family,	/* protocol family */
	      0,		/* header length */
	      NLM_F_REQUEST,	/* flags */
	      L2TP_CMD_TUNNEL_CREATE, /* command */
	      L2TP_GENL_VERSION);     /* version */

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, local_tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_PEER_CONN_ID, remote_tunnel_id);
  nla_put_u8(msg, L2TP_ATTR_PROTO_VERSION, 3);
  nla_put_u16(msg, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
  nla_put_u32(msg, L2TP_ATTR_FD, fd);

  nl_send_auto(nl_sock, msg);
  nlmsg_free(msg);

  int result = nl_wait_for_ack(nl_sock);

  if (result < 0)
    return -1;
  
}

int l2tp_create_session(uint32_t local_tunnel_id, uint32_t local_session_id, uint32_t remote_session_id, char *tunnel_ifname)
{
  struct nl_msg *msg = nlmsg_alloc();

  genlmsg_put(msg,		/* nl_msg */
	      NL_AUTO_PID,	/* port */
	      NL_AUTO_SEQ,	/* seq */
	      l2tp_family,	/* protocol family */
	      0,		/* header length */
	      NLM_F_REQUEST,	/* flags */
	      L2TP_CMD_SESSION_CREATE, /* command */
	      L2TP_GENL_VERSION);     /* version */

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, local_tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, local_session_id);
  nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, remote_session_id);
  nla_put_u16(msg, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
  nla_put_string(msg, L2TP_ATTR_IFNAME, tunnel_ifname);

  nl_send_auto(nl_sock, msg);
  nlmsg_free(msg);

  int result = nl_wait_for_ack(nl_sock);
  if (result < 0)
    return -1;
  
}

int l2tp_delete_session(uint32_t local_tunnel_id, uint32_t local_session_id, uint32_t remote_session_id, char *tunnel_ifname)
{
  struct nl_msg *msg = nlmsg_alloc();

  genlmsg_put(msg,		/* nl_msg */
	      NL_AUTO_PID,	/* port */
	      NL_AUTO_SEQ,	/* seq */
	      l2tp_family,	/* protocol family */
	      0,		/* header length */
	      NLM_F_REQUEST,	/* flags */
	      L2TP_CMD_SESSION_DELETE, /* command */
	      L2TP_GENL_VERSION);     /* version */

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, local_tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, local_session_id);
  nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, remote_session_id);
  nla_put_u16(msg, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
  nla_put_string(msg, L2TP_ATTR_IFNAME, tunnel_ifname);

  nl_send_auto(nl_sock, msg);
  nlmsg_free(msg);

  int result = nl_wait_for_ack(nl_sock);
  if (result < 0)
    return -1;
  
}

int l2tp_delete_tunnel(uint32_t local_tunnel_id, uint32_t remote_tunnel_id, int fd)
{
  struct nl_msg *msg = nlmsg_alloc();

  genlmsg_put(msg,		/* nl_msg */
	      NL_AUTO_PID,	/* port */
	      NL_AUTO_SEQ,	/* seq */
	      l2tp_family,	/* protocol family */
	      0,		/* header length */
	      NLM_F_REQUEST,	/* flags */
	      L2TP_CMD_TUNNEL_DELETE, /* command */
	      L2TP_GENL_VERSION);     /* version */

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, local_tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_PEER_CONN_ID, remote_tunnel_id);
  nla_put_u8(msg, L2TP_ATTR_PROTO_VERSION, 3);
  nla_put_u16(msg, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
  nla_put_u32(msg, L2TP_ATTR_FD, fd);

  nl_send_auto(nl_sock, msg);
  nlmsg_free(msg);

  int result = nl_wait_for_ack(nl_sock);

  if (result < 0)
    return -1;
  
}
