// SPDX-License-Identifier: GPL-2.0+
/* nm-l2tp-service - L2TP VPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2008, 2014 Red Hat, Inc.
 */

#ifndef NM_L2TP_SERVICE_DEFINES_H
#define NM_L2TP_SERVICE_DEFINES_H

#define NM_DBUS_SERVICE_L2TP    "org.freedesktop.NetworkManager.l2tp"

/* For the NM <-> VPN plugin service */
#define NM_DBUS_INTERFACE_L2TP  "org.freedesktop.NetworkManager.l2tp"
#define NM_DBUS_PATH_L2TP       "/org/freedesktop/NetworkManager/l2tp"

/* For the VPN plugin service <-> PPP plugin */
#define NM_DBUS_INTERFACE_L2TP_PPP  "org.freedesktop.NetworkManager.l2tp.ppp"
#define NM_DBUS_PATH_L2TP_PPP       "/org/freedesktop/NetworkManager/l2tp/ppp"

#define NM_L2TP_KEY_GATEWAY           "gateway"
#define NM_L2TP_KEY_USER_AUTH_TYPE    "user-auth-type"
#define NM_L2TP_KEY_USER              "user"
#define NM_L2TP_KEY_PASSWORD          "password"
#define NM_L2TP_KEY_DOMAIN            "domain"
#define NM_L2TP_KEY_USER_CA           "user-ca"
#define NM_L2TP_KEY_USER_CERT         "user-cert"
#define NM_L2TP_KEY_USER_KEY          "user-key"
#define NM_L2TP_KEY_USER_CERTPASS     "user-certpass"
#define NM_L2TP_KEY_MTU               "mtu"
#define NM_L2TP_KEY_MRU               "mru"
#define NM_L2TP_KEY_REFUSE_EAP        "refuse-eap"
#define NM_L2TP_KEY_REFUSE_PAP        "refuse-pap"
#define NM_L2TP_KEY_REFUSE_CHAP       "refuse-chap"
#define NM_L2TP_KEY_REFUSE_MSCHAP     "refuse-mschap"
#define NM_L2TP_KEY_REFUSE_MSCHAPV2   "refuse-mschapv2"
#define NM_L2TP_KEY_REQUIRE_MPPE      "require-mppe"
#define NM_L2TP_KEY_REQUIRE_MPPE_40   "require-mppe-40"
#define NM_L2TP_KEY_REQUIRE_MPPE_128  "require-mppe-128"
#define NM_L2TP_KEY_MPPE_STATEFUL     "mppe-stateful"
#define NM_L2TP_KEY_NOBSDCOMP         "nobsdcomp"
#define NM_L2TP_KEY_NODEFLATE         "nodeflate"
#define NM_L2TP_KEY_NO_VJ_COMP        "no-vj-comp"
#define NM_L2TP_KEY_NO_PCOMP          "nopcomp"
#define NM_L2TP_KEY_NO_ACCOMP         "noaccomp"
#define NM_L2TP_KEY_LCP_ECHO_FAILURE  "lcp-echo-failure"
#define NM_L2TP_KEY_LCP_ECHO_INTERVAL "lcp-echo-interval"
#define NM_L2TP_KEY_UNIT_NUM          "unit"
#define NM_L2TP_KEY_MACHINE_AUTH_TYPE "machine-auth-type"
#define NM_L2TP_KEY_MACHINE_CA        "machine-ca"
#define NM_L2TP_KEY_MACHINE_CERT      "machine-cert"
#define NM_L2TP_KEY_MACHINE_KEY       "machine-key"
#define NM_L2TP_KEY_MACHINE_CERTPASS  "machine-certpass"
#define NM_L2TP_KEY_IPSEC_ENABLE      "ipsec-enabled"
#define NM_L2TP_KEY_IPSEC_REMOTE_ID   "ipsec-remote-id"
#define NM_L2TP_KEY_IPSEC_GATEWAY_ID  "ipsec-gateway-id" /* deprecated, use ipsec-remote-id */
#define NM_L2TP_KEY_IPSEC_PSK         "ipsec-psk"
#define NM_L2TP_KEY_IPSEC_IKE         "ipsec-ike"
#define NM_L2TP_KEY_IPSEC_ESP         "ipsec-esp"
#define NM_L2TP_KEY_IPSEC_IKELIFETIME "ipsec-ikelifetime"
#define NM_L2TP_KEY_IPSEC_SALIFETIME  "ipsec-salifetime"
#define NM_L2TP_KEY_IPSEC_FORCEENCAPS "ipsec-forceencaps"
#define NM_L2TP_KEY_IPSEC_IPCOMP      "ipsec-ipcomp"
#define NM_L2TP_KEY_IPSEC_IKEV2       "ipsec-ikev2"
#define NM_L2TP_KEY_IPSEC_PFS         "ipsec-pfs"

/* Internal auth-dialog -> service token indicating that no secrets are required
 * for the connection if X.509 private keys are used with no password protection.
 */
#define NM_L2TP_KEY_NOSECRET          "no-secret"

#define NM_L2TP_AUTHTYPE_PASSWORD     "password"
#define NM_L2TP_AUTHTYPE_TLS          "tls"
#define NM_L2TP_AUTHTYPE_PSK          "psk"
#endif /* NM_L2TP_SERVICE_DEFINES_H */
