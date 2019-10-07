# NetworkMananger-l2tp

NetworkManager-l2tp is a VPN plugin for NetworkManager 1.2 and later which
provides support for L2TP and L2TP/IPsec (i.e. L2TP over IPsec) connections.

For L2TP support, it uses xl2tpd ( https://www.xelerance.com/software/xl2tpd/ )

For IPsec support, it uses either of the following :
* Libreswan ( https://libreswan.org )
* strongSwan ( https://www.strongswan.org )

For details on pre-built packages, known issues and build dependencies,
please visit the Wiki :
* https://github.com/nm-l2tp/NetworkManager-l2tp/wiki

## Building

    ./autogen.sh
    ./configure  # (see below)
    make

The default ./configure settings aren't reasonable and should be explicitly
overridden with ./configure arguments. In the configure examples below, you
may need to change the `--with-pppd-plugin-dir` value to an appropriate
directory that exists.

#### Debian >= 10 and Ubuntu >= 18.04 (AMD64, i.e. x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib/x86_64-linux-gnu \
      --libexecdir=/usr/lib/NetworkManager \
      --localstatedir=/var \
      --with-pppd-plugin-dir=/usr/lib/pppd/2.4.7

#### Debian 9 and Ubuntu 16.04 (AMD64, i.e. x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib/x86_64-linux-gnu \
      --libexecdir=/usr/lib/NetworkManager \
      --localstatedir=/var \
      --with-libnm-glib \
      --with-pppd-plugin-dir=/usr/lib/pppd/2.4.7

#### Fedora >= 28 and Red Hat Enterprise Linux 8 (x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib64 \
      --localstatedir=/var \
      --with-pppd-plugin-dir=/usr/lib64/pppd/2.4.7

#### Red Hat Enterprise Linux 7 (x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib64 \
      --localstatedir=/var \
      --with-libnm-glib \
      --with-pppd-plugin-dir=/usr/lib64/pppd/2.4.7

#### openSUSE (x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib64 \
      --libexecdir=/usr/lib \
      --localstatedir=/var \
      --with-pppd-plugin-dir=/usr/lib64/pppd/2.4.7

## Run-time generated files

The following files located under `/var/run` assume `--localstatedir=/var` or
`--runstatedir=/var/run` were supplied to the configure script at build time.

* /var/run/nm-l2tp-_UUID_/xl2tpd.conf
* /var/run/nm-l2tp-_UUID_/xl2tpd-control
* /var/run/nm-l2tp-_UUID_/xl2tpd.pid
* /var/run/nm-l2tp-_UUID_/ppp-options
* /var/run/nm-l2tp-_UUID_/ipsec.conf
* /etc/ipsec.d/ipsec.nm-l2tp.secrets

where _UUID_ is the NetworkManager UUID for the VPN connection.

If strongswan is being used, NetworkManager-l2tp will append the following line
to `/etc/ipsec.secrets` at run-time if the line is missing:

    include ipsec.d/ipsec.nm-l2tp.secrets

## Debugging

For Systemd based Linux distributions logging goes to the Systemd journal
which can be viewed by issuing the following :

    journalctl --unit=NetworkManager

For non-Systemd based Linux distributions, view the appropriate system log
file which is most likely located under `/var/log/`.

### Increase Debugging Output

To increase debugging output, issue the following on the command line, it
will also prevent the run-time generated config files from being deleted after
the VPN connection is disconnected :

#### Debian and Ubuntu
    sudo killall -TERM nm-l2tp-service
    sudo /usr/lib/NetworkManager/nm-l2tp-service --debug

#### Fedora and Red Hat Enterprise Linux
    sudo killall -TERM nm-l2tp-service
    sudo /usr/libexec/nm-l2tp-service --debug

#### openSUSE
    sudo killall -TERM nm-l2tp-service
    sudo /usr/lib/nm-l2tp-service --debug

then start your VPN connection and reproduce the problem.

For Systemd based Linux distributions when increasing the debugging output
by running `nm-l2tp-service --debug` on the command-line, do not use
`journalctl --unit=NetworkManager` as you may not see all the logs, instead
issue:

    journalctl -b

### Libreswan Custom Debugging

The Libreswan debugging can be cutomized by setting the `PLUTODEBUG` env
variable which corresponds to the `plutodebug` ipsec.conf config section option.
The syntax for `PLUTODEBUG` is a white-space separated list of the following
format :

    PLUTODEBUG="TYPE TYPE ... TYPE"

Where TYPE is a debug option from the list output by issuing the following on
the command-line :

    ipsec whack --debug list

*Examples:*

#### Debian and Ubuntu
    sudo PLUTODEBUG="all proposal-parser" /usr/lib/NetworkManager/nm-l2tp-service --debug

#### Fedora and Red Hat Enterprise Linux
    sudo PLUTODEBUG="all proposal-parser" /usr/libexec/nm-l2tp-service --debug

### strongSwan Custom Debugging

The strongSwan debugging can be cutomized by setting the `CHARONDEBUG` env
variable which corresponds to the `charondebug` ipsec.conf config section option.
The syntax for `CHARONDEBUG` is a comma separated list of the following format :

    CHARONDEBUG="TYPE LEVEL, TYPE LEVEL, ..., TYPE LEVEL"

where TYPE is:
  any|dmn|mgr|ike|chd|job|cfg|knl|net|asn|enc|tnc|imc|imv|pts|tls|esp|lib

and LEVEL is: -1|0|1|2|3|4

*Examples:*

#### Debian and Ubuntu
    sudo CHARONDEBUG="knl 1, ike 2, esp 2, lib 1, cfg 3" /usr/lib/NetworkManager/nm-l2tp-service --debug

#### Fedora and Red Hat Enterprise Linux
    sudo CHARONDEBUG="knl 1, ike 2, esp 2, lib 1, cfg 3" /usr/libexec/nm-l2tp-service --debug

#### openSUSE
    sudo CHARONDEBUG="knl 1, ike 2, esp 2, lib 1, cfg 3" /usr/lib/nm-l2tp-service --debug

## Issue with not stopping system xl2tpd service

NetworkManager-l2tp starts its own instance of xl2tpd and if the system xl2tpd
service is running, its own xl2tpd instance will not be able to use UDP port
1701, so will use an ephemeral port (i.e. random high port).

Although the use of an ephemeral port is considered acceptable in RFC3193, the
L2TP/IPsec standard co-authored by Microsoft and Cisco, there are some
L2TP/IPsec servers and/or firewalls that will have issues if an ephemeral port
is used.

Stopping the system xl2tpd service should free UDP port 1701 and on systemd
based Linux distributions, the xl2tpd service can be stopped with the
following:

    sudo systemctl stop xl2tpd

If stopping the xl2tpd service fixes your VPN connection issue, you can
disable the xl2tpd service from starting at boot time with :

    sudo systemctl disable xl2tpd

## Issue with VPN servers only proposing IPsec IKEv1 weak legacy algorithms

If you are not able to connect to a L2TP/IPsec server, but have no issue
connecting with a Windows 10 or macOS/iOS/iPadOS L2TP client, please also see
the Prevalent IKEv1 algorithms section below.

There is a general consensus that the following legacy algorithms are now
considered weak or broken in regards to security and should be phased out and
replaced with stronger algorithms.

Encryption Algorithms :
* 3DES
* Blowfish

Integrity Algorithms :
* MD5
* SHA1

Diffie Hellman Groups :
* MODP768
* MODP1024
* MODP1536

Legacy algorithms that are considered weak or broken are regularly removed from
the default set of allowed algorithms with newer releases of strongSwan and
Libreswan.

As of strongSwan 5.4.0, the above algorithms have been removed from
strongSwan's default set of allowed algorithms.

As of Libreswan 3.20, the above algorithms have been removed from Libreswan's
default set of allowed algorithms, except for 3DES, SHA1 and MODP1536 which
were kept for backwards compatibility.

If you are not sure if you are using Libreswan or Strongswan, issue the
following on the command-line:

```
ipsec --version
```

If you are not sure which IKEv1 algorithms your VPN server proposes, you can
query the VPN server with the `ike-scan.sh` script located in the IPsec IKEv1
algorithms section of the Wiki :
* https://github.com/nm-l2tp/NetworkManager-l2tp/wiki/Known-Issues

If for some reason the VPN server cannot be reconfigured or does not share any
proposals in the Libreswan or Strongswan default set of allowed algorithms,
user specified phase 1 (*ike* - Main Mode) and phase 2 (*esp* - Quick Mode)
algorithms can be specified in the **Advanced** section of NetworkManager-l2tp's
IPsec Options dialog box. Please see the Libreswan or openSwan `ipsec.conf`
documentation for the *ike* and *esp* (aka *phase2alg*) syntax.

### Prevalent IKEv1 algorithms

Pressing the **Prevalent Algorithms** button in the IPsec Options dialog box
populates the Phase 1 and 2 Algorithm text entry boxes with the following
proposals, which are a merge of Windows 10 and macOS/iOS/iPadOS L2TP clients'
IKEv1 proposals (**note:** it auto-detects if you are using strongSwan or
Libreswan and populates appropriately with the correct syntax):

* Phase 1 - Main Mode :
{enc=AES_CBC_256 integ=HMAC_SHA2_256_128 group=MODP_2048},
{enc=AES_CBC_256 integ=HMAC_SHA2_256_128 group=MODP_1536},
{enc=AES_CBC_256 integ=HMAC_SHA2_256_128 group=MODP_1024},
{enc=AES_CBC_256 integ=HMAC_SHA1_96 group=MODP_2048},
{enc=AES_CBC_256 integ=HMAC_SHA1_96 group=MODP_1536},
{enc=AES_CBC_256 integ=HMAC_SHA1_96 group=MODP_1024},
{enc=AES_CBC_256 integ=HMAC_SHA1_96 group=ECP_384},
{enc=AES_CBC_128 integ=HMAC_SHA1_96 group=MODP_1024},
{enc=AES_CBC_128 integ=HMAC_SHA1_96 group=ECP_256},
{enc=3DES_CBC integ=HMAC_SHA1_96 group=MODP_2048},
{enc=3DES_CBC integ=HMAC_SHA1_96 group=MODP_1024}

* Phase 2 - Quick Mode :
{enc=AES_CBC_256 integ=HMAC_SHA1_96},
{enc=AES_CBC_128 integ=HMAC_SHA1_96},
{enc=3DES_CBC integ=HMAC_SHA1_96}

