# NetworkMananger-l2tp

NetworkManager-l2tp is a VPN plugin for NetworkManager 1.2 and later which
provides support for L2TP and L2TP/IPsec (i.e. L2TP over IPsec) connections.

For L2TP support, it uses xl2tpd ( https://www.xelerance.com/software/xl2tpd/ )

For IPsec support, it uses either of the following :
* Libreswan ( https://libreswan.org )
* strongSwan ( https://www.strongswan.org )

For details on pre-built packages, known issues and build dependencies,
please visit the Wiki :
* https://github.com/nm-l2tp/network-manager-l2tp/wiki

## Building

    ./autogen.sh
    ./configure  # (see below)
    make

The default ./configure settings aren't reasonable and should be explicitly
overridden with ./configure arguments. In the configure examples below, you
may need to change the `--with-pppd-plugin-dir` value to an appropriate
directory that exists.

#### Debian and Ubuntu (AMD64, i.e. x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib/x86_64-linux-gnu \
      --libexecdir=/usr/lib/NetworkManager \
      --localstatedir=/var \
      --with-pppd-plugin-dir=/usr/lib/pppd/2.4.7

#### Fedora and Red Hat Enterprise Linux (x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib64 \
      --localstatedir=/var \
      --with-pppd-plugin-dir=/usr/lib64/pppd/2.4.7

#### openSUSE (x86-64)

    ./configure \
      --disable-static --prefix=/usr \
      --sysconfdir=/etc --libdir=/usr/lib64 \
      --libexecdir=/usr/lib \
      --localstatedir=/var \
      --with-pppd-plugin-dir=/usr/lib64/pppd/2.4.7

## Run-time generated files

* /var/run/nm-l2tp-xl2tpd-_UUID_.conf
* /var/run/nm-l2tp-ppp-options-_UUID_
* /var/run/nm-l2tp-xl2tpd-control-_UUID_
* /var/run/nm-l2tp-xl2tpd-_UUID_.pid
* /var/run/nm-l2tp-ipsec-_UUID_.conf
* /etc/ipsec.d/nm-l2tp-ipsec-_UUID_.secrets

where _UUID_ is the NetworkManager UUID for the VPN connection.

NetworkManager-l2tp will append the following line to `/etc/ipsec.secrets` at
run-time if the line is missing:

    include /etc/ipsec.d/*.secrets

The above files located under `/var/run` assume `--localstatedir=/var` or
`--runstatedir=/var/run` were supplied to the configure script at build time.

## Debugging

Issue the following on the command line which will increase xl2tpd and pppd
debugging, also the run-time generated config files will not be cleaned up
after a VPN disconnection :

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

NetworkManager and pppd logging goes to the Systemd journal which can be viewed
by issuing the following which will show the logs since the last boot:

    journalctl --boot

For non-Systemd based Linux distributions, view the appropriate system log
file which is most likely located under `/var/log/`.

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
Libreswan. As of strongSwan 5.4.0 and Libreswan 3.20, the above algorithms
(apart from SHA1 and MODP1536 for Libreswan which still includes them for
backwards compatibility) have been or in some cases already been removed from
the default set of allowed algorithms.

If you are not sure which IKEv1 algorithms your VPN server uses, you can query
the VPN server with the `ike-scan.sh` script located in the IPsec IKEv1
algorithms section of the Wiki :
* https://github.com/nm-l2tp/network-manager-l2tp/wiki/Known-Issues

If the VPN server is only proposing weak or broken algorithms, it is
recommended that it be reconfigured to propose stronger algorithms, e.g.
AES, SHA2 and MODP2048.

If for some reason the VPN server cannot be reconfigured and you are not too
concerned about security, for a workaround, user specified phase 1 (ike) and
phase 2 (esp) algorithms can be specified in the IPsec Options dialog box in
the `Advanced` section. See the following example and the IPsec IKEv1 algorithms section of the Wiki for more details :
* https://github.com/nm-l2tp/network-manager-l2tp/wiki/Known-Issues

### Example workaround for 3DES, SHA1 and MODP1024 broken algorithms

Unfortunately there are many L2TP/IPsec VPN servers still offering only 3DES,
SHA1 and MODP1024. One of the main reasons possibly for this is because it is
the default Microsoft has offered with their L2TP/IPsec VPN servers since the
days Windows XP was the main client.

If you are using strongSwan for IPsec client support, enter the following in
the corresponding IPsec Options dialog box advanced section:

* Phase1 Algorithms : 3des-sha1-modp1024
* Phase2 Algorithms : 3des-sha1

If you are using Libreswan >= 3.20 for IPsec client support, enter the
following in the IPsec Options dialog box advanced section:

* Phase1 Algorithms : 3des-sha1;modp1024
* Phase2 Algorithms : 3des-sha1


