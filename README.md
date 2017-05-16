# NetworkMananger-l2tp

NetworkManager-l2tp is a VPN plugin for NetworkManager 1.2 and later which
provides support for L2TP and L2TP/IPsec (i.e. L2TP over IPsec) connections.

For L2TP support, it uses xl2tpd ( https://www.xelerance.com/software/xl2tpd/ )

For IPsec support, it uses either of the following :
* Libreswan ( https://libreswan.org )
* strongSwan ( https://www.strongswan.org )

For details on pre-built packages, known issues and build package dependencies,
please visit the Wiki :
* https://github.com/nm-l2tp/network-manager-l2tp/wiki

## Building

    ./autogen.sh
    ./configure  # (optional, see below)
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

## Debugging

Issue the following on the command line which will increase xl2tpd and pppd
debugging :

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

The above files located under `/var/run` assume `--localstatedir=/var`was
supplied to the configure script at build time.

## User specified IPsec IKEv1 cipher suites

User specified phase 1 (ike) and phase 2 (esp) cipher suites that supplement
the default strongSwan or Libreswan cipher suites can be specified in the
IPsec configuration dialog box under Advanced options.

For example if you have no control of the cipher suites the VPN server uses
and you need to use the same ciphers (which are now most likely considered
broken) that older versions of strongSwan and this VPN plugin used, enter the
following in the corresponding IPsec configuration dialog text boxes:

* Phase1 Algorithms : aes128-sha1-modp2048,3des-sha1-modp1536,3des-sha1-modp1024
* Phase2 Algorithms : aes128-sha1,3des-sha1

Please see the following for more details on the `ike` (phase 1) and
`esp` (phase2alg) directives, including the syntax:

* https://wiki.strongswan.org/projects/strongswan/wiki/ConnSection
* https://libreswan.org/man/ipsec.conf.5.html

The following has recommendations on algorithms that are considered broken in
regards to security and advises against using them:
* https://wiki.strongswan.org/projects/strongswan/wiki/SecurityRecommendations

The current list of broken algorithms and Diffie Hellman groups can be found
here :
* https://wiki.strongswan.org/projects/strongswan/wiki/IKEv1CipherSuites

strongSwan 5.4.0 dropped the following phase 1 (IKE) cipher suites as defaults:

    aes128-sha1-modp2048,3des-sha1-modp1536

and for phase 2 (ESP), strongSwan 5.4.0 dropped :

    aes128-sha1,3des-sha1

Older versions of NetworkManager-l2tp also used 3des-sha1-modp1024 for phase 1.

