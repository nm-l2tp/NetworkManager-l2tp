# NetworkMananger-l2tp

NetworkManager-l2tp is a VPN plugin for NetworkManager 1.0 which provides support for L2TP and
L2TP/IPsec (i.e. L2TP over IPsec) connections.

For L2TP support, it uses xl2tpd ( https://www.xelerance.com/software/xl2tpd/ )

For IPsec support, it uses either of the following :
* Libreswan ( https://libreswan.org ) 
* strongSwan ( https://www.strongswan.org )

## Building

    ./autogen.sh
    ./configure  # (optional, see below)
    make

The default ./configure settings aren't reasonable and should be explicitly overridden
with ./configure arguments. In the configure examples below, you may need to change the
`--with-pppd-plugin-dir` value to an appropriate directory that exists.

#### Debian and Ubuntu

./configure \
  --prefix=/usr --localstatedir=/var --sysconfdir=/etc \
  --libexecdir=/usr/lib/NetworkManager \
  --with-pppd-plugin-dir=/usr/lib/pppd/2.4.7

#### Fedora and Red Hat Enterprise Linux (x86-64)

    ./configure \
      --prefix=/usr --localstatedir=/var --sysconfdir=/etc \
      --sharedstatedir=/var/lib --libexecdir=/usr/libexec \
      --with-pppd-plugin-dir=/usr/lib64/pppd/2.4.7

## Debugging mode

Issue the following on the command line :

#### Debian and Ubuntu
    sudo killall -TERM nm-l2tp-service
    sudo /usr/lib/NetworkManager/nm-l2tp-service --debug

#### Fedora and Red Hat Enterprise Linux
    sudo killall -TERM nm-l2tp-service
    sudo /usr/libexec/nm-l2tp-service --debug
