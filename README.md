# peervpn
The open source [peer-to-peer VPN](https://peervpn.net/)

Original Code: https://github.com/peervpn/peervpn

Tutorial: https://peervpn.net/tutorial/

## Compile on Debian

```shell
> apt-get install build-essential git libssl-dev debhelper
> git clone https://github.com/BugMaster510945/peervpn.git
> cd peervpn
> dpkg-buildpackage -rfakeroot
```
