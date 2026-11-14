#Snort

### install.sh

Installs Snort 3 from upstream source on Debian, Ubuntu, openSUSE, and Alpine.
It detects the distribution through `/etc/os-release`, installs the required
build dependencies with the distribution's package manager, downloads the
community rules, and configures a detection-only service. Debian, Ubuntu, and
openSUSE use systemd; Alpine uses OpenRC.

Run as root, providing the capture interface and a directory containing any
additional `*.rules` files:

```sh
sudo ./install.sh -i <interface> -r <rules-directory> [-H <home-network>] [-E <external-network>]
```

Snort and LibDAQ source versions are pinned in the script. Set `BUILD_JOBS` to
change the parallel build job count (default: 2). The build requires internet
access and can take several minutes.

###adorsyss\_install-snort.sh
Script for installing snort, from ADORSYS-GIS, not our work.

###install.sh
Our script for installing snort on a alpine router. With rules snort can highlight detect on going attacks. 

###our.rules
Custom snort rules for detecting nmap, reverse shells, unusual user agents, and more. 

###fireeye.rules
Snort fules from fire eye.

