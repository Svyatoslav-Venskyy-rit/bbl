#!/usr/bin/env bash

bigbangPkgs='ModemManager
NetworkManager
NetworkManager-adsl
NetworkManager-bluetooth
NetworkManager-fortisslvpn-gnome
NetworkManager-iodine-gnome
NetworkManager-l2tp-gnome
NetworkManager-libreswan-gnome
NetworkManager-openconnect-gnome
NetworkManager-openvpn-gnome
NetworkManager-ppp
NetworkManager-pptp-gnome
NetworkManager-ssh-gnome
NetworkManager-sstp-gnome
NetworkManager-strongswan-gnome
NetworkManager-team
NetworkManager-tui
NetworkManager-vpnc-gnome
NetworkManager-wifi
NetworkManager-wwan
PackageKit
PackageKit-gstreamer-plugin
abrt-cli
abrt-desktop
acl
adwaita-gtk2-theme
adwaita-icon-theme
alsa-sof-firmware
alsa-utils
amd-gpu-firmware
amd-ucode-firmware
at
at-spi2-atk
atheros-firmware
attr
audit
authselect
b43-fwcutter
b43-openfwwf
basesystem
bash
bash-color-prompt
bash-completion
bc
bind-utils-
blueman
bluez-cups
brcmfmac-firmware
brltty
btrfs-progs
bzip2
chrony
cifs-utils
cirrus-audio-firmware
cockpit
cockpit-networkmanager
cockpit-packagekit
cockpit-selinux
cockpit-storaged
colord
compsize
coreutils
cpio
crontabs
cryptsetup
cups
cups-browsed
cups-filters
cups-pk-helper
curl
cyrus-sasl-plain
dbus
default-editor
default-fonts-cjk-mono
default-fonts-cjk-sans
default-fonts-cjk-serif
default-fonts-core-emoji
default-fonts-core-math
default-fonts-core-mono
default-fonts-core-sans
default-fonts-core-serif
default-fonts-other-mono
default-fonts-other-sans
default-fonts-other-serif
deltarpm
desktop-backgrounds-compat
dhcp-client-
dnf5
dnf5-plugins
dnfdragora-updater
dnsmasq
dos2unix
dosfstools
dracut-config-rescue
e2fsprogs
ed
ethtool
exfatprogs
fedora-release-server
file
filesystem
firefox
firewall-config
firewalld
fpaste
fprintd-pam
fwupd
ghostscript
glibc
glx-utils
gnome-disk-utility
gnome-keyring-pam
gnupg2
greybird-dark-theme
greybird-light-theme
greybird-xfce4-notifyd-theme
greybird-xfwm4-theme
grub2-pc
grub2-tools
gstreamer1-plugin-dav1d
gstreamer1-plugin-libav
gstreamer1-plugin-openh264
gstreamer1-plugins-bad-free
gstreamer1-plugins-good
gstreamer1-plugins-ugly-free
gtk-xfce-engine
gtk3-immodule-xim
gutenprint
gutenprint-cups
gvfs-archive
gvfs-mtp
hostname
hplip
hunspell
hyperv-daemons
ibus-anthy
ibus-chewing
ibus-gtk3
ibus-hangul
ibus-libpinyin
ibus-m17n
ibus-table-chinese-cangjie
ibus-typing-booster
im-chooser
im-chooser-xfce
imsettings
imsettings-gsettings
initial-setup-gui
intel-audio-firmware
intel-gpu-firmware
intel-vsc-firmware
iproute
iptables-nft
iptstate
iputils
irqbalance
iwlegacy-firmware
iwlwifi-dvm-firmware
iwlwifi-mvm-firmware
kbd
kernel
langpacks-en
less
libertas-firmware
libva-intel-media-driver
lightdm-gtk
logrotate
lrzsz
lsof
lvm2
mailcap
man-db
man-pages
mcelog
mdadm
mesa-dri-drivers
mesa-vulkan-drivers
microcode_ctl
minicom
mint-y-theme
mpage
mt7xxx-firmware
mtr
mysql-server
ncurses
net-tools
network-manager-applet
nfs-utils
nm-connection-editor
nmap-ncat
nss-mdns
ntfs-3g
ntfsprogs
nvidia-gpu-firmware
nxpwireless-firmware
open-vm-tools-desktop
opensc
openssh-askpass
openssh-clients
openssh-server
orca
paps
parted
passwdqc
pciutils
pcsc-lite
pcsc-lite-ccid
pinfo
pipewire-alsa
pipewire-gstreamer
pipewire-pulseaudio
pipewire-utils
plocate
plymouth
plymouth-system-theme
policycoreutils
polkit
ppp
prefixdevname
procps-ng
psacct
qcom-wwan-firmware
qemu-guest-agent
quota
realmd
realtek-firmware
rootfiles
rpm
rsync
rsyslog
samba-client
selinux-policy-targeted
setroubleshoot
setup
shadow-utils
smartmontools
sos
speech-dispatcher
spice-vdagent
spice-webdavd
sssd-common
sssd-kcm
sssd-proxy
sudo
symlinks
system-config-language
system-config-printer-udev
systemd
systemd-oomd-defaults
systemd-resolved
systemd-udev
tar
tcpdump-
thunar-archive-plugin
thunar-media-tags-plugin
thunar-volman
time
tiwilink-firmware
traceroute
tree
tumbler
udisks2-iscsi
udisks2-lvm2
unzip
usb_modeswitch
usbutils
util-linux
vim-enhanced
vim-minimal
virtualbox-guest-additions
wget2-wget
which
whois
wireplumber
words
wpa_supplicant
xdg-user-dirs-gtk
xfce4-about
xfce4-appfinder
xfce4-datetime-plugin
xfce4-panel
xfce4-panel-profiles
xfce4-places-plugin
xfce4-power-manager
xfce4-pulseaudio-plugin
xfce4-screensaver
xfce4-screenshooter-plugin
xfce4-session
xfce4-settings
xfce4-taskmanager
xfce4-terminal
xfdesktop
xfsprogs
xfwm4
xfwm4-themes
xorg-x11-drv-amdgpu
xorg-x11-drv-ati
xorg-x11-drv-evdev
xorg-x11-drv-intel
xorg-x11-drv-libinput
xorg-x11-drv-nouveau
xorg-x11-drv-openchrome
xorg-x11-drv-qxl
xorg-x11-drv-vmware
xorg-x11-drv-wacom
xorg-x11-server-Xorg
xorg-x11-xauth
xorg-x11-xinit
zip
zram-generator-defaults'
bigbangServices='abrt-journal-core.service
abrt-oops.service
abrt-xorg.service
abrtd.service
atd.service
auditd.service
avahi-daemon.service
chronyd.service
crond.service
cups.service
dbus-broker.service
firewalld.service
getty@tty1.service
gssproxy.service
irqbalance.service
mcelog.service
ModemManager.service
mysqld.service
NetworkManager.service
polkit.service
rsyslog.service
sshd.service
systemd-homed.service
systemd-journald.service
systemd-logind.service
systemd-oomd.service
systemd-resolved.service
systemd-udevd.service
systemd-userdbd.service
udisks2.service
upower.service
user@1000.service'

chernobylPkgs='aajohan-comfortaa-fonts
anaconda
anaconda-install-env-deps
anaconda-live
chkconfig
docker-ce
dracut-live
efi-filesystem
efivar-libs
ftp
grub2-common
grub2-pc-modules
grub2-tools-minimal
initscripts
kernel
kernel
kernel-modules
kernel-modules
kernel-modules-extra
kernel-modules-extra
langpacks-en
libreoffice-calc
libreoffice-emailmerge
libreoffice-graphicfilter
libreoffice-impress
libreoffice-writer
livesys-scripts
memtest86+
syslinux'
chernobylServices='accounts-daemon.service
auditd.service
avahi-daemon.service
chronyd.service
colord.service
containerd.service
crond.service
dbus-broker.service
docker.service
firewalld.service
fwupd.service
gdm.service
gssproxy.service
irqbalance.service
ModemManager.service
NetworkManager.service
polkit.service
rpcbind.service
rsyslog.service
rtkit-daemon.service
spice-vdagentd.service
sssd-kcm.service
switcheroo-control.service
systemd-journald.service
systemd-logind.service
systemd-udevd.service
tuned-ppd.service
tuned.service
udisks2.service
upower.service
user@1000.service
wpa_supplicant.service'

dinoasteroidPkgs='apt-transport-https
base-files
bash
bsdutils
dash
debhelper
diffutils
findutils
grep
grub-pc
gzip
hostname
init
linux-generic
login
ncurses-base
ncurses-bin
openssh-server
ubuntu-minimal
ubuntu-server
ubuntu-server-minimal
ubuntu-standard
util-linux
wazuh-manager'
dinoasteroidServices='cron.service
dbus.service
getty@tty1.service
ModemManager.service
multipathd.service
polkit.service
rsyslog.service
ssh.service
systemd-journald.service
systemd-logind.service
systemd-networkd.service
systemd-resolved.service
systemd-timesyncd.service
systemd-udevd.service
udisks2.service
unattended-upgrades.service
user@1000.service'

enlightenmentPkgs='bsdutils
dash
debsums
diffutils
findutils
grep
grub-pc
gzip
hostname
htop
ibus-table-cangjie-big
ibus-table-cangjie3
ibus-table-cangjie5
init
language-pack-en
language-pack-en-base
language-pack-gnome-en
language-pack-gnome-en-base
libchewing3
libchewing3-data
libm17n-0
libmarisa0
libopencc-data
libopencc1.1
libotf1
libpinyin-data
libpinyin15
linux-generic-hwe-24.04
login
m17n-db
ncurses-base
ncurses-bin
openssh-server
python3-netifaces
ubuntu-desktop-minimal
ubuntu-minimal
ubuntu-restricted-addons
ubuntu-standard
ubuntu-wallpapers
vsftpd
wbritish'
enlightenmentServices='accounts-daemon.service
avahi-daemon.service
colord.service
cron.service
cups-browsed.service
cups.service
dbus.service
gdm.service
gnome-remote-desktop.service
kerneloops.service
ModemManager.service
NetworkManager.service
packagekit.service
polkit.service
power-profiles-daemon.service
rsyslog.service
rtkit-daemon.service
snapd.service
spice-vdagentd.service
switcheroo-control.service
systemd-journald.service
systemd-logind.service
systemd-oomd.service
systemd-resolved.service
systemd-timesyncd.service
systemd-udevd.service
udisks2.service
unattended-upgrades.service
upower.service
user@1000.service
vsftpd.service
wpa_supplicant.service'

vikingraidsPkgs='adduser
amd64-microcode
apt
apt-listchanges
apt-utils
base-files
base-passwd
bash
bash-completion
bind9-dnsutils
bind9-host
bsdutils
busybox
bzip2
ca-certificates
console-setup
coreutils
cpio
cron
cron-daemon-common
dash
dbus
debconf
debconf-i18n
debian-archive-keyring
debian-faq
debianutils
diffutils
discover
dmidecode
dmsetup
doc-debian
dpkg
e2fsprogs
eject
fdisk
file
findutils
gcc-12-base
gettext-base
gpgv
grep
groff-base
grub-common
grub-pc
gzip
hostname
ifupdown
inetutils-telnet
init
init-system-helpers
initramfs-tools
installation-report
iproute2
iputils-ping
isc-dhcp-client
isc-dhcp-common
keyboard-configuration
kmod
krb5-locales
laptop-detect
less
libacl1
libapparmor1
libapt-pkg6.0
libargon2-1
libattr1
libaudit-common
libaudit1
libblkid1
libbpf1
libbsd0
libbz2-1.0
libc-bin
libc6
libcap-ng0
libcap2
libcap2-bin
libcom-err2
libcrypt1
libcryptsetup12
libdb5.3
libdebconfclient0
libdevmapper1.02.1
libedit2
libelf1
libext2fs2
libfdisk1
libffi8
libgcc-s1
libgcrypt20
libgmp10
libgnutls30
libgpg-error0
libgssapi-krb5-2
libhogweed6
libidn2-0
libip4tc2
libjansson4
libjson-c5
libk5crypto3
libkeyutils1
libkmod2
libkrb5-3
libkrb5support0
liblocale-gettext-perl
liblockfile-bin
liblz4-1
liblzma5
libmd0
libmnl0
libmount1
libncursesw6
libnettle8
libnewt0.52
libnftables1
libnftnl11
libnss-systemd
libp11-kit0
libpam-modules
libpam-modules-bin
libpam-runtime
libpam-systemd
libpam0g
libpcre2-8-0
libpopt0
libproc2-0
libreadline8
libseccomp2
libselinux1
libsemanage-common
libsemanage2
libsepol2
libslang2
libsmartcols1
libss2
libssl3
libstdc++6
libsystemd-shared
libsystemd0
libtasn1-6
libtext-charwidth-perl
libtext-iconv-perl
libtext-wrapi18n-perl
libtinfo6
libtirpc-common
libtirpc3
libudev1
libunistring2
libuuid1
libxtables12
libxxhash0
libzstd1
linux-image-amd64
locales
login
logrotate
logsave
lsof
man-db
manpages
mawk
media-types
mime-support
mount
nano
ncurses-base
ncurses-bin
ncurses-term
netbase
netcat-traditional
nftables
openssh-client
openssh-server
os-prober
passwd
pciutils
perl
perl-base
procps
python3-reportbug
qemu-guest-agent
readline-common
reportbug
sed
sensible-utils
systemd
systemd-sysv
systemd-timesyncd
sysvinit-utils
tar
task-desktop
task-english
task-gnome-desktop
tasksel
tasksel-data
traceroute
tzdata
ucf
udev
usbutils
usr-is-merged
util-linux
util-linux-extra
vim-common
vim-tiny
wamerican
wget
whiptail
xz-utils
zlib1g
zstd'
vikingraidsServices='accounts-daemon.service
avahi-daemon.service
colord.service
cron.service
cups-browsed.service
cups.service
dbus.service
fwupd.service
gdm.service
low-memory-monitor.service
ModemManager.service
NetworkManager.service
packagekit.service
polkit.service
power-profiles-daemon.service
rtkit-daemon.service
ssh.service
switcheroo-control.service
systemd-journald.service
systemd-logind.service
systemd-timesyncd.service
systemd-udevd.service
udisks2.service
upower.service
user@1000.service
wpa_supplicant.service'

users='whiteteam
blackteam
grayteam
grayteam
dd-dog
datadog
drwho
martymcFly
arthurdent
sambeckett
loki
riphunter
theflash
tonystark
drstrange
bartallen'

function get_key {
    IFS= read -r -n1 -s key

    if [[ $key == $'\e' ]]; then
        IFS= read -r -n2 -s rest
        # printf 'You pressed: %s  (decimal=%d, hex=0x%02X)\n' "$(printf '%q' "$key")" "'$key" "'$key"
        key+=$rest
        case "$key" in
            $'\e[A')
                key='up'
                ;;
            $'\e[B')
                key='down'
                ;;
            $'\e[C')
                key='right'
                ;;
            $'\e[D')
                key='left'
                ;;
            $'\\')
                key='space'
                ;;
        esac
    else
        # printf 'You pressed: %s  (decimal=%d, hex=0x%02X)\n' "$(printf '%q' "$key")" "'$key" "'$key"
        case "$key" in
            '')
                key='return'
                ;;
            ' ')
                key='space'
                ;;
        esac
    fi

    echo $key
}

function select_option {
    options=("$@")
    index=0
    complete=false

    while [[ $complete == false ]]; do
        clear
        echo 'Select an option:'

        for i in "${!options[@]}"; do
            option="${options[$i]}"
            if [[ $i == $index ]]; then
                arrow=">"
            else
                arrow=" "
            fi

            echo "$arrow $option"
        done

        case "$(get_key)" in
            'down' | 'e')
                if (( $index < "${#options[@]}"-1)); then
                    ((index++))
                fi
                ;;
            'up' | 'u')
                if [[ $index > 0 ]]; then
                    ((index--))
                fi
                ;;
            'return' | 'space')
                complete=true
                ;;
        esac
    done
    selection="${options[$index]}"
}

function header {
    echo "====== [ $1 ] ======"
}

function subh {
    echo "---    < $1 >    ---"
}

function display {
    header "$1"

    if [[ -n "$3" ]]; then
        subh "filtered $1"
        echo "$2" | grep -v "$3"
        echo
    fi

    subh "all $1"
    echo "$2"

    get_key
}

function error {
    header "HOSTNAME NOT VALID!"
    get_key
}

function rpt {
    IFS=' ' read -a args <<< "$2"

    for arg in "${args[@]}"; do
        if [[ -z "$3" ]]; then
            echo -e "[$1 $arg]"
        else
            echo -e "[$1 $arg $3]"
        fi
        $1 $arg $3
        echo
    done
}

stty -echo -icanon min 1 time 0
trap $(stty sane) EXIT
if [[ -z $1 ]]; then
    hostname="$(hostname)"
else
    hostname="$1"
fi
services="${hostname}Services"
pkgs="${hostname}Pkgs"
if [[ "$hostname" == 'bigbang' || "$hostname" == 'chernobyl' ]]; then
    os='redhat'
elif [[ "$hostname" == 'dinoasteroid' || "$hostname" == 'enlightenment' || "$hostname" == 'vikingraids' ]]; then
    os='debian'
else
    os='INVALID'
fi
passwordUsers='drwho martymcFly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen'
finished=false

while [[ $finished == false ]]; do
    select_option 'inventory' 'services' 'users' 'packages' 'integrity' 'processes' 'cron' 'change passwords' 'stop services' 'lock users' 'remove packages' 'reinstall packages' 'clone' 'test' 'exit'
    clear
    case "$selection" in
        'inventory')
            header "inventory of $hostname"
            subh 'users'
            cat /etc/passwd | cut -d ":" -f 1 | tr '\n' ' '
            echo
            echo
            subh 'hostname'
            hostname
            echo
            subh 'ip'
            hostname -i
            echo
            subh 'operating system'
            source /etc/os-release
            echo "$NAME"
            echo
            subh 'version'
            echo "$VERSION"
            echo
            subh 'open ports'
            ss -tuln | awk '{print $5}'
            get_key
            ;;
        'services')
            display 'services' "$(systemctl list-units --type=service --state=running --no-pager --quiet | cut -d " " -f 3)" "${!services}"
            ;;
        'users')
            display 'unlocked users' "$(sudo cat /etc/shadow | grep -Ev ':!|:\*' | cut -d ':' -f 1)" "$users"
            ;;
        'packages')
            if [[ "$os" == 'redhat' ]]; then
                display 'packages' "$(dnf repoquery --userinstalled | cut -d ':' -f 1 | sed 's/..$//')" "${!pkgs}"
            elif [[ "$os" == 'debian' ]]; then
                display 'packages' "$(apt-mark showmanual)" "${!pkgs}"
            else
                error
            fi
            ;;
        'integrity')
            if [[ "$os" == 'redhat' ]]; then
                header 'running rpm'
                sudo rpm -Va
            elif [[ "$os" == 'debian' ]]; then
                if [[ -z "$(which debsums)" ]]; then
                    header 'installing debsums'
                    sudo apt install debsums
                    clear
                fi

                header 'running debsums'
                sudo debsums -s
            fi
            echo -e '\ndone!'
            get_key
            ;;
        'processes')
            ps -auxf | less
            ;;
        'cron')
            header 'crontabs'
            subh '/etc/crontab'
            cat /etc/crontab | grep -vE '^\s*($|#)'
            echo
            subh '/etc/cron.d'
            grep . /etc/cron.d/*
            echo
            subh '/etc/cron.*'
            grep . /etc/cron.*/*
            echo
            subh '/var/spool'
            if [ -d "/var/spool/cron/crontabs" ]; then
                spool="/var/spool/cron/crontabs"
            elif [ -d "/var/spool/cron" ]; then
                spool="/var/spool/cron"
            else
                echo "Could not locate cron spool directory."
                spool=""
            fi
            if [ -n "$spool" ]; then
                # Loop through each file in the directory
                for user in $(sudo ls $spool); do
                    echo
                    echo "USER: $user"
                    # Print the crontab, filtering out comments and empty lines for clarity
                    crontab -u "$user" -l | grep -vE '^\s*($|#)'
                done
            fi
            echo
            echo 'done!'
            get_key
            ;;
        'change passwords')
            read -s -p 'enter new password: ' password
            echo
            read -s -p 'confirm new password: ' passwordVerify
            echo

            if [[ "$password" != "$passwordVerify" ]]; then
                echo 'passwords do not match!'
            else
                for user in $passwordUsers; do
                    if id "$user" >/dev/null 2>&1; then
                        echo "$user:$password" | sudo chpasswd
                        echo "changed password for [$user]"
                    else
                        echo "user [$user] not found on the system!"
                    fi
                done
            fi
            echo
            echo 'done!'
            get_key

            ;;
        'stop services')
            header 'enter services to stop'
            read args
            rpt 'sudo systemctl disable --now' "$args"
            echo -e 'done!'
            get_key
            ;;
        'lock users')
            header 'enter users to lock'
            read args
            rpt 'sudo passwd -dl' "$args" "$3"
            echo -e 'done!'
            get_key
            ;;
        'uninstall packages')
            header 'enter packages to uninstall'
            read args
            if [[ "$os" == 'redhat' ]]; then
                sudo dnf remove "$args"
            elif [[ "$os" == 'debian' ]]; then
                sudo apt remove "$args"
            fi
            echo -e 'done!'
            get_key
            ;;
        'reinstall packages')
            header 'enter packages to reinstall'
            read args
            if [[ "$os" == 'redhat' ]]; then
                sudo dnf reinstall "$args"
            elif [[ "$os" == 'debian' ]]; then
                sudo apt install --reinstall "$args"
            fi
            echo -e 'done!'
            get_key
            ;;
        'clone')
            header 'cloning..'
            git clone https://github.com/pix-code/pix-code.github.io
            echo -e '\ndone!'
            get_key
            ;;
        'test')
            header 'diagnostic info'
            echo "detected os: $os"
            echo "detected hostname: $hostname"
            echo
            echo 'press m for more'
            if [[ "$(get_key)" == 'm' ]]; then
                subh 'user filter'
                echo "$users"
                echo
                subh 'service filter'
                echo "${!services}"
                echo
                subh 'pkg filter'
                echo "${!pkgs}"
                get_key
            fi
            ;;
        'exit')
            header 'HACK THE PLANET'
            finished=true
            ;;
    esac
done

