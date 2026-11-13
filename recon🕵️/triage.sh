#!/usr/bin/env bash
# triage.sh - Linux host triage (CyberForce reference script)
#
# Usage:
#   sudo ./triage.sh                 # run every section
#   sudo ./triage.sh users net       # run only some sections
#   sudo ./triage.sh baseline        # save current listening ports as the known-good baseline
#   source ./triage.sh; check_net    # load functions, run sections by hand
#
# Sections: users cron procs net logins files web smb
# Output is color-coded on a terminal and also saved (without colors) to
# ./triage_<host>_<timestamp>.log  (override with LOG=/path ./triage.sh)
#   [!] red    = suspicious, collected into the SUMMARY at the end
#   [i] yellow = context / sub-heading
#   [+] green  = check passed
# Port baseline lives in the sudo user's home as ports_baseline.txt
# (override with PORTS_BASELINE=/path). Same format as the portsnap/portcheck helpers.
 
# ---------- output helpers ----------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    B=$'\e[1m' R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' C=$'\e[36m' N=$'\e[0m'
else
    B='' R='' G='' Y='' C='' N=''
fi
 
FINDINGS=()
section() { printf '\n%s%s\n  %s\n%s%s\n' "$C$B" "$(printf '=%.0s' {1..70})" "$*" "$(printf '=%.0s' {1..70})" "$N"; }
sub()     { printf '\n%s--- %s ---%s\n' "$B" "$*" "$N"; }
warn()    { printf '%s[!] %s%s\n' "$R$B" "$*" "$N"; FINDINGS+=("$*"); }
info()    { printf '%s[i] %s%s\n' "$Y" "$*" "$N"; }
ok()      { printf '%s[+] %s%s\n' "$G" "$*" "$N"; }
have()    { command -v "$1" >/dev/null 2>&1; }
indent()  { sed 's/^/    /'; }
table()   { if have column; then column -t; else cat; fi; }
# Print stdin indented, or "(none)" if empty
show()    { local o; o=$(cat); if [[ -n $o ]]; then printf '%s\n' "$o" | indent; else printf '    (none)\n'; fi; }
nocomment() { grep -vE '^\s*(#|$)' "$@" 2>/dev/null; }
# Resolve symlinked paths (/lib -> /usr/lib) and de-duplicate
uniq_real() { local p; while IFS= read -r p; do readlink -f -- "$p"; done | sort -u; }
 
# Effective sshd config (filled in by check_users) and a lookup helper
SSHCFG=""
sshv() { awk -v k="$1" '$1==k {$1=""; sub(/^ /,""); print}' <<<"$SSHCFG"; }
 
# GNU find has -printf; busybox (Alpine) doesn't
if find /dev/null -printf '' 2>/dev/null; then
    find_ts() { find "$@" -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null; }
else
    find_ts() { find "$@" -print 2>/dev/null; }
fi
 
# ---------- package ownership ----------
# Files no package owns are custom installs or attacker drops - both worth a look.
have_pkgdb() { { have rpm && rpm -q rpm >/dev/null 2>&1; } || have dpkg-query || have apk; }
 
# Print each argument that no installed package owns
pkg_unowned() {
    (($#)) || return 0
    local f alt owned
    if have rpm && rpm -q rpm >/dev/null 2>&1; then
        rpm -qf "$@" 2>/dev/null | sed -n 's/^file \(.*\) is not owned by any package$/\1/p'
    elif have dpkg-query; then
        # "pkg:amd64, pkg2: /path" -> "/path"
        owned=$(dpkg-query -S "$@" 2>/dev/null | sed 's/^.*: //')
        for f; do
            grep -qxF -- "$f" <<<"$owned" && continue
            alt=${f#/usr}     # usrmerge: package may list /lib/... for /usr/lib/...
            [[ $alt != "$f" ]] && dpkg-query -S "$alt" >/dev/null 2>&1 && continue
            printf '%s\n' "$f"
        done
    elif have apk; then
        for f; do apk info --who-owns "$f" >/dev/null 2>&1 || printf '%s\n' "$f"; done
    fi
}
 
# ---------- port baseline ----------
portsnap() {
    ss -Htulnp 2>/dev/null \
        | awk '{n="-"; if (match($7,/\(\("[^"]+"/)) n=substr($7,RSTART+3,RLENGTH-4); print $1, $5, n}' \
        | LC_ALL=C sort -u
}
baseline_file() {
    if [[ -n ${PORTS_BASELINE:-} ]]; then printf '%s\n' "$PORTS_BASELINE"; return; fi
    local h; h=$(getent passwd "${SUDO_USER:-$(id -un)}" | cut -d: -f6)
    printf '%s/ports_baseline.txt\n' "${h:-$HOME}"
}
 
# ---------- sections ----------
check_users() {
    section "USERS & AUTHENTICATION"
    local name uid hash sh f g line any fp fps pub active tok k home p users owner
    local -A akfp=()   # authorized key fingerprint -> file
 
    sub "UID 0 accounts (should only be root)"
    while IFS=: read -r name _ uid _; do
        [[ $uid == 0 ]] || continue
        if [[ $name == root ]]; then ok "root"; else warn "Extra UID 0 account: $name"; fi
    done < /etc/passwd
 
    if [[ -r /etc/shadow ]]; then
        sub "Accounts with EMPTY password (anyone can log in)"
        local found=0
        while IFS=: read -r name hash _; do
            [[ -z $hash ]] && { warn "Empty password: $name"; found=1; }
        done < /etc/shadow
        ((found)) || ok "none"
 
        sub "Accounts with a usable password (not locked)"
        awk -F: '$2 != "" && $2 !~ /^[!*]/ {print $1}' /etc/shadow | show
    else
        info "/etc/shadow not readable - run as root"
    fi
 
    sub "Accounts with a login shell"
    { echo "USER UID GID HOME SHELL"
      awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1, $3, $4, $6, $7}' /etc/passwd
    } | table | indent
 
    sub "Service accounts (UID 1-999) with a login shell"
    any=0
    while IFS=: read -r name _ uid _ _ _ sh; do
        [[ $uid =~ ^[0-9]+$ ]] && ((uid > 0 && uid < 1000)) || continue
        [[ $sh =~ (nologin|false|sync|shutdown|halt)$ ]] && continue
        warn "Service account with login shell: $name (uid $uid, $sh)"; any=1
    done < /etc/passwd
    ((any)) || ok "none"
 
    sub "Privileged group members"
    for g in sudo wheel admin adm docker lxd; do
        line=$(getent group "$g") || continue
        printf '    %-7s %s\n' "$g" "${line##*:}"
    done
 
    sub "sudoers rules"
    local sf=()
    for f in /etc/sudoers /etc/sudoers.d/* /usr/etc/sudoers.d/*; do [[ -f $f ]] && sf+=("$f"); done
    if ((${#sf[@]})); then
        # Hide only the harmless stock Defaults lines; keep anything that changes auth
        grep -HE '^\s*(@include|#include|[^#[:space:]])' "${sf[@]}" 2>/dev/null \
            | grep -vE ':\s*Defaults(\s+(env_keep|env_reset|secure_path|always_set_home|!?insults|!?lecture|mail_badpass|use_pty|!visiblepw)|!/usr/sbin/visudo)' \
            | show
        while IFS= read -r line; do warn "NOPASSWD sudo: $line"; done \
            < <(grep -HE '^\s*[^#[:space:]].*NOPASSWD' "${sf[@]}" 2>/dev/null)
        while IFS= read -r line; do warn "sudo without authentication: $line"; done \
            < <(grep -HE '^\s*Defaults.*!authenticate' "${sf[@]}" 2>/dev/null)
        active=$(grep -hE '^\s*[^#[:space:]]' "${sf[@]}" 2>/dev/null)
        if grep -qE '^\s*ALL\s+ALL\s*=' <<<"$active"; then
            if grep -qE '^\s*Defaults\b.*\btargetpw\b' <<<"$active"; then
                info "'ALL ALL=(ALL) ALL' + targetpw: any user can sudo with the ROOT password"
            else
                warn "sudoers has 'ALL ALL=(ALL) ALL' without 'Defaults targetpw' - every user is root"
            fi
        fi
    else
        info "no sudoers files readable"
    fi
 
    sub "PAM (pam_exec hooks and modules not from a package)"
    any=0
    while IFS= read -r line; do warn "PAM runs a script: $line"; any=1; done \
        < <(grep -HnE '^\s*[^#].*pam_(exec|script)\.so' /etc/pam.d/* /usr/lib/pam.d/* /usr/etc/pam.d/* 2>/dev/null)
    if have_pkgdb; then
        local mods=()
        mapfile -t mods < <(find /lib/security /lib64/security /usr/lib/security /usr/lib64/security \
            /lib/*-linux-gnu/security /usr/lib/*-linux-gnu/security -maxdepth 1 -name '*.so' -type f 2>/dev/null | uniq_real)
        while IFS= read -r f; do warn "PAM module not from any package: $f"; any=1; done < <(pkg_unowned "${mods[@]}")
    fi
    ((any)) || ok "nothing unusual"
 
    SSHCFG=""; have sshd && SSHCFG=$(sshd -T 2>/dev/null)
 
    sub "SSH authorized_keys (every account x every key file sshd reads)"
    # sshd reads AuthorizedKeysFile for EVERY account in /etc/passwd, not just /home/*.
    # Expand it per user (%h %u %U %%), always add both stock names (authorized_keys2 is
    # a favorite hiding spot), then sweep for stray copies no account points at.
    local akf=()
    local -A akuser=() akcustom=()
    read -ra akf <<<"$(sshv authorizedkeysfile)"
    ((${#akf[@]})) || akf=(.ssh/authorized_keys .ssh/authorized_keys2)
    while IFS=: read -r name _ uid _ _ home _; do
        [[ -n $home ]] || continue
        for tok in "${akf[@]}" .ssh/authorized_keys .ssh/authorized_keys2; do
            [[ $tok == none ]] && continue
            p=${tok//%%/$'\001'}; p=${p//%h/$home}; p=${p//%u/$name}; p=${p//%U/$uid}; p=${p//$'\001'/%}
            [[ $p == /* ]] || p=${home%/}/$p
            [[ -e $p || -L $p ]] || continue
            [[ " ${akuser[$p]:-} " == *" $name "* ]] || akuser[$p]+="$name "
            [[ $tok == .ssh/authorized_keys || $tok == .ssh/authorized_keys2 ]] || akcustom[$p]=1
        done
    done < /etc/passwd
    # Stray key files no account uses (wrong home, staged for later). Skips evidence dirs like /root/ir.
    while IFS= read -r p; do
        [[ -n ${akuser[$p]:-} ]] || akuser[$p]="-"
    done < <(find /root /home /etc/ssh -name 'authorized_keys*' -type f \
                 \( -path '*/.ssh/*' -o -path '/etc/ssh/*' \) 2>/dev/null)
 
    any=0
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        any=1
        users=${akuser[$f]% }
        if [[ $users == - ]]; then
            warn "Key file no account uses (staged or leftover): $f"
        elif [[ -n ${akcustom[$f]:-} ]]; then
            warn "Key file from a custom AuthorizedKeysFile path: $f (users: $users)"
        elif [[ ${f##*/} == authorized_keys2 ]]; then
            warn "authorized_keys2 (legacy file, common hiding spot): $f (user: $users)"
        else
            info "$f (user: $users)"
        fi
        [[ -L $f ]] && warn "Key file is a symlink: $f -> $(readlink -f "$f")"
        owner=$(stat -Lc %U "$f" 2>/dev/null)
        if [[ $users != - && $users != *' '* && -n $owner && $owner != root && $owner != "$users" ]]; then
            warn "Key file $f is owned by '$owner', not '$users'"
        fi
        [[ -n $(find -L "$f" -maxdepth 0 -perm /022 2>/dev/null) ]] && warn "Key file is group/world-writable: $f"
        if [[ ! -s $f ]]; then printf '    (empty - no keys yet, but someone created the file)\n'; continue; fi
        if have ssh-keygen; then
            fps=$(ssh-keygen -lf "$f" 2>/dev/null)
            if [[ -z $fps ]]; then
                warn "authorized_keys content ssh-keygen can't parse: $f"
                nocomment "$f" | cut -c1-100 | indent
                continue
            fi
            printf '%s\n' "$fps" | indent
            while read -r _ fp _; do akfp[$fp]=$f; done <<<"$fps"
        else
            nocomment "$f" | awk '{print $1, substr($2,1,16) "...", $NF}' | indent
        fi
        # Keys with options (command=, from=, ...) - forced commands can hide backdoors
        grep -nvE '^\s*(#|$|ssh-|ecdsa-|sk-)' "$f" 2>/dev/null | cut -c1-120 \
            | sed 's/^/    key options: /'
    done < <(printf '%s\n' "${!akuser[@]}" | LC_ALL=C sort)
    ((any)) || ok "none found"
 
    sub "Private SSH keys on this box"
    any=0
    while IFS= read -r f; do
        any=1; fp=""
        pub="$f.pub"
        [[ -r $pub ]] && fp=$(ssh-keygen -lf "$pub" 2>/dev/null | awk '{print $2}')
        if [[ -n $fp && -n ${akfp[$fp]:-} ]]; then
            warn "Box trusts its own private key $f (listed in ${akfp[$fp]}) - every clone of this image can SSH into the others"
        else
            printf '    %s %s\n' "$f" "$fp"
        fi
    done < <(find /root/.ssh /home/*/.ssh -maxdepth 1 -type f -name 'id_*' ! -name '*.pub' 2>/dev/null)
    ((any)) || ok "none"
 
    sub "sshd settings"
    if [[ -n $SSHCFG ]]; then
        grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|gatewayports|allowtcpforwarding|allowagentforwarding|permittunnel|hostbasedauthentication|trustedusercakeys|allowusers|allowgroups) ' <<<"$SSHCFG" \
            | while read -r k v; do printf '    %-30s %s\n' "$k" "$v"; done
        [[ $(sshv permitemptypasswords) == yes ]] && warn "sshd: PermitEmptyPasswords yes"
        [[ $(sshv permitrootlogin) == yes ]] && warn "sshd: PermitRootLogin yes"
        [[ -n $(sshv gatewayports) && $(sshv gatewayports) != no ]] && warn "sshd: GatewayPorts $(sshv gatewayports) - box can be used as a network pivot"
        [[ -n $(sshv authorizedkeyscommand) && $(sshv authorizedkeyscommand) != none ]] && warn "sshd: AuthorizedKeysCommand $(sshv authorizedkeyscommand)"
        for tok in $(sshv authorizedkeysfile); do
            [[ $tok == .ssh/authorized_keys || $tok == .ssh/authorized_keys2 ]] && continue
            warn "sshd reads extra key file(s): $tok"
        done
    else
        nocomment /etc/ssh/sshd_config | grep -Ei 'permitroot|passwordauth|emptypass|authorizedkeys|gatewayports|hostbased|trustedusercakeys' | show
    fi
    for f in /etc/ssh/sshd_config.d/*.conf /usr/etc/ssh/sshd_config.d/*.conf; do
        [[ -f $f ]] || continue
        nocomment "$f" | sed "s|^|    ${f##*/}: |"
        # Files named "disable-*" that actually turn something on
        if [[ ${f##*/} == *disable* ]] && grep -qiE '^\s*[a-z]+\s+yes\b' "$f"; then
            warn "sshd drop-in $f is named 'disable' but sets 'yes'"
        fi
    done
    while IFS= read -r f; do warn "Hidden file/dir in /etc/ssh: $f"; done \
        < <(find /etc/ssh -mindepth 1 -name '.*' 2>/dev/null)
 
    sub "Other SSH trust (host-based login, CA-signed keys, principals)"
    # Ways in that never touch authorized_keys
    any=0
    if [[ -n $SSHCFG ]]; then
        [[ $(sshv hostbasedauthentication) == yes ]] && { warn "sshd: HostbasedAuthentication yes - hosts in shosts.equiv/.shosts log in with no key or password"; any=1; }
        [[ $(sshv ignorerhosts) == no ]] && { warn "sshd: IgnoreRhosts no - per-user .rhosts/.shosts files are honored"; any=1; }
        tok=$(sshv trustedusercakeys)
        [[ -n $tok && $tok != none ]] && { warn "sshd: TrustedUserCAKeys $tok - whoever holds that CA key can sign their own login certificate"; any=1; }
        for k in authorizedprincipalsfile authorizedprincipalscommand; do
            tok=$(sshv "$k")
            [[ -n $tok && $tok != none ]] && { warn "sshd: $k $tok"; any=1; }
        done
    fi
    for f in /etc/hosts.equiv /etc/ssh/shosts.equiv; do
        [[ -s $f ]] && { warn "Host trust file: $f"; nocomment "$f" | head -n 5 | indent; any=1; }
    done
    while IFS= read -r f; do
        warn "Per-user host trust file: $f"; nocomment "$f" | head -n 5 | indent; any=1
    done < <(cut -d: -f6 /etc/passwd | sort -u | while IFS= read -r home; do
                 [[ -n $home ]] || continue
                 for p in .rhosts .shosts; do [[ -e ${home%/}/$p ]] && printf '%s\n' "${home%/}/$p"; done
             done)
    ((any)) || ok "none"
}
 
check_cron() {
    section "SCHEDULED TASKS & PERSISTENCE"
 
    sub "User crontabs"
    local u out any=0 f d
    while IFS=: read -r u _; do
        out=$(crontab -u "$u" -l 2>/dev/null | grep -vE '^\s*(#|$)')
        [[ -n $out ]] || continue
        any=1; info "$u"; printf '%s\n' "$out" | indent
    done < /etc/passwd
    ((any)) || ok "none"
 
    sub "System cron (/etc/crontab, /etc/cron.d)"
    nocomment -H /etc/crontab /etc/cron.d/* | show
 
    sub "cron.hourly / daily / weekly / monthly"
    for d in /etc/cron.{hourly,daily,weekly,monthly}; do
        [[ -d $d ]] && printf '    %-20s %s\n' "$d" "$(ls -A "$d" | tr '\n' ' ')"
    done
 
    if have systemctl; then
        sub "systemd timers"
        systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $(NF-1), $NF}' | table | show
 
        sub "Unit files in /etc/systemd/system (newest first - admin/attacker added)"
        find_ts /etc/systemd/system -type f \( -name '*.service' -o -name '*.timer' \) | sort -r | show
 
        sub "Unit files not from any package (custom installs or attacker drops)"
        if have_pkgdb; then
            local dirs=() units=()
            for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/systemd/user /usr/lib/systemd/user; do
                [[ -d $d ]] && dirs+=("$d")
            done
            mapfile -t units < <(find "${dirs[@]}" -maxdepth 2 -type f \
                \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -path '*.d/*.conf' \) 2>/dev/null | uniq_real)
            any=0
            while IFS= read -r f; do
                any=1
                warn "Unit not from any package: $f"
                grep -hE '^\s*(Exec[A-Za-z]*|OnBootSec|OnUnitActiveSec|OnCalendar|Unit)=' "$f" 2>/dev/null | head -n 4 | indent
            done < <(pkg_unowned "${units[@]}")
            ((any)) || ok "all ${#units[@]} unit files come from packages"
        else
            info "no package database found - skipped"
        fi
 
        sub "Per-user systemd units"
        any=0
        while IFS= read -r f; do warn "User systemd unit: $f"; any=1; done \
            < <(find /root/.config/systemd /home/*/.config/systemd -type f 2>/dev/null)
        ((any)) || ok "none"
    fi
 
    if have atq; then
        sub "at jobs"
        atq 2>/dev/null | show
    fi
 
    sub "Boot scripts"
    for f in /etc/inittab /etc/rc.local /etc/rc.d/rc.local; do
        [[ -f $f ]] && { info "$f"; nocomment "$f" | show; }
    done
 
    sub "Shell startup files with download / reverse-shell / preload code"
    any=0
    while IFS= read -r f; do warn "Suspicious shell init line: $f"; any=1; done < <(
        grep -HnE '(curl|wget)[^|#]*\|\s*(ba)?sh|/dev/(tcp|udp)/|\bnc(at)?\b.*\s-[ec]\b|\bsocat\b|base64\s+(-d|--decode)|LD_PRELOAD|python[0-9.]*\s+-c' \
            /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/bash.bashrc.local /etc/environment \
            /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile \
            2>/dev/null | cut -c1-160)
    ((any)) || ok "none"
 
    sub "Library preload hijack"
    if [[ -s /etc/ld.so.preload ]]; then
        warn "/etc/ld.so.preload is set:"; indent < /etc/ld.so.preload
    else
        ok "/etc/ld.so.preload empty/absent"
    fi
}
 
check_procs() {
    section "PROCESSES & SERVICES"
 
    sub "Process tree"
    if have pstree; then pstree -ap | indent; else ps -ef --forest 2>/dev/null | indent || ps -ef | indent; fi
 
    sub "Processes with deleted binaries or running from temp dirs"
    # (deleted) can be legit right after a package upgrade - check the name
    local p exe any=0 line names n bad
    local -A exes=()
    for p in /proc/[0-9]*; do
        exe=$(readlink "$p/exe" 2>/dev/null) || continue
        if [[ $exe == *'(deleted)'* || $exe == /tmp/* || $exe == /var/tmp/* || $exe == /dev/shm/* ]]; then
            warn "PID ${p#/proc/}: $exe  [$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-80)]"
            any=1
        else
            exes[$exe]+="${p#/proc/} "
        fi
    done
    ((any)) || ok "none"
 
    sub "Running binaries not from any package (e.g. a fake ntpd)"
    if [[ $EUID -eq 0 ]] && have_pkgdb && ((${#exes[@]})); then
        any=0
        while IFS= read -r exe; do
            warn "Running binary not from any package: $exe (pids ${exes[$exe]% })"
            any=1
        done < <(pkg_unowned "${!exes[@]}")
        ((any)) || ok "all ${#exes[@]} running binaries come from packages"
    else
        info "no package database or not root - skipped"
    fi
 
    sub "Packet / raw sockets (sniffers, magic-packet and ICMP backdoors)"
    if [[ $EUID -ne 0 ]]; then
        info "needs root to see which process owns each socket - skipped"
    elif have ss; then
        any=0
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            any=1
            names=$(grep -oE '"[^"]+"' <<<"$line" | tr -d '"' | sort -u | paste -sd' ')
            bad=0
            for n in $names; do
                [[ $n =~ ^(NetworkManager|dhclient|dhcpcd|systemd-network|systemd-networkd|wpa_supplicant|lldpd|ModemManager)$ ]] || bad=1
            done
            [[ -z $names ]] && bad=1
            if ((bad)); then
                warn "Packet/raw socket held by ${names:-unknown process}: $(awk '{$NF=""; print}' <<<"$line")"
            else
                printf '    %s\n' "$line"
            fi
        done < <({ ss -Hp -0 2>/dev/null; ss -Hpw 2>/dev/null; } | awk '{$1=$1; print}')
        ((any)) || ok "none"
    else
        info "ss not installed - skipped"
    fi
 
    sub "Zombie processes (a daemon whose shells die = it's running commands)"
    any=0
    local pid ppid stat comm pcomm
    while read -r pid ppid stat comm; do
        any=1
        pcomm=$(ps -o comm= -p "$ppid" 2>/dev/null)
        if [[ $comm =~ ^(sh|bash|dash|zsh|ksh|busybox)$ && ! $pcomm =~ ^(bash|sh|dash|zsh|sshd|sshd-session|sudo|cron|crond|systemd|init|login|su|tmux.*|screen)$ ]]; then
            warn "Zombie shell '$comm' (pid $pid) under '$pcomm' (pid $ppid)"
        else
            printf '    %s (pid %s) under %s (pid %s)\n' "$comm" "$pid" "$pcomm" "$ppid"
        fi
    done < <(ps -eo pid=,ppid=,stat=,comm= 2>/dev/null | awk '$3 ~ /^Z/')
    ((any)) || ok "none"
 
    sub "Running services"
    if have systemctl; then
        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
            | awk '{sub(/^[^a-zA-Z0-9]+/, ""); print $1}' | { if have column; then column; else cat; fi; } | indent
    elif have rc-status; then
        rc-status 2>/dev/null | indent
    fi
}
 
check_net() {
    section "NETWORK"
 
    sub "Listening ports"
    if have ss; then
        { echo "PROTO LOCAL PROCESS"
          ss -tulnp 2>/dev/null | tail -n +2 | awk '{p=$7; gsub(/users:\(\(|\)\)|"/, "", p); print $1, $5, (p=="" ? "-" : p)}'
        } | table | indent
    else
        netstat -tulnp 2>/dev/null | indent
    fi
 
    sub "Listening ports vs baseline"
    local bf line any=0
    bf=$(baseline_file)
    if [[ $EUID -ne 0 ]]; then
        info "run with sudo to compare against the baseline (process names need root)"
    elif [[ -r $bf ]] && grep -qE ' -$' "$bf" && ! grep -qvE ' -$' "$bf"; then
        warn "Baseline $bf was saved without sudo (no process names) - redo it: sudo $0 baseline"
    elif [[ -r $bf ]] && have ss; then
        while IFS= read -r line; do warn "New listener since baseline: $line"; any=1; done \
            < <(LC_ALL=C comm -23 <(portsnap) <(LC_ALL=C sort -u "$bf"))
        while IFS= read -r line; do warn "Listener GONE since baseline (service down?): $line"; any=1; done \
            < <(LC_ALL=C comm -13 <(portsnap) <(LC_ALL=C sort -u "$bf"))
        ((any)) || ok "matches $bf"
    else
        info "no baseline at $bf - create one with: sudo $0 baseline"
    fi
 
    sub "Established connections"
    if have ss; then
        { echo "LOCAL PEER PROCESS"
          ss -tnp state established 2>/dev/null | tail -n +2 | awk '{p=$5; gsub(/users:\(\(|\)\)|"/, "", p); print $3, $4, (p=="" ? "-" : p)}'
        } | table | indent
    else
        netstat -antp 2>/dev/null | grep ESTAB | indent
    fi
 
    sub "/etc/hosts (look for bad redirects)"
    nocomment /etc/hosts | show
 
    sub "DNS servers"
    grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | show
 
    sub "Firewall"
    if have ufw; then ufw status verbose 2>/dev/null | indent
    elif have firewall-cmd; then firewall-cmd --list-all 2>/dev/null | indent
    elif have nft; then nft list ruleset 2>/dev/null | head -n 40 | show
    elif have iptables; then iptables -S 2>/dev/null | head -n 40 | show
    else info "no firewall tool found"; fi
}
 
check_logins() {
    section "LOGINS"
 
    sub "Logged in now (should only be your team)"
    w 2>/dev/null | indent
 
    sub "Recent logins"
    last -a 2>/dev/null | head -n 15 | indent
 
    if have lastb; then
        sub "Recent failed logins"
        lastb -a 2>/dev/null | head -n 10 | show
    fi
}
 
check_files() {
    section "FILES"
 
    sub "SUID binaries (red = known GTFOBins escalation, check gtfobins.github.io)"
    local risky='^(bash|sh|dash|zsh|ksh|csh|find|vi|vim|nano|less|more|python[0-9.]*|perl|ruby|php|lua|node|nmap|awk|gawk|mawk|env|tee|dd|cp|mv|tar|zip|socat|nc|ncat|docker|systemctl|base64|xxd|chmod|chown|busybox)$'
    local f any suid=() dirs=() d path caps
    mapfile -t suid < <(find / -xdev -perm -4000 -type f 2>/dev/null | sort)
    for f in "${suid[@]}"; do
        if [[ ${f##*/} =~ $risky ]]; then warn "Risky SUID: $f"; else printf '    %s\n' "$f"; fi
    done
    if have_pkgdb && ((${#suid[@]})); then
        while IFS= read -r f; do warn "SUID binary not from any package: $f"; done < <(pkg_unowned "${suid[@]}")
    fi
 
    sub "File capabilities (setuid-like powers without the SUID bit)"
    if have getcap; then
        for d in /usr /bin /sbin /opt /home /root /srv /var /tmp /etc; do [[ -d $d && ! -L $d ]] && dirs+=("$d"); done
        any=0
        while read -r path caps; do
            any=1
            caps=${caps#= }
            if [[ $caps =~ cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|sys_ptrace|chown|fowner|sys_module) \
                  && ! ${path##*/} =~ ^(newuidmap|newgidmap)$ ]]; then
                warn "Dangerous capability: $path $caps"
            else
                printf '    %s %s\n' "$path" "$caps"
            fi
        done < <(getcap -r "${dirs[@]}" 2>/dev/null)
        ((any)) || ok "none"
    else
        info "getcap not installed"
    fi
 
    sub "Executable files in /tmp, /var/tmp, /dev/shm"
    local out
    out=$(find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null)
    if [[ -n $out ]]; then
        while IFS= read -r f; do warn "Executable in temp: $f"; done <<< "$out"
    else
        ok "none"
    fi
 
    sub "Immutable / append-only files (chattr +i/+a - blocks deletion)"
    dirs=()
    for d in /etc /root /home /usr/local /usr/lib/systemd /usr/bin /usr/sbin /opt /srv /var/www /var/spool/cron; do
        [[ -d $d && ! -L $d ]] && dirs+=("$d")
    done
    any=0
    if have lsattr; then
        while IFS= read -r f; do warn "Immutable/append-only: $f"; any=1; done < <(
            lsattr -Ra "${dirs[@]}" 2>/dev/null \
                | awk '$1 ~ /^[-a-zA-Z]+$/ && $1 ~ /[ia]/ {p=substr($0, index($0," ")+1); if (p !~ /\/\.\.?$/) print p}')
        ((any)) || ok "none"
    else
        info "lsattr not installed"
    fi
 
    sub "Hidden files in system directories"
    any=0
    while IFS= read -r f; do warn "Hidden file in system dir: $f"; any=1; done < <(
        find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib/systemd /etc/systemd /etc/cron.d /etc/cron.hourly /etc/cron.daily \
            -maxdepth 2 -xdev -name '.*' -type f ! -name '*.hmac' ! -name '.placeholder' ! -name '.keep' 2>/dev/null)
    ((any)) || ok "none"
 
    sub "Hidden files directly in /etc (killswitches, markers, droppers)"
    find_ts /etc -maxdepth 1 -name '.*' -type f ! -name '.pwd.lock' ! -name '.updated' | show
 
    sub "Unusual dot-files in home directories (staging folders, toolkits)"
    local common='^\.(bash_history|bash_logout|bash_profile|bashrc|profile|cache|config|local|ssh|gnupg|viminfo|vimrc|vim|lesshst|mysql_history|python_history|sudo_as_admin_successful|wget-hsts|selected_editor|motd_shown|cloud-locale-test\.skip|dbus|pki|npm|emacs|inputrc|xinitrc|xim\.template|fonts|mozilla|Xauthority|zshrc|zsh_history|kshrc|cshrc|login|logout|tcshrc|muttrc|i18n|rnd|psql_history|node_repl_history|ansible|docker|kube|nanorc|tmux\.conf|screenrc|gitconfig|xsession-errors|ICEauthority|landscape|hushlogin|bash_aliases)$'
    find /root /home/* -mindepth 1 -maxdepth 1 -name '.*' 2>/dev/null \
        | while IFS= read -r f; do [[ ${f##*/} =~ $common ]] || printf '%s\n' "$f"; done | sort | show
 
    sub "Files modified in the last 24h (newest first, top 50)"
    find_ts / -xdev \( -path /var/log -o -path /var/cache -o -path /var/lib/apt -o -path '/home/*/.cache' -o -path /root/.cache \) -prune \
        -o -type f -mmin -1440 2>/dev/null | grep -v '^$' | sort -r | head -n 50 | show
}
 
# Read a define('KEY', 'value') out of wp-config.php
wp_define() { sed -nE "s/^[^#]*define\(\s*['\"]$2['\"]\s*,\s*['\"]([^'\"]*)['\"].*/\1/p" "$1" | head -n1; }
 
# Check the dangerous WordPress settings using the site's own DB credentials
wp_check() {
    local cfg=$1 client=$2 dbn dbu dbp dbh pfx host port="" sock="" tmp out k v reg="" role="" plugins=""
    dbn=$(wp_define "$cfg" DB_NAME); dbu=$(wp_define "$cfg" DB_USER)
    dbp=$(wp_define "$cfg" DB_PASSWORD); dbh=$(wp_define "$cfg" DB_HOST)
    pfx=$(sed -nE "s/^\s*\\\$table_prefix\s*=\s*['\"]([A-Za-z0-9_]+)['\"].*/\1/p" "$cfg" | head -n1)
    pfx=${pfx:-wp_}
    printf '    DB_NAME=%s DB_USER=%s DB_HOST=%s prefix=%s\n' "$dbn" "$dbu" "$dbh" "$pfx"
    [[ -n $client ]] || { info "no mysql client found - check users_can_register/default_role by hand"; return; }
    [[ -n $dbn && $pfx =~ ^[A-Za-z0-9_]+$ ]] || return
 
    host=${dbh:-localhost}
    if [[ $host == *:/* ]]; then sock=${host#*:}; host=${host%%:*}
    elif [[ $host == *:* ]]; then port=${host##*:}; host=${host%:*}; fi
    [[ $host == localhost && -z $sock ]] && host=127.0.0.1
 
    # Password goes in a private temp file, not on the command line
    tmp=$(umask 077; mktemp) || return
    printf '[client]\npassword="%s"\n' "$(sed 's/\\/\\\\/g; s/"/\\"/g' <<<"$dbp")" > "$tmp"
    local args=(--defaults-extra-file="$tmp" -N -B --connect-timeout=5 -u "$dbu")
    if [[ -n $sock ]]; then args+=(--socket="$sock"); else args+=(-h "$host"); fi
    [[ -n $port ]] && args+=(-P "$port")
 
    if ! out=$("$client" "${args[@]}" "$dbn" -e \
        "SELECT option_name, option_value FROM ${pfx}options WHERE option_name IN ('users_can_register','default_role','active_plugins')" 2>/dev/null); then
        info "could not query the WordPress database with wp-config credentials"
        rm -f "$tmp"; return
    fi
    while IFS=$'\t' read -r k v; do
        case $k in
            users_can_register) reg=$v ;;
            default_role)       role=$v ;;
            active_plugins)     plugins=$v ;;
        esac
    done <<<"$out"
    printf '    users_can_register=%s  default_role=%s\n' "$reg" "$role"
    if [[ $reg == 1 && $role =~ ^(administrator|editor|author)$ ]]; then
        warn "WordPress: anyone can register and gets role '$role' ($cfg)"
    elif [[ $reg == 1 ]]; then
        info "WordPress: open registration (new users get '$role')"
    elif [[ $role == administrator ]]; then
        warn "WordPress: default_role is administrator (instant admin if registration is turned back on)"
    fi
    grep -oE '"[^"]+\.php"' <<<"$plugins" | tr -d '"' | sed 's/^/    active plugin: /'
    "$client" "${args[@]}" "$dbn" -e \
        "SELECT u.user_login, u.user_registered FROM ${pfx}users u JOIN ${pfx}usermeta m ON m.user_id=u.ID
         WHERE m.meta_key='${pfx}capabilities' AND m.meta_value LIKE '%administrator%'" 2>/dev/null \
        | while IFS=$'\t' read -r k v; do printf '    admin: %s (registered %s)\n' "$k" "$v"; done
    rm -f "$tmp"
}
 
check_web() {
    section "WEB SERVER"
    local roots=() d f any perm n v client
    for d in /srv/www /var/www /usr/share/nginx/html /var/lib/www /opt/lampp/htdocs; do [[ -d $d ]] && roots+=("$d"); done
    if ! ((${#roots[@]})); then info "no web root found"; return; fi
    info "web roots: ${roots[*]}"
 
    sub "PHP files inside upload directories (almost always webshells)"
    any=0
    while IFS= read -r f; do warn "PHP in uploads: $f"; any=1; done < <(
        find "${roots[@]}" -type f -path '*/uploads/*' \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \) 2>/dev/null)
    ((any)) || ok "none"
 
    sub "Upload directory permissions"
    any=0
    while IFS= read -r d; do
        any=1
        perm=$(stat -c '%a' "$d" 2>/dev/null)
        if [[ $perm =~ ^[0-7]+$ ]] && (( 8#$perm & 2 )); then
            warn "World-writable upload dir: $d ($perm)"
        else
            printf '    %s %s %s\n' "$perm" "$(stat -c '%U:%G' "$d" 2>/dev/null)" "$d"
        fi
        if [[ -f $d/.htaccess ]] && grep -qiE 'Require all denied|Deny from all|php_flag engine off|RemoveHandler' "$d/.htaccess"; then
            ok "PHP execution blocked by $d/.htaccess"
        else
            info "PHP not blocked in $d - add a .htaccess that denies *.php"
        fi
    done < <(find "${roots[@]}" -type d -name uploads -path '*wp-content*' 2>/dev/null)
    ((any)) || info "no WordPress uploads dir"
 
    sub "WordPress must-use plugins (always load, hidden from the plugin list)"
    any=0
    while IFS= read -r f; do warn "mu-plugin: $f"; any=1; done < <(
        find "${roots[@]}" -path '*/wp-content/mu-plugins/*' -type f 2>/dev/null)
    ((any)) || ok "none"
 
    sub "PHP that runs shell commands or eval()s request data (review each)"
    local pat='(^|[^>:$[:alnum:]_])(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)[[:space:]]*\(|eval[[:space:]]*\([[:space:]]*\$_|assert[[:space:]]*\([[:space:]]*\$_|base64_decode[[:space:]]*\([[:space:]]*\$_|\$_SERVER\[.HTTP_X_'
    any=0
    while IFS= read -r f; do
        any=1
        if [[ $f == */vendor/* ]]; then info "(bundled library, often benign) $f"; else warn "Shell/eval code in PHP: $f"; fi
        grep -nE "$pat" "$f" 2>/dev/null | head -n 3 | cut -c1-140 | indent
    done < <(grep -rlE --include='*.php' --include='*.phtml' --exclude-dir=wp-includes --exclude-dir=wp-admin "$pat" "${roots[@]}" 2>/dev/null)
    ((any)) || ok "none"
 
    sub "PHP disable_functions (web PHP only)"
    any=0
    for f in /etc/php*/apache2/php.ini /etc/php/*/apache2/php.ini /etc/php*/fpm/php.ini /etc/php/*/fpm/php.ini; do
        [[ -f $f ]] || continue
        any=1
        n=$(grep -cE '^\s*disable_functions\s*=' "$f")
        v=$(grep -E '^\s*disable_functions\s*=' "$f" | tail -n1 | cut -d= -f2- | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        if [[ -z $v ]]; then info "$f: disable_functions empty - PHP can run shell commands"
        else printf '    %s: %s\n' "$f" "$v"; fi
        ((n > 1)) && info "$f sets disable_functions $n times (the last one wins)"
    done
    ((any)) || info "no apache2/fpm php.ini found"
 
    sub "WordPress settings (read with wp-config.php credentials)"
    client=$(command -v mysql || command -v mariadb || ls /opt/mysql/bin/mysql /usr/local/mysql/bin/mysql 2>/dev/null | head -n1)
    any=0
    while IFS= read -r f; do
        any=1; info "$f"
        wp_check "$f" "$client"
    done < <(find "${roots[@]}" -maxdepth 5 -name wp-config.php -type f 2>/dev/null)
    ((any)) || info "no wp-config.php found"
}
 
check_smb() {
    section "FILE SHARING (SAMBA)"
    if ! have testparm; then info "testparm not found - Samba not installed"; return; fi
    local sec key val s l any=0
    local -A guest=() ro=() spath=()
 
    sub "Shares (non-default settings)"
    testparm -s 2>/dev/null | show
 
    sub "Risky Samba settings"
    while IFS=$'\t' read -r sec key val; do
        case $key in
            'guest ok')   guest[$sec]=${val,,} ;;
            'read only')  ro[$sec]=${val,,} ;;
            'path')       spath[$sec]=$val ;;
            'force user'|'force group')
                [[ ${val,,} == root ]] && { warn "SMB [$sec]: $key = root (every file op runs as root)"; any=1; } ;;
            'wide links')
                [[ ${val,,} == yes ]] && { warn "SMB [$sec]: wide links = Yes (symlinks can escape the share)"; any=1; } ;;
            'allow insecure wide links')
                [[ ${val,,} == yes ]] && { warn "SMB: allow insecure wide links = Yes"; any=1; } ;;
            'admin users')
                [[ -n $val ]] && { warn "SMB [$sec]: admin users = $val (act as root on the share)"; any=1; } ;;
            'root preexec'|'root postexec'|'preexec'|'postexec'|'magic script'|'add user script'|'username map script')
                [[ -n $val ]] && { warn "SMB [$sec]: $key = $val (runs a command)"; any=1; } ;;
        esac
    done < <(testparm -s 2>/dev/null | awk '
        /^\[/ {s=$0; gsub(/[][]/,"",s); next}
        /=/   {l=$0; sub(/^[ \t]+/,"",l); i=index(l,"="); k=substr(l,1,i-1); v=substr(l,i+1)
               gsub(/^[ \t]+|[ \t]+$/,"",k); gsub(/^[ \t]+|[ \t]+$/,"",v); print s "\t" tolower(k) "\t" v}')
 
    for s in "${!spath[@]}"; do
        if [[ ${guest[$s]:-no} == yes && ${ro[$s]:-yes} == no ]]; then
            warn "SMB [$s]: guest-writable share (fine only if scoring needs it)"; any=1
        fi
        while IFS= read -r l; do
            warn "Symlink inside share [$s]: $l -> $(readlink "$l")"; any=1
        done < <(find "${spath[$s]}" -maxdepth 3 -type l 2>/dev/null)
    done
    ((any)) || ok "nothing risky"
 
    if have pdbedit; then
        sub "Samba user accounts"
        pdbedit -L 2>/dev/null | show
    fi
}
 
summary() {
    section "SUMMARY"
    if ((${#FINDINGS[@]})); then
        printf '%s%d item(s) flagged:%s\n' "$R$B" "${#FINDINGS[@]}" "$N"
        printf '    - %s\n' "${FINDINGS[@]}"
    else
        ok "Nothing auto-flagged - still read the output above"
    fi
}
 
# ---------- main ----------
main() {
    local all=(users cron procs net logins files web smb) s bf
    local sections=("$@")
 
    if [[ ${1:-} == baseline ]]; then
        # Without root, ss hides process names and the baseline would never match a sudo run
        [[ $EUID -eq 0 ]] || { echo "Run the baseline with sudo: sudo $0 baseline" >&2; exit 1; }
        bf=$(baseline_file)
        portsnap > "$bf" || exit 1
        [[ -n ${SUDO_USER:-} ]] && chown "$SUDO_USER" "$bf" 2>/dev/null
        echo "Saved port baseline to $bf:"; indent < "$bf"
        exit 0
    fi
 
    ((${#sections[@]})) || sections=("${all[@]}")
    for s in "${sections[@]}"; do
        declare -F "check_$s" >/dev/null || { echo "Unknown section: $s (valid: ${all[*]} baseline)" >&2; exit 1; }
    done
 
    LOG=${LOG:-./triage_$(hostname)_$(date +%Y%m%d_%H%M%S).log}
    (umask 077; : > "$LOG")   # log may contain account info - keep it private
    exec > >(tee >(sed -E 's/\x1b\[[0-9;]*m//g' >> "$LOG")) 2>&1
 
    section "HOST TRIAGE: $(hostname) - $(date '+%F %T %Z')"
    printf '    Kernel: %s\n    Running as: %s\n    Up: %s\n' "$(uname -r)" "$(id -un)" "$(uptime -p 2>/dev/null || uptime)"
    [[ $EUID -ne 0 ]] && info "Not root - shadow, crontabs, process owners and package checks will be incomplete"
 
    for s in "${sections[@]}"; do "check_$s"; done
    summary
    printf '\n%sLog saved to %s%s\n' "$B" "$LOG" "$N"
    sleep 0.3   # let tee flush before the prompt returns
}
 
# Run main only when executed, not when sourced
[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"
