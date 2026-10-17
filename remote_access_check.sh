#!/bin/bash
# remote_access_check.sh - CCDC: find every way into this box (Ubuntu + Fedora/RHEL)
# SSH, telnet, r-services, VNC, RDP, web admin panels, tunnels, bind shells, PAM/sshd backdoors
# Read-only. Usage: sudo ./remote_access_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo) or you won't see which program owns each port."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
sus()    { echo -e "  ${RED}[SUS] $1${NC}"; }
chk()    { echo -e "  ${YEL}[CHECK] $1${NC}"; }

if command -v rpm >/dev/null && ! command -v dpkg >/dev/null; then DISTRO=rpm; else DISTRO=deb; fi
command -v ss >/dev/null || echo -e "${RED}[!] 'ss' missing - install iproute2 (deb) / iproute (rpm). Port checks will be empty.${NC}"

# Known remote-access ports -> what they are
declare -A RPORT=(
  [22]="SSH" [23]="TELNET (plaintext login!)" [512]="rexec" [513]="rlogin" [514]="rsh"
  [3389]="RDP / xrdp" [5800]="VNC (web)" [5900]="VNC" [5901]="VNC" [5902]="VNC" [5903]="VNC"
  [6000]="X11 (open X server)" [6001]="X11" [9090]="Cockpit web admin" [10000]="Webmin"
  [5938]="TeamViewer" [7070]="AnyDesk" [21115]="RustDesk" [21116]="RustDesk" [21118]="RustDesk"
  [2222]="SSH (alt port?)" [4444]="common backdoor port" [1337]="common backdoor port"
  [31337]="common backdoor port" [8888]="common backdoor port" [5555]="adb / backdoor"
  [21]="FTP" [69]="TFTP" [161]="SNMP" [2049]="NFS" [111]="rpcbind"
)
SHELLS='^(sh|bash|dash|zsh|ksh|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|php|lua|busybox|telnet|ngrok|chisel|frpc|frps|gost|ligolo.*)$'

# ---------------------------------------------------------------
header "1. Everything listening for connections"
echo "  (anything not on your scored-services list should be explained or shut off)"
ss -tulnpH 2>/dev/null | while read -r proto _ _ _ local _ procs; do
    port="${local##*:}"
    addr="${local%:*}"
    name=$(echo "$procs" | grep -oE '"[^"]+"' | head -1 | tr -d '"')
    pid=$(echo "$procs" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    exe=""; [ -n "$pid" ] && exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
    what="${RPORT[$port]}"
    line="$proto $local  ${name:-?} (pid ${pid:-?}) ${exe:+-> $exe}"
    if [[ "$name" =~ $SHELLS ]]; then
        sus "$line   <- shell/tool listening = BIND SHELL"
    elif [[ "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* || "$exe" == */.* || "$exe" == *"(deleted)"* ]]; then
        sus "$line   <- running from a weird/deleted path"
    elif [ -n "$what" ] && [ "$port" != 22 ]; then
        sus "$line   <- $what"
    elif [[ "$addr" == "127.0.0.1" || "$addr" == "[::1]" || "$addr" == 127.0.0.53* ]]; then
        echo "        $line   (localhost only)"
    else
        echo "        $line${what:+   ($what)}"
    fi
done

# More than one sshd listener = second (often backdoored) SSH daemon
n=$(pgrep -fc 'sshd.*\[listener\]|^/usr/sbin/sshd' 2>/dev/null)
sshports=$(ss -tlnpH 2>/dev/null | grep '"sshd"' | awk '{n=split($4,a,":"); print a[n]}' | sort -u | tr '\n' ' ')
[ -n "$sshports" ] && echo -e "\n  SSH is listening on port(s): $sshports"
[ "$(echo $sshports | wc -w)" -gt 1 ] && sus "SSH on more than one port - check for a second sshd with its own config"
ps -eo pid=,args= | grep -E '^ *[0-9]+ (sshd(-session)?:? |/usr/s?bin/sshd |/s?bin/sshd |sshd )' | grep -E ' -f | -p ?[0-9]' \
    | while read -r l; do sus "sshd started with custom config/port: $l"; done

# ---------------------------------------------------------------
header "2. Remote-access services installed / enabled"
for svc in ssh sshd telnet.socket telnetd inetd xinetd openbsd-inetd rsh.socket rlogin.socket rexec.socket \
           vsftpd proftpd pure-ftpd tftp tftpd-hpa tftp.socket xrdp xrdp-sesman vncserver@ x11vnc tigervnc \
           teamviewerd anydesk rustdesk cockpit.socket cockpit webmin ngrok snmpd rpcbind nfs-server; do
    st=$(systemctl is-enabled "$svc" 2>/dev/null)
    act=$(systemctl is-active "$svc" 2>/dev/null)
    [ -z "$st" ] || [ "$st" = "not-found" ] && continue
    [[ "$svc" =~ ^ssh ]] && { echo "        $svc: $st / $act"; continue; }
    if [ "$act" = active ] || [ "$st" = enabled ]; then
        sus "$svc is $st / $act"
    else
        echo "        $svc: $st / $act"
    fi
done
# Old-school inetd/xinetd configs (telnet/rsh often hide here)
if [ -f /etc/inetd.conf ]; then
    grep -vE '^\s*#|^\s*$' /etc/inetd.conf | while read -r l; do sus "inetd.conf: $l"; done
fi
for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    if ! grep -qiE '^\s*disable\s*=\s*yes' "$f"; then
        sus "xinetd service ENABLED: $f ($(grep -iE 'server\s*=' "$f" | head -1 | xargs))"
    fi
done

# ---------------------------------------------------------------
header "3. Remote-access / tunneling programs on disk"
for b in telnetd in.telnetd in.rshd in.rlogind in.rexecd rshd rlogind x11vnc vncserver Xvnc xrdp \
         teamviewer anydesk rustdesk ngrok chisel frpc frps gost ligolo socat ncat netcat nc; do
    p=$(command -v "$b" 2>/dev/null) || continue
    case "$b" in
        nc|netcat|ncat|socat) chk "$b at $p (normal on some systems, but it's how bind/reverse shells are made)";;
        *) sus "$b installed at $p";;
    esac
done
# Tunnel tools dropped in temp/home dirs (often renamed, so match by content too)
find /tmp /var/tmp /dev/shm /root /home /opt /usr/local/bin /usr/local/lib -xdev -type f -perm /111 \
     \( -iname '*ngrok*' -o -iname '*chisel*' -o -iname 'frp*' -o -iname '*ligolo*' -o -iname 'gost*' -o -iname '*socat*' \) \
     2>/dev/null | while read -r f; do sus "tunnel tool: $f"; done
find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x 2>/dev/null | while read -r f; do
    sus "executable in temp dir: $f ($(file -b "$f" 2>/dev/null | cut -c1-50))"
done

# ---------------------------------------------------------------
header "4. SSH server settings that allow sneaky access"
if command -v sshd >/dev/null; then
    sshd -T 2>/dev/null | grep -iE '^(port|listenaddress|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|gatewayports|allowtcpforwarding|permittunnel|x11forwarding|allowusers|denyusers|usepam|forcecommand) ' \
    | while read -r k v; do
        case "$k $v" in
            "permitemptypasswords yes"|"gatewayports yes"|"gatewayports clientspecified"|"permittunnel yes"|"permittunnel point-to-point"|"permittunnel ethernet")
                sus "$k $v";;
            "permitrootlogin yes")
                chk "$k $v (root can log in with a password)";;
            authorizedkeyscommand*)
                [ "$v" != none ] && sus "$k $v (runs a program to fetch keys - see ssh_check.sh)";;
            *) echo "        $k $v";;
        esac
    done
    ls /etc/ssh/sshd_config.d/ 2>/dev/null | sed 's|^|        drop-in: /etc/ssh/sshd_config.d/|'
else
    echo "        sshd not installed"
fi

# ---------------------------------------------------------------
header "5. Backdoored login programs (sshd / PAM / login replaced?)"
echo "  (compares files against what the package originally installed)"
verify() {   # $1 = package name; prints changed binaries/libs (not config edits)
    if [ "$DISTRO" = rpm ]; then
        rpm -V "$1" 2>/dev/null | grep -E '^..5' | grep -vE ' c /'
    else
        dpkg --verify "$1" 2>/dev/null | grep -E '^..5' | grep -v ' c /'
    fi
}
if [ "$DISTRO" = rpm ]; then PKGS="openssh-server openssh pam util-linux shadow-utils sudo"; else PKGS="openssh-server openssh-client libpam-modules libpam-runtime login passwd sudo"; fi
bad=0
for pkg in $PKGS; do
    out=$(verify "$pkg")
    [ -n "$out" ] && { echo "$out" | while read -r l; do sus "$pkg: file changed since install: $l"; done; bad=1; }
done
[ $bad -eq 0 ] && echo "        sshd / PAM / login binaries match their packages"

# PAM: lines that let anyone in or run a program at login
for f in /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sudo /etc/pam.d/su; do
    [ -f "$f" ] || continue
    grep -nE '^\s*[^#].*(pam_exec|pam_permit\.so)' "$f" | while read -r l; do
        if echo "$l" | grep -q pam_exec; then sus "$f:$l  (runs a program at login)"
        elif echo "$l" | grep -qE '^\s*[0-9]+:\s*auth\s+(sufficient|\[success=[^]]*done[^]]*\])\s+pam_permit'; then sus "$f:$l  (auth always succeeds = any password works)"
        fi
    done
done
# PAM module files nobody installed
PAMDIRS=$(for d in /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib64/security /usr/lib64/security /lib/security /usr/lib/security; do
    [ -d "$d" ] && readlink -f "$d"; done | sort -u)
for d in $PAMDIRS; do
    for m in "$d"/*.so; do
        [ -f "$m" ] || continue
        short="${m#/usr}"
        if [ "$DISTRO" = rpm ]; then
            rpm -qf "$m" >/dev/null 2>&1 || rpm -qf "$short" >/dev/null 2>&1 || sus "PAM module no package owns: $m"
        else
            dpkg -S "$m" >/dev/null 2>&1 || dpkg -S "$short" >/dev/null 2>&1 || sus "PAM module no package owns: $m"
        fi
    done
done
grep -lE 'LD_PRELOAD|\.so' /etc/ld.so.preload 2>/dev/null && sus "/etc/ld.so.preload exists: $(cat /etc/ld.so.preload) (preloaded library = rootkit trick)"

# ---------------------------------------------------------------
header "6. Who is connected RIGHT NOW"
echo "  Logged-in terminals (who):"
who | sed 's/^/        /'
echo "  SSH sessions incl. ones with no terminal (who can't see these):"
ps -eo pid,etime,args | grep -E '[s]shd(-session)?: [^ /]+($|@| \[priv\]| \[net\])' | sed 's/^/        /'
echo "        (\"sshd: user\" with no @tty = tunnel-only session, e.g. ssh -N port forwarding)"
echo "  Connections to remote-access ports on this box:"
ss -tnpH state established 2>/dev/null | while read -r _ _ local peer procs; do
    lport="${local##*:}"
    [ -n "${RPORT[$lport]}" ] && echo "        ${RPORT[$lport]}: $peer -> $local  $(echo "$procs" | grep -oE '"[^"]+",pid=[0-9]+' | head -1)"
done
echo "  Outbound tunnels (this box connecting OUT with ssh/tunnel tools = reverse tunnel):"
ss -tnpH state established 2>/dev/null | grep -E '"(ssh|chisel|ngrok|frpc|gost|socat|nc|ncat|autossh)"' | while read -r _ _ local peer procs; do
    sus "$local -> $peer  $(echo "$procs" | grep -oE '"[^"]+",pid=[0-9]+' | head -1)"
done
ps -eo pid,args | grep -E '[s]sh .*-[a-zA-Z]*[RLD] ' | while read -r l; do sus "ssh port-forward running: $l"; done

# ---------------------------------------------------------------
header "7. Recent logins"
echo "  Last 15 successful logins:"
last -n 15 -a 2>/dev/null | grep -v '^$' | sed 's/^/        /'
echo "  Failed logins (brute force?):"
if command -v lastb >/dev/null && lastb -n 1 >/dev/null 2>&1; then
    lastb -a 2>/dev/null | grep -vE '^\s*$|^btmp' | awk '{print $NF}' | sort | uniq -c | sort -rn | head -5 | sed 's/^/        attempts from: /'
fi
LOG=""; for f in /var/log/auth.log /var/log/secure; do [ -f "$f" ] && LOG="$f"; done
if [ -n "$LOG" ]; then
    echo "  Accepted logins in $LOG:"
    grep -E 'Accepted (password|publickey)' "$LOG" 2>/dev/null | tail -10 | sed 's/^/        /'
else
    echo "  Accepted logins (journal):"
    journalctl -u sshd -u ssh --no-pager 2>/dev/null | grep -E 'Accepted' | tail -10 | sed 's/^/        /'
fi

echo -e "\n${GRN}[*] Done. Kill a listener: ss -tlnp | grep :PORT  -> kill -9 PID ; disable a service: systemctl disable --now NAME${NC}"
