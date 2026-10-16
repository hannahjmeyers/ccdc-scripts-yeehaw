#!/bin/bash
# systemd_check.sh - CCDC systemd persistence check (Ubuntu)
# Usage: sudo ./systemd_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

SUS='curl|wget|nc |ncat|netcat|/dev/tcp|/dev/udp|bash -i|sh -i|bash -c|sh -c|base64|python|perl|php -r|ruby|socat|mkfifo|/tmp/|/dev/shm|/var/tmp|/home/|chmod \+s|useradd|passwd'

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }

# Unit directories (system + user)
DIRS="/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system \
/usr/local/lib/systemd/system /etc/systemd/user /run/systemd/user /usr/lib/systemd/user \
/usr/local/lib/systemd/user /usr/local/lib"

# Build list of every file installed by a package (normalize /lib -> /usr/lib)
declare -A PKGFILES
while IFS= read -r f; do
    PKGFILES["${f/#\/lib\//\/usr\/lib\/}"]=1
done < <(cat /var/lib/dpkg/info/*.list 2>/dev/null)

# Add every user's ~/.config/systemd/user
for h in /root /home/*; do
    [ -d "$h/.config/systemd/user" ] && DIRS="$DIRS $h/.config/systemd/user"
done

# Check one unit file: show Exec lines, flag SUS ones, flag files no package owns
check_unit() {
    local f="$1" flagged=0 owner out=""
    local norm="${f/#\/lib\//\/usr\/lib\/}"
    [ -n "${PKGFILES[$norm]}" ] && owner="yes"
    while IFS= read -r line; do
        if echo "$line" | grep -qiE "$SUS"; then
            out+="  ${RED}[SUS] $line${NC}\n"; flagged=1
        else
            out+="        $line\n"
        fi
    done < <(grep -E '^\s*Exec[A-Za-z]*=' "$f" 2>/dev/null)

    # Only print units worth looking at: flagged, or not from a package
    if [ $flagged -eq 1 ] || [ -z "$owner" ]; then
        local note="from a package"
        [ -z "$owner" ] && note="${RED}NO PACKAGE OWNS THIS FILE${NC}"
        echo -e "${YEL}--- $f${NC}  ($(stat -c '%U %a modified %y' "$f" | cut -d. -f1)) $note"
        echo -ne "$out"
    fi
}

# Resolve symlinked dirs and drop duplicates
DIRS=$(for d in $DIRS; do [ -d "$d" ] && readlink -f "$d"; done | sort -u)

header "Unit files that are SUS or not installed by a package"
echo "(stock package-owned units with clean Exec lines are hidden)"
for d in $DIRS; do
    [ -d "$d" ] || continue
    # /usr/local/lib: only look at unit files, not every library
    if [ "$d" = "/usr/local/lib" ]; then
        files=$(find "$d" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null)
    else
        files=$(find "$d" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) 2>/dev/null)
    fi
    for f in $files; do check_unit "$f"; done
done

header "Symlinks in /etc/systemd/system pointing outside normal dirs"
find /etc/systemd/system -type l 2>/dev/null | while read -r l; do
    t=$(readlink -f "$l")
    case "$t" in
        /usr/lib/systemd/*|/lib/systemd/*|/etc/systemd/*|/dev/null) ;;
        *) echo -e "  ${RED}[SUS] $l -> $t${NC}" ;;
    esac
done

header "Drop-in overrides (*.d/*.conf) - can hijack legit services"
find /etc/systemd/system /run/systemd/system -path '*.d/*.conf' -type f 2>/dev/null | while read -r f; do
    echo -e "${YEL}--- $f${NC}"
    grep -E '^\s*Exec' "$f" | sed 's/^/        /'
done

header "Enabled services (non-default ones are worth a look)"
systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend

header "Running services"
systemctl list-units --type=service --state=running --no-pager --no-legend

header "Timers (systemd's version of cron)"
systemctl list-timers --all --no-pager

header "Unit files modified in last 7 days"
for d in $DIRS; do
    [ -d "$d" ] && find "$d" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) -mtime -7 -exec ls -la {} \; 2>/dev/null
done

echo -e "\n${GRN}[*] Done. Inspect a unit with: systemctl cat <name>   status: systemctl status <name>${NC}"
