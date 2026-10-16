#!/bin/bash
# shell_check.sh - CCDC shell startup file persistence check (Ubuntu)
# Usage: sudo ./shell_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

# Bad commands + shell-specific tricks (aliases over real commands, hooks that run every prompt, preload)
SUS='curl|wget|nc |ncat|netcat|/dev/tcp|/dev/udp|bash -i|sh -i|base64|python|perl|php -r|ruby|socat|mkfifo|/tmp/|/dev/shm|/var/tmp|chmod \+s|useradd|passwd|PROMPT_COMMAND|LD_PRELOAD|LD_LIBRARY_PATH|trap |alias (sudo|su|ls|ps|cd|ssh|cat|netstat|ss|who|w|top|kill|systemctl)=|nohup|disown|setsid|&\s*$|export PATH=\.|PATH=.*:\.(:|$)'

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }

# Known-good hashes for /etc conffiles, from dpkg
declare -A CONFMD5
while read -r f sum _; do
    [ -n "$f" ] && CONFMD5["$f"]="$sum"
done < <(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | grep '^ /')

# Print only flagged lines from a file (full bashrc is too long to read)
flag_lines() {
    local f="$1"
    grep -nvE '^\s*#|^\s*$' "$f" | grep -E "$SUS" \
        | grep -vE "alias (ls|dir|vdir|grep|fgrep|egrep)='(ls|dir|vdir|grep|fgrep|egrep) --color=auto'" | while IFS= read -r line; do
        echo -e "  ${RED}[SUS] line $line${NC}"
    done
}

# Compare a system file to its package version
check_system_file() {
    local f="$1"
    [ -f "$f" ] || return
    local note
    local base="/usr/share/base-files/$(basename "$f")"
    if [ "$f" = /etc/profile ] && [ -f "$base" ]; then
        if cmp -s "$f" "$base"; then note="${GRN}same as Ubuntu default${NC}"; else note="${RED}MODIFIED from Ubuntu default ($base)${NC}"; fi
    elif [ -n "${CONFMD5[$f]}" ]; then
        if [ "$(md5sum "$f" | cut -d' ' -f1)" = "${CONFMD5[$f]}" ]; then
            note="${GRN}unchanged from package${NC}"
        else
            note="${RED}MODIFIED from package version${NC}"
        fi
    elif dpkg -S "$f" >/dev/null 2>&1; then
        note="from a package"
    else
        note="${RED}NO PACKAGE OWNS THIS FILE${NC}"
    fi
    echo -e "${YEL}--- $f${NC}  ($(stat -c '%U %a modified %y' "$f" | cut -d. -f1)) $note"
    flag_lines "$f"
}

# 1. System-wide files
header "System-wide startup files"
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/profile.d/*; do
    check_system_file "$f"
done
[ -f /etc/bashrc ] || echo "  (/etc/bashrc does not exist - normal on Ubuntu; if it appears, look at it)"

# 2. Per-user files for every user with a home dir
header "Per-user startup files (compared to defaults)"
while IFS=: read -r user _ _ _ _ home _; do
    [ -d "$home" ] || continue
    for name in .bash_profile .bash_login .profile .bashrc .bash_logout; do
        f="$home/$name"
        [ -f "$f" ] || continue
        skel="/etc/skel/$name"
        [ "$user" = root ] && [ -f "/usr/share/base-files/dot$name" ] && skel="/usr/share/base-files/dot$name"
        if [ -f "$skel" ] && cmp -s "$f" "$skel"; then
            note="${GRN}same as default${NC}"
            # Still check (in case /etc/skel itself was poisoned) but skip the diff
            echo -e "${YEL}--- $f${NC}  (user: $user) $note"
            flag_lines "$f"
            continue
        fi
        if [ -f "$skel" ]; then
            note="${RED}DIFFERENT from default ($skel)${NC}"
        else
            note="${YEL}no default to compare (not created by default - who made it?)${NC}"
        fi
        echo -e "${YEL}--- $f${NC}  (user: $user, $(stat -c '%U %a modified %y' "$f" | cut -d. -f1)) $note"
        flag_lines "$f"
        # Show what was added compared to the default
        if [ -f "$skel" ]; then
            diff "$skel" "$f" | grep '^>' | sed 's/^>/        added:/'
        else
            grep -vE '^\s*#|^\s*$' "$f" | sed 's/^/        /'
        fi
    done
done < /etc/passwd

# 3. /etc/skel itself (poisoning it backdoors every NEW user)
header "/etc/skel (template for new users)"
for f in /etc/skel/.[!.]*; do check_system_file "$f"; done

# 4. Recently changed
header "Startup files modified in last 7 days"
find /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /etc/environment /etc/skel \
     /root /home/* -maxdepth 1 -type f \
     \( -name 'profile' -o -name '*.sh' -o -name 'bash.bashrc' -o -name 'bashrc' -o -name 'environment' \
        -o -name '.bash*' -o -name '.profile' \) -mtime -7 -exec ls -la {} \; 2>/dev/null

echo -e "\n${GRN}[*] Done. Fix a user file: cp /etc/skel/.bashrc /home/USER/.bashrc  (then chown USER:USER it)${NC}"
