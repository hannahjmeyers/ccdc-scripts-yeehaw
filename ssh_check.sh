#!/bin/bash
# ssh_check.sh - CCDC SSH key persistence check (Ubuntu)
# Usage: sudo ./ssh_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }

# Print each key: fingerprint, comment, and flag risky options
show_keys() {
    local f="$1" user="$2"
    echo -e "${YEL}--- $f${NC}  (user: $user, $(stat -c '%U %a modified %y' "$f" | cut -d. -f1))"
    local n=0
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        n=$((n+1))
        fp=$(echo "$line" | ssh-keygen -lf - 2>/dev/null)
        [ -z "$fp" ] && fp="(could not parse key)"
        # Key options before the key type, e.g. command="..." / from="..."
        # Anything in front of the key type is an option (command=, from=, etc.)
        opts=$(echo "$line" | sed -E 's/(ssh-|ecdsa-|sk-).*//; s/[[:space:]]+$//')
        if [ -n "$opts" ]; then
            echo -e "  ${RED}[SUS] key #$n has options: $opts${NC}"
        fi
        echo "        key #$n: $fp"
    done < "$f"
    [ $n -eq 0 ] && echo "        (empty)"
    [ $n -gt 0 ] && echo -e "  ${YEL}=> $n key(s). Do you recognize every one?${NC}"
}

# 1. sshd config: where does sshd look for keys?
header "sshd config (AuthorizedKeysFile / AuthorizedKeysCommand)"
CONFS="/etc/ssh/sshd_config $(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
for c in $CONFS; do
    [ -f "$c" ] || continue
    echo -e "${YEL}--- $c${NC}"
    grep -iE '^\s*(AuthorizedKeysFile|AuthorizedKeysCommand|AuthorizedKeysCommandUser|PermitRootLogin|PubkeyAuthentication|PasswordAuthentication|PermitEmptyPasswords|Include|Match)' "$c" \
        | while IFS= read -r line; do
            if echo "$line" | grep -qiE '^\s*AuthorizedKeysCommand\s|PermitEmptyPasswords\s+yes|PermitRootLogin\s+yes'; then
                echo -e "  ${RED}[SUS] $line${NC}"
            elif echo "$line" | grep -qiE '^\s*AuthorizedKeysFile' && ! echo "$line" | grep -qE 'AuthorizedKeysFile\s+\.ssh/authorized_keys(\s+\.ssh/authorized_keys2)?\s*$'; then
                echo -e "  ${RED}[SUS] non-default: $line${NC}"
            else
                echo "        $line"
            fi
        done
done

# Effective config (what sshd is actually using after all includes)
if command -v sshd >/dev/null; then
    header "Effective sshd settings (sshd -T)"
    sshd -T 2>/dev/null | grep -iE '^(authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|permitrootlogin|pubkeyauthentication|passwordauthentication|permitemptypasswords) '
    # Show the AuthorizedKeysCommand script if one is set
    akc=$(sshd -T 2>/dev/null | awk '/^authorizedkeyscommand /{print $2}')
    if [ -n "$akc" ] && [ "$akc" != "none" ]; then
        echo -e "${RED}[SUS] AuthorizedKeysCommand runs: $akc${NC}"
        [ -f "$akc" ] && { echo "--- contents:"; cat "$akc"; }
    fi
fi

# Key file paths sshd will check (default + any custom AuthorizedKeysFile)
KEYPATHS=$(sshd -T 2>/dev/null | awk '/^authorizedkeysfile /{$1=""; print}')
# Always check the defaults too, even if config says otherwise
KEYPATHS=$(echo "$KEYPATHS .ssh/authorized_keys .ssh/authorized_keys2" | tr ' ' '\n' | grep -v '^$' | sort -u)

# 2. Every user in /etc/passwd (not just /home - service accounts too)
header "authorized_keys for every user"
while IFS=: read -r user _ uid _ _ home shell; do
    [ -d "$home" ] || continue
    for p in $KEYPATHS; do
        p="${p//%h/$home}"; p="${p//%u/$user}"; p="${p//%U/$uid}"
        [[ "$p" != /* ]] && p="$home/$p"
        [ -f "$p" ] || continue
        show_keys "$p" "$user"
        case "$shell" in
            */nologin|*/false) echo -e "  ${RED}[SUS] $user has keys but shell is $shell (check it wasn't changed)${NC}" ;;
        esac
    done
done < /etc/passwd

# 3. Stray key files anywhere (catches keys hidden outside home dirs)
header "Any authorized_keys* file on the system"
find / -xdev -name 'authorized_keys*' -type f 2>/dev/null

# 4. Users with a real login shell (keys only work if the shell works)
header "Users with login shells"
grep -vE '(nologin|false|sync|halt|shutdown)$' /etc/passwd | cut -d: -f1,3,6,7

# 5. Recently changed
header "SSH files modified in last 7 days"
find /etc/ssh /root/.ssh /home/*/.ssh -type f -mtime -7 -exec ls -la {} \; 2>/dev/null

echo -e "\n${GRN}[*] Done. Remove a bad key: edit the file and delete that line. Then: systemctl restart ssh${NC}"
