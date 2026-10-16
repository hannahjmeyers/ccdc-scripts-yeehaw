#!/bin/bash
# webshell_check.sh - CCDC web shell hunt (Ubuntu / Apache / OpenCart)
# Usage: sudo ./webshell_check.sh [webroot] [logdir]
#   defaults: webroot=/var/www   logdir=/var/log/apache2

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

WEB="${1:-/var/www}"
LOGDIR="${2:-/var/log/apache2}"
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }

[ -d "$WEB" ] || { echo "[!] $WEB not found. Pass the webroot: sudo $0 /path/to/webroot"; exit 1; }
echo "Webroot: $WEB    Logs: $LOGDIR"

# Every file that the server could execute as code
SCRIPTS=$(find "$WEB" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' \
          -o -iname '*.phar' -o -iname '*.inc' -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.py' \
          -o -iname '*.jsp' -o -iname '*.asp' -o -iname '*.aspx' -o -iname '*.shtml' \) 2>/dev/null)

# Code-exec functions, and user input coming from the web request
EXEC='(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|call_user_func(_array)?)\s*\('
INPUT='\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|php://input|getallheaders'
OBFUS='(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev)\s*\('

cut80() { cut -c1-200; }   # keep long obfuscated lines from flooding the screen

# 1. HIGH: request input fed straight into an exec function (the classic one-liner)
header "HIGH: user input -> code execution (almost always a web shell)"
HIGHFILES=""
for f in $SCRIPTS; do
  {
    grep -nE "$EXEC" "$f" 2>/dev/null | grep -E "$INPUT" | cut80 | while IFS= read -r l; do
        echo -e "  ${RED}[SUS] $f:$l${NC}"
    done
    # eval/assert of decoded blob:  eval(base64_decode(...))
    grep -nE "(eval|assert)\s*\(\s*@?$OBFUS" "$f" 2>/dev/null | cut80 | while IFS= read -r l; do
        echo -e "  ${RED}[SUS] $f:$l${NC}"
    done
    # backticks running request input:  `$_GET[c]`
    grep -nE '`[^`]*\$_(GET|POST|REQUEST|COOKIE)' "$f" 2>/dev/null | cut80 | while IFS= read -r l; do
        echo -e "  ${RED}[SUS] $f:$l${NC}"
    done
    # preg_replace /e modifier (old eval trick)
    grep -nE "preg_replace\s*\(\s*['\"].*/[a-z]*e[a-z]*['\"]" "$f" 2>/dev/null | cut80 | while IFS= read -r l; do
        echo -e "  ${RED}[SUS] $f:$l${NC}"
    done
  } > /tmp/.wsc_hits 2>/dev/null
  if [ -s /tmp/.wsc_hits ]; then sort -u /tmp/.wsc_hits; HIGHFILES="$HIGHFILES $f "; fi
done
rm -f /tmp/.wsc_hits

# 2. MEDIUM: exec / obfuscation functions anywhere (legit apps use some - read them)
header "MEDIUM: exec or decode functions (OpenCart uses a few legitimately - read these)"
for f in $SCRIPTS; do
    [[ "$HIGHFILES" == *" $f "* ]] && continue   # already shown above
    hits=$(grep -nE "$EXEC|$OBFUS" "$f" 2>/dev/null | grep -vE "$INPUT" | grep -vE '^\s*[0-9]+:\s*(//|\*|#)')
    [ -z "$hits" ] && continue
    echo -e "${YEL}--- $f${NC}"
    echo "$hits" | cut80 | head -5 | sed 's/^/        /'
    n=$(echo "$hits" | wc -l); [ "$n" -gt 5 ] && echo "        ... ($n total)"
done

# 3. Obfuscated: very long lines in scripts
header "Very long lines (>1000 chars = packed/obfuscated code)"
for f in $SCRIPTS; do
    awk -v f="$f" 'length($0)>1000 {printf "  \033[0;31m[SUS] %s:%d (%d chars)\033[0m\n", f, NR, length($0)}' "$f" 2>/dev/null | head -3
done

# 4. Scripts where they don't belong
header "Scripts inside upload / image / cache folders (should be data only)"
for f in $SCRIPTS; do
    rel="${f#$WEB}"
    echo "$rel" | grep -qiE '/(uploads?|images?|img|media|cache|tmp|temp|files|upload|download)/' && echo -e "  ${RED}[SUS] $f${NC}"
done

header "Odd extensions / double extensions / hidden files"
find "$WEB" -type f \( -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' \
     -o -iname '*.jpg.php' -o -iname '*.png.php' -o -iname '*.gif.php' -o -iname '*.php.*' \
     -o -iname '*.jsp' -o -iname '*.aspx' -o -iname '*.cgi' \) 2>/dev/null | sed "s/^/  [SUS] /"
find "$WEB" -name '.*' ! -name '.htaccess' ! -name '.' ! -path '*/.git/*' 2>/dev/null | sed "s/^/  [CHECK] hidden: /"
# Images that contain PHP code
find "$WEB" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.ico' -o -iname '*.txt' \) \
     -exec grep -lE '<\?php|<\?=' {} + 2>/dev/null | sed "s/^/  [SUS] PHP inside non-PHP file: /"

header ".htaccess files that make other extensions run as PHP"
find "$WEB" -name '.htaccess' 2>/dev/null | while read -r f; do
    grep -inE 'AddType|AddHandler|SetHandler|php_value\s+auto_prepend|php_value\s+auto_append|ForceType' "$f" \
        | sed "s|^|  [SUS] $f:|"
done

# 5. Recently changed (the 'appended to a legit file' case)
header "Webroot files changed in last 2 days (newest first)"
echo "  (uses ctime - attackers can fake mtime with 'touch', but not ctime)"
find "$WEB" -type f -ctime -2 ! -path '*/cache/*' ! -path '*/storage/cache/*' -printf '%CY-%Cm-%Cd %CH:%CM  %-9u %p\n' 2>/dev/null \
    | sort -r | head -40 | sed 's/^/        /'

header "Script files owned by the web server user (it wrote them - why?)"
for f in $SCRIPTS; do
    o=$(stat -c %U "$f")
    [[ "$o" == www-data || "$o" == apache || "$o" == nginx ]] && echo "        $f ($o)"
done | head -30

# 6. Live: is the web server running shells right now?
header "Processes running as www-data (a shell here = someone is using a web shell NOW)"
ps -o pid,ppid,etime,cmd -u www-data 2>/dev/null | grep -vE 'apache2|httpd|php-fpm|nginx' | sed 's/^/        /'
ps -o pid,cmd -u www-data 2>/dev/null | grep -E '\b(sh|bash|dash|nc|ncat|python[0-9.]*|perl|socat|curl|wget)\b' | grep -v grep \
    | sed "s/^/  [SUS] /"

header "Network connections from www-data / apache"
ss -tnp 2>/dev/null | grep -E 'apache2|php|www-data|"sh"|"bash"|"nc"' | grep -v LISTEN | sed 's/^/        /'

# 7. Logs
header "Access logs - shell-style requests"
LOGS=$(ls "$LOGDIR"/access.log* "$LOGDIR"/*access*.log* 2>/dev/null | sort -u)
if [ -z "$LOGS" ]; then
    echo "  (no access logs in $LOGDIR - check: ls /var/log/apache2 /var/log/nginx /var/log/httpd)"
else
    # zcat -f reads both plain and .gz rotated logs
    zcat -f $LOGS 2>/dev/null | grep -iE '[?&](cmd|exec|command|c|shell|run|e|x|q|pass)=|whoami|uname|/etc/passwd|/bin/(ba)?sh|%2Fbin%2F|wget|curl|base64|nc\+|\.\./\.\./' \
        | tail -30 | cut -c1-250 | sed 's/^/        /'

    echo -e "\n  ${YEL}POST requests per file (web shells are usually POSTed to, from 1-2 IPs):${NC}"
    zcat -f $LOGS 2>/dev/null | awk '$6 ~ /POST/ {split($7,a,"?"); print a[1]}' | sort | uniq -c | sort -rn | head -15 | sed 's/^/        /'

    echo -e "\n  ${YEL}Requests to files in the HIGH/upload lists above, by IP:${NC}"
    zcat -f $LOGS 2>/dev/null | grep -iE '/(uploads?|images?|cache|tmp)/[^ ]*\.ph' | awk '{print $1, $6, $7, $9}' | sort | uniq -c | sort -rn | head -15 | sed 's/^/        /'

    echo -e "\n  ${YEL}Top IPs:${NC}"
    zcat -f $LOGS 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/        /'
fi

header "Error log - signs of commands being run"
zcat -f "$LOGDIR"/error.log* 2>/dev/null | grep -iE 'sh: |sh: [0-9]|command not found|system\(\)|exec\(\)|shell_exec|passthru|eval\(\)|Permission denied' \
    | tail -15 | cut -c1-250 | sed 's/^/        /'

echo -e "\n${GRN}[*] Done. Before deleting: copy the shell somewhere safe for your report (cp file /root/evidence/).${NC}"
