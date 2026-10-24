#!/usr/bin/env bash
#
# elf-hunter.sh — hidden/suspicious ELF triage for Linux blue team (CCDC-safe)
#
# Philosophy: HUNT and SHOW first, delete last. On a box you're defending,
# half of /usr/bin is a legit ELF — blind deletion is how you score your own
# services into the ground. So this tool:
#
#   1) scan     (default) find suspicious ELFs, show you exactly what they are,
#                delete nothing.
#   2) quarantine          move flagged files aside (chmod 000, reversible),
#                          keep a manifest so you can restore.
#   3) restore             undo a quarantine.
#   4) purge               actually rm the quarantined files — gated behind a
#                          typed confirmation. This is the "nuke" step.
#
# Nothing is ever removed in scan mode. You read, THEN you decide.
#
# Usage:
#   sudo ./elf-hunter.sh scan [--path /] [--all] [--paranoid]
#   sudo ./elf-hunter.sh quarantine [--from <candidates-file>]
#   sudo ./elf-hunter.sh restore <quarantine-dir>
#   sudo ./elf-hunter.sh purge <quarantine-dir>
#
set -uo pipefail

# ---------------------------------------------------------------- config -----
WORKDIR="${ELF_HUNTER_WORKDIR:-/root/.elf-hunter}"
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="$WORKDIR/report-$STAMP.txt"
CANDIDATES="$WORKDIR/candidates-$STAMP.lst"
QUARANTINE_ROOT="$WORKDIR/quarantine"

# Directories where an executable ELF is inherently suspicious.
HOT_DIRS=(/tmp /var/tmp /dev/shm /dev /run /var/run /var/lock)

# Directories to skip entirely (not real on-disk attacker turf, or huge/noisy).
PRUNE_DIRS=(/proc /sys "$WORKDIR")

# Known-benign hidden paths under /usr. These are standard OS furniture, not
# indicators — on any box with debuginfo installed, /usr/lib/debug/.build-id/
# holds hundreds of legit ELF .debug files inside a hidden dir. Without this
# allowlist they drown the real signal. Override with --paranoid to see them.
USR_BENIGN_GLOBS=(
  '*/.build-id/*'    # detached debug symbols (gdb / debuginfo packages)
  '*/.dwz/*'         # DWARF-compressed debug data
)

# Scan root (overridable with --path). Default to full FS for a real sweep.
SCAN_PATH="/"
SCAN_ALL=0      # --all also reports setuid ELFs outside standard bin dirs
PARANOID=0      # --paranoid: do NOT skip the benign /usr debug trees above

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; DIM=$'\e[2m'; BOLD=$'\e[1m'; RST=$'\e[0m'
[[ -t 1 ]] || { RED=; YEL=; GRN=; DIM=; BOLD=; RST=; }

log()  { printf '%s\n' "$*" | tee -a "$REPORT" >/dev/null; }
say()  { printf '%s\n' "$*"; }

# ------------------------------------------------------------- helpers --------
need_root() {
  if [[ $EUID -ne 0 ]]; then
    say "${YEL}Warning:${RST} not running as root — you'll miss files you can't read/stat. Re-run with sudo for a full sweep."
  fi
}

is_elf() {
  # Reliable magic-byte check, independent of the `file` command.
  local f=$1
  [[ -f "$f" && -r "$f" ]] || return 1
  local magic
  magic=$(head -c 4 -- "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
  [[ "$magic" == "7f454c46" ]]   # \x7fELF
}

# True for files on the benign /usr allowlist (unless --paranoid disables it).
is_benign_usr() {
  [[ $PARANOID -eq 1 ]] && return 1
  local f=$1 g
  for g in "${USR_BENIGN_GLOBS[@]}"; do
    # shellcheck disable=SC2053
    [[ "$f" == $g ]] && return 0
  done
  return 1
}

hash_of()  { command -v sha256sum >/dev/null && sha256sum -- "$1" 2>/dev/null | awk '{print $1}' || echo "n/a"; }
filetype() { command -v file     >/dev/null && file -b -- "$1" 2>/dev/null || echo "ELF (file(1) not installed)"; }

# Print the dossier for one file into the report and stdout.
dossier() {
  local f=$1 reason=$2
  {
    echo "=================================================================="
    echo "${BOLD}FLAGGED:${RST} $f"
    echo "  reason : $reason"
    echo "  size   : $(stat -c '%s bytes' -- "$f" 2>/dev/null)"
    echo "  owner  : $(stat -c '%U:%G (uid %u gid %g)' -- "$f" 2>/dev/null)"
    echo "  perms  : $(stat -c '%A (%a)' -- "$f" 2>/dev/null)"
    echo "  mtime  : $(stat -c '%y' -- "$f" 2>/dev/null)"
    echo "  sha256 : $(hash_of "$f")"
    echo "  type   : $(filetype "$f")"

    # setuid/setgid is a loud persistence signal
    if [[ -u "$f" ]]; then echo "  ${RED}>> SETUID bit set${RST}"; fi
    if [[ -g "$f" ]]; then echo "  ${RED}>> SETGID bit set${RST}"; fi

    # Dynamic deps (can reveal what it talks to); ldd on untrusted binaries
    # can execute code, so we use objdump/readelf instead — safe, static.
    echo "  --- shared library deps (static read) ---"
    if command -v readelf >/dev/null; then
      readelf -d -- "$f" 2>/dev/null | grep -i 'NEEDED' | sed 's/^/    /' || echo "    (none / unreadable)"
    else
      echo "    (readelf not installed)"
    fi

    # Human-readable strings give you the clearest 'what does it do' at a glance:
    # IPs, domains, /bin/sh, curl, wget, nc, crypto, paths, cron, etc.
    echo "  --- strings preview (first 40 printable, >=5 chars) ---"
    if command -v strings >/dev/null; then
      strings -n 5 -- "$f" 2>/dev/null | head -n 40 | sed 's/^/    /'
    else
      # fallback: grep printable runs
      tr -c '[:print:]' '\n' < "$f" 2>/dev/null | grep -E '.{5,}' | head -n 40 | sed 's/^/    /'
    fi

    # Highlight the juicy indicators specifically
    echo "  --- IOC-ish hits (ip/url/shell/net tools/persistence) ---"
    strings -n 4 -- "$f" 2>/dev/null \
      | grep -Ei '(([0-9]{1,3}\.){3}[0-9]{1,3})|https?://|/bin/(ba)?sh|nc |ncat|/dev/tcp|wget|curl|crontab|/etc/cron|ld\.so\.preload|LD_PRELOAD|reverse|backdoor|xmrig|miner' \
      | sort -u | head -n 25 | sed 's/^/    /' || echo "    (none matched)"

    echo
  } | tee -a "$REPORT"
  echo "$f" >> "$CANDIDATES"
}

# ------------------------------------------------------------- scan -----------
build_prune_expr() {
  local expr=()
  for d in "${PRUNE_DIRS[@]}"; do expr+=( -path "$d" -prune -o ); done
  printf '%s\0' "${expr[@]}"
}

cmd_scan() {
  mkdir -p "$WORKDIR"; : > "$REPORT"; : > "$CANDIDATES"
  need_root
  say "${BOLD}Hunting hidden/suspicious ELF files under ${SCAN_PATH}${RST}"
  say "${DIM}Report: $REPORT${RST}"
  say "${DIM}Nothing will be deleted. This only looks and tells you.${RST}"
  echo

  log "elf-hunter scan @ $STAMP  (host $(hostname), root=$SCAN_PATH, all=$SCAN_ALL)"
  log ""

  local count=0 benign=0

  # Pass 1: executable/regular ELFs living in hot directories (temp, /dev, /run...)
  for d in "${HOT_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      is_elf "$f" || continue
      dossier "$f" "ELF in high-risk dir $d"
      ((count++))
    done < <(find "$d" -xdev -type f -print0 2>/dev/null)
  done

  # Pass 2a: hidden ELFs under /usr — runs EVERY scan, regardless of --path.
  # /usr ships no legitimate dotfile ELFs, so a hidden ELF here (dotfile name,
  # OR buried inside a hidden directory like /usr/lib/.cache/.x/impl) is a
  # high-confidence indicator — a favorite hiding spot for rootkits/implants
  # in /usr/lib, /usr/share, /usr/local.
  if [[ -d /usr ]]; then
    while IFS= read -r -d '' f; do
      is_elf "$f" || continue
      is_benign_usr "$f" && { ((benign++)); continue; }
      grep -qxF "$f" "$CANDIDATES" 2>/dev/null && continue
      dossier "$f" "HIDDEN ELF IN /usr — high-confidence IOC"
      ((count++))
    done < <(find /usr -xdev -path '*/.*' -type f -print0 2>/dev/null)
  fi

  # Pass 2b: hidden ELFs anywhere else on the real fs. "Hidden" now means a
  # dotfile basename (.sshd, .systemd) OR any file living under a hidden dir.
  while IFS= read -r -d '' f; do
    is_elf "$f" || continue
    is_benign_usr "$f" && { ((benign++)); continue; }       # skip debug-symbol trees
    grep -qxF "$f" "$CANDIDATES" 2>/dev/null && continue    # already flagged above
    base=$(basename -- "$f")
    if [[ "$base" == .* ]]; then
      dossier "$f" "hidden (dotfile) ELF: $base"
    else
      dossier "$f" "ELF inside hidden directory"
    fi
    ((count++))
  done < <(find "$SCAN_PATH" -xdev \
             $(for d in "${PRUNE_DIRS[@]}"; do printf -- '-path %q -prune -o ' "$d"; done) \
             -path '*/.*' -type f -print0 2>/dev/null)

  # Pass 3 (optional, --all): setuid ELFs outside the normal trusted bin dirs.
  if [[ $SCAN_ALL -eq 1 ]]; then
    while IFS= read -r -d '' f; do
      case "$f" in
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/libexec/*) continue ;;
      esac
      is_elf "$f" || continue
      grep -qxF "$f" "$CANDIDATES" 2>/dev/null && continue
      dossier "$f" "setuid ELF outside standard bin dirs"
      ((count++))
    done < <(find "$SCAN_PATH" -xdev -type f -perm -4000 -print0 2>/dev/null)
  fi

  echo
  [[ $benign -gt 0 ]] && say "${DIM}(skipped $benign known-benign debug-symbol ELF(s) under /usr — re-run with --paranoid to include them)${RST}"
  if [[ $count -eq 0 ]]; then
    say "${GRN}No suspicious ELFs flagged.${RST} (Doesn't prove clean — tune HOT_DIRS / try --all.)"
  else
    say "${RED}${BOLD}$count file(s) flagged.${RST}"
    say "Read the full dossiers:   ${BOLD}less -R $REPORT${RST}"
    say "Candidate list:           $CANDIDATES"
    echo
    say "When you've reviewed and want them gone:"
    say "  1) move aside (reversible):  ${BOLD}sudo $0 quarantine --from $CANDIDATES${RST}"
    say "  2) then nuke for good:       ${BOLD}sudo $0 purge <quarantine-dir>${RST}"
  fi
}

# --------------------------------------------------------- quarantine ---------
cmd_quarantine() {
  local src=${1:-}
  [[ -f "$src" ]] || { say "${RED}Candidate list not found:${RST} $src"; exit 1; }
  local qdir="$QUARANTINE_ROOT/$STAMP"
  mkdir -p "$qdir"
  local manifest="$qdir/MANIFEST.tsv"
  echo -e "original_path\tsha256\tquarantined_as" > "$manifest"

  local n=0
  while IFS= read -r f; do
    [[ -n "$f" && -e "$f" ]] || continue
    local h; h=$(hash_of "$f")
    # Flatten path so it's restorable and collision-free.
    local safe; safe=$(printf '%s' "$f" | sed 's#/#__#g')
    cp -a --preserve=all -- "$f" "$qdir/$safe" 2>/dev/null && rm -f -- "$f"
    chmod 000 -- "$qdir/$safe" 2>/dev/null
    printf '%s\t%s\t%s\n' "$f" "$h" "$safe" >> "$manifest"
    say "${YEL}quarantined${RST} $f"
    ((n++))
  done < "$src"

  say
  say "${GRN}$n file(s) quarantined to:${RST} $qdir"
  say "They are moved out of the way and set to chmod 000 — not yet destroyed."
  say "Restore if wrong:  sudo $0 restore $qdir"
  say "Destroy for good:  sudo $0 purge   $qdir"
}

cmd_restore() {
  local qdir=${1:-}; local manifest="$qdir/MANIFEST.tsv"
  [[ -f "$manifest" ]] || { say "${RED}No manifest in${RST} $qdir"; exit 1; }
  tail -n +2 "$manifest" | while IFS=$'\t' read -r orig h safe; do
    if [[ -e "$qdir/$safe" ]]; then
      mkdir -p -- "$(dirname -- "$orig")"
      cp -a -- "$qdir/$safe" "$orig" && chmod --reference=/dev/null "$orig" 2>/dev/null
      say "${GRN}restored${RST} $orig"
    fi
  done
  say "Restore complete. Review perms on restored files before trusting them."
}

cmd_purge() {
  local qdir=${1:-}; local manifest="$qdir/MANIFEST.tsv"
  [[ -f "$manifest" ]] || { say "${RED}No manifest in${RST} $qdir"; exit 1; }
  say "${RED}${BOLD}PERMANENT DELETE${RST} of everything quarantined in:"
  say "  $qdir"
  tail -n +2 "$manifest" | cut -f1 | sed 's/^/    /'
  echo
  read -r -p "Type exactly  NUKE  to delete these forever: " ans
  if [[ "$ans" != "NUKE" ]]; then say "Aborted. Nothing deleted."; exit 0; fi
  # shred if available for anti-forensics-grade removal, else rm
  if command -v shred >/dev/null; then
    find "$qdir" -type f ! -name MANIFEST.tsv -exec shred -u -- {} +
  fi
  rm -rf -- "$qdir"
  say "${RED}Gone.${RST} Quarantine dir $qdir destroyed."
}

# ------------------------------------------------------------- args -----------
cmd=${1:-scan}; shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) SCAN_PATH=${2:-/}; shift 2;;
    --all)  SCAN_ALL=1; shift;;
    --paranoid) PARANOID=1; shift;;
    --from) FROM=${2:-}; shift 2;;
    *)      POS+=("$1"); shift;;
  esac
done

case "$cmd" in
  scan)        cmd_scan ;;
  quarantine)  cmd_quarantine "${FROM:-${POS[0]:-}}" ;;
  restore)     cmd_restore "${POS[0]:-}" ;;
  purge)       cmd_purge   "${POS[0]:-}" ;;
  *) say "Usage: $0 {scan [--path P] [--all] | quarantine --from LIST | restore DIR | purge DIR}"; exit 1 ;;
esac
