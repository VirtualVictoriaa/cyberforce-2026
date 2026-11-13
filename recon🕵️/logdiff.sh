#!/usr/bin/env bash
# logdiff.sh - show what changed between two triage.sh logs (works on any two text files)
#
# Usage:
#   ./logdiff.sh                  # compare the two newest triage_*.log in this folder
#   ./logdiff.sh old.log new.log  # compare two specific files (older first)
#   ./logdiff.sh -a old new       # also show GONE lines in rolling sections (logins, recent files)
#   ./logdiff.sh -r old new       # raw: plain line-by-line diff, no masking
#
#   + green = NEW in the second log      - red = GONE since the first log
#
# Lines are compared as a set within each section, so things that only moved
# around (process order, port order) don't count. PIDs, fds, ephemeral ports,
# idle times, column spacing and file timestamps are masked out.

set -o pipefail

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    B=$'\e[1m' R=$'\e[31m' G=$'\e[32m' C=$'\e[36m' D=$'\e[2m' N=$'\e[0m'
else
    B='' R='' G='' C='' D='' N=''
fi

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

raw=0 all=0
while getopts "rah" o; do
    case $o in r) raw=1 ;; a) all=1 ;; *) usage ;; esac
done
shift $((OPTIND - 1))

if (($# == 0)); then
    mapfile -t logs < <(ls -1t triage_*.log 2>/dev/null | head -n 2)
    ((${#logs[@]} == 2)) || { echo "Need two triage_*.log files here, or give two files: $0 old new" >&2; exit 1; }
    set -- "${logs[1]}" "${logs[0]}"    # older first
elif (($# != 2)); then
    usage
fi
for f; do [[ -r $f ]] || { echo "Can't read: $f" >&2; exit 1; }; done
OLD=$1 NEW=$2

mtime() { date -r "$1" '+%F %T' 2>/dev/null; }
printf '%sOLD:%s %s  %s(%s)%s\n' "$B" "$N" "$OLD" "$D" "$(mtime "$OLD")" "$N"
printf '%sNEW:%s %s  %s(%s)%s\n' "$B" "$N" "$NEW" "$D" "$(mtime "$NEW")" "$N"

strip_ansi() { sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' "$1"; }

# ---------- raw mode ----------
if ((raw)); then
    diff -u <(strip_ansi "$OLD") <(strip_ansi "$NEW") | tail -n +3 | sed -E \
        -e "s/^(\+.*)$/${G}\1${N}/" -e "s/^(-.*)$/${R}\1${N}/" -e "s/^(@@.*)$/${C}\1${N}/"
    [[ ${PIPESTATUS[0]} == 0 ]] && echo "No differences."
    exit 0
fi

# ---------- smart mode ----------
# Turn a log into "section<TAB>subsection<TAB>normalized line"
normalize() {
    strip_ansi "$1" | awk '
    BEGIN { OFS = "\t" }
    /^=+$/                                  { next }
    /HOST TRIAGE:|^Log saved to /           { next }
    /^    (Kernel|Running as|Up):/          { next }
    /^ *(wtmp|btmp) begins/                 { next }
    /^  [A-Z][A-Z &]+$/   { sec = substr($0, 3); sub_ = ""; next }
    /^--- .* ---$/        { sub_ = substr($0, 5, length($0) - 8); next }
    {
        gsub(/[ \t]+/, " "); sub(/^ /, ""); sub(/ $/, "")
        if ($0 == "") next

        # timestamps at the start of a line (modified files, unit files)
        sub(/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9] /, "")

        gsub(/pid=[0-9]+/, "pid=N"); gsub(/fd=[0-9]+/, "fd=N"); gsub(/PID [0-9]+/, "PID N")

        if (sub_ ~ /Process tree/) {
            gsub(/│|├|└|─|┬|`|\|/, ""); gsub(/^[- ]+/, "")
            gsub(/,[0-9]+/, ",N")
            if ($0 ~ /^\((sed|tee),N\)$/) next      # triage.sh own logging pipeline
        }
        if (sub_ ~ /Established/) {             # mask ephemeral (high) ports
            line = ""; s = $0
            while (match(s, /:[0-9]+/)) {
                p = substr(s, RSTART + 1, RLENGTH - 1)
                line = line substr(s, 1, RSTART - 1) ":" (p + 0 >= 32768 ? "EPH" : p)
                s = substr(s, RSTART + RLENGTH)
            }
            $0 = line s
        }
        if (sub_ ~ /Logged in now/) {           # w: keep user, tty, from, login time only
            if ($1 == "USER" || $0 ~ /load average/) next
            $0 = $1 " " $2 " " $3 " " $4
        }
        if (sub_ ~ /Running services/) {        # column layout shifts - one name per line
            for (i = 1; i <= NF; i++) print sec, sub_, $i
            next
        }
        print sec, sub_, $0
    }'
}

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

normalize "$OLD" > "$tmp/old.raw"
normalize "$NEW" > "$tmp/new.raw"
LC_ALL=C sort -u "$tmp/old.raw" > "$tmp/old"
LC_ALL=C sort -u "$tmp/new.raw" > "$tmp/new"

# section order as it appears in the logs (new first, then anything only in old)
cat "$tmp/new.raw" "$tmp/old.raw" | awk -F'\t' '!seen[$1 FS $2]++ { print $1 FS $2 }' > "$tmp/order"

{
    LC_ALL=C comm -13 "$tmp/old" "$tmp/new" | sed 's/^/+\t/'
    LC_ALL=C comm -23 "$tmp/old" "$tmp/new" | sed 's/^/-\t/'
} > "$tmp/changes"

if [[ ! -s $tmp/changes ]]; then
    printf '\n%sNo changes.%s\n' "$G$B" "$N"
    exit 0
fi

awk -F'\t' -v all="$all" -v B="$B" -v R="$R" -v G="$G" -v C="$C" -v D="$D" -v N="$N" '
    FNR == NR { order[++n] = $1 FS $2; next }
    {
        key = $2 FS $3
        rolling = ($3 ~ /Recent|modified/)
        if ($1 == "-" && rolling && !all) { hidden++; next }
        if ($1 == "+") { add[key] = add[key] "  " G "+ " $4 N "\n"; nadd++ }
        else           { del[key] = del[key] "  " R "- " $4 N "\n"; ndel++ }
    }
    END {
        printf "\n%s%d new, %d gone%s", B, nadd, ndel, N
        if (hidden) printf "  %s(%d gone lines in rolling sections hidden, use -a)%s", D, hidden, N
        print ""
        for (i = 1; i <= n; i++) {
            k = order[i]
            if (!(k in add) && !(k in del)) continue
            split(k, p, FS)
            title = p[1]; if (title == "") title = "(no section)"
            if (p[1] != last) { printf "\n%s== %s ==%s\n", C B, title, N; last = p[1] }
            if (p[2] != "") printf "%s--- %s%s\n", B, p[2], N
            printf "%s%s", add[k], del[k]
        }
    }' "$tmp/order" "$tmp/changes"
