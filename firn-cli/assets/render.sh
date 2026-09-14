#!/usr/bin/env bash
# Regenerate the README screenshots from live firn output using freeze
# (https://github.com/charmbracelet/freeze). Needs a working connection;
# pass its name as $1 (default: the default connection).
set -euo pipefail
cd "$(dirname "$0")"

conn="${1:-}"
# freeze ignores the SGR 39 (default foreground) reset comfy-table emits
# between cells, so force color through the pipe and turn 39 into a full
# reset; on a real terminal firn's output needs no such help.
firn() {
  command firn ${conn:+-c "$conn"} --color always --format table "$@" 2>&1 \
    | sed -u $'s/\x1b\\[39m/\x1b[0m/g'
}
export -f firn
export conn

prompt() { printf '\033[32m❯\033[0m %s\n' "$1"; }
export -f prompt

# TX-02 (Berkeley Mono's successor) must be installed locally; change
# --font.family if you do not have it.
export COLUMNS=140
# freeze reads code from stdin when stdin is not a terminal, so every call
# below redirects it from /dev/null to make it run --execute instead.
FREEZE=(freeze --window --padding 20,30,20,30 --border.radius 10 --font.size 14
        --font.family "TX-02"
        --theme catppuccin-mocha --execute.timeout 60s)

Q="SELECT * FROM VALUES
  (1001, 'Acme Corp', 15230.50::number(10,2), '2026-09-01'::date, '2026-09-12 14:03:11.250'::timestamp_ntz, true,  'net 30'),
  (1002, 'Globex',      980.00::number(10,2), '2026-09-03'::date, '2026-09-12 09:41:07.000'::timestamp_ntz, false, NULL),
  (1003, 'Initech',   42117.99::number(10,2), '2026-09-05'::date, NULL,                                         true,  'rush'),
  (1004, 'Umbrella',      7.25::number(10,2), '2026-09-09'::date, '2026-09-13 18:20:45.913'::timestamp_ntz, false, NULL)
  AS t(id, customer, total, ordered, updated, paid, note)"
export Q

"${FREEZE[@]}" </dev/null -o table.png --execute 'bash -c "
  prompt \"firn sql \\\"SELECT * FROM orders ...\\\"\"
  firn sql \"\$Q\""'

"${FREEZE[@]}" </dev/null -o jsonl.png --execute 'bash -c "
  prompt \"firn sql \\\"SELECT * FROM orders ...\\\" | jq -c .\"
  command firn \${conn:+-c \$conn} sql \"\$Q\" 2>/dev/null | jq -c .
  echo
  prompt \"firn sql --submit \\\"CALL slow_report()\\\"\"
  echo \"{\\\"query_id\\\":\\\"01c70e3b-020b-4818-0029-4c872d1b48ee\\\",\\\"request_id\\\":\\\"8b1f2c9e-...\\\"}\"
  prompt \"firn query wait 01c70e3b-020b-4818-0029-4c872d1b48ee\"
  echo \"{\\\"query_id\\\":\\\"01c70e3b-020b-4818-0029-4c872d1b48ee\\\",\\\"status\\\":\\\"Success\\\",\\\"terminal\\\":true,\\\"success\\\":true}\""'

printf 'id,customer,total\n1001,Acme Corp,15230.50\n1002,Globex,980.00\n' > /tmp/orders.csv
"${FREEZE[@]}" </dev/null -o stage.png --execute 'bash -c "
  cd /tmp
  prompt \"firn stage put orders.csv @~/imports/\"
  firn stage put orders.csv @~/imports/ --overwrite
  echo
  prompt \"firn stage get @~/imports/orders.csv.gz ./restored\"
  firn stage get @~/imports/orders.csv.gz ./restored
  echo
  prompt \"firn auth status\"
  firn auth status"'
firn sql 'REMOVE @~/imports/' >/dev/null
rm -rf /tmp/orders.csv /tmp/restored
