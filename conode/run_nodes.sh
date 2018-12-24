#!/usr/bin/env bash
set -e

NBR=${1:-3}
DEBUG=${2:-0}
PORTBASE=7000
IP=${3:-localhost}
cd /conode_data
export DEBUG_TIME=true

rm -f public.toml
mkdir -p log
for n in $( seq $NBR ); do
  co=co$n
  PORT=$(($PORTBASE + 2 * n))
  if [ ! -d $co ]; then
    echo -e "$IP:$PORT\nConode_$n\n$co" | /root/conode setup
  fi
  (
    LOG=log/conode_$co_$PORT
    while sleep 1; do
      /root/conode -d $DEBUG -c $co/private.toml server 2>&1 | tee $LOG-$(date +%y%m%d-%H%M).log
    done
  ) &
  cat $co/public.toml >> public.toml
  # Wait for LOG to be initialized
  sleep 1
done

while true; do
  sleep 1;
done
