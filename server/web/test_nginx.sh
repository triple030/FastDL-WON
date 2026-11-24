#!/bin/bash
# Review 1: fastdl.conf against a hostile tree, nginx exactly as in docker-compose.yml (uid 101, read-only, no
# capabilities) but without any network (--network none; requests from inside the container to 127.0.0.1).
# usage: web/test_nginx.sh    exit status 1 if any request gets an unexpected answer.  Needs docker.
set -u; cd "$(dirname "$0")/.."; S=$PWD
IMG=$(grep -o 'nginx:[^ "]*@sha256:[0-9a-f]*' docker-compose.yml | head -1)
D=$(mktemp -d); N=fdl-nginx-test-$$; bad=0
trap 'docker rm -f $N >/dev/null 2>&1; rm -rf "$D"' EXIT
M=$D/data/cstrike; W=$D/data/fastdl-won; mkdir -p $M/maps $M/sound/x $D/outside $W/logs; chmod 1733 $W/logs
printf '\x1e\0\0\0ok' > $M/maps/ok.bsp; printf 'RIFFxxxxWAVE' > $M/sound/x/a.wav; echo 'rcon_password "SECRET"' > $M/server.cfg
chmod 644 $M/server.cfg; echo secret > $D/outside/s.bsp; ln -s $D/outside/s.bsp $M/maps/link.bsp
FASTDL_KEY=$W/keys/fastdl.key FASTDL_OUT=$W/dl tools/mkfastdl.sh cstrike $M >/dev/null 2>&1 || { echo "mkfastdl failed"; exit 1; }
ln $M/server.cfg $M/maps/cfg.txt; ln $W/keys/fastdl.key $M/maps/key.txt		# hardlinks under allowed names
FASTDL_KEY=$W/keys/fastdl.key FASTDL_OUT=$W/dl tools/mkfastdl.sh cstrike $M >/dev/null 2>&1
G=$(readlink $W/dl/cstrike)
ln -s /etc/passwd $W/dl/cstrike/maps/sym.bsp; printf X > $W/dl/cstrike/maps/.hidden.bsp	# planted after the build
docker run -d --name $N --network none --user 101:101 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /var/cache/nginx:size=16m,uid=101,gid=101 --tmpfs /run:size=1m,uid=101,gid=101 --tmpfs /tmp:size=1m,uid=101,gid=101 \
  -v $W/dl:/usr/share/nginx/html:ro -v $S/web/fastdl.conf:/etc/nginx/conf.d/default.conf:ro -v $W/logs:/var/log/fastdl $IMG >/dev/null || exit 1
sleep 1
req() {	# req WANT PATH [UA] [extra wget args]
	local want=$1 p=$2 ua=${3-FastDL-WON/1.0} got; shift $(( $# < 3 ? $# : 3 ))
	got=$(docker exec $N wget -S -q -O /dev/null ${ua:+-U "$ua"} "$@" "http://127.0.0.1:8080$p" 2>&1 | awk '/^  HTTP\//{c=$2} END{print c}')
	if [ "$got" = "$want" ]; then echo "ok   $want $p"; else echo "FAIL $p: got ${got:-none}, want $want"; bad=1; fi
}
req 200 /cstrike/fastdl.manifest; req 200 /cstrike/maps/ok.bsp; req 200 /cstrike/sound/x/a.wav
req 404 /cstrike/maps/ok.bsp ""											# no plugin user agent
req 404 /cstrike/maps/ok.bsp Mozilla/5.0
req 405 /cstrike/maps/ok.bsp FastDL-WON/1.0 --post-data=x
req 404 /cstrike/maps/sym.bsp; req 404 /cstrike/maps/.hidden.bsp; req 404 /cstrike/maps/link.bsp
req 404 /$G/maps/ok.bsp; req 404 /.cstrike.skipped; req 404 /.cstrike.lock; req 404 /cstrike/; req 404 /cstrike/maps/; req 404 /
req 404 /cstrike/server.cfg; req 404 /cstrike/maps/../../.cstrike.skipped; req 404 /cstrike/%2e%2e/.cstrike.skipped
req 400 /cstrike/maps/ok.bsp%00.txt; req 404 /cstrike/maps/ok.BSP; req 204 /healthz
req 404 /cstrike/maps/key.txt											# key: mode 0600, nginx cannot read it
req 404 /cstrike/maps/cfg.txt											# GAP: hardlinked server.cfg is listed and served
exit $bad
