#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYSIM_DIR="$ROOT_DIR/../pysim"
VENV_PY="$PYSIM_DIR/venv/bin/python3"
CERT_DIR="$PYSIM_DIR/smdpp-data/certs/DPtls"
NGINX_CONF="$ROOT_DIR/nginx-smdpp.conf"

echo "[+] Starting osmo-smdpp (HTTP backend)"
cd "$PYSIM_DIR"
"$VENV_PY" osmo-smdpp.py --host 127.0.0.1 --port 8080 --certdir certs --nossl >/tmp/osmo-smdpp.log 2>&1 &
SMDPP_PID=$!
echo "    PID: $SMDPP_PID (logs: /tmp/osmo-smdpp.log)"

echo "[+] Preparing nginx TLS proxy config"
if [[ ! -f "$NGINX_CONF" ]]; then
  cat > "$NGINX_CONF" << 'EOF'
server {
  listen 443 ssl;
  server_name testsmdpplus1.example.com;

  ssl_certificate     /certs/CERT_S_SM_DP_TLS_NIST.pem;
  ssl_certificate_key /certs/SK_S_SM_DP_TLS_NIST.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;

  location / {
    proxy_set_header Host testsmdpplus1.example.com;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://host.docker.internal:8080;
  }
}
EOF
fi

echo "[+] (Re)starting nginx TLS proxy container"
docker rm -f smdpp-proxy >/dev/null 2>&1 || true
docker run --name smdpp-proxy -d --restart unless-stopped \
  -p 8443:443 \
  -v "$CERT_DIR":/certs:ro \
  -v "$NGINX_CONF":/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine >/tmp/smdpp-proxy.cid
CID=$(cat /tmp/smdpp-proxy.cid)
echo "    Container: $CID"

echo "[+] Verifying TLS via curl with --resolve (bypasses /etc/hosts)"
curl --silent --show-error --fail \
  --resolve testsmdpplus1.example.com:8443:127.0.0.1 \
  https://testsmdpplus1.example.com:8443/ \
  --cacert "$CERT_DIR/CERT_S_SM_DP_TLS_NIST.pem" || echo "    (info) Expected non-200 for root path."

echo "[+] Running comprehensive demo (EXTERNAL_SMDP=1)"
cd "$ROOT_DIR"
EXTERNAL_SMDP=1 python3 "$ROOT_DIR/comprehensive_sgp22_demo.py"

echo "[+] Cleanup: leaving nginx running for reuse; stopping osmo-smdpp"
kill "$SMDPP_PID" || true
wait "$SMDPP_PID" 2>/dev/null || true
echo "[+] Done"


