#!/bin/bash
# Deploy Kali VPN Vulnerability Scanner al servidor AWS
# Uso: ./deploy.sh

KALI_HOST="18.117.130.45"
KALI_USER="kali"
KEY="./kali-aws.pem"
REMOTE_DIR="/opt/scanner"

set -e
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Deploy → Kali VPN Vulnerability Scanner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SSH="ssh -i $KEY -o StrictHostKeyChecking=no $KALI_USER@$KALI_HOST"
SCP="scp -i $KEY -o StrictHostKeyChecking=no"

echo "[1/4] Preparando directorio remoto..."
$SSH "sudo mkdir -p $REMOTE_DIR/vpn_configs $REMOTE_DIR/scans && \
      sudo chown -R $KALI_USER:$KALI_USER $REMOTE_DIR"

echo "[2/4] Subiendo web_scanner.py..."
$SCP web_scanner.py $KALI_USER@$KALI_HOST:$REMOTE_DIR/web_scanner.py

echo "[3/4] Instalando dependencias en Kali..."
$SSH "pip3 install flask --quiet 2>/dev/null || sudo pip3 install flask --quiet"

echo "[4/4] Configurando servicio systemd..."
$SSH "sudo tee /etc/systemd/system/vuln-scanner.service > /dev/null <<'EOF'
[Unit]
Description=Kali VPN Vulnerability Scanner
After=network.target

[Service]
Type=simple
User=$KALI_USER
WorkingDirectory=$REMOTE_DIR
ExecStart=/usr/bin/python3 $REMOTE_DIR/web_scanner.py
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF"

$SSH "sudo systemctl daemon-reload && \
      sudo systemctl enable vuln-scanner && \
      sudo systemctl restart vuln-scanner"

sleep 2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
STATUS=$($SSH "systemctl is-active vuln-scanner" 2>/dev/null || echo "unknown")
if [ "$STATUS" = "active" ]; then
  echo "  ✓ Servicio activo"
  echo ""
  echo "  Abre en tu navegador:"
  echo "  → http://$KALI_HOST:8040"
else
  echo "  ✗ El servicio no arrancó. Logs:"
  $SSH "sudo journalctl -u vuln-scanner --no-pager -n 20"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "Comandos útiles:"
echo "  Ver logs en tiempo real: ssh -i $KEY $KALI_USER@$KALI_HOST 'sudo journalctl -u vuln-scanner -f'"
echo "  Reiniciar servicio:      ssh -i $KEY $KALI_USER@$KALI_HOST 'sudo systemctl restart vuln-scanner'"
echo "  Detener servicio:        ssh -i $KEY $KALI_USER@$KALI_HOST 'sudo systemctl stop vuln-scanner'"
