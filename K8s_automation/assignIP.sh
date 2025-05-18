#!/usr/bin/env bash
set -euo pipefail

# assign_ip.sh — Asigna una IP estática a la interfaz de red interna k8net
#
# Uso:
#   sudo ./assign_ip.sh <INTERFAZ> <IP/CIDR> <PUERTA_ENLACE>
# Ejemplo:
#   sudo ./assign_ip.sh enp0s8 192.168.56.101/24 192.168.56.1

if [[ $# -ne 3 ]]; then
  echo "Uso: sudo $0 <INTERFAZ> <IP/CIDR> <PUERTA_ENLACE>"
  exit 1
fi

IFACE="$1"
IP_CIDR="$2"
GATEWAY="$3"
CON_NAME="internal-${IFACE}"

# Comprueba que nmcli existe
if ! command -v nmcli &>/dev/null; then
  echo "Error: nmcli no está instalado. Ejecuta 'dnf install NetworkManager -y'."
  exit 1
fi

echo "[assign_ip] Configurando $IFACE → $IP_CIDR, gateway $GATEWAY"

# 1. Si ya existía una conexión con este nombre, la borramos
if nmcli connection show "$CON_NAME" &>/dev/null; then
  echo "  → Eliminando conexión previa '$CON_NAME'"
  nmcli connection delete "$CON_NAME"
fi

# 2. Creamos la conexión manual
echo "  → Creando conexión '$CON_NAME'"
nmcli connection add \
  type ethernet \
  ifname "$IFACE" \
  con-name "$CON_NAME" \
  autoconnect yes \
  ipv4.addresses "$IP_CIDR" \
  ipv4.gateway "$GATEWAY" \
  ipv4.method manual

# 3. Levantamos la conexión
echo "  → Activando conexión '$CON_NAME'"
nmcli connection up "$CON_NAME"

echo "[assign_ip] Hecho. Comprueba con 'ip addr show $IFACE'."
