#!/usr/bin/env bash
set -euo pipefail

# prepare_node.sh
# Script to prepare a Fedora Server 42 node for Kubernetes using containerd
# Usage: sudo ./prepare_node.sh <role>
#   role: "master" or "worker"

if [[ $# -ne 1 ]]; then
  echo "Usage: sudo $0 <master|worker>"
  exit 1
fi
ROLE="$1"

# 1. Disable swap
swapoff -a
sed -i '/ swap / s|^|#|' /etc/fstab
echo "[*] Swap disabled."

# 2. Set SELinux to permissive mode
# Required for Kubernetes kubeadm until full SELinux support is in place
echo "[*] Setting SELinux to permissive mode..."
setenforce 0
sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
echo "[*] SELinux set to permissive."

# 3. Load kernel modules for Kubernetes networking
echo "[*] Loading kernel modules overlay and br_netfilter..."
cat <<EOF >/etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

# 4. Set sysctl params for networking
echo "[*] Setting sysctl parameters..."
cat <<EOF >/etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system >/dev/null

echo "[*] Sysctl parameters applied."

# 5. Configure firewall for Kubernetes
# Control plane ports
MASTER_PORTS=(6443 2379 2380 10250 10251 10257 10259)
# Worker ports
WORKER_PORTS=(10250 10256)
# NodePort range
NODEPORT_RANGE="30000-32767"

echo "[*] Configuring firewall for role: $ROLE"
# Always allow SSH
firewall-cmd --permanent --add-service=ssh

if [[ "$ROLE" == "master" ]]; then
  for p in "${MASTER_PORTS[@]}"; do
    firewall-cmd --permanent --add-port=${p}/tcp
  done
elif [[ "$ROLE" == "worker" ]]; then
  for p in "${WORKER_PORTS[@]}"; do
    firewall-cmd --permanent --add-port=${p}/tcp
  done
  # NodePort services
  firewall-cmd --permanent --add-port=${NODEPORT_RANGE}/tcp
  firewall-cmd --permanent --add-port=${NODEPORT_RANGE}/udp
else
  echo "Unknown role: $ROLE"
  exit 1
fi

firewall-cmd --reload
echo "[*] Firewall ports opened for $ROLE."

# 6. Install and configure containerd
echo "[*] Installing containerd..."
dnf update -y
dnf install -y containerd
systemctl enable --now containerd

echo "[*] containerd installed and started."

# 6.1 Generate default config if not exists
if [[ ! -f /etc/containerd/config.toml ]]; then
  containerd config default | tee /etc/containerd/config.toml
fi

# 6.2 Ensure systemd cgroup driver
sed -i 's#SystemdCgroup = false#SystemdCgroup = true#' /etc/containerd/config.toml
systemctl restart containerd

echo "[*] containerd configured to use systemd cgroup driver."

# 7. Add Kubernetes repo and install kubeadm, kubelet, kubectl
# Using official Kubernetes v1.33 stable repo
echo "[*] Adding Kubernetes repository (v1.33 stable)..."
cat <<EOF >/etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.33/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.33/rpm/repodata/repomd.xml.key
exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni
EOF

echo "[*] Installing kubelet, kubeadm, kubectl..."
# Refresh metadata and install
dnf makecache
dnf install -y kubelet kubeadm kubectl
systemctl enable --now kubelet

echo "[*] kubelet, kubeadm, kubectl installed and kubelet started."
