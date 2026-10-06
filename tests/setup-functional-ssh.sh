#!/usr/bin/env bash
# Localhost SSH/SFTP fixture for tests/Functional (mirrors .github/workflows/ci.yml).
# Source from grind scripts:  source tests/setup-functional-ssh.sh

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "setup-functional-ssh.sh: Linux only (skipped on $(uname -s))" >&2
    return 0 2>/dev/null || exit 0
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "setup-functional-ssh.sh: openssh-client required" >&2
    exit 1
fi

if ! systemctl is-active --quiet ssh 2>/dev/null; then
    sudo service ssh start 2>/dev/null || sudo systemctl start ssh 2>/dev/null || true
fi

PHPSECLIB_SSH_USERNAME='phpseclib'
PHPSECLIB_SSH_PASSWORD='EePoov8po1aethu2kied1ne0'

if ! id "$PHPSECLIB_SSH_USERNAME" &>/dev/null; then
    sudo useradd --create-home --base-dir /home "$PHPSECLIB_SSH_USERNAME"
fi
echo "$PHPSECLIB_SSH_USERNAME:$PHPSECLIB_SSH_PASSWORD" | sudo chpasswd

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
if [[ ! -f "$HOME/.ssh/id_rsa" ]]; then
    ssh-keygen -t rsa -b 1024 -f "$HOME/.ssh/id_rsa" -q -N ""
fi

eval "$(ssh-agent -s)"
ssh-add "$HOME/.ssh/id_rsa"

sudo mkdir -p "/home/$PHPSECLIB_SSH_USERNAME/.ssh/"
sudo cp "$HOME/.ssh/id_rsa.pub" "/home/$PHPSECLIB_SSH_USERNAME/.ssh/authorized_keys"
ssh-keyscan -t rsa localhost 2>/dev/null | sudo tee "/home/$PHPSECLIB_SSH_USERNAME/.ssh/known_hosts" >/dev/null
sudo chown "$PHPSECLIB_SSH_USERNAME:$PHPSECLIB_SSH_USERNAME" "/home/$PHPSECLIB_SSH_USERNAME/.ssh/" -R

export PHPSECLIB_SSH_HOSTNAME=localhost
export PHPSECLIB_SSH_USERNAME="$PHPSECLIB_SSH_USERNAME"
export PHPSECLIB_SSH_PASSWORD="$PHPSECLIB_SSH_PASSWORD"
export PHPSECLIB_SSH_HOME="/home/$PHPSECLIB_SSH_USERNAME"
