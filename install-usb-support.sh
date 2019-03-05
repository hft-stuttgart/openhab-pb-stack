#!/bin/bash
BASE_DIR=${BASH_SOURCE%/*}

echo "Copy swarm device enabler"
cp $BASE_DIR/template_configs/devices/enable-swarm-device /usr/bin/enable-swarm-device

echo "Copy swarm device service watcher"
cp $BASE_DIR/template_configs/devices/swarm-device-watcher /usr/bin/swarm-device-watcher

echo "Copy swam device rules"
cp $BASE_DIR/template_configs/devices/docker-devices.rules /etc/udev/rules.d/99-docker-devices.rules

echo "Copy swarm device service file"
cp $BASE_DIR/template_configs/devices/swarm-device@.service /etc/systemd/system/swarm-device@.service

echo "Reload udev rules"
udevadm control --reload-rules
