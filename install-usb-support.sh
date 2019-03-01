#!/bin/bash
echo "Copy swarm device enabler"
cp ./template_configs/devices/enable-swarm-device /usr/bin/enable-swarm-device

echo "Copy swarm device service watcher"
cp ./template_configs/devices/swarm-device-watcher /usr/bin/swarm-device-watcher

echo "Copy swam device rules"
cp ./template_configs/devices/docker-devices.rules /etc/udev/rules.d/99-docker-devices.rules

echo "Copy swarm device service file"
cp ./template_configs/devices/swarm-device@.service /etc/systemd/system/swarm-device@.service

echo "Reload udev rules"
udevadm control --reload-rules
