#!/bin/bash

# Assign possible arguments
SCRIPT_NAME=$0
BUILDING_NAME=$1
NEW_NODE=$2

# Print usage
usage() {
  echo -n "
  This script restores backuped volumes of a building on a specified machine.

  USAGE:  $0 [BUILDING_NAME] [NEW_NODE]

"
}

# Disable all services matching building
stop_building_services() {
  service_ids=$(docker service ls -q -f label=backup=$BUILDING_NAME)
  echo "Halting backuped services of building $BUILDING_NAME"
  for sid in $service_ids ; do
    docker service update --replicas=0 $sid
  done
}

# Enable all services matching building
restore_building_services() {
  service_ids=$(docker service ls -q -f label=backup=$BUILDING_NAME)
  echo "Restoring services of building $BUILDING_NAME"
  for sid in $service_ids ; do
    docker service update --replicas=1 $sid
  done
}

# Execute restore on new node
restore_backup() {
  echo "restore"  
}

# Assign building label to node
add_building_label() {
  echo "Assigning building label $BUILDING_NAME to machine $NEW_NODE"
  docker node update --label-add building=$BUILDING_NAME $NEW_NODE
}

restore_volumes() {
  echo "Restoring backups to volumes"
  # set variables for backup container restore
  CONTAINER_NAME=backup
  COMMAND=restore

  # remember previous node and switch docker-machine context to new node
  OLD_NODE=$(docker-machine active)
  NODE_USED=$?
  eval "$(docker-machine env $NEW_NODE)"

  matched_ids=$(docker ps -f name=$CONTAINER_NAME -q)
  count_ids=$(echo "$matched_ids" | wc -l)
  if [ $count_ids -eq 1 ];
  then
    docker exec -it $matched_ids $(echo $COMMAND)
  else
    echo "Found $count_ids ids matching name $CONTAINER_NAME, choose unique name"
  fi

  # switch docker-machine context back to old host or clear env
  if [ $NODE_USED -eq 0 ]; then
    eval "$(docker-machine env $OLD_NODE)"
  else
    eval "$(docker-machine env -u)"
  fi
}

# Script
if [ "$#" -eq 2 ];
then
  stop_building_services
  add_building_label
  echo "Waiting until containers start..."
  sleep 7;
  restore_volumes
  restore_building_services
else
  usage
fi


