#!/bin/bash

# Assign possible arguments
SCRIPT_NAME=$0
CONTAINER_NAME=$1
COMMAND=${*:2}

# Print usage
usage() {
  echo -n "
  This script executes a command in a container based on its name.

  USAGE:  $0 [CONTAINER_NAME] [COMMAND]

"
}

execute_command_in_container() {
  matched_ids=$(docker ps -f name=$CONTAINER_NAME -q)
  count_ids=$(echo "$matched_ids" | wc -l)
  if [ $count_ids -eq 1 ];
  then
    docker exec -it $matched_ids $(echo $COMMAND)
  else
    echo "Found $count_ids ids matching name $CONTAINER_NAME, choose unique name"
  fi

}

# Script
if [ "$#" -ge 2 ];
then
  execute_command_in_container
else
  usage
fi


