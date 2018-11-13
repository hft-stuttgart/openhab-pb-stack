# openHAB Public Building Stack

This repository contains files describing how an openHAB stack could look for a public instition with multiple buildings.
It consists of a main docker file, example configurations for the included components and explanations how to handle and adapt them.

## Getting Started

This project only provides a template and explanations to build an own setup of distributed openHAB instance. Therefore it needs to be adapted and customized to the actual environment before usage.

### Prerequisites

The template and it's infrastructure relies heavily on docker to achive an easy automated setup and maintenance. The first step would be the ![installation of docker](https://docs.docker.com/install/). In addition it is also necessary to ![install docker compose](https://docs.docker.com/compose/install/#install-compose).

The setup is tailored towards the usage on multiple machines. Therefore it expects docker to run in ![swarm mode](https://docs.docker.com/engine/swarm/swarm-tutorial/). To start our example configuration that defines three buildings we need three hosts running docker.

To initialize swarm mode on the main host machine we run: 
```sh
docker swarm init --advertise-addr <MANAGER-IP> # Replace <MANAGER-IP> IP by the ip of the machine
```
This will setup a swarm environment and print a command to be used on other machines to join this swarm similar to this:
```sh
docker swarm join --token SWMTKN-1-44lk56nj5h6jk4h56yz0fb0xx14ie39trti4wxv-8vxv8rssmk743ojnwachk4h567c <MANAGER-IP>:2377
```
After executing this on the other two hosts we have a ready to use swarm environment, it can be checked by running `docker node ls` on our main host.

### Installing

With our swarm environment ready we can continue with starting our example setup. First switch to the main host again. First it is necessary to clone the template to the machine using git:

```sh
git clone https://github.com/Dobli/openhab-pb-stack/edit/master/README.md
```

To start it up then it is enough to change into the cloned directory and run:

```sh
docker staack deploy -c docker-compose.yml ohSwarmTest # ohSwarmTest is the name of the exmaple stack
```
This will instruct docker swarm to download the corresponding application images and run them.

#### Add building labels

This will not start openHAB yet as it needs to now the assignment of hosts to buildings first. This is solved by labels assigned to the nodes. The example configurations uses the labels `b1`, `b2` and `b3` to assign these run the following commands on the main host:

```sh
docker node update --label-add building=b1 <NAME_OF_HOST_1>
docker node update --label-add building=b2 <NAME_OF_HOST_2>
docker node update --label-add building=b3 <NAME_OF_HOST_3>
```
Docker swarm should pick up the changes automatically and start openHAB on each machine.

The instances should then be available on the subdomains b1, b2, b3 on each of the hosts.
