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

## Building Manager Script

To ease initial setup and management the `building_manager.py` is provided. This script adds commands to create and control a multi building setup. To use it you first have to install its requirements by calling `pip install requirements.txt`

### Requirements
The script has a few requirements for the system and the python environment.

**System:**
```
docker
docker-compose
docker-machine
python3 (at least 3.6)
python3-pip
mosquitto (needed to for mosquitto_passwd utility)
ssh-keygen
```

On a Ubuntu System these can be installed following these commands:

```bash
sudo apt install mosquitto, python3-pip		# Needed to use mosquitto_passwd
sudo systemctl stop mosquitto				# Stop Mosquitto service
sudo systemctl disable mosquitto			# Disable Mosquitto service
```

The setup also expects a working docker-machine environment. To connect all instances (on at least one of the machines) follow [these instructions](https://docs.docker.com/machine/drivers/generic/).



**Python:**

```sh
docker
PyInquirer
pyyaml
bcrypt
pip-tools
```

All python requirements managed using `pip-tool` in the `requirements.in` file. The command `pip-compile`  generates a `requirements.txt` file that  can be used with with `pip install--user -r requirements.txt`  to install all needed python dependencies. E.g. on Ubuntu you can execute the following:



```
pip3 install --user -r requirements.txt
```

Updating the `requirements.txt` file can be done using `pip-compile` again. In an virtual environment `pip-sync` can be used instead of pip install to install needed packages.

### Config file generation

The openhab-pb stack consists of multiple configuration files that need to be available and will be used by the docker containers. The Manager Script generates these for convinience. In addition they are documented here, sorted by application/folder, to understand their usecases.

**mosquitto**

- *mosquitto.conf*: basic configuration of mosquitto
  - copy from template folder
  - disables anonymous access
  - enables usage of password file
- *mosquitto_passwords*: List of users/passwords that gain access to mosquitto
  - generated with `mosquitto_passwd`
  - Uses SHA512 crypt -> maybe generated using pythons crypt library

**nodered**

- *nodered_package.json*: packages to be installed when node red is setup
  - copy from template folder
  - contains entry for openhab package
- *nodered_settings.js*: basic node red config
  - copy from template folder

**ssh**

- *sshd_config*: basic ssh config
  - copy from template folder
- *sftp_users.conf*: file containing users for sftp container
  - generated, grants access to configuration files
  - uses `makepasswd` to generate MD5 hashed passwords
    - script uses pythons `crypt` to generate them
    - as it relies on the Linux password system we can even use stronger hashes like SHA512
- *known_hosts*: make backup (volumerize) hosts know internal ssh servers
  - generated using ssh-keygen
- *id_rsa/id_rsa.pub*: key pair for passwordless ssh between containers
  - generated using ssh-keygen
- *ssh_host_x_key*: hostkey for ssh, X is cryptosystem
  - generated using ssh-keygen

**traefik**

- *traefik.toml*: basic traefik configuration
  - copy from template folder 
  - entryPoints.http.auth.basic contains usersFile that describes the path to a htpasswd file
- *traefik_users*: htpasswd style file that contains users and hashed passwords
  - generated

**volumerize**

- *backup_config_X.json*: backup/volumerize config for each building, X is replaced by building name