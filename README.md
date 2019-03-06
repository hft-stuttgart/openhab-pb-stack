# openHAB Public Building Stack

This repository contains files describing an openHAB stack for a public institutions with multiple buildings.

An openHAB public building stack consists of a docker swarm setup that is build around a compose file and several configuration files for all needed services.

Heart of the stack is the **Building Manager Script** served as `building_manager.py` and a set of templates. This script provides commands to create and control a multi building setup. 

**Content**

[TOC]


## Getting Started

Before working with the script it first needs to be loaded onto one of the desired machines to be used. This can easily be achieved by cloning the script to the machine using git (`sudo apt install git` if it is missing):

```sh
git clone https://github.com/Dobli/openhab-pb-stack.git
```

This will create a local copy of the script in the current folder. Change to its directory:

```sh
cd openhab-pb-stack
```

#### Requirements

The building manager script has a few requirements for the system and the python environment before being able to be executed.

**System:**

First of it needs a few system components, they essentially consist of Docker and Python:

```
docker
docker-compose
docker-machine
python3 (at least 3.6)
python3-pip
mosquitto (needed to for mosquitto password generation)
ssh-keygen
```

On a Ubuntu System these can be installed following these commands:

```bash
sudo apt install mosquitto, python3-pip		# Needed to use mosquitto_passwd
sudo systemctl stop mosquitto				# Stop Mosquitto service
sudo systemctl disable mosquitto			# Disable Mosquitto service
```

To install docker it is not recommended to use the versions in the Ubuntu repository. Instead the official Docker install instructions should be used to install [Docker](https://docs.docker.com/install/linux/docker-ce/ubuntu/), [Docker Compose](https://docs.docker.com/compose/install/) and [Docker Machine](https://docs.docker.com/machine/install-machine/).

While the other requirements are only necessary on a single machine to work with the script, Docker needs to be available on all machines.

**Python:**

Beside the system requirements the following python libraries are needed too:

```sh
docker			# Docker client library
questionary		# Prompt library
ruamel.yaml		# Yaml library that preserves structure
bcrypt			# generate bcrypt hashes
pip-tools		# manage requirements (Optional)
```

Again on an Ubuntu system the following command can be used to install them (you need to be in the cloned folder) for the current user:

```
pip3 install --user -r requirements.txt
```

All python requirements are managed using `pip-tool` in the `requirements.in` file. The command `pip-compile`  generates a `requirements.txt` file that  can be used with with `pip ` to install all needed python dependencies. 

Updating the `requirements.txt` file can be done using `pip-compile` again. In an virtual environment `pip-sync` can be used instead of pip install to install needed packages.

### Preparation

After installing the requirements it is necessary to connect all instances intended to be used with docker-machine. Docker-machine allows to manage multiple machines running the docker.

[These instructions](https://docs.docker.com/machine/drivers/generic/) explain how to add a machine to docker-machine.

**NOTE:** Following is assumed the machines have the hostnames *building1* (IP: 192.168.1.10) and *building2* (IP: 192.168.1.20) both have a user called *pbuser*. These values need to be **adapted** to your setup.

Following steps need to be executed for every machine that should run the script:

1. Generate keys on the master node for ssh access

   ```sh
   ssh-keygen -b 4096 		# will be saved to ./ssh/id_rsa
   ```

2. Copy the key from the main machine to all nodes (even the master itself):

   ```sh
   ssh-copy-id pbuser@building1
   ssh-copy-id pbuser@building2
   ```

   This allows to access the machines using ssh without a password.

3. Docker-machine needs the users on *each node* to be able to use sudo without a password, to enable it for our example *pbuser* add the following line to the `/etc/sudoers`:

   ```sh
   pbuser ALL=(ALL) NOPASSWD: ALL
   ```

   To add this line with a single command to the file execute the following (on each node):

   ```sh
   echo "pbuser ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
   ```

4. Add the nodes to docker-machine:

   ```sh
   docker-machine create --driver generic --generic-ip-address=192.168.1.10 --generic-ssh-key ~/.ssh/id_rsa --generic-ssh-user pbuser building1		# Building 1
   docker-machine create --driver generic --generic-ip-address=192.168.1.20 --generic-ssh-key ~/.ssh/id_rsa --generic-ssh-user pbuser building2		# Building 2
   ```

### Run it!

When requirements are installed and docker-machine preparations are finished the script can be started by calling it.

```sh
cd openhab-pb-stack		# Change to script directory
./building-manager.py	# Execute script add --help for further options
```

This will open the script in interactive mode. It shows a menu with various options to choose from described below.

## What can it do?

### Initial Setup

When the script is started for the first time the only option is to create an initial setup. This will ask multiple questions about the setup, e.g. which machine nodes will be used, what services they shall provide and administrative passwords.

## Config file generation

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





## OLD CONTENT

This repository contains files describing how an openHAB stack could look for a public instition with multiple buildings.
It consists of a main docker file, example configurations for the included components and explanations how to handle and adapt them.

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

- 