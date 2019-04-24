#!/usr/bin/env python3
""" Python module to assist creating and maintaining docker openHab stacks."""
import crypt
from enum import Enum
from typing import NamedTuple
import logging
import os
import sys
from hashlib import md5
from shutil import copy2
from subprocess import PIPE, run
from time import sleep

import bcrypt
import docker
import questionary as qust
from ruamel.yaml import YAML
from prompt_toolkit.styles import Style

# Configure YAML
yaml = YAML()
yaml.indent(mapping=4, sequence=4, offset=2)

# Log level during development is info
logging.basicConfig(level=logging.WARNING)

# Prompt style
st = Style([
    ('qmark', 'fg:#00c4b4 bold'),     # token in front of question
    ('question', 'bold'),             # question text
    ('answer', 'fg:#00c4b4 bold'),    # submitted answer question
    ('pointer', 'fg:#00c4b4 bold'),   # pointer for select and checkbox
    ('selected', 'fg:#00c4b4'),       # selected item checkbox
    ('separator', 'fg:#00c4b4'),      # separator in lists
    ('instruction', '')               # user instructions for selections
])


# ******************************
# Constants <<<
# ******************************

# Directories for config generation
CUSTOM_DIR = 'custom_configs'
TEMPLATE_DIR = 'template_configs'
COMPOSE_NAME = 'docker-stack.yml'
SKELETON_NAME = 'docker-skeleton.yml'
TEMPLATES_NAME = 'docker-templates.yml'
CONFIG_DIRS = ['mosquitto', 'nodered', 'ssh', 'filebrowser',
               'traefik', 'volumerize', 'postgres', 'pb-framr']
TEMPLATE_FILES = [
    'mosquitto/mosquitto.conf', 'nodered/nodered_package.json',
    'pb-framr/logo.svg', 'nodered/nodered_settings.js',
    'ssh/sshd_config', 'traefik/traefik.toml'
]
EDIT_FILES = {
    "mosquitto_passwords": "mosquitto/mosquitto_passwords",
    "sftp_users": "ssh/sftp_users.conf",
    "traefik_users": "traefik/traefik_users",
    "id_rsa": "ssh/id_rsa",
    "host_key": "ssh/ssh_host_ed25519_key",
    "known_hosts": "ssh/known_hosts",
    "backup_config": "volumerize/backup_config",
    "postgres_user": "postgres/user",
    "postgres_passwd": "postgres/passwd",
    "pb_framr_pages": "pb-framr/pages.json",
    "filebrowser_conf": "filebrowser/filebrowser.json"
}
CONSTRAINTS = {"building": "node.labels.building"}

# Default Swarm port
SWARM_PORT = 2377
# UID for admin
UID = 9001
# Username for admin
ADMIN_USER = 'ohadmin'

# USB DEVICES (e.g. Zwave stick)
USB_DEVICES = [{
    "name": "Aeotec Z-Stick Gen5 (ttyACM0)",
    "value": "zwave_stick"
}]


class ServiceBody(NamedTuple):
    fullname: str
    prefix: str
    additional: bool
    frontend: bool
    sftp: bool = False
    icon: str = None


class Service(ServiceBody, Enum):
    SFTP = ServiceBody("SFTP", "sftp", False, False)
    OPENHAB = ServiceBody("OpenHAB", "openhab", True,
                          True, icon='dashboard', sftp=True)
    NODERED = ServiceBody("Node-RED", "nodered", False,
                          True, icon='ballot', sftp=True)
    POSTGRES = ServiceBody("Postgre SQL", "postgres", True, False)
    MQTT = ServiceBody("Mosquitto MQTT Broker", "mqtt", True, False)
    FILES = ServiceBody("File Manager", "files", False, True, icon='folder')
    BACKUP = ServiceBody("Volumerize Backups", "backup",
                         False, False, sftp=True)

    @classmethod
    def service_by_prefix(cls, prefix):
        # cls here is the enumeration
        return next(service for service in cls if service.prefix == prefix)
# >>>


# ******************************
# State Variables <<<
# ******************************
base_dir = sys.path[0]
template_path = f'{base_dir}/{TEMPLATE_DIR}'
custom_path = f'{base_dir}/{CUSTOM_DIR}'
# >>>


# ******************************
# Compose file functions <<<
# ******************************

# Functions to generate initial file
def generate_initial_compose():
    """Creates the initial compose using the skeleton
    """
    # compose file
    compose = custom_path + '/' + COMPOSE_NAME
    # skeleton file
    skeleton = template_path + '/' + SKELETON_NAME

    with open(skeleton, 'r') as skeleton_f, open(compose, 'w+') as compose_f:
        init_content = yaml.load(skeleton_f)
        yaml.dump(init_content, compose_f)


def add_sftp_service(building, number=0):
    """Generates an sftp entry and adds it to the compose file

    :building: names of building that the services is added to
    :number: increment of exposed port to prevent overlaps
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # service name
    service_name = f'sftp_{building}'
    # template
    template = get_service_template(Service.SFTP.prefix)
    # only label contraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")
    template['ports'] = [f'{2222 + number}:22']

    # attach volumes
    volume_base = '/home/ohadmin/'
    template['volumes'] = get_attachable_volume_list(volume_base, building)

    add_or_update_compose_service(compose_path, service_name, template)


def add_openhab_service(building, host):
    """Generates an openhab entry and adds it to the compose file

    :building: name of building that the services is added to
    :host: host the building is added to, used for routing
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # service name
    service_name = f'openhab_{building}'
    # template
    template = get_service_template(Service.OPENHAB.prefix)
    # only label contraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")
    # include in backups of this building
    template['deploy']['labels'].append(f'backup={building}')
    # traefik backend
    template['deploy']['labels'].append(f'traefik.backend={service_name}')
    # traefik frontend domain->openhab
    template['deploy']['labels'].extend(
        generate_traefik_host_labels(host, segment='main'))
    # traefik frontend subdomain openhab_hostname.* -> openhab
    template['deploy']['labels'].append(
        f'traefik.sub.frontend.rule=HostRegexp:'
        f'{service_name}.{{domain:[a-zA-z0-9-]+}}')
    template['deploy']['labels'].append('traefik.sub.frontend.priority=2')

    # replace volumes with named entries in template
    template['volumes'] = generate_named_volumes(
        template['volumes'], service_name, compose_path)

    add_or_update_compose_service(compose_path, service_name, template)


def add_nodered_service(building):
    """Generates an nodered entry and adds it to the compose file

    :building: name of building that the services is added to
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # service name
    service_name = f'nodered_{building}'
    # template
    template = get_service_template(Service.NODERED.prefix)
    # only label contraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")
    template['deploy']['labels'].append(f'traefik.backend={service_name}')
    template['deploy']['labels'].append(f'backup={building}')
    template['deploy']['labels'].extend(
        generate_traefik_path_labels(service_name, segment='main'))
    template['deploy']['labels'].extend(
        generate_traefik_subdomain_labels(service_name, segment='sub'))

    # replace volumes with named entries in template
    template['volumes'] = generate_named_volumes(
        template['volumes'], service_name, compose_path)

    add_or_update_compose_service(compose_path, service_name, template)


def add_mqtt_service(building, number=0):
    """Generates an mqtt entry and adds it to the compose file

    :building: name of building that the services is added to
    :number: increment of exposed port to prevent overlaps
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # service name
    service_name = f'mqtt_{building}'
    # template
    template = get_service_template(Service.MQTT.prefix)
    # only label contraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")
    # ports incremented by number of services
    template['ports'] = [f'{1883 + number}:1883', f'{9001 + number}:9001']

    # replace volumes with named entries in template
    template['volumes'] = generate_named_volumes(
        template['volumes'], service_name, compose_path)

    add_or_update_compose_service(compose_path, service_name, template)


def add_postgres_service(building, postfix=None):
    """Generates an postgres entry and adds it to the compose file

    :building: name of building that the services is added to
    :postfix: an identifier for this service
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # use building as postfix when empty
    if postfix is None:
        service_name = f'postgres_{building}'
    else:
        service_name = f'postgres_{postfix}'

    # template
    template = get_service_template(Service.POSTGRES.prefix)
    # only label constraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")

    # replace volumes with named entries in template
    template['volumes'] = generate_named_volumes(
        template['volumes'], service_name, compose_path)

    add_or_update_compose_service(compose_path, service_name, template)


def add_file_service(building):
    """Generates a file manager entry and adds it to the compose file

    :building: names of host that the services is added to
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # service name
    service_name = f'{Service.FILES.prefix}_{building}'
    # template
    template = get_service_template(Service.FILES.prefix)
    # add command that sets base url
    template['command'] = f'-b /{service_name}'
    # only label contraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")
    template['deploy']['labels'].append(f'traefik.backend={service_name}')
    template['deploy']['labels'].extend(
        generate_traefik_path_labels(service_name, segment='main',
                                     redirect=False))

    # attach volumes
    volume_base = '/srv/'
    template['volumes'] = get_attachable_volume_list(volume_base, building)

    add_or_update_compose_service(compose_path, service_name, template)


def add_volumerize_service(building):
    """Generates a volumerize backup entry and adds it to the compose file

    :building: names of host that the services is added to
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # service name
    service_name = f'{Service.BACKUP.prefix}_{building}'
    # template
    template = get_service_template(Service.BACKUP.prefix)

    # only label contraint is building
    template['deploy']['placement']['constraints'][0] = (
        f"{CONSTRAINTS['building']} == {building}")

    # attach volumes
    volume_base = '/source/'
    template['volumes'].extend(
        get_attachable_volume_list(volume_base, building))

    # adjust config
    config_list = template['configs']
    # get backup entry from configs
    index, entry = next((i, c) for i, c in enumerate(config_list)
                        if c['source'] == 'backup_config')
    entry['source'] = f'backup_config_{building}'
    template['configs'][index] = entry

    add_or_update_compose_service(compose_path, service_name, template)


# Functions to delete services
def delete_service(service_name):
    """Deletes a service from the compose file

    :returns: list of current services
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    with open(compose_path, 'r+') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # generate list of names
        compose['services'].pop(service_name, None)
        # start writing from file start
        compose_f.seek(0)
        # write new compose content
        yaml.dump(compose, compose_f)
        # reduce file to new size
        compose_f.truncate()


# Functions to extract information
def get_current_services(placement=None):
    """Gets a list of currently used services may be restricted to a placement

    :placement: placement contraint the service shall match
    :returns: list of current services
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    with open(compose_path, 'r') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # generate list of names
        service_names = []
        for (name, entry) in compose['services'].items():
            if placement is None or get_building_of_entry(entry) == placement:
                service_names.append(name)

        return service_names


def get_current_building_constraints():
    """Gets a list of currently used building constraints

    :returns: set of current buildings
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    with open(compose_path, 'r') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # generate list of buildings
        building_names = set()
        for (name, entry) in compose['services'].items():
            building = get_building_of_entry(entry)
            if building:
                building_names.add(building)

        return building_names


def get_building_of_entry(service_dict):
    """Extract the configured building constraint from an yaml service entry

    :service_dict: service dict from yaml
    :returns: building that is set
    """
    # get constraints
    constraint_list = service_dict['deploy']['placement']['constraints']
    # convert them to dicts
    label_dict = {i.split("==")[0].strip(): i.split("==")[1].strip()
                  for i in constraint_list}
    return label_dict.get('node.labels.building')


def get_service_entry_info(service_entry):
    """Gets service name and instance of a service entry

    :service_entry: service entry name
    :return: tuple with service_name and instance name
    """
    entry_split = service_entry.split("_")
    name = entry_split[0]
    instance = entry_split[1]
    return name, instance


def get_service_volumes(service_name):
    """Gets a list of volumes of a service

    :returns: list of volumes
    """
    # compose file
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    with open(compose_path, 'r') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # load service
        service = compose['services'].get(service_name)

        # extract volume names
        volume_dict = yaml_list_to_dict(service['volumes'])
        volumes = list(volume_dict.keys())
        # filter only named volumes
        named_volumes = [v for v in volumes if '/' not in v]

        return named_volumes


# Helper functions
def get_attachable_volume_list(volume_base, building):
    """Get a list of volumes from a building that can be attatched for file acccess

    :volume_base: Base path of volumes
    :building: building to consider
    :returns: list of attachable volume entries
    """
    volume_list = []
    host_services = get_current_services(building)
    for host_service in host_services:
        name, instance = get_service_entry_info(host_service)
        volume_service = Service.service_by_prefix(name)
        # only apply to services that want their volumes attatched
        if volume_service.sftp:
            volumes = get_service_volumes(host_service)
            # collect volumes not already in list
            vlist = [
                f'{v}:{volume_base}{v}' for v in volumes
                if f'{v}:{volume_base}{v}' not in volume_list]
            volume_list.extend(vlist)
    return volume_list


def generate_named_volumes(template_volume_list, service_name, compose_path):
    """Generates volumes including name of services and ads them to
    the compose file

    :template_volume_list: List of volume entries from template
    :service_name: Name of the service instance
    :compose_path: path to compose file
    :returns: list of named entries

    """
    volume_entries = yaml_list_to_dict(template_volume_list)
    # add name to entries (that are named volumes
    named_volume_entries = {}
    for (volume, target) in volume_entries.items():
        if "/" not in volume:
            named_volume_entries[f"{service_name}_{volume}"] = target
        else:
            named_volume_entries[f"{volume}"] = target

    for (volume, target) in named_volume_entries.items():
        # declare volume if it is a named one
        if "/" not in volume:
            add_volume_entry(compose_path, volume)

    return dict_to_yaml_list(named_volume_entries)


def yaml_list_to_dict(yaml_list):
    """Converts a yaml list (volumes, configs etc) into a python dict

    :yaml_list: list of a yaml containing colon separated entries
    :return: python dict
    """
    return {i.split(":")[0]: i.split(":")[1] for i in yaml_list}


def dict_to_yaml_list(pdict):
    """Converts a python dict into a yaml list (volumes, configs etc)

    :pdict: python dict
    :return: list of a yaml containing colon separated entries
    """
    return [f'{k}:{v}' for (k, v) in pdict.items()]


def get_service_template(service_name):
    """Gets a service template entry from the template yaml

    :return: yaml entry of a service
    """
    templates = template_path + '/' + TEMPLATES_NAME

    with open(templates, 'r') as templates_file:
        template_content = yaml.load(templates_file)

    return template_content['services'][service_name]


def generate_traefik_host_labels(hostname, segment=None, priority=1):
    """Generates a traefik path url with necessary redirects

    :hostname: Hostname that gets assigned by the label
    :segment: Optional traefik segment when using multiple rules
    :priority: Priority of frontend rule
    :returns: list of labels for traefik
    """
    label_list = []
    # check segment
    segment = f'.{segment}' if segment is not None else ''
    # fill list
    label_list.append(
        f'traefik{segment}.frontend.rule=HostRegexp:{{domain:{hostname}}}')
    label_list.append(f'traefik{segment}.frontend.priority={priority}')
    return label_list


def generate_traefik_subdomain_labels(subdomain, segment=None, priority=2):
    """Generates a traefik subdomain with necessary redirects

    :subdomain: subdomain that will be assigned to a service
    :segment: Optional traefik segment when using multiple rules
    :priority: Priority of frontend rule
    :returns: list of labels for traefik
    """
    label_list = []
    # check segment
    segment = f'.{segment}' if segment is not None else ''
    # fill list
    label_list.append(
        f'traefik{segment}.frontend.rule='
        f'HostRegexp:{subdomain}.{{domain:[a-zA-z0-9-]+}}')
    label_list.append(f'traefik{segment}.frontend.priority={priority}')
    return label_list


def generate_traefik_path_labels(url_path, segment=None, priority=2,
                                 redirect=True):
    """Generates a traefik path url with necessary redirects

    :url_path: path that should be used for the site
    :segment: Optional traefik segment when using multiple rules
    :priority: Priority of frontend rule
    :redirect: Redirect to path with trailing slash
    :returns: list of labels for traefik
    """
    label_list = []
    # check segment
    segment = f'.{segment}' if segment is not None else ''
    # fill list
    label_list.append(f'traefik{segment}.frontend.priority={priority}')
    if redirect:
        label_list.append(
            f'traefik{segment}.frontend.redirect.regex=^(.*)/{url_path}$$')
        label_list.append(
            f'traefik{segment}.frontend.redirect.replacement=$$1/{url_path}/')
        label_list.append(
            f'traefik{segment}.frontend.rule=PathPrefix:/{url_path};'
            f'ReplacePathRegex:^/{url_path}/(.*) /$$1')
    else:
        label_list.append(
            f'traefik{segment}.frontend.rule=PathPrefix:/{url_path}')
    return label_list


def add_or_update_compose_service(compose_path, service_name, service_content):
    """Adds or replaces a service in a compose file

    :compose_path: path of the compose file to change
    :service_name: name of the service to add/replace
    :service_content: service definition to add
    """
    with open(compose_path, 'r+') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # add / update service with template
        compose['services'][service_name] = service_content
        # write content starting from first line
        compose_f.seek(0)
        # write new compose content
        yaml.dump(compose, compose_f)
        # reduce file to new size
        compose_f.truncate()


def add_volume_entry(compose_path, volume_name):
    """Creates an additional volume entry in the stack file

    :compose_path: path of the compose file to change
    :volume_name: name of the additional volume
    """
    with open(compose_path, 'r+') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # add volume
        compose['volumes'][volume_name] = None
        # write content starting from first line
        compose_f.seek(0)
        # write new compose content
        yaml.dump(compose, compose_f)
        # reduce file to new size
        compose_f.truncate()


def add_config_entry(compose_path, config_name, config_path):
    """Creates an additional config entry in the stack file or updates it

    :compose_path: path of the compose file to change
    :config_name: name of the additional config
    :config_path: path of the additional config
    """
    with open(compose_path, 'r+') as compose_f:
        # load compose file
        compose = yaml.load(compose_f)
        # add config
        compose['configs'][config_name] = {"file": config_path}
        # write content starting from first line
        compose_f.seek(0)
        # write new compose content
        yaml.dump(compose, compose_f)
        # reduce file to new size
        compose_f.truncate()
# >>>


# ******************************
# Config file functions <<<
# ******************************
def generate_config_folders():
    """Generate folders for configuration files
    """
    if not os.path.exists(custom_path):
        os.makedirs(custom_path)

    print(f'Initialize configuration in {custom_path}')

    # generate empty config dirs
    for d in CONFIG_DIRS:
        new_dir = f'{custom_path}/{d}'
        if not os.path.exists(new_dir):
            os.makedirs(new_dir)

    # copy template configs
    for template_file in TEMPLATE_FILES:
        copy_template_config(template_file)


def copy_template_config(config_path):
    """Copies template configuration files into custom folder

    :config_path: relative path of config to copy from template
    """
    custom_config_path = f'{custom_path}/{config_path}'
    template_config = f"{template_path}/{config_path}"

    logging.info(
        f'Copy {config_path} from {template_config} to {custom_path}')
    copy2(template_config, custom_config_path)


def generate_mosquitto_user_line(username, password):
    """Generates a line for a mosquitto user with a crypt hashed password

    :username: username to use
    :password: password that will be hashed (SHA512)

    :returns: a line as expected by mosquitto
    """
    password_hash = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    line = f"{username}:{password_hash}"
    return line


def generate_sftp_user_line(username, password, directories=None):
    """Generates a line for a sftp user with a hashed password

    :username: username to use
    :password: password that will be hashed (SHA512)
    :directories: list of directories which the user should have

    :returns: a line as expected by sshd
    """
    # generate user line with hashed password
    password_hash = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    line = f"{username}:{password_hash}:e:{UID}:{UID}"
    # add directory entries when available
    if directories:
        # create comma separated string from list
        dir_line = ','.join(d for d in directories)
        line = f"{line}:{dir_line}"
    return line


def generate_traefik_user_line(username, password):
    """Generates a line for a traefik user with a bcrypt hashed password

    :username: username to use
    :password: password that will be hashed (bcrypt)

    :returns: a line as expected by traefik
    """
    password_hash = get_bcrypt_hash(password)
    line = f"{username}:{password_hash}"
    return line


def generate_pb_framr_entry(building, host, service):
    """Generates a single entry of the framr file

    :building: building this entry is intended for
    :host: host this entry is intended for
    :service: entry from service enum
    :returns: a dict fitting the asked entry

    """
    entry = {}
    entry['title'] = service.fullname
    if service == Service.OPENHAB:
        entry['url'] = f'http://{host}/'
        pass
    else:
        entry['url'] = f'/{service.prefix}_{building}/'
    entry['icon'] = service.icon
    return entry


def generate_mosquitto_file(username, password):
    """Generates a mosquitto password file using mosquitto_passwd system tool

    :username: username to use
    :password: password that will be used
    """
    passwd_path = f"{custom_path}/{EDIT_FILES['mosquitto_passwords']}"

    # ensure file exists
    if not os.path.exists(passwd_path):
        open(passwd_path, 'a').close()

    # execute mosquitto passwd
    mos_result = run(
        ['mosquitto_passwd', '-b', passwd_path, username, password],
        universal_newlines=True)
    return mos_result.returncode == 0


def generate_sftp_file(username, password, direcories=None):
    """Generates a sftp password file

    :username: username to use
    :password: password that will be used
    :directories: list of directories which the user should have
    """
    # generate line and save it into a file
    file_content = generate_sftp_user_line(username, password, direcories)
    create_or_replace_config_file(EDIT_FILES['sftp_users'], file_content)


def generate_postgres_files(username, password):
    """Generates postgres user and password files

    :username: username to use
    :password: password that will be used
    """
    # content is purely username and (hashed) password
    hashed_pass = (
        f'md5{md5(username.encode() + password.encode()).hexdigest()}')
    create_or_replace_config_file(EDIT_FILES['postgres_user'], username)
    create_or_replace_config_file(EDIT_FILES['postgres_passwd'], hashed_pass)


def generate_id_rsa_files():
    """Generates id_rsa and id_rsa.pub private/public keys using ssh-keygen
    """
    id_path = f"{custom_path}/{EDIT_FILES['id_rsa']}"

    # execute ssh-keygen
    id_result = run(
        ['ssh-keygen', '-m', 'PEM', '-t', 'rsa',
            '-b', '4096', '-f', id_path, '-N', ''],
        universal_newlines=True, stdout=PIPE)
    return id_result.returncode == 0


def generate_host_key_files(hosts):
    """Generates ssh host keys and matching known_hosts using ssh-keygen
    """
    key_path = f"{custom_path}/{EDIT_FILES['host_key']}"
    # ssh-keygen generates public key with .pub postfix
    pub_path = key_path + '.pub'
    # host_names with sftp_ postfix
    sftp_hosts = [f'sftp_{host}' for host in hosts]

    # execute ssh-keygen
    id_result = run(['ssh-keygen', '-t', 'ed25519', '-f', key_path, '-N', ''],
                    universal_newlines=True, stdout=PIPE)

    # read content of public key as known line
    known_line = ""
    with open(pub_path, 'r') as pub_file:
        pub_line = pub_file.readline()
        split_line = pub_line.split()
        # delete last list element
        del split_line[-1]
        # collect sftp hosts as comma separated string
        hosts_line = ','.join(h for h in sftp_hosts)
        split_line.insert(0, hosts_line)
        # collect parts as space separated string
        known_line = ' '.join(sp for sp in split_line)

    # write new known_line file
    create_or_replace_config_file(EDIT_FILES['known_hosts'], known_line)

    return id_result.returncode == 0


def generate_filebrowser_file(username, password):
    """Generates a configuration for the filebrowser web app

    :username: username to use
    :password: password that will be used
    """
    # generate line and save it into a file
    file_content = {
        "port": "80",
        "address": "",
        "username": f"{username}",
        "password": f"{get_bcrypt_hash(password)}",
        "log": "stdout",
        "root": "/srv"
    }

    create_or_replace_config_file(EDIT_FILES['filebrowser_conf'],
                                  file_content, json=True)


def generate_traefik_file(username, password):
    """Generates a traefik password file

    :username: username to use
    :password: password that will be used
    """
    # generate line and save it into a file
    file_content = generate_traefik_user_line(username, password)
    create_or_replace_config_file(EDIT_FILES['traefik_users'], file_content)


def generate_volumerize_files(host_entries):
    """Generates config for volumerize backups

    :host_entries: dickt of host entries
    """
    compose_path = f'{custom_path}/{COMPOSE_NAME}'
    # create one config per host
    for h in host_entries:
        configs = []
        # Each host knows other hosts
        for t in host_entries:
            host_config = {
                'description': f"'Backup Server on {t['building_name']}",
                'url': f"sftp://ohadmin@sftp_{t['building_id']}:"
                f"//home/ohadmin/backup_data/backup/{h['building_id']}"
            }
            configs.append(host_config)

        config_file = f"{EDIT_FILES['backup_config']}_{h['building_id']}.json"
        create_or_replace_config_file(config_file, configs, json=True)
        add_config_entry(
            compose_path,
            f"backup_config_{h['building_id']}",
            f"./{config_file}")


def generate_pb_framr_file(frames):
    """Generates config for pb framr landing page

    :frames: a dict that contains hosts with matching name and services
    """
    configs = []

    for f in frames:
        building = {
            'instance': f['building_name'],
            'entries': [generate_pb_framr_entry(f['building_id'], f['host'], s)
                        for s in f['services'] if s.frontend]
        }
        configs.append(building)

    create_or_replace_config_file(
        EDIT_FILES['pb_framr_pages'], configs, json=True)


def create_or_replace_config_file(config_path, content, json=False):
    """Creates or replaces a config file with new content

    :config_path: relative path of config
    :content: content of the file as a string
    """
    custom_config_path = f'{custom_path}/{config_path}'
    with open(custom_config_path, 'w+') as file:
        if json:
            import json
            json.dump(content, file, indent=2)
        else:
            file.write(content)


# Functions to modify existing files
def add_user_to_traefik_file(username, password):
    """Adds or modifies user in traefik file

    :username: username to use
    :password: password that will be used
    """
    # get current users
    current_users = get_traefik_users()
    # ensure to delete old entry if user exists
    users = [u for u in current_users if u['username'] != username]
    # collect existing users lines
    user_lines = []
    for u in users:
        user_lines.append(f"{u['username']}:{u['password']}")
    # add new/modified user
    user_lines.append(generate_traefik_user_line(username, password))
    # generate content
    file_content = "\n".join(user_lines)
    create_or_replace_config_file(EDIT_FILES['traefik_users'], file_content)


def remove_user_from_traefik_file(username):
    """Removes user from traefik file

    :username: username to delete
    """
    # get current users
    current_users = get_traefik_users()
    # ensure to delete entry if user exists
    users = [u for u in current_users if u['username'] != username]
    # collect other user lines
    user_lines = []
    for u in users:
        user_lines.append(f"{u['username']}:{u['password']}")
    # generate content and write file
    file_content = "\n".join(user_lines)
    create_or_replace_config_file(EDIT_FILES['traefik_users'], file_content)


# Functions to get content from files
def get_users_from_files():
    """Gets a list of users in files

    :returns: list of users
    """
    users = []

    # add treafik users
    users.extend([u['username'] for u in get_traefik_users()])

    return users


def get_traefik_users():
    """Gets a list of dicts containing users and password hashes

    :returns: list of users / password dicts
    """
    users = []

    # get treafik users
    traefik_file = f"{custom_path}/{EDIT_FILES['traefik_users']}"
    with open(traefik_file, 'r') as file:
        lines = file.read().splitlines()
        for line in lines:
            # username in traefik file is first entry unitl colon
            username = line.split(':')[0]
            password = line.split(':')[1]
            users.append({"username": username, "password": password})
    return users


# Additional helper functions
def get_bcrypt_hash(password):
    """Returns bcrypt hash for a password

    :password: password to hash
    :returns: bcrypt hash of password

    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# >>>


# ******************************
# Docker machine functions <<<
# ******************************
def get_machine_list():
    """Get a list of docker machine names using the docker-machine system command

    :returns: a list of machine names managed by docker-machine
    """
    machine_result = run(['docker-machine', 'ls', '-q'],
                         universal_newlines=True,
                         stdout=PIPE)
    return machine_result.stdout.splitlines()


def check_machine_exists(machine_name):
    """Checks weather a docker machine exists and is available

    :machine_name: Name of the machine to check
    :returns: True when machine is available
    """
    machines = get_machine_list()

    return machine_name in machines


def get_machine_env(machine_name):
    """Gets dict of env settings from a machine

    :machine_name: Name of the machine to check
    :returns: Dict of env variables for this machine
    """
    env_result = run(['docker-machine', 'env', machine_name],
                     universal_newlines=True,
                     stdout=PIPE)

    machine_envs = {}

    lines = env_result.stdout.splitlines()
    for line in lines:
        if 'export' in line:
            assign = line.split('export ', 1)[1]
            env_entry = [a.strip('"') for a in assign.split('=', 1)]
            machine_envs[env_entry[0]] = env_entry[1]
    return machine_envs


def get_machine_ip(machine_name):
    """Asks for the ip of the docker machine

    :machine_name: Name of the machine to use for init
    """
    machine_result = run(['docker-machine', 'ip', machine_name],
                         universal_newlines=True,
                         stdout=PIPE)
    return machine_result.stdout.strip()


def init_swarm_machine(machine_name):
    """Creates a new swarm with the specified machine as leader

    :machine_name: Name of the machine to use for init
    :return: True if swarm init was successful
    """
    machine_ip = get_machine_ip(machine_name)
    init_command = 'docker swarm init --advertise-addr ' + machine_ip
    init_result = run(['docker-machine', 'ssh', machine_name, init_command],
                      universal_newlines=True)
    return init_result.returncode == 0


def join_swarm_machine(machine_name, leader_name):
    """Joins the swarm of the specified leader

    :machine_name: Name of the machine to join a swarm
    :leader_name: Name of the swarm leader machine
    :return: True if join to swarm was successful
    """
    token_command = 'docker swarm join-token manager -q'
    token_result = run(['docker-machine', 'ssh', leader_name, token_command],
                       universal_newlines=True,
                       stdout=PIPE)
    token = token_result.stdout.strip()
    leader_ip = get_machine_ip(leader_name)
    logging.info(f"Swarm leader with ip {leader_ip} uses token {token}")

    join_cmd = f'docker swarm join --token {token} {leader_ip}:{SWARM_PORT}'
    logging.info(f'Machine {machine_name} joins using command {join_cmd}')
    join_result = run(['docker-machine', 'ssh', machine_name, join_cmd],
                      universal_newlines=True)

    return join_result.returncode == 0


def generate_swarm(machines):
    """Generates a swarm, the first machine will be the initial leader

    :machines: list of machines in the swarm
    """
    leader = None
    for machine in machines:
        # init swarm with first machine
        if leader is None:
            leader = machine
            print(f'Create initial swarm with leader {leader}')
            if init_swarm_machine(leader):
                print('Swarm init successful\n')
                assign_label_to_node(leader, 'building',
                                     leader, manager=leader)
        else:
            print(f'Machine {machine} joins swarm of leader {leader}')
            if (join_swarm_machine(machine, leader)):
                print('Joining swarm successful\n')
                assign_label_to_node(machine, 'building',
                                     machine, manager=leader)


def check_dir_on_machine(dirpath, machine):
    """Checks weather a dir exists on a machine

    :dirpath: Directory to check
    :machine: Machine to check
    :returns: True when dir exists false otherwise
    """
    check_command = f"[ -d {dirpath} ]"
    check_result = run(['docker-machine', 'ssh', machine, check_command])
    return check_result.returncode == 0


def check_file_on_machine(filepath, machine):
    """Checks weather a file exists on a machine

    :filepath: File to check
    :machine: Machine to check
    :returns: True when file exists false otherwise
    """
    check_command = f"[ -f {filepath} ]"
    check_result = run(['docker-machine', 'ssh', machine, check_command])
    return check_result.returncode == 0


def copy_files_to_machine(filepath, machine):
    """Copyies a directory and its content or a file to a machine

    :filepath: Direcotry or file to copy
    :machine: Machine to copy to
    """
    run(['docker-machine', 'scp', '-r', filepath, f'{machine}:'])


def execute_command_on_machine(command, machine):
    """Executes a command on a docker machine

    :command: Command to execute
    :machine: Machine to execute command
    """
    run([f'docker-machine ssh {machine} {command}'], shell=True)
# >>>


# ******************************
# Systemd functions <<<
# ******************************
def list_enabled_devices():
    """Presents a list of enabled devices (systemd services)
    :returns: list of enabled devices

    """
    list_result = run(['systemctl', 'list-units'],
                      stdout=PIPE, universal_newlines=True)
    device_list = list_result.stdout.splitlines()
    # Filter out only swarm-device services
    device_list = [d.strip() for d in device_list if 'swarm-device' in d]
    # Extract service name
    device_list = [d.split()[0] for d in device_list]
    return device_list
# >>>


# ******************************
# Docker client commands <<<
# ******************************
def deploy_docker_stack(machine):
    """Deploys the custom stack in the custom_path

    :machine: Docker machine to execute command
    """
    # Set CLI environment to target docker machine
    machine_env = get_machine_env(machine)
    os_env = os.environ.copy()
    os_env.update(machine_env)

    # Get compose file and start stack
    compose_file = f'{custom_path}/{COMPOSE_NAME}'
    deploy_command = f'docker stack deploy -c {compose_file} ohpb'
    run([f'{deploy_command}'], shell=True, env=os_env)


def remove_docker_stack(machine):
    """Removes the custom stack in the custom_path

    :machine: Docker machine to execute command
    """
    # Set CLI environment to target docker machine
    machine_env = get_machine_env(machine)
    os_env = os.environ.copy()
    os_env.update(machine_env)

    remove_command = f'docker stack rm ohpb'
    run([f'{remove_command}'], shell=True, env=os_env)


def resolve_service_nodes(service):
    """Returnes nodes running a specified service

    :service: name or id of a service
    :returns: list of nodes running the service
    """
    node_result = run(['docker', 'service', 'ps', service,
                       '--format', '{{.Node}}',
                       '-f', 'desired-state=running'],
                      universal_newlines=True,
                      stdout=PIPE)
    return node_result.stdout.splitlines()


def get_container_list(manager=None):
    """Return a list of containers running on a machine

    :manager: Docker machine to use for command, otherwise local
    :returns: list of containers
    """
    client = get_docker_client(manager)
    return [c.name for c in client.containers.list()]


def get_service_list(manager=None):
    """Return a list of services managed by a machine

    :manager: Docker machine to use for command, otherwise local
    :returns: list of services
    """
    client = get_docker_client(manager)
    return [s.name for s in client.services.list()]


def remove_label_from_nodes(label, value, manager=None):
    """Removes label with matching value from all nodes

    :label: Label you want to remove
    :value: The value to match before removing
    :manager: Docker machine to use for command, otherwise local
    """
    client = get_docker_client(manager)

    nodes = client.nodes.list()
    matching_nodes = [n for n in nodes
                      if label in n.attrs['Spec']['Labels']
                      and n.attrs['Spec']['Labels'][label] == value]
    print(f'Matches {matching_nodes}')
    for m in matching_nodes:
        spec = m.attrs['Spec']
        spec['Labels'].pop(label)
        m.update(spec)
        logging.info(f'Remove label {label} with value {value} from {m}')

    client.close()


def assign_label_to_node(nodeid, label, value, manager=None):
    """Assigns a label to a node (e.g. building)

    :nodeid: Id or name of the node
    :label: Label you want to add
    :value: The value to assign to the label
    :manager: Docker machine to use for command, otherwise local
    """
    client = get_docker_client(manager)

    node = client.nodes.get(nodeid)
    spec = node.attrs['Spec']
    spec['Labels'][label] = value
    node.update(spec)
    logging.info(f'Assign label {label} with value {value} to {nodeid}')

    client.close()


def run_command_in_service(service, command, building=None):
    """Runs a command in a service based on its name.
    When no matching container is found or the service name is ambigous
    an error will be displayed and the function exits

    :param service: Name of the service to execute command
    :param command: Command to execute
    :param building: Optional building, make service unambigous (Default: None)
    """

    client = get_docker_client(building)

    # Find containers matching name
    service_name_filter = {"name": service}
    containers = client.containers.list(filters=service_name_filter)

    # Ensure match is unambigous
    if (len(containers) > 1):
        print(f'Found multiple containers matching service name {service}, '
              'ensure service is unambigous')
    elif (len(containers) < 1):
        print(f'Found no matching container for service name {service}')
    else:
        service_container = containers[0]
        print(f'Executing {command} in container {service_container.name}'
              f'({service_container.id}) on building {building}\n')
        command_exec = service_container.exec_run(command)
        print(command_exec.output.decode())
    client.close()


def get_docker_client(manager=None):
    """Returns docker client instance

    :manager: Optional machine to use, local otherwise
    :returns: Docker client instance
    """
    if manager:
        machine_env = get_machine_env(manager)
        client = docker.from_env(environment=machine_env)
    else:
        client = docker.from_env()
    return client


def restore_building_backup(manager, building, new_machine=None):
    client = get_docker_client(manager)
    # get backup services of the building
    services = client.services.list(filters={'label': f'backup={building}'})

    # scale down services (to prevent writes during restore)
    for s in services:
        s.scale(0)

    # Give services 10 seconds to shutdown
    print("Wait for services to shutdown...")
    sleep(10)

    # When a new machine is used, (un-)assign labels
    if new_machine:
        remove_label_from_nodes('building', building, manager)
        assign_label_to_node(new_machine, 'building', building, manager)
        print("Wait for services to start on new machine")
        sleep(10)
        run_command_in_service('backup', 'restore', new_machine)
    else:
        # execute restore command in backup service
        run_command_in_service('backup', 'restore', manager)

    # reload and scale up services again
    for s in services:
        s.reload()
        s.scale(1)

    # close client
    client.close()
# >>>


# ******************************
# CLI base commands <<<
# ******************************
def init_config_dirs_command(args):
    """Initialize config directories

    :args: parsed commandline arguments
    """
    # generate basic config folder
    generate_config_folders()


def assign_building_command(args):
    """Assigns the role of a building to a node

    :args: parsed commandline arguments
    """
    node = args.node
    building = args.building

    print(f'Assign role of building {building} to node {node}')

    assign_label_to_node(node, 'building', building)


def execute_command(args):
    """Top level function to manage command executions from CLI

    :args: parsed commandline arguments
    """
    service = args.service
    command = " ".join(str(x) for x in args.command)  # list to string
    building = args.building

    run_command_in_service(service, command, building)


def restore_command(args):
    """Top level function to manage command executions from CLI

    :args: parsed commandline arguments
    """
    building = args.building
    target = args.target

    if not check_machine_exists(target):
        print(f'Machine with name {target} not found')
        return

    print(f'Restoring building {building} on machine {target}')

    get_machine_env(target)


def interactive_command(args):
    """Top level function to start the interactive mode

    :args: parsed command line arguments
    """
    main_menu(args)


# >>>


# ******************************
# Interactive menu entries <<<
# ******************************
def main_menu(args):
    """ Display main menu
    """
    # Main menu prompts selection contains function
    choice = qust.select('Public Building Manager - Main Menu',
                         choices=load_main_entires(), style=st).ask()

    # Call funtion of menu entry
    choice(args)


def load_main_entires():
    """Loads entries for main menu depending on available files

    :returns: entries of main menu
    """

    entries = []
    if not os.path.exists(custom_path):
        entries.append({'name': 'Create initial structure',
                        'value': init_menu})
    else:
        entries.append({'name': 'Manage Services',
                        'value': service_menu})
        entries.append({'name': 'Manage Users',
                        'value': user_menu})
        entries.append({'name': 'Manage Devices',
                        'value': device_menu})
        entries.append({'name': 'Manage Backups',
                        'value': backup_menu})
        entries.append({'name': 'Execute a command in a service container',
                        'value': exec_menu})

    entries.append({'name': 'Exit', 'value': sys.exit})

    return entries


def exit_menu(args):
    """Exits the programm
    """
    sys.exit()


# *** Init Menu Entries ***
def init_menu(args):
    """Menu entry for initial setup and file generation

    :args: Passed commandline arguments
    """
    # Prompts
    stack_name = qust.text('Choose a name for your setup', style=st).ask()
    hosts = qust.checkbox('What docker machines will be used?',
                          choices=generate_cb_choices(
                              get_machine_list()), style=st).ask()
    # Ensure passwords match
    password_match = False
    while not password_match:
        password = qust.password(
            'Choose a password for the ohadmin user:', style=st).ask()
        confirm = qust.password(
            'Repeat password for the ohadmin user:', style=st).ask()
        if password == confirm:
            password_match = True
        else:
            print("Passwords did not match, try again")

    # Initialize custom configuration dirs and templates
    generate_config_folders()
    generate_initial_compose()
    # Generate config files based on input
    username = ADMIN_USER
    generate_sftp_file(username, password, ['backup_data/backup'])
    generate_postgres_files(username, password)
    generate_mosquitto_file(username, password)
    generate_traefik_file(username, password)
    generate_filebrowser_file(username, password)
    generate_id_rsa_files()

    frames = []
    for i, host in enumerate(hosts):
        building_id, building_name, services = init_machine_menu(host, i)
        frames.append({'host': host,
                       'building_id': building_id,
                       'building_name': building_name,
                       'services': services})

    # When frames is not empty generate frame config
    if frames:
        generate_pb_framr_file(frames)
        generate_volumerize_files(frames)
        building_ids = [f['building_id'] for f in frames]
        generate_host_key_files(building_ids)

    # print(answers)
    print(f"Configuration files for {stack_name} generated in {custom_path}")

    # Check if changes shall be applied to docker environment
    generate = qust.confirm(
        'Apply changes to docker environment?', default=True, style=st).ask()

    if generate:
        generate_swarm(hosts)


def init_machine_menu(host, increment):
    """Prompts to select server services

    :host: docker-machine host
    :increment: incrementing number to ensure ports are unique
    :return: choosen building id, name and services
    """
    # Print divider
    print('----------')
    # Prompt for services
    building_id = qust.text(
        f'Choose an identifier for the building on server {host} '
        '(lowercase no space)',
        default=f'{host}', style=st).ask()
    building = qust.text(
        f'Choose a display name for building on server {host}',
        default=f'{host.capitalize()}', style=st).ask()
    services = qust.checkbox(f'What services shall {host} provide?',
                             choices=generate_cb_service_choices(checked=True),
                             style=st).ask()
    if Service.OPENHAB in services:
        add_openhab_service(building_id, host)
    if Service.NODERED in services:
        add_nodered_service(building_id)
    if Service.MQTT in services:
        add_mqtt_service(building_id, increment)
    if Service.POSTGRES in services:
        add_postgres_service(building_id)
    if Service.BACKUP in services:
        add_volumerize_service(building_id)
    if Service.FILES in services:
        add_file_service(building_id)
    if Service.SFTP in services:
        add_sftp_service(building_id, increment)
    return building_id, building, services


# *** Exec Menu Entries ***
def exec_menu(args):
    """Menu entry for executing commands in services

    :args: Passed commandline arguments
    """
    machine = docker_client_prompt(" to execute command at")
    service_name = qust.select(
        'Which service container shall execute the command?',
        choices=get_container_list(machine), style=st).ask()
    command = qust.text('What command should be executed?', style=st).ask()

    run_command_in_service(service_name, command, machine)


# *** User Menu Entries ***
def user_menu(args):
    """Menu entry for user managment

    :args: Passed commandline arguments
    """
    # Ask for action
    choice = qust.select("What do you want to do?", choices=[
        'Add a new user', 'Modify existing user', 'Exit'],
        style=st).ask()
    if "Add" in choice:
        new_user_menu()
    elif "Modify" in choice:
        modify_user_menu()


def new_user_menu():
    """Menu entry for new users
    """
    current_users = get_users_from_files()
    new_user = False
    while not new_user:
        username = qust.text("Choose a new username:", style=st).ask()
        if username not in current_users:
            new_user = True
        else:
            print(f"User with name {username} already exists, try again")

    # Ensure passwords match
    password_match = False
    while not password_match:
        password = qust.password(
            f'Choose a password for the user {username}:', style=st).ask()
        confirm = qust.password(
            f'Repeat password for the user {username}:', style=st).ask()
        if password == confirm:
            password_match = True
        else:
            print("Passwords did not match, try again")

    add_user_to_traefik_file(username, password)


def modify_user_menu():
    """Menu entry to remove users or change passwords
    """
    current_users = get_users_from_files()
    user = qust.select("Choose user to modify:",
                       choices=current_users, style=st).ask()

    if user == 'ohadmin':
        choices = [{'name': 'Delete user',
                    'disabled': 'Disabled: cannot delete admin user'},
                   'Change password', 'Exit']
    else:
        choices = ['Delete user', 'Change password', 'Exit']

    action = qust.select(
        f"What should we do with {user}?", choices=choices, style=st).ask()

    if 'Delete' in action:
        is_sure = qust.confirm(
            f"Are you sure you want to delete user {user}?", style=st).ask()
        if is_sure:
            remove_user_from_traefik_file(user)
    elif 'Change' in action:
        password_match = False
        while not password_match:
            password = qust.password(
                f'Choose a password for the user {user}:', style=st).ask()
            confirm = qust.password(
                f'Repeat password for the user {user}:', style=st).ask()
            if password == confirm:
                password_match = True
            else:
                print("Passwords did not match, try again")
        add_user_to_traefik_file(user, password)


# *** Service Menu Entries ***
def service_menu(args):
    """Menu entry for service managment

    :args: Passed commandline arguments
    """
    # Ask for action
    choice = qust.select("What do you want to do?", choices=[
        'Re-/Start docker stack', 'Stop docker stack',
        'Modify existing services', 'Add additional service',
        'Exit'], style=st).ask()
    if "Add" in choice:
        service_add_menu()
    elif "Modify" in choice:
        service_modify_menu()
    elif "Start" in choice:
        machine = docker_client_prompt(" to execute deploy")
        deploy_docker_stack(machine)
    elif "Stop" in choice:
        machine = docker_client_prompt(" to execute remove")
        remove_docker_stack(machine)


def service_add_menu():
    """Menu to add additional services
    """
    services = [s for s in Service if s.additional]
    service = qust.select(
        'What service do you want to add?', style=st,
        choices=generate_cb_service_choices(service_list=services)).ask()

    host = qust.select('Where should the service be located?',
                       choices=generate_cb_choices(
                           get_machine_list()), style=st).ask()
    identifier = qust.text(
        'Input an all lower case identifier:', style=st).ask()

    if service and host and identifier:
        if service == Service.POSTGRES:
            add_postgres_service(host, postfix=identifier)


def service_modify_menu():
    """Menu to modify services
    """
    services = get_current_services()
    service = qust.select(
        'What service do you want to modify?', choices=services).ask()

    if service in ['proxy', 'landing']:
        choices = [{'name': 'Remove service',
                    'disabled': 'Disabled: cannot remove framework services'},
                   'Exit']
    else:
        choices = ['Remove service', 'Exit']

    action = qust.select(
        f"What should we do with {service}?", choices=choices, style=st).ask()

    if 'Remove' in action:
        delete_service(service)


# *** Device Menu Functions ***
def device_menu(args):
    """Menu to manage devices

    :args: Arguments form commandline
    """
    # Check if device scripts are installed
    bin_path = '/usr/bin/enable-swarm-device'

    choices = ['Install device scripts']
    if os.path.exists(bin_path):
        choices.append('Link device to service')
        choices.append('Unlink device')

    choices.append('Exit')

    # Ask for action
    choice = qust.select("What do you want to do? (root required)",
                         choices=choices, style=st).ask()
    if "Install" in choice:
        print("Installing device scripts (needs root)")
        device_install_menu()
    elif "Link" in choice:
        device_link_menu()
    elif "Unlink" in choice:
        device_unlink_menu()


def device_install_menu():
    """Install scripts to link devices
    """
    machine = docker_client_prompt(" to install usb support")

    # Name of base dir on machines
    external_base_dir = os.path.basename(base_dir)

    # Check if files are available on targeted machine
    machine_dir = f"{external_base_dir}/install-usb-support.sh"
    print(machine_dir)
    if not check_file_on_machine(machine_dir, machine):
        print("Scripts missing on machine, will be copied")
        copy_files_to_machine(base_dir, machine)
    else:
        print("Scripts available on machine")

    execute_command_on_machine(f'sudo {machine_dir}', machine)


def device_link_menu():
    """Link device to a service
    """
    machine = docker_client_prompt(" to link device on")
    device = qust.select("What device should be linked?",
                         choices=USB_DEVICES, style=st).ask()

    # Start systemd service that ensures link (escapes of backslash needed)
    link_cmd = f"sudo systemctl enable --now swarm-device@" + \
        f"{device}\\\\\\\\x20openhab.service"

    # Needs enable to keep after reboot
    execute_command_on_machine(link_cmd, machine)
    print(f"Linked device {device} to openHAB service on machine {machine}")


def device_unlink_menu():
    """Unlink a device from a service
    """
    machine = docker_client_prompt(" to unlink device from")
    device = qust.select("What device should be unlinked?",
                         choices=USB_DEVICES, style=st).ask()

    # Stop systemd service that ensures link (escapes of backslash needed)
    link_cmd = f"sudo systemctl disable --now swarm-device@" + \
        f"{device}\\\\\\\\x20openhab.service"

    execute_command_on_machine(link_cmd, machine)
    print(f"Unlinked device {device} on machine {machine}")


# *** Backup Menu Entries ***
def backup_menu(args):
    """Menu entry for backup managment

    :args: Passed commandline arguments
    """
    # Ask for action
    choice = qust.select("What do you want to do?", choices=[
        'Execute backup', 'Restore backup', 'Move building', 'Exit'],
        style=st).ask()
    if "Execute" in choice:
        execute_backup_menu()
    elif "Restore" in choice:
        restore_backup_menu()
        print("Restore")
    elif "Move" in choice:
        restore_new_building_menu()
        print("Move")


def execute_backup_menu():
    """Submenu for backup execution
    """
    machine = docker_client_prompt(" to backup")

    full = qust.confirm("Execute full backup (otherwise partial)?",
                        default=False, style=st).ask()
    if full:
        run_command_in_service('backup', 'backupFull', machine)
        print("Full backup completed")
    else:
        run_command_in_service('backup', 'backup', machine)
        print("Partial backup completed")


def restore_backup_menu():
    """Submenu for backup execution
    """
    machine = docker_client_prompt(" to restore")

    confirm = qust.confirm(
        f'Restore services from last backup on machine {machine} '
        '(current data will be lost)?',
        default=False,
        style=st).ask()

    if confirm:
        restore_building_backup(machine, machine)
        print("Restore completed")
    else:
        print("Restore canceled")


def restore_new_building_menu():
    """Submenu for backup execution on a new building
    """
    machine = docker_client_prompt(" to execute restores with.")
    current_building = compose_building_prompt(" to move")
    new_machine = docker_client_prompt(" to move building to")
    confirm = qust.confirm(
        f'Recreate {current_building} from last backup'
        f' on machine {new_machine}',
        default=False,
        style=st).ask()

    if confirm:
        restore_building_backup(machine, current_building, new_machine)
        print("Restore completed")
    else:
        print("Restore canceled")


# *** Menu Helper Functions ***
def generate_cb_choices(list, checked=False):
    """Generates checkbox entries for lists of strings

    :list: pyhton list that shall be converted
    :checked: if true, selections will be checked by default
    :returns: A list of dicts with name keys
    """
    return [{'name': m, 'checked': checked} for m in list]


def generate_cb_service_choices(checked=False, service_list=None):
    """Generates checkbox entries for the sevice enum

    :checked: if true, selections will be checked by default
    :service_list: optional list of services, use all if empty
    :returns: A list of dicts with name keys
    """
    services = service_list if service_list is not None else Service
    return [
        {'name': s.fullname, 'value': s, 'checked': checked} for s in services
    ]


def docker_client_prompt(message_details=''):
    """Show list of docker machines and return selection

    :manager: Optional machine to use, prompt otherwise
    :returns: Docker client instance
    """
    machine = qust.select(f'Choose manager machine{message_details}',
                          choices=get_machine_list(), style=st).ask()
    return machine


def compose_building_prompt(message_details=''):
    """Show list of building contraints used in compose

    :returns: Docker client instance
    """
    building = qust.select(f'Choose building{message_details}:',
                           choices=get_current_building_constraints(),
                           style=st).ask()
    return building
# >>>


# ******************************
# Script main (entry) <<<
# ******************************
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        prog='building_manager',
        description='Generate and manage multi'
        'building configurations of openHAB with docker swarm')
    parser.add_argument(
        '--config_dir',
        '-d',
        help='Directory to creat config folders in, default is current dir')
    subparsers = parser.add_subparsers()

    # Interactive mode
    parser_interactive = subparsers.add_parser(
        'interactive',
        help='Starts the interactive mode of the building manager')
    parser_interactive.set_defaults(func=interactive_command)

    # Restore command
    parser_restore = subparsers.add_parser('restore', help='Restore backups')
    parser_restore.add_argument(
        'building', help='Name (label) of the building that shall be restored')
    parser_restore.add_argument(
        'target', help='Name of the machine to restore to')
    parser_restore.set_defaults(func=restore_command)

    # Assign building command
    parser_assign_building = subparsers.add_parser(
        'assign_building', help='Assign the role of a building to a node')
    parser_assign_building.add_argument(
        'node', help='Name (or ID) of the node that gets the role assigned')
    parser_assign_building.add_argument(
        'building', help='Name of the building that will be assigned')
    parser_assign_building.set_defaults(func=assign_building_command)

    # Execute command
    parser_exec = subparsers.add_parser(
        'exec', help='Execute commands in a service container')
    parser_exec.add_argument(
        'service', help='Name of the service that will run the command')
    parser_exec.add_argument(
        'command', help='Command to be executed', nargs=argparse.REMAINDER)
    parser_exec.add_argument(
        '--building',
        '-b',
        help='Building name (label) of the service if '
        'service location is ambiguous')
    parser_exec.set_defaults(func=execute_command)

    # Config commands
    parser_config = subparsers.add_parser(
        'config', help='Manage configuration files')
    parser_config_subs = parser_config.add_subparsers()
    # - Config init
    parser_config_init = parser_config_subs.add_parser(
        'init', help='Initialize config file directories')
    parser_config_init.set_defaults(func=init_config_dirs_command)

    # Parse arguments into args dict
    args = parser.parse_args()

    # Check if custom config dir is used
    if args.config_dir:
        custom_path = args.config_dir

    # when no subcommand is defined show interactive menu
    try:
        args.func(args)
    except AttributeError:
        interactive_command(args)
# >>>

# --- vim settings ---
# vim:foldmethod=marker:foldlevel=0:foldmarker=<<<,>>>
