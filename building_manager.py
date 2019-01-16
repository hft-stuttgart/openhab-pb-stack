#!/usr/bin/env python
import docker
import logging
import os

from shutil import copy2
from subprocess import run
from PyInquirer import prompt

# Log level during development is info
logging.basicConfig(level=logging.WARNING)

# Directories for config generation
CUSTOM_DIR = 'custom_configs'
TEMPLATE_DIR = 'template_configs'
CONFIG_DIRS = ['mosquitto', 'nodered', 'ssh', 'traefik', 'volumerize']
TEMPLATE_FILES = [
    'mosquitto/mosquitto.conf', 'nodered/nodered_package.json',
    'nodered/nodered_settings.js', 'ssh/sshd_config', 'traefik/traefik.toml'
]

# Default Swarm port
SWARM_PORT = 2377


# ******************************
# Config file functions {{{
# ******************************
def generate_config_folders(base_dir):
    """Generate folders for configuration files

    :base_dir: Path to add folders to
    """
    base_path = base_dir + '/' + CUSTOM_DIR
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    print(f'Initialize configuration in {base_path}')

    for d in CONFIG_DIRS:
        new_dir = base_path + '/' + d
        if not os.path.exists(new_dir):
            os.makedirs(new_dir)


def copy_template_config(base_dir, config_path):
    """Copies template configuration files into custom folder

    :base_dir: path that contains template and custom folders
    :config_path: relative path of config to copy from template
    """
    custom_path = base_dir + '/' + CUSTOM_DIR + "/" + config_path
    template_path = base_dir + '/' + TEMPLATE_DIR + "/" + config_path

    logging.info(f'Copy {config_path} from {custom_path} to {template_path}')
    copy2(template_path, custom_path)


def generate_mosquitto_user_line(username, password):
    """Generates a line for a mosquitto user with a crypt hashed password

    :username: username to use
    :password: password that will be hashed (SHA512)
    :returns: a line as expected by mosquitto

    """
    import crypt
    password_hash = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    line = f"{username}:{password_hash}"
    return line


# }}}


# ******************************
# Docker machine functions {{{
# ******************************
def get_machine_list():
    """Get a list of docker machine names using the docker-machine system command

    :returns: a list of machine names managed by docker-machine
    """
    machine_result = run(['docker-machine', 'ls', '-q'],
                         text=True,
                         capture_output=True)
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
                     text=True,
                     capture_output=True)

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
                         text=True,
                         capture_output=True)
    return machine_result.stdout.strip()


def init_swarm_machine(machine_name):
    """Creates a new swarm with the specified machine as leader

    :machine_name: Name of the machine to use for init
    :return: True if swarm init was successful
    """
    machine_ip = get_machine_ip(machine_name)
    init_command = 'docker swarm init --advertise-addr ' + machine_ip
    init_result = run(['docker-machine', 'ssh', machine_name, init_command],
                      text=True,
                      capture_output=True)
    return init_result.returncode == 0


def join_swarm_machine(machine_name, leader_name):
    """Joins the swarm of the specified leader

    :machine_name: Name of the machine to join a swarm
    :leader_name: Name of the swarm leader machine
    :return: True if join to swarm was successful
    """
    token_command = 'docker swarm join-token manager -q'
    token_result = run(['docker-machine', 'ssh', leader_name, token_command],
                       text=True,
                       capture_output=True)
    token = token_result.stdout.strip()
    leader_ip = get_machine_ip(leader_name)
    logging.info(f"Swarm leader with ip {leader_ip} uses token {token}")

    join_cmd = f'docker swarm join --token {token} {leader_ip}:{SWARM_PORT}'
    logging.info(f'Machine {machine_name} joins using command {join_cmd}')
    join_result = run(['docker-machine', 'ssh', machine_name, join_cmd],
                      text=True,
                      capture_output=True)

    return join_result.returncode == 0


# }}}


# ******************************
# Docker client commands {{{
# ******************************
def assign_label_to_node(nodeid, label, value):
    """Assigns a label to a node (e.g. building)

    :nodeid: Id or name of the node
    :label: Label you want to add
    :value: The value to assign to the label
    """
    client = docker.from_env()

    node = client.nodes.get(nodeid)
    spec = node.attrs['Spec']
    spec['Labels'][label] = value
    node.update(spec)

    client.close()


def run_command_in_service(service, command, building=None):
    """Runs a command in a service based on its name.
    When no matching container is found or the service name is ambigous
    an error will be displayed and the function exits

    :param service: Name of the service to execute command
    :param command: Command to execute
    :param building: Optional building, make service unambigous (Default: None)
    """

    if building:
        building_env = get_machine_env(building)
        client = docker.from_env(environment=building_env)
    else:
        client = docker.from_env()

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
              f'({service_container.id}) on building {building}')
        print(service_container.exec_run(command))
    client.close()


# }}}


# ******************************
# CLI base commands {{{
# ******************************
def init_config_dirs_command(args):
    """Initialize config directories

    :args: parsed commandline arguments
    """
    base_dir = args.base_dir

    if base_dir is None:
        base_dir = os.getcwd()

    # generate basic config folder
    generate_config_folders(base_dir)

    # copy template configs
    for template_file in TEMPLATE_FILES:
        copy_template_config(base_dir, template_file)


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

    :args: command line arguments
    """
    print(main_menu())


# }}}


# ******************************
# Interactive menu entries {{{
# ******************************
def main_menu():
    """ Display main menu
    """
    questions = [{
        'type':
        'list',
        'name':
        'main',
        'message':
        'Public Building Manager - Main Menu',
        'choices': ['Create initial structure', 'Execute command', 'Exit']
    }]
    answers = prompt(questions)

    if 'Create' in answers['main']:
        init_menu()

    return answers


def init_menu():
    """Menu entry for initial setup and file generation
    """
    questions = [{
        'type': 'input',
        'name': 'stack_name',
        'message': 'Choose a name for your setup'
    },
                 {
                     'type': 'checkbox',
                     'name': 'machines',
                     'message': 'What docker machines will be used?',
                     'choices': generate_checkbox_choices(get_machine_list())
                 },
                 {
                     'type': 'input',
                     'name': 'username',
                     'message': 'Choose a username for the initial user'
                 },
                 {
                     'type': 'password',
                     'name': 'password',
                     'message': 'Choose a password for the initial user'
                 }]
    answers = prompt(questions)

    leader = None

    for machine in answers['machines']:
        # init swarm with first machine
        if leader is None:
            leader = machine
            print(f'Create initial swarm with leader {leader}')
            if init_swarm_machine(leader):
                print('Swarm init successful\n')
        else:
            print(f'Machine {machine} joins swarm of leader {leader}')
            if (join_swarm_machine(machine, leader)):
                print('Joining swarm successful\n')

    user_line = generate_mosquitto_user_line(answers['username'],
                                             answers['password'])
    print(user_line)
    print(answers)


def generate_checkbox_choices(list):
    """Generates checkbox entries for lists of strings

    :returns: A list of dicts with name keys
    """
    return [{'name': m} for m in list]


# }}}

# ******************************
# Script main (entry) {{{
# ******************************
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        prog='building_manger',
        description='Generate and manage multi'
        'building configurations of openHAB with docker swarm')
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
    parser_config_init.add_argument(
        '--base_dir',
        '-d',
        help='Directory to creat config folders in, default is current dir')
    parser_config_init.set_defaults(func=init_config_dirs_command)

    args = parser.parse_args()
    args.func(args)
# }}}

# --- vim settings ---
# vim:foldmethod=marker:foldlevel=0
