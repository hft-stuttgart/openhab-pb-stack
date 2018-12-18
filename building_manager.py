#!/usr/bin/env python
import docker
import os

# Directories for config generation
CONFIG_DIRS = [
    'influxdb', 'mosquitto', 'nodered', 'ssh', 'treafik', 'volumerize'
]


# Config file functions
def generate_config_folders(base_path):
    """Generate folders for configuration files

    :base_path: Path to add folders to
    """
    for d in CONFIG_DIRS:
        new_dir = base_path + '/' + d
        if not os.path.exists(new_dir):
            os.makedirs(new_dir)


# Docker machine functions
def get_machine_list():
    """Get a list of docker machine names using the docker-machine system command

    :returns: a list of machine names managed by docker-machine
    """
    from subprocess import run
    machine_result = run(['docker-machine', 'ls', '-q'],
                         text=True,
                         capture_output=True)
    return machine_result.stdout.splitlines()


def check_machine_exists(machine_name):
    """Checks weather a docker machine exists and is available

    :machine_name: Name of the machine to check
    :returns: TODO
    """
    machines = get_machine_list()

    return machine_name in machines


def get_machine_env(machine_name):
    """Gets dict of env settings from a machine

    :machine_name: Name of the machine to check
    :returns: Dict of env variables for this machine
    """
    from subprocess import run
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


# Docker client commands
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
        print('Found multiple containers matching service name, '
              'ensure service is unambigous')
    elif (len(containers) < 1):
        print(
            'Found no matching container for service name {}'.format(service))
    else:
        service_container = containers[0]
        print('Executing {} in container {} ({}) on building {}'.format(
            command, service_container.name, service_container.short_id,
            building))
        print(service_container.exec_run(command))
    client.close()


# CLI base commands and main
def init_config_dirs_command(args):
    """Initialize config directories

    :args: parsed commandline arguments
    """
    base_dir = args.base_dir

    if base_dir is None:
        current_dir = os.getcwd()
        base_dir = current_dir + '/custom_configs'
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

    print('Initialize configuration in {}'.format(base_dir))
    generate_config_folders(base_dir)


def assign_building_command(args):
    """Assigns the role of a building to a node

    :args: parsed commandline arguments
    """
    node = args.node
    building = args.building

    print('Assign role of building {} to node {}'.format(building, node))

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
        print('Machine with name {} not found'.format(target))
        return

    print('Restoring building {} on machine {}'.format(building, target))

    get_machine_env(target)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        prog='building_manger',
        description='Generate and manage multi'
        'building configurations of openHAB with docker swarm')
    subparsers = parser.add_subparsers()

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
