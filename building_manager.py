#!/usr/bin/env python
import docker


# Docker machine commands
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


# CLI base commands and main
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

    args = parser.parse_args()
    args.func(args)
