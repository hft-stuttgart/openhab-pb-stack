#!/usr/bin/env python
import docker


def run_command_in_service(service, command, building=None):
    """Runs a command in a service based on its name.
    When no matching container is found or the service name is ambigous
    an error will be displayed and the function exits

    :param service: Name of the service to execute command
    :param command: Command to execute
    :param building: Optional building, make service unambigous (Default: None)
    """

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
    pass


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
        'building_name',
        help='Name (label) of the building that shall be restored')
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
