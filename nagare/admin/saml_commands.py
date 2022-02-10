# --
# Copyright (c) 2008-2022 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare.admin import command
from nagare.services.security import saml_auth


class Commands(command.Commands):
    DESC = 'SAML authentication subcommands'


class Metadata(command.Command):
    DESC = 'display SP metadata'

    def set_arguments(self, parser):
        super(Metadata, self).set_arguments(parser)
        parser.add_argument('-n', '--name', help='name of the SAML service')

    @staticmethod
    def run(name, services_service):
        status = 0

        if name:
            saml_service_name = name.strip('/').split('/')
        else:

            def to_names(services):
                for service, children in services:
                    name = (service.name,)

                    if not children:
                        yield name
                    else:
                        for e in to_names(children):
                            yield name + tuple(e)

            saml_services = services_service.find_services(lambda service: isinstance(service, saml_auth.Authentication))
            names = list(to_names(saml_services))
            if not names:
                print('No SAML service found')
                return 1

            if len(names) > 1:
                names = ['/'.join(name) for name in names]
                print('Several SAML service found:', ', '.join(names))
                print('Select one with the `-n` option')
                return 1

            saml_service_name = names[0]

        try:
            saml_service = services_service.get_service(saml_service_name)
        except KeyError:
            print('SAML service {} not found'.format(repr(name)))
            return 1

        errors, metadata = saml_service.get_sp_metadata()

        if errors:
            print('Validation errors: ' + ', '.join(errors))
            status = 1
        else:
            if isinstance(metadata, bytes):
                metadata = metadata.decode('utf-8')

            print(metadata)

        return status
