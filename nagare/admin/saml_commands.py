# --
# Copyright (c) 2008-2021 Net-ng.
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

    @staticmethod
    def run(services_service):
        status = 0

        for saml_service in services_service.values():
            if not isinstance(saml_service, saml_auth.Authentication):
                continue

            errors, metadata = saml_service.get_sp_metadata()

            if errors:
                print('Validation errors: ' + ', '.join(errors))
                status = 1
            else:
                if isinstance(metadata, bytes):
                    metadata = metadata.decode('utf-8')

                print(metadata)

        return status
