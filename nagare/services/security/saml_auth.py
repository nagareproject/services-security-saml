# Encoding: utf-8

# --
# Copyright (c) 2008-2021 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import os
import re
import copy
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode

from jwcrypto import jwk
from python_jwt import generate_jwt, verify_jwt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from nagare import partial
from nagare.renderers import xml
from nagare.services.security import cookie_auth


class Log(xml.Component):
    ACTION_PRIORITY = 5

    def __init__(self, renderer, create_redirection_url):
        self.renderer = renderer
        self.create_redirection_url = create_redirection_url

        self._action = None
        self.with_request = False
        self.args = ()
        self.kw = {}

    @partial.max_number_of_args(2)
    def action(self, action, args, with_request=False, **kw):
        self._action = action
        self.with_request = with_request
        self.args = args
        self.kw = kw

        return self

    def set_sync_action(self, action_id, params):
        pass

    def render(self, h):
        if self._action is not None:
            action_id, _ = self.renderer.register_callback(
                self,
                self.ACTION_PRIORITY,
                self._action,
                self.with_request, *self.args, **self.kw
            )
        else:
            action_id = None

        response = h.response
        response.status_code = 307
        response.headers['Location'] = self.create_redirection_url(h.session_id, h.state_id, action_id)

        return response


def config_to_settings(d):
    r = {}

    for k, v in d.items():
        if v is None:
            continue

        if isinstance(v, dict):
            v = config_to_settings(v)
            if not v:
                continue

        k = re.sub('_([a-z])', lambda m: m.group(1).upper(), k)

        r[k] = v

    return r


class Authentication(cookie_auth.Authentication):
    LOAD_PRIORITY = cookie_auth.Authentication.LOAD_PRIORITY + 1

    CONFIG_SPEC = dict(
        copy.deepcopy(cookie_auth.Authentication.CONFIG_SPEC),
        principal_attribute='string',
        key='string(default=None, help="cookie encoding key")',
        certs_directory='string(default="$data")',

        strict='boolean(default=True)',
        debug='boolean(default=False)',

        sp={
            'entity_id': 'string',
            'assertion_consumer_service': {
                'url': 'string',
                'binding': 'string(default=None)'
            },
            'single_logout_service': {
                'url': 'string(default=None)',
                'binding': 'string(default=None)'

            },
            'attribute_consuming_service': {
                'service_name': 'string(default=None)',
                'service_description': 'string(default=None)'
            },
            'x509cert': 'string(default=None)',
            'private_key': 'string(default=None)'
        },

        idp={
            'metadata_url': 'string(default=None)',

            'entity_id': 'string(default=None)',
            'single_sign_on_service': {
                'url': 'string(default=None)',
                'binding': 'string(default=None)'
            },
            'single_logout_service': {
                'url': 'string(default=None)',
                'binding': 'string(default=None)'
            },
            'x509cert': 'string(default=None)',
            'cert_fingerprint': 'boolean(default=None)',
            'cert_fingerprint_algorithm': 'string(default=None)',
            'x509cert_multi': {
                'signing': 'string(default=None)',
                'encryption': 'string(default=None)'
            }
        },

        security={
            'want_name_id_encrypted': 'boolean(default=None)',
            'name_id_encrypted': 'boolean(default=None)',
            'want_assertions_signed': 'boolean(default=None)',
            'want_assertions_encrypted': 'boolean(default=None)',
            'want_messages_signed': 'boolean(default=None)',
            'authn_requests_signed': 'boolean(default=None)',
            'logout_request_signed': 'boolean(default=None)',
            'logout_response_signed': 'boolean(default=None)',
            'metadata_valid_until': 'string(default=None)',
            'metadata_cache_duration': 'integer(default=None)',
            'sign_metadata': {
                'key_file_name': 'string(default=None)',
                'cert_file_name': 'string(default=None)'
            }
        },

        contact_person={
            'technical': {
                'given_name': 'string(default=None)',
                'email_address': 'string(default=None)',
            },
            'support': {
                'given_name': 'string(default=None)',
                'email_address': 'string(default=None)',
            },
            'administrative': {
                'given_name': 'string(default=None)',
                'email_address': 'string(default=None)',
            },
            'billing': {
                'given_name': 'string(default=None)',
                'email_address': 'string(default=None)',
            },
            'other': {
                'given_name': 'string(default=None)',
                'email_address': 'string(default=None)',
            }
        },
        organization={
            '__many__': {
                'displayname': 'string(default=None)',
                'url': 'string(default=None)'
            }
        }
    )
    CONFIG_SPEC['cookie']['activated'] = 'boolean(default=False)'
    CONFIG_SPEC['cookie']['encrypt'] = 'boolean(default=False)'

    def __init__(
            self,
            name, dist,
            principal_attribute, key, certs_directory,
            services_service,
            **config
    ):
        services_service(
            super(Authentication, self).__init__,
            name, dist,
            principal_attribute=principal_attribute, key=key, certs_directory=certs_directory,
            **config
        )

        self.principal_attribute = principal_attribute
        self.key = key or urlsafe_b64encode(os.urandom(32)).decode('ascii')
        self.iv = modes.CBC(os.urandom(16))
        self.jwk_key = jwk.JWK(kty='oct', k=key)
        self.certs_directory = certs_directory

        config = config_to_settings(config)
        organization = config.get('organization')
        if organization:
            config['organization'] = {k: dict(name=k, **v) for k, v in organization.items()}

        self.config = config
        self.ident = str(random.randint(10000000, 99999999))

    @property
    def cipher(self):
        return Cipher(algorithms.AES(urlsafe_b64decode(self.key)), self.iv)

    @staticmethod
    def create_request(request):
        scheme, host, port = request.scheme_hostname_port
        if port and ((scheme == 'http' and port != 80) or (scheme == 'https' and port != 443)):
            host += ':' + str(port)

        return {
            'https': 'on' if scheme == 'https' else 'off',
            'http_host': host,
            'script_name': request.script_name,
            'path_info': request.path_info,
            'post_data': request.params
        }

    @staticmethod
    def filter_credentials(credentials, to_keep):
        return {k: v for k, v in credentials.items() if k in to_keep | {'_name_id', '_session_index'}}

    def store_credentials(self, session, credentials):
        if not self.cookie and session and credentials:
            session['nagare.credentials'] = self.filter_credentials(credentials, {self.principal_attribute})

    @staticmethod
    def extract_credentials(auth):
        return auth.get_friendlyname_attributes()

    def normalize_credentials(self, credentials):
        credentials = {k: (v[0] if len(v) == 1 else v) for k, v in credentials.items()}

        return credentials[self.principal_attribute], credentials

    def get_sp_metadata(self):
        config = OneLogin_Saml2_Settings(self.config, self.certs_directory, sp_validation_only=True)
        metadata = config.get_sp_metadata()
        errors = config.validate_metadata(metadata)

        return errors, metadata

    def handle_start(self, _, saml_listener_service):
        saml_listener_service.register_service(self.ident, self)

        metadata_url = self.config.get('idp', {}).get('metadataUrl')
        if metadata_url:
            idp = OneLogin_Saml2_IdPMetadataParser().parse_remote(metadata_url).get('idp', {})
            self.config['idp'] = idp

    def to_cookie(self, **credentials):
        credentials = self.filter_credentials(credentials, {self.principal_attribute})

        if self.encrypted:
            cookie = super(Authentication, self).to_cookie(credentials.pop(self.principal_attribute), **credentials)
        else:
            cookie = generate_jwt(credentials, self.jwk_key, 'HS256')

        return cookie

    def from_cookie(self, cookie, max_age):
        if self.encrypted:
            principal, credentials = super(Authentication, self).from_cookie(cookie, max_age)
            credentials[self.principal_attribute] = principal
        else:
            _, credentials = verify_jwt(cookie.decode('ascii'), self.jwk_key, ['HS256'], checks_optional=True)
            credentials = self.filter_credentials(credentials, {self.principal_attribute})

        return credentials.get(self.principal_attribute), credentials

    def retrieve_credentials(self, session):
        if self.cookie or not session:
            return None, {}

        credentials = session.get('nagare.credentials', {})
        return credentials.get(self.principal_attribute), credentials

    def create_state(self, type_, session_id, state_id, action_id):
        encryptor = self.cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        state = b'%d#%d#%s' % (session_id, state_id, (action_id or '').encode('ascii'))
        state = padder.update(state) + padder.finalize()
        state = encryptor.update(state) + encryptor.finalize()
        state = '#{}#{}{}'.format(self.ident, type_, urlsafe_b64encode(state).decode('ascii'))

        return state

    def create_login_request(self, session_id, state_id, action_id):
        state = self.create_state(1, session_id, state_id, action_id)
        return OneLogin_Saml2_Auth({}, self.config, self.certs_directory).login(state)

    def create_logout_request(self, name_id, session_index, session_id, state_id, action_id):
        state = self.create_state(0, session_id, state_id, action_id)
        return OneLogin_Saml2_Auth({}, self.config, self.certs_directory).logout(state)  # name_id=name_id, session_index=session_index)

    def is_auth_response(self, request):
        is_valid_response = False
        session_id, state_id, login, action_id = 0, 0, True, ''

        code = request.params.get('SAMLResponse')
        state = request.params.get('RelayState', '')

        if code and state.startswith('#'):
            try:
                state = state.rsplit('#', 1)[1]
                login = state[0] == '1'

                decryptor = self.cipher.decryptor()
                unpadder = padding.PKCS7(128).unpadder()

                state = decryptor.update(urlsafe_b64decode(state[1:])) + decryptor.finalize()
                state = unpadder.update(state) + unpadder.finalize()

                session_id, state_id, action_id = state.decode('ascii').split('#')
                is_valid_response = True
            except Exception as e:
                self.logger.error('Invalid SAML response state: ' + str(e))

        return is_valid_response, int(session_id), int(state_id), login, action_id

    def process_login_response(self, request):
        redirect = False
        principal = None
        credentials = {}

        auth = OneLogin_Saml2_Auth(self.create_request(request), self.config, self.certs_directory)
        auth.process_response()

        if auth.get_errors() or not auth.is_authenticated:
            self.logger.error('SAML error: ' + ','.join(auth.get_errors()))
        else:
            credentials = self.extract_credentials(auth)
            if not credentials:
                self.logger.error('SAML error: no credentials ' + ' ,'.join(auth.get_errors()))
            else:
                principal, credentials = self.normalize_credentials(credentials)
                # credentials['_session_index'] = auth.get_session_index()
                # credentials['_name_id'] = auth.get_nameid()
                redirect = True

        return redirect, principal, credentials

    def process_logout_response(self, request):
        scheme, host, port = request.scheme_hostname_port
        if (scheme == 'http' and port != 80) or (scheme == 'https' and port != 443):
            host += ':' + str(port)

        auth = OneLogin_Saml2_Auth(self.create_request(request), self.config, self.certs_directory)
        auth.process_slo()

        error = auth.get_errors()
        if error:
            self.logger.error('SAML logout error: ' + ','.errors)

        return True

    def get_principal(self, request, response, session, session_id, state_id, **params):
        credentials = {}
        principal = None
        new_response = None

        code, _, _, login, action_id = self.is_auth_response(request)

        if code:
            if login:
                redirect, principal, credentials = self.process_login_response(request)
                self.store_credentials(session, credentials)
            else:
                redirect = self.process_logout_response(request)

            if redirect:
                new_response = request.create_redirect_response(
                    response=response,
                    _s=session_id,
                    _c='%05d' % state_id
                )
        else:
            principal, credentials = self.retrieve_credentials(session)
            if not principal:
                principal, credentials, r = super(Authentication, self).get_principal(
                    request=request, response=response,
                    **params
                )

        if action_id:
            request.environ['QUERY_STRING'] = action_id + '='

        return principal, credentials, new_response

    def login(self, h):
        return Log(h, self.create_login_request)

    def logout(self, h, location='', delete_session=True, user=None):
        user = super(Authentication, self).logout(location, delete_session, user)

        name_id = user.credentials.get('_name_id') if user else None
        session = user.credentials.get('_session_index') if user else None

        return Log(h, partial.Partial(self.create_logout_request, name_id, session))
