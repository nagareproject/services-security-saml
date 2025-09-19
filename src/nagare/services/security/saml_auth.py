# --
# Copyright (c) 2008-2025 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import os
import re
import copy
from base64 import urlsafe_b64decode, urlsafe_b64encode

from jose import jwk, jwt
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from nagare import partial
from nagare.security import fernet
from nagare.renderers import xml
from nagare.services.security import cookie_auth


class Log(xml.Renderable):
    ACTION_PRIORITY = 5

    def __init__(self, renderer, create_redirection_url):
        self.renderer = renderer
        self.create_redirection_url = create_redirection_url

        self._action = None
        self.with_request = False
        self.args = ()
        self.kw = {}
        self.action_id = None

    @partial.max_number_of_args(2)
    def action(self, action, args, with_request=False, **kw):
        self._action = action
        self.with_request = with_request
        self.args = args
        self.kw = kw

        return self

    def set_action(self, action_id, _):
        self.action_id = action_id

    def render(self, h):
        if self._action is not None:
            self.renderer.register_callback(
                self, self.ACTION_PRIORITY, self._action, self.with_request, *self.args, **self.kw
            )

        response = h.response
        response.status_code = 307
        response.headers['Location'] = self.create_redirection_url(h.session_id, h.state_id, self.action_id)

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
            'assertion_consumer_service': {'url': 'string', 'binding': 'string(default=None)'},
            'single_logout_service': {'url': 'string(default=None)', 'binding': 'string(default=None)'},
            'attribute_consuming_service': {
                'service_name': 'string(default=None)',
                'service_description': 'string(default=None)',
            },
            'x509cert': 'string(default=None)',
            'private_key': 'string(default=None)',
        },
        idp={
            'metadata_url': 'string(default=None)',
            'entity_id': 'string(default=None)',
            'single_sign_on_service': {'url': 'string(default=None)', 'binding': 'string(default=None)'},
            'single_logout_service': {'url': 'string(default=None)', 'binding': 'string(default=None)'},
            'x509cert': 'string(default=None)',
            'cert_fingerprint': 'boolean(default=None)',
            'cert_fingerprint_algorithm': 'string(default=None)',
            'x509cert_multi': {'signing': 'string(default=None)', 'encryption': 'string(default=None)'},
        },
        security={
            'want_name_id_encrypted': 'boolean(default=None)',
            'name_id_encrypted': 'boolean(default=None)',
            'want_assertions_signed': 'boolean(default=None)',
            'want_assertions_encrypted': 'boolean(default=None)',
            'want_messages_signed': 'boolean(default=None)',
            'requested_authn_context': 'boolean(default=None)',
            'authn_requests_signed': 'boolean(default=None)',
            'logout_request_signed': 'boolean(default=None)',
            'logout_response_signed': 'boolean(default=None)',
            'want_attribute_statement': 'boolean(default=None)',
            'allow_repeat_attribute_name': 'boolean(default=None)',
            'metadata_valid_until': 'string(default=None)',
            'metadata_cache_duration': 'integer(default=None)',
            'sign_metadata': {'key_file_name': 'string(default=None)', 'cert_file_name': 'string(default=None)'},
        },
        contact_person={
            'technical': {'given_name': 'string(default=None)', 'email_address': 'string(default=None)'},
            'support': {'given_name': 'string(default=None)', 'email_address': 'string(default=None)'},
            'administrative': {'given_name': 'string(default=None)', 'email_address': 'string(default=None)'},
            'billing': {'given_name': 'string(default=None)', 'email_address': 'string(default=None)'},
            'other': {'given_name': 'string(default=None)', 'email_address': 'string(default=None)'},
        },
        organization={'__many__': {'displayname': 'string(default=None)', 'url': 'string(default=None)'}},
    )
    CONFIG_SPEC['cookie']['activated'] = 'boolean(default=False)'
    CONFIG_SPEC['cookie']['encrypt'] = 'boolean(default=False)'

    def __init__(self, name, dist, principal_attribute, key, certs_directory, services_service, **config):
        services_service(
            super().__init__,
            name,
            dist,
            principal_attribute=principal_attribute,
            key=key,
            certs_directory=certs_directory,
            **config,
        )

        self.ident = name
        self.principal_attribute = principal_attribute
        key = urlsafe_b64decode(key) if key else os.urandom(32)
        self.jwk_key = jwk.construct(key, 'HS256')
        self.key = urlsafe_b64encode(key).decode('ascii')
        self.certs_directory = certs_directory

        config = config_to_settings(config)
        organization = config.get('organization')
        if organization:
            config['organization'] = {k: dict(name=k, **v) for k, v in organization.items()}

        self.config = config

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
            'post_data': request.params,
        }

    @staticmethod
    def filter_credentials(credentials, to_keep):
        return {k: v for k, v in credentials.items() if k in to_keep | {'_name_id', '_session_index'}}

    def store_credentials(self, session, credentials):
        if not self.cookie and session and credentials:
            session['nagare.credentials'] = self.filter_credentials(credentials, {self.principal_attribute})

    @staticmethod
    def extract_credentials(auth):
        return auth.get_friendlyname_attributes() or auth.get_attributes()

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
            self.config['idp'] = (
                OneLogin_Saml2_IdPMetadataParser()
                .parse_remote(metadata_url, headers={'User-Agent': 'Nagare security'})
                .get('idp', {})
            )

    def to_cookie(self, **credentials):
        credentials = self.filter_credentials(credentials, {self.principal_attribute})

        if self.encrypted:
            cookie = super().to_cookie(credentials.pop(self.principal_attribute), **credentials)
        else:
            cookie = jwt.encode(credentials, self.jwk_key, 'HS256')

        return cookie

    def from_cookie(self, cookie, max_age):
        if self.encrypted:
            principal, credentials = super().from_cookie(cookie, max_age)
            credentials[self.principal_attribute] = principal
        else:
            credentials = jwt.decode(cookie.decode('ascii'), self.jwk_key, 'HS256')
            credentials = self.filter_credentials(credentials, {self.principal_attribute})

        return credentials.get(self.principal_attribute), credentials

    def retrieve_credentials(self, session):
        if self.cookie or not session:
            return None, {}

        credentials = session.get('nagare.credentials', {})
        return credentials.get(self.principal_attribute), credentials

    def create_state(self, type_, session_id, state_id, action_id):
        state = b'%d#%d#%s' % (session_id, state_id, (action_id or '').encode('ascii'))
        return '#{}#{}{}'.format(self.ident, type_, fernet.Fernet(self.key).encrypt(state).decode('ascii'))

    def create_login_request(self, session_id, state_id, action_id, *args, **kw):
        state = self.create_state(1, session_id, state_id, action_id)
        return OneLogin_Saml2_Auth({}, self.config, self.certs_directory).login(state, *args, **kw)

    def create_logout_request(self, name_id, session_index, session_id, state_id, action_id):
        state = self.create_state(0, session_id, state_id, action_id)
        return OneLogin_Saml2_Auth({}, self.config, self.certs_directory).logout(
            state
        )  # name_id=name_id, session_index=session_index)

    def is_auth_response(self, request):
        is_valid_response = False
        session_id, state_id, login, action_id = 0, 0, True, ''

        code = request.params.get('SAMLResponse')
        state = request.params.get('RelayState', '')

        if code and state.startswith('#'):
            try:
                state = state.rsplit('#', 1)[1]
                login = state[0] == '1'

                state = fernet.Fernet(self.key).decrypt(state[1:])
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
                new_response = request.create_redirect_response(response=response, _s=session_id, _c='%05d' % state_id)
        else:
            principal, credentials = self.retrieve_credentials(session)
            if not principal:
                principal, credentials, r = super().get_principal(request=request, response=response, **params)

        if action_id:
            request.environ['QUERY_STRING'] = action_id + '='

        return principal, credentials, new_response

    def login(self, h, *args, **kw):
        return Log(h, lambda *_args, **_kw: self.create_login_request(*args, *_args, **kw, **_kw))

    def logout(self, h, location='', delete_session=True, user=None):
        user = super().logout(location, delete_session, user)

        name_id = user.credentials.get('_name_id') if user else None
        session = user.credentials.get('_session_index') if user else None

        return Log(h, partial.Partial(self.create_logout_request, name_id, session))
