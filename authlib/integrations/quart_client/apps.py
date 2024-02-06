from quart import g, redirect, request, session
from ..requests_client import OAuth1Session, OAuth2Session
from ..base_client import (
    BaseApp, OAuthError,
    OAuth1Mixin, OAuth2Mixin, OpenIDMixin,
)


class QuartAppMixin:
    @property
    async def token(self):
        attr = f'_oauth_token_{self.name}'
        token = getattr(g, attr, None)
        if token:
            return token
        if self._fetch_token:
            token = await self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        attr = f'_oauth_token_{self.name}'
        setattr(g, attr, token)

    async def _get_requested_token(self, *args, **kwargs):
        return await self.token

    def save_authorize_data(self, **kwargs):
        state = kwargs.pop('state', None)
        if state:
            self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError('Missing state value')

    async def authorize_redirect(self, redirect_uri=None, **kwargs):
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(redirect_uri=redirect_uri, **rv)
        return redirect(rv['url'])


class QuartOAuth1App(QuartAppMixin, OAuth1Mixin, BaseApp):
    client_cls = OAuth1Session

    async def authorize_access_token(self, **kwargs):
        params = request.args.to_dict(flat=True)
        state = params.get('oauth_token')
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = self.framework.get_state_data(session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params['request_token'] = data['request_token']
        params.update(kwargs)
        self.framework.clear_state_data(session, state)
        token = await self.fetch_access_token(**params)
        self.token = token
        return token


class QuartOAuth2App(QuartAppMixin, OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Session

    async def authorize_access_token(self, **kwargs):
        if request.method == 'GET':
            error = request.args.get('error')
            if error:
                description = request.args.get('error_description')
                raise OAuthError(error=error, description=description)

            params = {
                'code': request.args['code'],
                'state': request.args.get('state'),
            }
        else:
            params = {
                'code': request.form['code'],
                'state': request.form.get('state'),
            }

        claims_options = kwargs.pop('claims_options', None)
        state_data = self.framework.get_state_data(session, params.get('state'))
        self.framework.clear_state_data(session, params.get('state'))
        params = self._format_state_params(state_data, params)
        token = await self.fetch_access_token(**params, **kwargs)
        self.token = token

        if 'id_token' in token and 'nonce' in state_data:
            userinfo = await self.parse_id_token(token, nonce=state_data['nonce'], claims_options=claims_options)
            token['userinfo'] = userinfo
        return token
