from quart import Response, redirect, request
from ..base_client import OAuthError
from ..base_client import BaseApp
from ..base_client.async_app import AsyncOAuth1Mixin, AsyncOAuth2Mixin
from ..base_client.async_openid import AsyncOpenIDMixin
from ..httpx_client import AsyncOAuth1Client, AsyncOAuth2Client


class QuartAppMixin:
    async def save_authorize_data(self, session, **kwargs):
        state = kwargs.pop('state', None)
        if state:
            await self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError('Missing state value')

    async def authorize_redirect(self, session, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param session: Quart session instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        await self.save_authorize_data(session, redirect_uri=redirect_uri, **rv)
        return redirect(rv['url'])


class QuartOAuth1App(QuartAppMixin, AsyncOAuth1Mixin, BaseApp):
    client_cls = AsyncOAuth1Client

    async def authorize_access_token(self, session, **kwargs):
        params = dict(request.args)
        state = params.get('oauth_token')
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = await self.framework.get_state_data(session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params['request_token'] = data['request_token']
        params.update(kwargs)
        await self.framework.clear_state_data(session, state)
        return await self.fetch_access_token(**params)


class QuartOAuth2App(QuartAppMixin, AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp):
    client_cls = AsyncOAuth2Client

    async def authorize_access_token(self, session, **kwargs):
        error = request.args.get('error')
        if error:
            description = request.args.get('error_description')
            raise OAuthError(error=error, description=description)

        params = {
            'code': request.args.get('code'),
            'state': request.args.get('state'),
        }

        claims_options = kwargs.pop('claims_options', None)
        state_data = await self.framework.get_state_data(session, params.get('state'))
        await self.framework.clear_state_data(session, params.get('state'))
        params = self._format_state_params(state_data, params)
        token = await self.fetch_access_token(**params, **kwargs)

        if 'id_token' in token and 'nonce' in state_data:
            userinfo = await self.parse_id_token(token, nonce=state_data['nonce'], claims_options=claims_options)
            token['userinfo'] = userinfo
        return token
