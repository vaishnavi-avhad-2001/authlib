# flake8: noqa

from ..base_client import BaseOAuth, OAuthError
from .integration import QuartIntegration
from .apps import QuartOAuth1App, QuartOAuth2App


class OAuth(BaseOAuth):
    oauth1_client_cls = QuartOAuth1App
    oauth2_client_cls = QuartOAuth2App
    framework_integration_cls = QuartIntegration

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None):
        super().__init__(
            cache=cache, fetch_token=fetch_token, update_token=update_token)
        self.config = config


__all__ = [
    'OAuth', 'OAuthError',
    'QuartIntegration', 'QuartOAuth1App', 'QuartOAuth2App',
]
