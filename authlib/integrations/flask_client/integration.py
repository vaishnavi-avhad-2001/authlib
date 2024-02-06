from quart import current_app
from quart.signals import Signal

from ..base_client import FrameworkIntegration

_signal = Signal()
#: signal when token is updated
token_update = _signal.signal('token_update')


class QuartIntegration(FrameworkIntegration):
    async def update_token(self, token, refresh_token=None, access_token=None):
        await token_update.send(
            current_app,
            name=self.name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )

    @staticmethod
    async def load_config(oauth, name, params):
        rv = {}
        for k in params:
            conf_key = f'{name}_{k}'.upper()
            v = await oauth.app.config.get(conf_key, None)
            if v is not None:
                rv[k] = v
        return rv
