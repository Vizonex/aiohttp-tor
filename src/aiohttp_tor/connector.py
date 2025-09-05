import asyncio
from typing import Any, Generator

from aiohttp import ClientConnectionError
from aiohttp.client_proto import ResponseHandler
from aiohttp_socks import ProxyConnector, ProxyType
from aiostem.controller import DEFAULT_CONTROL_HOST, DEFAULT_CONTROL_PORT, Controller
from aiostem.reply import ReplySignal
from aiostem.structures import Signal
from .typedefs import Self

DEFAULT_PROXY_PORT = 9050  # socks5


# TODO: Maybe sperate library for this new class object?
class RepeatingTimeout:
    """Ratelimits execution based on one task at a time."""

    def __init__(self, timeout: float, loop: asyncio.AbstractEventLoop | None = None):
        self._timeout = timeout
        self._loop = loop or asyncio.get_event_loop()
        self._fut: asyncio.Future[None] | None = None
        self._handle: asyncio.TimerHandle | None = None
        self._lock = asyncio.Lock()

    def __new_callback(self) -> None:
        """Creats a new timer-handle to wait on."""
        self._fut = self._loop.create_future()
        self._handle = self._loop.call_later(self._timeout, self._fut.set_result, None)

    def reset(self) -> None:
        """resets current cycle so that a new one afterwards can be made."""
        self._handle.cancel()
        self._fut.set_result(None)

    async def wait(self) -> None:
        """Wait for running objects to complete"""
        async with self._lock:
            if not self._fut:
                self.__new_callback()
                # first time or rejected so use a checkpoint
                return await asyncio.sleep(0)
            else:
                await self._fut
                # reset timer...
                self.__new_callback()

    async def __aenter__(self) -> Self:
        await self.wait()
        return self

    async def __aexit__(self, *args) -> None:
        return

    def __await__(self) -> Generator[Any, None, None]:
        return self.wait().__await__()


class ControllerResponseError(Exception):
    """Bad Reply recieved while working with a tor controller"""

    def __init__(self, status: int, msg: str) -> None:
        """Initalizes the error

        :param status: the bad status from the controller
        :param msg: the message given by the controller
        """
        self.status = status
        self.msg = msg

    def __str__(self):
        """return exception as a string"""
        return self.msg


class TorConnector(ProxyConnector):
    """Handles aiohttp Client Releated sessions with tor."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9050,
        proxy_type=ProxyType.SOCKS5,
        username=None,
        password=None,
        proxy_ssl=None,
        ctrl_host: str = DEFAULT_CONTROL_HOST,
        ctrl_port: str = DEFAULT_CONTROL_PORT,
        ctrl_auth: str | None = None,
        **kwargs,
    ) -> None:
        """
        Initnalizes ProxyConnector and tor client

        :param host: the host of the tor proxy Defaults to 127.0.0.1 (localhost)
        :param port: the tor proxy's port Defaults to 9050 assuming
            you've launched a tor process with those specific settings inplace

        :param proxy_type: Default is socks5 and changing the default is discouraged.
        :param username: the proxy username (Using this is discouraged)
        :param password: the proxy password (Please use ctrl_auth for the your tor password)
        :param ctrl_host: the controller's hostname (default is 127.0.0.1)
        :param ctrl_auth: your tor password (default is None)
        :param ctrl_port: tor contoller's port (default is 9051)
        """

        super().__init__(
            host,
            port,
            proxy_type,
            username,
            password,
            rdns=True,
            proxy_ssl=proxy_ssl,
            **kwargs,
        )

        self._ctrl_host = ctrl_host
        self._ctrl_port = ctrl_port
        self._ctrl_auth = ctrl_auth
        self._controller = Controller.from_port(host=ctrl_host, port=ctrl_port)
        self._newnym_ratelimit = RepeatingTimeout(10, loop=self._loop)

    async def _wrap_create_connection(
        self,
        *args,
        addr_infos,
        req,
        timeout,
        client_error=ClientConnectionError,
        **kwargs,
    ):
        # Run even if we don't have a _ctrl_auth to pass
        await self._controller.__aenter__()
        auth = await self._controller.authenticate(self._ctrl_auth)
        if auth.is_error:
            raise ControllerResponseError(auth.status, auth.status_text)
        return await super()._wrap_create_connection(
            *args,
            addr_infos=addr_infos,
            req=req,
            timeout=timeout,
            client_error=client_error,
            **kwargs,
        )

    async def close(self, *, abort_ssl=False):
        # We hack the contextmanager for the controller to make things a bit easier to control.
        await self._controller.__aexit__(None, None, None)
        return await super().close(abort_ssl=abort_ssl)

    async def reset_identity(self) -> ReplySignal:
        """Rotates tor exit node based on a 10 second cycle."""
        await self._newnym_ratelimit.wait()
        return await self.reset_identity_async()

    async def reset_identity_async(self) -> ReplySignal:
        """Resets tor exit exit node without a 10 second cycle"""
        resp = await self._controller.signal(Signal.NEWNYM)
        if resp.is_error:
            raise ControllerResponseError(resp.status, resp.status_text)
        return resp

    @classmethod
    def from_url(
        cls,
        url: str,
        ctrl_host: str = DEFAULT_CONTROL_HOST,
        ctrl_port: str = DEFAULT_CONTROL_PORT,
        ctrl_auth: str | None = None,
    ) -> Self:
        """return Connection to tor from a given proxy url

        :param ctrl_host: the controller's hostname (default is 127.0.0.1)
        :param ctrl_auth: your tor password (default is None)
        :param ctrl_port: tor contoller's port (default is 9051)
        """
        return cls.from_url(
            url, ctrl_auth=ctrl_auth, ctrl_host=ctrl_host, ctrl_port=ctrl_port
        )
