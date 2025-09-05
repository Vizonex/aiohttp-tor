import asyncio
import logging
import os
import socket
import typing as t
from collections.abc import Iterable as TypingIterable
from contextlib import suppress
from pathlib import Path
from ssl import SSLContext
from typing import Optional, Type, Union

from aiofiles import open as aopen
from aiohttp.abc import AbstractAccessLogger
from aiohttp.log import access_logger
from aiohttp.typedefs import PathLike
from aiohttp.web import Application, GracefulExit, HostSequence, _cancel_tasks, _run_app
from aiohttp.web_log import AccessLogger
from aiosignal import Signal
from aiostem import Controller
from aiostem.exceptions import ControllerError
from multidict import MultiMapping

from .process import MessageHandler, launch


class HiddenServiceController(Controller):
    async def host_hidden_service(
        self,
        port: int = 5000,
        host: str = "127.0.0.1",
        hidden_service_directory: Union[str, Path, None] = None,
        ssl_port: Optional[int] = None,
    ):
        """Sets a hidden service to host returning with the string of our newly made hidden-service"""
        if not hidden_service_directory:
            # one annoying thing is finding out where your hidden service went.
            # so lets bring the directory of it back to us...
            hidden_service_directory = os.path.join(os.getcwd(), ".tor-hs")
            if not os.path.exists(hidden_service_directory):
                os.mkdir(".tor-hs")

        # Tor's Parser can't take windows Paths so we need to fix them oursleves
        # it's stupid but there's nothing you can do about it except for what I am showing,
        # Know however that windows is not designed to host servers very well
        # but in order to not OS-Gate people (which I discourage from practicing)
        # We will simply fix it ourselves.
        hs_path = Path(hidden_service_directory)
        args = dict()
        args["HiddenServiceDir"] = hs_path.as_posix()
        args["HiddenServicePort"] = [f"80 {host}:{port}"]

        # Add a second argument incase there's more incomming
        if ssl_port:
            args["HiddenServicePort"].append(f"443 {host}:{ssl_port}")
        await self.set_conf(args)

        # Obtain hidden service's hostname for reporting back
        async with aopen(hs_path / "hostname", "r") as r:
            hostname = await r.read()
        return hostname


class TorHiddenServiceHandler(MessageHandler):
    def __init__(self):
        super().__init__()
        self._on_startup: Signal[str] = Signal(self)

    @property
    def on_startup(self):
        """
        Shares message reguarding hidden service domain's name::

            from aiohttp_tor.web import TorHiddenServiceHandler

            events = TorHiddenServiceHandler()

            @events.on_startup()
            async def on_startup(domain_name:str):
                print(f"Hidden Service is hosting at {domain}")

        """
        return self._on_startup

    def freeze(self):
        self.on_startup.freeze()
        return super().freeze()


async def _run_app_as_hidden_service(
    app: Union[Application, t.Awaitable[Application]],
    ctrl_config: t.Union[
        MultiMapping[t.Union[list[t.Union[str, int]], str, int]],
        dict[str, t.Union[list[t.Union[str, int]], str, int]],
    ] = {},
    ctrl_port: Optional[int] = None,  # Default is 9051
    launcher_timeout: Optional[int] = 90,
    message_handler: Optional[TorHiddenServiceHandler] = None,
    ctrl_auth: Optional[str] = None,
    hidden_service_dir: Optional[PathLike] = None,
    *,
    host: Optional[Union[str, HostSequence]] = None,
    port: Optional[int] = None,
    path: Union[PathLike, TypingIterable[PathLike], None] = None,
    sock: Optional[Union[socket.socket, TypingIterable[socket.socket]]] = None,
    shutdown_timeout: float = 60.0,
    keepalive_timeout: float = 75.0,
    ssl_context: Optional[SSLContext] = None,
    print: Optional[t.Callable[..., None]] = print,
    backlog: int = 128,
    access_log_class: Type[AbstractAccessLogger] = AccessLogger,
    access_log_format: str = AccessLogger.LOG_FORMAT,
    access_log: Optional[logging.Logger] = access_logger,
    handle_signals: bool = True,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
    handler_cancellation: bool = False,
) -> None:
    ctrl = None
    try:
        ctrl: HiddenServiceController = await HiddenServiceController.from_port(
            port=ctrl_port,
            host=host or "127.0.0.1",
        ).__aenter__()

        await ctrl.authenticate(ctrl_auth)
    except (ControllerError, OSError):
        _process = await launch(
            take_ownership=True,
            close_output=True,
            timeout=launcher_timeout,
            init_msg_handler=message_handler,
        )
        ctrl: HiddenServiceController = await HiddenServiceController.from_port(
            port=9051, host=host or "127.0.0.1"
        ).__aenter__()
        await ctrl.authenticate(ctrl_auth)
    hostname = await ctrl.host_hidden_service(
        port=port, host=host or "127.0.0.1", hidden_service_directory=hidden_service_dir
    )
    if message_handler:
        await message_handler.on_startup.send(hostname)
    else:
        print(f"======== Running Hidden Service on {hostname} ========")
    try:
        return await _run_app(
            app,
            host=host or "127.0.0.1",
            port=port,
            path=path,
            sock=sock,
            shutdown_timeout=shutdown_timeout,
            keepalive_timeout=keepalive_timeout,
            ssl_context=ssl_context,
            print=print,
            backlog=backlog,
            access_log_class=access_log_class,
            access_log_format=access_log_format,
            access_log=access_log,
            handle_signals=handle_signals,
            reuse_address=reuse_address,
            reuse_port=reuse_port,
            handler_cancellation=handler_cancellation,
        )
    finally:
        await ctrl.__aexit__(None, None, None)
        if _process:
            await _process.close()


def run_app(
    app: Union[Application, t.Awaitable[Application]],
    ctrl_config: t.Union[
        MultiMapping[t.Union[list[t.Union[str, int]], str, int]],
        dict[str, t.Union[list[t.Union[str, int]], str, int]],
    ] = {},
    ctrl_port: Optional[int] = None,  # Default is 9051
    launcher_timeout: Optional[int] = 90,
    message_handler: Optional[MessageHandler] = None,
    ctrl_auth: Optional[str] = None,
    hidden_service_dir: Optional[PathLike] = None,
    *,
    host: Optional[Union[str, HostSequence]] = None,
    port: Optional[int] = None,
    path: Union[PathLike, TypingIterable[PathLike], None] = None,
    sock: Optional[Union[socket.socket, TypingIterable[socket.socket]]] = None,
    shutdown_timeout: float = 60.0,
    keepalive_timeout: float = 75.0,
    ssl_context: Optional[SSLContext] = None,
    print: Optional[t.Callable[..., None]] = print,
    backlog: int = 128,
    access_log_class: Type[AbstractAccessLogger] = AccessLogger,
    access_log_format: str = AccessLogger.LOG_FORMAT,
    access_log: Optional[logging.Logger] = access_logger,
    handle_signals: bool = True,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
    handler_cancellation: bool = False,
    loop: Optional[asyncio.AbstractEventLoop] = None,
    loop_factory: Optional[t.Callable[[], asyncio.AbstractEventLoop]] = None,
) -> None:
    """Run an app locally as a tor-hidden-service aka a .onion domain"""
    if loop is None:
        loop = loop_factory() if loop_factory else asyncio.new_event_loop()

    # Configure if and only if in debugging mode and using the default logger
    if loop.get_debug() and access_log and access_log.name == "aiohttp.access":
        if access_log.level == logging.NOTSET:
            access_log.setLevel(logging.DEBUG)
        if not access_log.hasHandlers():
            access_log.addHandler(logging.StreamHandler())

    main_task = loop.create_task(
        _run_app_as_hidden_service(
            app,
            ctrl_config=ctrl_config or 9051,
            ctrl_port=ctrl_port,
            launcher_timeout=launcher_timeout,
            message_handler=message_handler,
            ctrl_auth=ctrl_auth,
            host=host,
            port=port or 6000,
            path=path,
            sock=sock,
            shutdown_timeout=shutdown_timeout,
            keepalive_timeout=keepalive_timeout,
            ssl_context=ssl_context,
            print=print,
            backlog=backlog,
            access_log_class=access_log_class,
            access_log_format=access_log_format,
            access_log=access_log,
            handle_signals=handle_signals,
            reuse_address=reuse_address,
            reuse_port=reuse_port,
            handler_cancellation=handler_cancellation,
            hidden_service_dir=hidden_service_dir,
        )
    )

    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main_task)
    except (GracefulExit, KeyboardInterrupt):  # pragma: no cover
        pass
    finally:
        try:
            main_task.cancel()
            with suppress(asyncio.CancelledError):
                loop.run_until_complete(main_task)
        finally:
            _cancel_tasks(asyncio.all_tasks(loop), loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
