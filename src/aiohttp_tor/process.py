"""
Launcher
-------
Used to launch and close tor processes asynchrnonously
"""

from __future__ import annotations

import asyncio
import os
import platform
import re
import tempfile
from functools import lru_cache, wraps
from pathlib import Path
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Generator,
    Generic,
    Optional,
    Type,
    TypeAlias,
)
from ssl import SSLContext

from .connector import TorConnector

import async_timeout
from aiosignal import Signal

from .typedefs import _P, _T, Self

from multidict import MultiMapping, MultiDict


@lru_cache()
def is_available(command: str):
    """
    Checks the current PATH to see if a command is available or not. If more
    than one command is present (for instance "ls -a | grep foo") then this
    just checks the first.

    Note that shell (like cd and ulimit) aren't in the PATH so this lookup will
    try to assume that it's available. This only happends for recognized shell
    commands (those in SHELL_COMMANDS).

    :param str command: command to search for

    :returns: **True** if an executable we can use by that name exists in the
      PATH, **False** otherwise
    """

    if " " in command:
        command = command[: command.find(" ")]

    if command == "ulimit":
        return True  # we can't actually look it up, so hope the shell really provides it...

    elif "PATH" not in os.environ:
        return False  # lacking a path will cause find_executable() to internally fail

    cmd_exists = False

    for path in os.environ["PATH"].split(os.pathsep):
        cmd_path = os.path.join(path, command)

        if platform.system() == "Windows" and not cmd_path.endswith(".exe"):
            cmd_path += ".exe"

        if os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
            cmd_exists = True
            break

    return cmd_exists


class MessageHandler:
    """Logger for handling messages when launching tor processes"""

    def __init__(self) -> None:
        """initalizes a new handler"""
        self.on_message: Signal[str] = Signal(self)

    def freeze(self):
        """Freezes all signals"""
        return self.on_message.freeze()

    async def send(self, msg: str) -> None:
        """Sends callback to event"""
        await self.on_message.send(msg)


# WARNING: Do not use _launch_tor directly it may just
# be a fork of the stem version but please use it at your own risk!!!
async def _launch_tor(
    tor_cmd: str = "tor",
    args: list[str] | None = None,
    torrc_path: Optional[str | Path] = "<no torrc>",
    completion_percent: int = 100,
    init_msg_handler: MessageHandler | None = None,
    timeout: Optional[float] = 90,
    take_ownership: bool = False,
    stdin: str | bytes | None = None,
):
    # sanity check that we got a tor binary

    if os.path.sep in tor_cmd:
        # got a path (either relative or absolute), check what it leads to

        if os.path.isdir(tor_cmd):
            raise OSError(f"'{tor_cmd}' is a directory, not the tor executable")
        elif not os.path.isfile(tor_cmd):
            raise OSError(f"'{tor_cmd}' doesn't exist")
    elif not is_available(tor_cmd):
        raise OSError(
            f"'{tor_cmd}' isn't available on your system and is not a PATH enviornment variable."
        )

    # double check that we have a torrc to work with
    if torrc_path not in [None, "<no torrc>"] and not os.path.exists(torrc_path):
        raise OSError(f"torrc doesn't exist ({torrc_path})")

    # starts a tor subprocess, raising an OSError if it fails
    runtime_args, temp_file = [tor_cmd], None

    if args:
        runtime_args += args

    if torrc_path:
        if torrc_path is None:
            temp_file = (
                await asyncio.to_thread(
                    tempfile.mkstemp, prefix="empty-torrc-", text=True
                )
            )[1]
            runtime_args += ["-f", temp_file]
        else:
            runtime_args += ["-f", torrc_path]

    if take_ownership:
        runtime_args.append("__OwningControllerProcess")
        runtime_args.append(str(os.getpid()))

    tor_process = None

    try:
        tor_process = await asyncio.subprocess.create_subprocess_exec(
            *runtime_args,
            stdout=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if stdin:
            tor_process.stdin.write(
                stdin.encode("utf-8", "replace") if isinstance(stdin, str) else stdin
            )
            await tor_process.stdin.drain()
            tor_process.stdin.close()

        async with async_timeout.timeout(timeout):
            bootstrap_line = re.compile("Bootstrapped ([0-9]+)%")
            problem_line = re.compile("\\[(warn|err)\\] (.*)$")
            last_problem = "Timed out"

            while True:
                init_line = (
                    (await tor_process.stdout.readline())
                    .decode("utf-8", "replace")
                    .strip()
                )

                # this will provide empty results if the process is terminated

                if not init_line:
                    raise OSError(f"Process terminated: {last_problem}")

                # provide the caller with the initialization message if they want it

                if init_msg_handler:
                    await init_msg_handler.send(init_line)

                # return the process if we're done with bootstrapping

                bootstrap_match = bootstrap_line.search(init_line)
                problem_match = problem_line.search(init_line)

                if (
                    bootstrap_match
                    and int(bootstrap_match.group(1)) >= completion_percent
                ):
                    return tor_process
                elif problem_match:
                    runlevel, msg = problem_match.groups()

                    if "see warnings above" not in msg:
                        if ": " in msg:
                            msg = msg.split(": ")[-1].strip()

                        last_problem = msg
    finally:
        if temp_file:
            try:
                await asyncio.shield(asyncio.to_thread(os.remove, temp_file))
            except:
                pass


# WARNING: The internal structure is likely to change but
# The TorProcess api will remain in-tact.
class TorProcess:
    """Helps to handle shutdown of a tor-process
    You shouldn't be initializing using this directly,
    use it with launch() instead."""

    def __init__(
        self,
        process: asyncio.subprocess.Process,
        ctrl_port: Optional[int] = None,
        socks_port: Optional[int] = None,
    ):
        self.process = process
        self._closed = False
        self._ctrl_port = ctrl_port
        self._socks_port = socks_port

    async def close(self):
        """Shuts down a given Tor process"""
        if not self._closed:
            self.process.terminate()
            await self.process.wait()

    def connect(
        self,
        auth: Optional[str] = None,
        ctrl_port: Optional[int] = None,
        socks_port: Optional[int] = None,
        host: str = "127.0.0.1",
        ssl: Optional[SSLContext] = None,
    ) -> TorConnector:
        """return a connection from a given launched process

        :param auth: a password to use for the connection (Optional).
        :param ctrl_port: provide a control port for the connection
            if none were given (Optional).
        :param socks_port: provide a proxy port for the connection
            if none were given (Optional).
        :param host: The host of the given proxy, this should always be 127.0.0.1 (localhost)
            unless under rare conditions where it must be obtained from somewhere else.
        :param ssl: provide a given ssl context to use.

        Raises
        ------

        ConnectionError
            if `TorProcess` was already closed

        TypeError 
            if `TorProcess` doesn't have a control port or socks port provided to it.
        """
        if self._closed:
            raise ConnectionError(f"{self.__class__.__name__} was already closed")

        _socks_port = self._socks_port or socks_port
        if not _socks_port:
            raise TypeError("No socks port has been provided")

        _ctrl_port = self._ctrl_port or ctrl_port
        if not _ctrl_port:
            raise TypeError("No control port has been provided")

        return TorConnector(
            host=host,
            port=_socks_port,
            ctrl_port=_ctrl_port,
            ctrl_auth=auth,
            proxy_ssl=ssl,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()


class _TorProcessContextManager(Coroutine[Any, Any, TorProcess]):
    __slots__ = ("_coro", "_resp")

    def __init__(
        self, coro: Coroutine["asyncio.Future[Any]", None, TorProcess]
    ) -> None:
        self._coro: Coroutine["asyncio.Future[Any]", None, TorProcess] = coro

    def send(self, arg: None) -> "asyncio.Future[Any]":
        return self._coro.send(arg)

    def throw(self, *args: Any, **kwargs: Any) -> "asyncio.Future[Any]":
        return self._coro.throw(*args, **kwargs)

    def close(self) -> None:
        return self._coro.close()

    def __await__(self) -> Generator[Any, None, TorProcess]:
        ret = self._coro.__await__()
        return ret

    def __iter__(self) -> Generator[Any, None, TorProcess]:
        return self.__await__()

    async def __aenter__(self) -> TorProcess:
        self._resp: TorProcess = await self._coro
        return await self._resp.__aenter__()

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        await self._resp.__aexit__(exc_type, exc, tb)


def _wrap_async(
    func: Callable[_P, Awaitable[asyncio.subprocess.Process]],
) -> Callable[_P, _TorProcessContextManager]:
    @wraps(func)
    def wrapper(*args: _P.args, **kw: _P.kwargs):
        return _TorProcessContextManager(func(*args, **kw))

    return wrapper


@_wrap_async
async def launch(
    ctrl_port: int = 9051,
    socks_port: Optional[int] = 9050,
    config: dict[str, list[str] | str | int] | MultiMapping[str | int] = {},
    tor_cmd: str = "tor",
    completion_percent: int = 100,
    init_msg_handler: MessageHandler | None = None,
    timeout: int = 90,
    take_ownership: bool = False,
) -> asyncio.subprocess.Process:
    """
    return a tor process after launching one::

        from aiohttp_tor.process import launch, MessageHandler

        # if you want to use the init_msg_handler here's the steps to follow.

        on_message: Signal[str] = MessageHandler()

        @on_message
        async def send_message(msg:str):
            print(msg)

        async with launch(9051, 9050, init_msg_handler=on_message):
            ...


    :param ctrl_port: The Controller port to use default: 9051
    :param socks_port: the Socks port to use default: 9050 this
        can also be ignored by passing None
    :param config: Your Tor Configuration this can also be a MultiDict
    :param tor_cmd: the command to launch tor with
    :param completion_percent: the completetion percent before exiting
    :param init_msg_handler: transformed to a signal callback via aiosignal
        is used for sending back messages asynchronously.
    :param timeout: The time to wait before quitting
    :param take_ownership: weather the program takes ownership over the given process
    """

    config["ControlPort"] = str(ctrl_port)
    if socks_port is not None:
        config["SocksPort"] = str(socks_port)

    if init_msg_handler:
        init_msg_handler.freeze()

    if "Log" in config:
        stdout_options = {"DEBUG stdout", "INFO stdout", "NOTICE stdout"}

        # NOTE: MultiDict has a bit of an advantage with 
        # one key taking multiple values hence why I added it in. - Vizonex
        if not isinstance(config, MultiDict):
            if isinstance(config["Log"], str):
                config['Log'] = [config["Log"]]
                
            if not any([log_config in stdout_options for log_config in config["Log"]]):
                config["Log"].append("NOTICE stdout")
        
        elif not any([log_config in stdout_options for log_config in config.getall("Log")]):
            config.add("Log", "NOTICE stdout")



    config_str = ""

    for key, values in config.items():
        if isinstance(values, (str, int)):
            config_str += f"{key} {values} "
        else:
            for value in values:
                config_str += f"{key} {value} "

    return TorProcess(
        await _launch_tor(
            tor_cmd,
            ["-f", "-"],
            None,
            completion_percent,
            init_msg_handler,
            timeout,
            take_ownership,
            stdin=config_str.encode("utf-8", "replace"),
        ),
        ctrl_port=ctrl_port,
        socks_port=socks_port
    )
