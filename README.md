# Aiohttp-Tor

Inspired by the stem library from the tor-project, this project attempts to make 
seemless transitions with aiohttp and tor. For both clients and hosting. 

## Running Clients
```python
from aiohttp_tor import TorConnector, launch, MessageHandler
from aiohttp import ClientSession
import asyncio


# if you want to use the init_msg_handler here's the steps to follow.
handler = MessageHandler()

@handler.on_message
async def send_message(msg:str):
    print(msg)



async def request_for_onionsite():
    async with launch(ctrl_port=9051, socks_port=9050, init_msg_handler=handler):
        # TorConnector should mirror what you've launched tor with.
        async with ClientSession(connector=TorConnector(port=9050, ctrl_port=9051)) as session:
            async with session.get("http://mf34jlghauz5pxjcmdymdqbe5pva4v24logeys446tdrgd5lpsrocmqd.onion/index.html") as resp:
                data = await resp.read()
                print(data)
                # b'\n\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n ... and so on...

    

if __name__ == "__main__":
    asyncio.run(request_for_onionsite())
```


## Running Tor Hidden Services

```python
from aiohttp_tor.web import run_app
from aiohttp.web import Application, RouteTableDef, Request, Response

import winloop # There's custom options for uvloop/winloop thanks to loop_factory

routes = RouteTableDef()
app = Application()

@routes.get('/')
async def index(request:Request):
    return Response(body=b"<html><body><h1>Hi Grandma!</h1></body></html>", content_type="text/html")

# Tor hidden service will be located in a .tor-hs directory
# unless you pass a hidden_service_dir parameter, this is to make 
# things friendly for beginners but it's encouraged to change it's path 
# so that bad actors can't find it.

if __name__ == "__main__":
    app.add_routes(routes)
    run_app(app, loop_factory=winloop.new_event_loop, port=6999)

```

## Requirements
- Python 3.10+ (Due to how aiostem works)
- aiostem
- aiohttp-socks (For sending Client Requests)
- aiohttp


