import asyncio
import re
import ssl
import sys
import time
import traceback
from crypto import encryptflag, decryptflag
from importlib import reload
from typing import List

import config

last_reload = 0

bind_address = '0.0.0.0'
bind_port = 1338

async def pipe(reader, writer, is_from_server, buf):
    try:
        while not reader.at_eof():
            data = await reader.read(2048)
            #data = await reader.readline()
            from_addr, from_port = writer.get_extra_info('sockname')
            to_addr, to_port = writer.get_extra_info('peername')
            buf[int(is_from_server)] = (buf[int(is_from_server)] + data)[-config.BUFSIZE:]
            data = process_data(data, from_addr, from_port, to_addr, to_port, is_from_server, buf)
            if data is None:
                data = b''
                writer.close()
            writer.write(data)
    finally:
        writer.close()


async def handle_client(local_reader, local_writer):
    # reload config each 5 seconds
    global last_reload
    if time.time() - last_reload > 5:
        last_reload = time.time()
        try:
            reload(config)  # noqa
        except Exception:
            traceback.print_exception(*sys.exc_info())

    buf = [b'', b'']
    try:
        ssl_context = None
        if config.PROXY_REMOTE_SSL:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE

        remote_reader, remote_writer = await asyncio.open_connection(
            config.PROXY_REMOTE_ADDR, config.PROXY_REMOTE_PORT, ssl=ssl_context,
        )
        pipe1 = pipe(local_reader, remote_writer, False, buf)
        pipe2 = pipe(remote_reader, local_writer, True, buf)
        await asyncio.gather(pipe1, pipe2)
    finally:
        local_writer.close()


def process_data(
    data: bytes, from_addr: str, from_port: int, to_addr: str, to_port: int, is_from_server: bool, buf: List[bytes],
):
    # buf[0] - last BUFSIZE bytes from client to server
    # buf[1] - last BUFSIZE bytes from server to client
    # buf contains non-modified bytes
    # return None -> drop connection

    # try:
    #     if config.RESP_MAX_ALLOWED_FLAGS > 0 and is_from_server:
    #         flags_from_server = len(re.findall(config.FLAG_REGEXP, buf[1]))
    #         if flags_from_server > config.RESP_MAX_ALLOWED_FLAGS:
    #             print('Leak of %s flags blocked' % flags_from_server)
    #             return None

    #     if is_from_server:
    #         for word in config.RESP_BAD_WORDS:
    #             if isinstance(word, str):
    #                 word = word.encode(errors='ignore')
    #             if word in buf[1]:
    #                 # print('Response blocked by word "%s"' % word)
    #                 return None
    #             pass
    #     else:
    #         for word in config.REQ_BAD_WORDS:
    #             if isinstance(word, str):
    #                 word = word.encode(errors='ignore')
    #             if word in buf[0]:
    #                 # print('Request blocked by word "%s"' % word)
    #                 return None

    #     if not config.process_data_custom(
    #         data=data, from_addr=from_addr, from_port=from_port,
    #         to_addr=to_addr, to_port=to_port, is_from_server=is_from_server, buf=buf,
    #     ):
    #         return None

    # except Exception:
    #     traceback.print_exception(*sys.exc_info())
    
    # print(data)

    # TestFlag = 'FRS485V58ADVL5QVUOJBTX3C904VRLR='
    # TestFlag = encryptflag(TestFlag)
    
    
    print("BEFORE ", data)
    
    data = data.replace(bind_address.encode(), config.PROXY_REMOTE_ADDR.encode())
    
    if is_from_server:
        data = re.sub(rb'\b[A-Z0-9]{31}(=|%3d|%3D)', lambda a: decryptflag(a.group(0).decode()).encode(), data)
        print("FROM SERVER")
    else:
        data = re.sub(rb'\b[A-Z0-9]{31}(=|%3d|%3D)', lambda a: encryptflag(a.group(0).decode()).encode(), data)
        print("TO SERVER")
        
    print("AFTER ", data)
    return data
    
    

if __name__ == '__main__':

    ssl_context = None
    if config.PROXY_BIND_SSL:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain('ssl.crt', 'ssl.key')

    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_client, bind_address, bind_port, loop=loop, ssl=ssl_context)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
