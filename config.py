from typing import List, Union

PROXY_REMOTE_ADDR = "10.118.0.20"
PROXY_REMOTE_PORT = 1103

# ssl
PROXY_BIND_SSL = False
PROXY_REMOTE_SSL = False

BUFSIZE = 4096

def process_data_custom(
    data: bytes, from_addr: str, from_port: int,
    to_addr: str, to_port: int, is_from_server: bool, buf: List[bytes],
) -> bool:
    # buf[0] - last BUFSIZE bytes from client to server
    # buf[1] - last BUFSIZE bytes from server to client
    return True
