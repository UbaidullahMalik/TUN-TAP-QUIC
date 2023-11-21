import asyncio
from typing import cast
import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, DatagramFrameReceived, PingAcknowledged
from collections import deque
from typing import Deque, Dict
import logging
from datetime import datetime
import select
import fcntl
import struct
import os
from scapy.all import *

USER_AGENT = "aioquic/" + aioquic.__version__

class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._request_events: Dict[int, Deque] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque]] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, PingAcknowledged):
            print("Ping acknowledged at", datetime.now())

        if isinstance(event, DatagramFrameReceived):
            if b"quack-ack" == event.data:
                print("Received QUACK-ACK")

        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data
            pkt = IP(data)
            # pass the extracted packet to tun interface
            os.write(tun, bytes(pkt))
            
            self._request_events[stream_id].append(data)
            waiter = self._request_waiter.pop(stream_id)
            waiter.set_result(self._request_events.pop(stream_id))

    # send quack every 20 seconds
    async def send_quack(self) -> None:
        while True:
            await asyncio.sleep(2)
            self._quic.send_datagram_frame(b"quack")
            self.transmit()
            print("Sent QUACK")

    async def send_pings(self) -> None:
        while True:
            await asyncio.sleep(30)
            await self.ping()
            print("Sent PING at", datetime.now())

    async def send_message(self, stream_id, message, end_stream=False) -> None:
        self._quic.send_stream_data(stream_id, message, end_stream=end_stream)
        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)
    
    async def communicate(self) -> None:
        stream_id = self._quic.get_next_available_stream_id()
        _packet = os.read(tun, 2048)
        await self.send_message(stream_id, _packet)

async def main(connectors) -> None:
    while True:
        tasks = []
        for connector in connectors:
            task = asyncio.create_task(connect_and_run(*connector.get_config_parameters()))
            tasks.append(task)

        await asyncio.gather(*tasks)
        await asyncio.sleep(5)

async def connect_and_run(host, port, configuration) -> None:
    while True:
        try:
            async with connect(
                host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
            ) as client:
                client = cast(HttpClient, client)
                print("Connected to", host, ":", port)

                t1 = asyncio.create_task(client.communicate())
                await asyncio.gather(t1)
                client._quic.close()
        except Exception as e:
            print(f"Connection to {host}:{port} failed: {e}")
            print("Retrying in 5 seconds")
            await asyncio.sleep(5)

class ConnectConfig:
    host: str
    port: int
    configuration: QuicConfiguration

    def __init__(self, host, port, configuration):
        self.host = host
        self.port = port
        self.configuration = configuration

    def get_config_parameters(self):
        return self.host, self.port, self.configuration

if __name__ == "__main__":

    tunnelremoteprealip = "192.168.121.6"
    tunnelremoteprealport = 9090
    tunnellocalip = "10.0.0.1"
    tunnelsubnetmask = "24"
    tunneltargetsubnet = "192.168.122.0"
    tunneltargetsubnetmask = "24"

    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    # Create the tun interface
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

    # Get the interface name
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")

    #setup the ip and bring the interface up
    os.system("ip addr add {}/{} dev {}".format(tunnellocalip,tunnelsubnetmask,ifname))
    os.system("ip link set dev {} up".format(ifname))

    #setup the ip route to target subnet
    os.system("ip route add {}/{} dev {} via {}".format(tunneltargetsubnet,tunneltargetsubnetmask,ifname,tunnellocalip))

    defaults = QuicConfiguration(is_client=True)
    
    # prepare configuration
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["myproto"])
    ca_certs = "tests/pycacert.pem"
    configuration.load_verify_locations(ca_certs)

    Connector01 = ConnectConfig(tunnelremoteprealip, 4433, configuration)

    Connectors = [Connector01]

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO
    )

    asyncio.run(
        main(Connectors)
    )