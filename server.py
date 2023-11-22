import asyncio
from typing import Callable, Dict, Optional
import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionIdIssued, ConnectionIdRetired, ConnectionTerminated, DatagramFrameReceived
from aioquic.tls import SessionTicket
import logging
import select
import fcntl
import struct
import os
from scapy.all import *

AsgiApplication = Callable

SERVER_NAME = "aioquic/" + aioquic.__version__

class HttpServerProtocol(QuicConnectionProtocol):
    def __init__(self, tun, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.tun = tun

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionIdIssued):
            print("Connection ID issued", event.connection_id.hex())

        if isinstance(event, ConnectionIdRetired):
            print("Connection ID retired", event.connection_id.hex())

        if isinstance(event, ConnectionTerminated):
            print("Connection terminated", event.error_code, event.frame_type, event.reason_phrase)

        if isinstance(event, DatagramFrameReceived):
            if b"quack" == event.data:
                print("Received QUACK")
                self._quic.send_datagram_frame(b"quack-ack")
                self.transmit()

        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data
            pkt = IP(data)
            # pass the extracted packet to tun interface
            os.write(self.tun, bytes(pkt))

    async def data_received_resource(self):
        while True:
            pkt = await self.loop.run_in_executor(None, os.read, self.tun, 2048)
            if pkt:
                self._quic.send_datagram_frame(pkt)
                self.transmit()

class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)

async def main(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
    tun: int,  # Add tun as a parameter
) -> None:
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: HttpServerProtocol(tun, *args, **kwargs),
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    await asyncio.Future()


if __name__ == "__main__":

    tunnellocalip = "10.0.0.2"
    tunnelsubnetmask = "24"

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

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables -A FORWARD -i tun0 -o enp0s8 -j ACCEPT")
    os.system("iptables -A FORWARD -i enp0s8 -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT")
    os.system("iptables -t nat -A POSTROUTING -o enp0s8 -j MASQUERADE")

    host = "localhost"
    port = 4433

    configuration = QuicConfiguration(
        alpn_protocols=["myproto"],
        is_client=False,
        max_datagram_frame_size=65536
    )

    # load SSL certificate and key
    configuration.load_cert_chain("tests/ssl_cert.pem", "tests/ssl_key.pem")

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO
    )

    try:
        asyncio.run(
            main(
                host=host,
                port=port,
                configuration=configuration,
                session_ticket_store=SessionTicketStore(),
                retry=True,
                tun=tun,
            )
        )
    except KeyboardInterrupt:
        pass
