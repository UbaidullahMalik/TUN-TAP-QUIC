import asyncio
from typing import Callable, Dict, Optional

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionIdIssued, ConnectionIdRetired, ConnectionTerminated, DatagramFrameReceived
from aioquic.tls import SessionTicket
import logging

AsgiApplication = Callable

SERVER_NAME = "aioquic/" + aioquic.__version__

class HttpServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

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
            print("Received DATA", data)

            reversed_data = data[::-1]
            self._quic.send_stream_data(stream_id, reversed_data, end_stream=event.end_stream)
            print("Sent DATA", reversed_data)

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
) -> None:
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    await asyncio.Future()


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 4434

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
            )
        )
    except KeyboardInterrupt:
        pass
