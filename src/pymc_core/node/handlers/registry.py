"""Handler registry for creating and wiring standard MeshCore protocol handlers.

Both the :class:`Dispatcher` and :class:`CompanionBridge` need the same core
set of handlers — this module provides a shared factory so handler creation
and cross-wiring only lives in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .advert import AdvertHandler
from .group_text import GroupTextHandler
from .login_response import LoginResponseHandler
from .path import PathHandler
from .protocol_response import ProtocolResponseHandler
from .text import TextMessageHandler


@dataclass
class CoreHandlers:
    """Bundle of the core protocol handlers shared by Dispatcher and Bridge."""

    text_handler: TextMessageHandler
    advert_handler: AdvertHandler
    group_text_handler: GroupTextHandler
    protocol_response_handler: ProtocolResponseHandler
    login_response_handler: LoginResponseHandler
    path_handler: PathHandler


def create_core_handlers(
    *,
    identity: Any,
    contacts: Any,
    channels: Any,
    event_service: Any,
    send_packet_fn: Callable,
    log_fn: Callable,
    node_name: str,
    radio_config: Optional[dict] = None,
    ack_handler: Any = None,
) -> CoreHandlers:
    """Create and wire the standard set of MeshCore protocol handlers.

    This is the single source of truth for handler construction.  Both
    :meth:`Dispatcher.register_default_handlers` and
    :class:`CompanionBridge.__init__` delegate here.

    Args:
        identity: The local identity for encryption/signing.
        contacts: Contact storage.
        channels: Channel database.
        event_service: Event service for broadcasting mesh events.
        send_packet_fn: Async callable to send a packet (the transport).
        log_fn: Logging callable (``str -> None``).
        node_name: Human-readable node name.
        radio_config: Optional radio configuration dict.
        ack_handler: ACK handler instance (varies between Dispatcher and
            Bridge).  If ``None``, the :class:`PathHandler` is constructed
            without ACK forwarding.
    """
    protocol_response_handler = ProtocolResponseHandler(log_fn, identity, contacts)

    login_response_handler = LoginResponseHandler(identity, contacts, log_fn)
    login_response_handler.set_protocol_response_handler(protocol_response_handler)

    path_handler = PathHandler(
        log_fn,
        ack_handler,
        protocol_response_handler,
        login_response_handler,
    )

    text_handler = TextMessageHandler(
        identity,
        contacts,
        log_fn,
        send_packet_fn,
        event_service,
        radio_config,
    )

    advert_handler = AdvertHandler(log_fn, event_service=event_service)

    group_text_handler = GroupTextHandler(
        identity,
        contacts,
        log_fn,
        send_packet_fn,
        channels,
        event_service,
        node_name,
    )

    return CoreHandlers(
        text_handler=text_handler,
        advert_handler=advert_handler,
        group_text_handler=group_text_handler,
        protocol_response_handler=protocol_response_handler,
        login_response_handler=login_response_handler,
        path_handler=path_handler,
    )
