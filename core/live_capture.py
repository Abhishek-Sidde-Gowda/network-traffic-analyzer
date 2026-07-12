"""
Live packet capture from a network interface.
Requires scapy + root/CAP_NET_RAW privilege.
Yields Packet objects for streaming analysis.
"""
from __future__ import annotations

import threading
import queue
from typing import Iterator, Optional, Callable
from .packet_parser import Packet, _proto_name

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class LiveCapture:
    """
    Non-blocking live capture that pushes packets into a queue.

    Usage:
        cap = LiveCapture(iface="eth0", bpf_filter="tcp or udp")
        cap.start()
        for pkt in cap.stream(timeout=30):
            print(pkt)
        cap.stop()
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        bpf_filter: str = "ip or ip6",
        packet_count: int = 0,
    ):
        if not HAS_SCAPY:
            raise RuntimeError("scapy is required for live capture: pip install scapy")
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self._q: queue.Queue[Optional[Packet]] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._q.put(None)  # sentinel

    def _capture_loop(self) -> None:
        def _cb(raw_pkt):
            if self._stop_event.is_set():
                return True  # stops sniff
            pkt = _scapy_to_packet(raw_pkt)
            if pkt:
                self._q.put(pkt)

        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=_cb,
            count=self.packet_count,
            stop_filter=lambda _: self._stop_event.is_set(),
        )
        self._q.put(None)  # sentinel when done

    def stream(self, timeout: Optional[float] = None) -> Iterator[Packet]:
        """Yield packets until stop() is called or timeout expires."""
        import time
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            remaining = (deadline - time.monotonic()) if deadline else 5.0
            if remaining <= 0:
                break
            try:
                pkt = self._q.get(timeout=min(remaining, 5.0))
                if pkt is None:
                    break
                yield pkt
            except queue.Empty:
                if self._stop_event.is_set():
                    break


def _scapy_to_packet(raw) -> Optional[Packet]:
    try:
        ts = float(raw.time)
        if IP in raw:
            ip = raw[IP]; version = 4
        elif IPv6 in raw:
            ip = raw[IPv6]; version = 6
        else:
            return None
        src_ip, dst_ip = ip.src, ip.dst
        ttl = getattr(ip, "ttl", getattr(ip, "hlim", 0))
        proto = _proto_name(ip.proto)
        src_port = dst_port = 0
        flags = {}; payload_len = 0
        if TCP in raw:
            tcp = raw[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            f = tcp.flags
            flags = {
                "SYN": bool(f & 0x02), "ACK": bool(f & 0x10),
                "FIN": bool(f & 0x01), "RST": bool(f & 0x04),
                "PSH": bool(f & 0x08),
            }
            payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
        elif UDP in raw:
            udp = raw[UDP]
            src_port, dst_port = udp.sport, udp.dport
            payload_len = len(bytes(udp.payload)) if udp.payload else 0
        return Packet(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=proto, length=len(raw),
            payload_len=payload_len, flags=flags,
            ttl=ttl, ip_version=version,
        )
    except Exception:
        return None


def list_interfaces() -> list[str]:
    """Return available network interface names."""
    try:
        import netifaces
        return netifaces.interfaces()
    except ImportError:
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []
