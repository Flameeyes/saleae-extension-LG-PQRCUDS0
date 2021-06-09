# SPDX-FileCopyrightText: 2021 Diego Elio Pettenò
#
# SPDX-License-Identifier: MIT

import functools
import operator
from typing import Any, Dict, List, Optional

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
from saleae.data import GraphTime, GraphTimeDelta


_PACKETS_DISTANCE = GraphTimeDelta(1)


def _checksum(packet):
    return (functools.reduce(operator.add, packet) & 0xFF) ^ 0x55


_FAN_SPEED = {
    0x00: "low",
    0x10: "medium",
    0x20: "high",
    0x40: "power",
}

_MODE = {
    0x00: "Cool",
    0x10: "dH",
    0x20: "Fan",
    0x40: "Heat",
}


def annotate_hvac_packet(packet_data: bytes, packet_attributes: Dict[str, Any]) -> None:
    packet_attributes["source"] = "HVAC"

    if not (packet_data[1] & 0x80):
        packet_attributes["room_temperature"] = (packet_data[1] / 2) + 10

    packet_attributes["unknown_data"] = bytes(
        (
            packet_data[0],
            0 if "room_temperature" in packet_attributes else packet_data[1],
            packet_data[2],
            packet_data[3],
            packet_data[4],
        )
    )


def annotate_panel_packet(
    packet_data: bytes, packet_attributes: Dict[str, Any]
) -> None:
    packet_attributes["source"] = "Panel"

    if packet_data[0] & 0x90 == 0x90:
        packet_attributes["features_inquiry"] = True

        if packet_data[1:4] != b"\x00\x00\x00\x00":
            packet_attributes["unknown_data"] = b"\x00" + packet_data[1:4]

    else:
        mode_val = packet_data[0] & 0x70
        packet_attributes["mode"] = _MODE.get(mode_val, hex(mode_val))

        packet_attributes["resistor?"] = bool(packet_data[0] & 0x08)

        packet_attributes["running"] = bool(packet_data[0] & 0x04)

        packet_attributes["settings_changed"] = bool(packet_data[0] & 0x01)

        packet_attributes["room_temperature"] = (packet_data[1] / 2) + 10

        packet_attributes["plasma"] = bool(packet_data[2] & 0x80)

        packet_attributes["fan_speed"] = _FAN_SPEED[packet_data[2] & 0x70]

        packet_attributes["set_temperature"] = str((packet_data[2] & 0x0F) + 16)

        packet_attributes["swivel"] = bool(packet_data[3] & 0x20)

        packet_attributes["swirl"] = bool(packet_data[4] & 0x01)

        packet_attributes["unknown_data"] = bytes(
            (
                packet_data[0] & 0x02,
                0,
                0,
                packet_data[3] & ~0x20,
                packet_data[4] & ~0x01,
            )
        )


def recompose_packet(
    packet_frames: List[AnalyzerFrame], last_end: Optional[GraphTime]
) -> AnalyzerFrame:
    packet_data = b""
    for frame in packet_frames:
        packet_data += frame.data["data"]

    received_checksum = packet_data[-1]
    calculated_checksum = _checksum(packet_data[:-1])

    if received_checksum != calculated_checksum:
        return AnalyzerFrame(
            "invalid_checksum",
            packet_frames[0].start_time,
            packet_frames[-1].end_time,
            {"data": packet_data.hex()},
        )

    packet_attributes = {
        "data": packet_data[:-1].hex(),
        "checksum": received_checksum,
    }

    packet_distance = (
        (packet_frames[0].start_time - last_end)
        if last_end
        else GraphTimeDelta(second=30)
    )

    if packet_distance < GraphTimeDelta(millisecond=300):
        # This was a response from the Controller, so source is HVAC.
        annotate_hvac_packet(packet_data, packet_attributes)
    else:
        annotate_panel_packet(packet_data, packet_attributes)

    return AnalyzerFrame(
        "valid_packet",
        packet_frames[0].start_time,
        packet_frames[-1].end_time,
        packet_attributes,
    )


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    result_types = {
        "invalid_checksum": {"format": "Invalid Checksum: {{data.packet}}"},
        "valid_packet": {"format": "{{data.source}} {{data.data}}"},
    }

    def __init__(self):
        """
        Initialize HLA.

        Settings can be accessed using the same name used above.
        """
        self._last_start = None
        self._last_end = None
        self._packet = []

    def decode(self, frame: AnalyzerFrame):
        if frame.type != "data":
            return

        if (
            self._packet
            and (frame.end_time - self._packet[-1].end_time) > _PACKETS_DISTANCE
        ):
            self._packet = []

        self._packet.append(frame)

        if len(self._packet) == 6:
            analyzed_frame = recompose_packet(self._packet, self._last_end)

            self._packet = []
            self._last_end = analyzed_frame.end_time

            return analyzed_frame
