import dataclasses
import math
import multiprocessing
import os
import re
import subprocess
from multiprocessing import Pool
from typing import Iterable

import pyshark


@dataclasses.dataclass
class CountJob:
    name: str
    input_file: str
    display_filter: str


@dataclasses.dataclass(frozen=True)
class CountJobResult:
    name: str
    count: int

    def __truediv__(self, other: 'CountJobResult') -> float:
        try:
            return self.count / other.count
        except (ZeroDivisionError, TypeError):
            return math.nan


def get_metadata(input_file):
    """
    Extract relevant metadata from PCAP file name.

    Pattern: <known-driver-name>[-<version-indicator>]-<STA MAC>-<direction>.pcap

    :param input_file: file name to analyze
    :return: Tuple (driver_name, driver_version, sta_mac, direction)
    """

    basename = os.path.basename(input_file)
    if m := re.search(
        '^(8192cu|rtl8192cu|rtl8xxxu)(-([^:]+))?-(([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2}))?-?([rt]x).pcap',
        basename,
    ):
        return m.group(1, 3, 4, 7)
    else:
        raise RuntimeError(f"Unexpected filename: {basename}")


def count_packets_process(job: CountJob) -> CountJobResult:
    count = 0

    def count_callback(_pkt):
        nonlocal count
        count += 1

    with pyshark.FileCapture(job.input_file, display_filter=job.display_filter, only_summaries=True) as capture:
        capture.set_debug()
        capture.apply_on_packets(count_callback)

    return CountJobResult(job.name, count)


def create_by_filter_capture(input_file: str, output_file: str, display_filter: str):
    """This implements some primitive caching mechanism. Saves 50-60% on 2nd+ run."""
    if not os.path.isfile(output_file):
        # Using PySharks PCAP writing feature seems to break the PySharks code :/
        subprocess.run(
            [
                'tshark',
                '-n',
                '-Y',
                display_filter,
                '-w',
                tmp_file := f'{output_file}.tmp',
                '-r',
                input_file,
            ],
            check=True,
        )
        os.rename(tmp_file, output_file)


def process_pcap_file(global_capture: str, ap_mac=None, dut_mac=None) -> Iterable[CountJobResult]:
    """All of this is due Python/PyShark being slow and me not having implemented a better way to speed it up."""
    create_by_filter_capture(
        global_capture,
        network_capture := f"{global_capture}-network",
        f'( wlan.fc.type_subtype != 0x0008) && (wlan.ta in {{{ap_mac} {dut_mac}}} || !wlan.ta)',
    )
    create_by_filter_capture(
        global_capture,
        by_ap_capture := f"{network_capture}-by-ap",
        f"(wlan.ta == {ap_mac})",
    )
    create_by_filter_capture(
        global_capture,
        by_dut_capture := f"{network_capture}-by-dut",
        f"(wlan.ta == {dut_mac})",
    )
    create_by_filter_capture(
        global_capture,
        by_other_capture := f"{network_capture}-by-other",
        f"wlan.ta && !(wlan.ta in {{{ap_mac} {dut_mac}}})",
    )
    create_by_filter_capture(
        global_capture, no_ta_capture := f"{network_capture}-no-ta", "!wlan.ta"
    )

    jobs = [
        CountJob(
            "global.network.amsdu_present",
            network_capture,
            "wlan.qos.amsdupresent == 1",
        ),
        CountJob(
            "global.network.ba_replies",
            network_capture,
            "wlan.fixed.category_code == 3 && wlan.fixed.action_code == 0x01",
        ),
        CountJob(
            "global.network.ba_requests",
            network_capture,
            "wlan.fixed.category_code == 3 && wlan.fixed.action_code == 0x00",
        ),
        CountJob(
            "global.network.by_ap.802_11b",
            by_ap_capture,
            "wlan_radio.phy == 4",
        ),
        CountJob(
            "global.network.by_ap.802_11g",
            by_ap_capture,
            "wlan_radio.phy == 6",
        ),
        CountJob(
            "global.network.by_ap.802_11n",
            by_ap_capture,
            "wlan_radio.phy == 7",
        ),
        CountJob("global.network.by_ap", by_ap_capture, ""),
        CountJob(
            "global.network.by_ap.retries", by_ap_capture, "wlan.fc.retry == 1"
        ),
        CountJob(
            "global.network.by_dut.802_11b",
            by_dut_capture,
            "wlan_radio.phy == 4",
        ),
        CountJob(
            "global.network.by_dut.802_11g",
            by_dut_capture,
            "wlan_radio.phy == 6",
        ),
        CountJob(
            "global.network.by_dut.802_11n",
            by_dut_capture,
            "wlan_radio.phy == 7",
        ),
        CountJob("global.network.by_dut", by_dut_capture, ""),
        CountJob(
            "global.network.by_dut.retries",
            by_dut_capture,
            "wlan.fc.retry == 1",
        ),
        CountJob("global.network.by_others", by_other_capture, ""),
        CountJob(
            "global.network.by_others.retries",
            by_other_capture,
            "wlan.fc.retry == 1",
        ),
        CountJob("global.network.no_ta", no_ta_capture, ""),
        CountJob(
            "global.network.no_ta.retries", no_ta_capture, "wlan.fc.retry == 1"
        ),
        CountJob("global.network", network_capture, ""),
        CountJob(
            "global.network.retries", network_capture, "wlan.fc.retry == 1"
        ),
        CountJob("global", global_capture, ""),
        CountJob("global.retries", global_capture, "wlan.fc.retry == 1"),
    ]

    with Pool(processes=multiprocessing.cpu_count()) as pool:
        return pool.map(count_packets_process, jobs)
