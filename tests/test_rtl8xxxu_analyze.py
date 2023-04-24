import os.path
from multiprocessing import Value

import pytest

from analyze import get_metadata, count_packets_process, CountJob, CountJobResult


def test_get_metadata_invalid_filenames():
    with pytest.raises(RuntimeError):
        get_metadata("")
    with pytest.raises(RuntimeError):
        get_metadata("rtl8xxxu-rs-rtl8xxxu-testing-for-chris-2021-10-18-v2-00:1d:43:c0:0b:50-tx")
    with pytest.raises(RuntimeError):
        get_metadata("rtl8xxxu-rs-rtl8xxxu-testing-for-chris-2021-10-18-v2-00:1d:43:c0:0b:50.pcap")
    with pytest.raises(RuntimeError):
        get_metadata("rs-rtl8xxxu-testing-for-chris-2021-10-18-v2-00:1d:43:c0:0b:50-tx.pcap")
    with pytest.raises(RuntimeError):
        get_metadata("iwifi-rs-rtl8xxxu-testing-for-chris-2021-10-18-v2-00:1d:43:c0:0b:50-tx.pcap")
    with pytest.raises(RuntimeError):
        get_metadata("rtl8xxxu-rs-rtl8xxxu-testing-for-chris-2021-10-18-v2-00:1d:43:c0:0b:50-Xx.pcap")


def test_get_metadata_valid_filenames():
    driver_name, driver_version, sta_mac, direction = get_metadata(
        "rtl8xxxu-rs-rtl8xxxu-testing-for-chris-2021-10-18-v2-00:1d:43:c0:0b:50-tx.pcap")
    assert driver_name == "rtl8xxxu"
    assert driver_version == "rs-rtl8xxxu-testing-for-chris-2021-10-18-v2"
    assert direction == "tx"
    assert sta_mac == "00:1d:43:c0:0b:50"

    driver_name, driver_version, sta_mac, direction = get_metadata("8192cu-00:11:22:33:44:55-rx.pcap")
    assert driver_name == "8192cu"
    assert driver_version is None
    assert direction == "rx"
    assert sta_mac == "00:11:22:33:44:55"


@pytest.fixture()
def path_to_pcap():
    return f'{os.path.dirname(__file__)}/rtl8xxxu_capture.pcap'


def test_count_packets_no_filter(path_to_pcap):
    job = CountJob('Name', path_to_pcap, '')
    result = count_packets_process(job)
    assert isinstance(result, CountJobResult)
    assert result.name == 'Name'
    assert result.count == 5068


def test_count_packets_retries(path_to_pcap):
    job = CountJob('', path_to_pcap, 'wlan.fc.retry == 1')
    result = count_packets_process(job)
    assert result.count == 831
