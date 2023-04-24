#!/usr/bin/env python3
import argparse
import datetime
import itertools
import logging
import re
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

from fabric import Connection
from invoke import CommandTimedOut

log = logging.getLogger('rtl8xxxu benchmark')
hide_ssh_output = True


class DUT:
    def __init__(self, hostname: str):
        self.hostname = hostname
        self.connection = Connection(f'root@{self.hostname}')
        self.unload_all_drivers()
        self.flush_logs()
        self.wlan_interface = self.connection.run(
            "modprobe rtl8xxxu && sleep 3 && cd /sys/class/net/ && ls -d wlx*", timeout=10,
            hide=hide_ssh_output).stdout.strip()
        if not self.wlan_interface:
            raise RuntimeError("Could not figure out WLAN interface on DUT")
        self.wpa_supplicant_stop()
        self.unload_all_drivers()

    def flush_logs(self):
        log.info('Flushing journalctl')
        self.connection.run('sudo journalctl --rotate --vacuum-size=1', timeout=5, hide=hide_ssh_output)

    @property
    def phy_index(self):
        """ Works only for mac80211 drivers (rtl8xxxu, rtl8192cu) """
        phy_index = self.connection.run(
            f'cat /sys/class/net/{self.wlan_interface}/device/ieee80211/phy*/index', timeout=5,
            hide=hide_ssh_output).stdout.strip()
        return int(phy_index)

    def unload_all_drivers(self):
        log.info('Unloading all drivers')
        self.connection.run('rmmod rtl8xxxu rtl8192cu rtl8192c_common rtl_usb rtlwifi 8192cu 2>/dev/null',
                            warn=True,
                            timeout=5,
                            hide=hide_ssh_output)

    def wpa_supplicant_stop(self):
        log.info('Stopping wpa_supplicant')
        self.connection.run(f'systemctl stop wpa_supplicant@{self.wlan_interface}.service', timeout=15,
                            hide=hide_ssh_output)

    def wpa_supplicant_start(self):
        log.info('Starting wpa_supplicant')
        self.connection.run(f'systemctl start wpa_supplicant@{self.wlan_interface}.service', timeout=15,
                            hide=hide_ssh_output)

    def dhclient_request(self):
        log.info('Request IPv4 address via DHCP')
        self.connection.run(f'dhclient -i  {self.wlan_interface}', timeout=30, hide=hide_ssh_output)

    def dhclient_release(self):
        log.info('Return IPv4 address via DHCP')
        self.connection.run(f'dhclient -r  {self.wlan_interface}', timeout=15, hide=hide_ssh_output)

    def load_driver(self, driver):
        log.info(f'Loading driver "{driver}"')
        for dependency in driver.driver_dependencies():
            self.connection.run(f'modprobe {dependency}', timeout=10, hide=hide_ssh_output)
        for driver_filename in driver.driver_filenames():
            self.connection.run(f'insmod {driver_filename} {driver.load_arguments}', timeout=10, hide=hide_ssh_output)

    def set_link_up(self):
        log.info(f'Setting link {self.wlan_interface} up')
        self.connection.run(f'ip link set dev {self.wlan_interface} up', timeout=10, hide=hide_ssh_output)

    def setup_wpa_supplicant(self, network_ssid, network_psk):
        log.info('Configuring wpa_supplicant')
        self.connection.run(
            f'''mkdir -p /etc/wpa_supplicant/ &&
             echo "network={{
             ssid=\\"{network_ssid}\\"
             scan_ssid=1
             key_mgmt=WPA-PSK
             psk=\\"{network_psk}\\"
            }}" > /etc/wpa_supplicant/wpa_supplicant-{self.wlan_interface}.conf''', timeout=5, hide=hide_ssh_output)


class Driver:
    name: str
    src_dir: str
    linux_build_dir: str
    module_args: str

    def __init__(self, name, src_dir, linux_build_dir, module_args=''):
        self.name = name
        self.src_dir = src_dir
        self.linux_build_dir = linux_build_dir
        self.version = subprocess.check_output(
            ['git', '-C', self.src_dir, 'describe', '--tags', '--dirty']).decode().strip()

    def __str__(self):
        return self.name

    @property
    def load_arguments(self):
        args = 'dyndbg=+p'
        if self.name == 'rtl8192cu':
            args += ' debug_level=5 debug_mask=0xFFFFF'
        elif self.name == 'rtl8xxxu':
            args += ' debug=0xFFFFF dma_aggregation=1 rtl8xxxu_dma_agg_timeout=127'
        return args

    @property
    def version_usable_on_filesystem(self):
        return self.version.replace('/', '-')

    def sources_are_clean(self):
        """Return true if driver source repository is clean, false otherwise"""
        diff = subprocess.check_output(['git', '-C', self.src_dir, 'diff', 'HEAD']).decode().strip()
        if diff:
            log.warning(f'Repository in {self.src_dir} is not clean!')
            log.warning(diff)
        return diff == ""

    def build(self):
        log.info(f'Building driver {self.name}')
        number_of_build_processes_to_launch = subprocess.check_output('nproc').decode().strip()
        if self.name in ('rtl8192cu', 'rtl8xxxu'):
            subdirectory = 'rtlwifi' if self.name == 'rtl8192cu' else 'rtl8xxxu'
            subprocess.check_output(['make',
                                     '-C',
                                     f'{self.linux_build_dir}',
                                     'CC=ccache gcc',
                                     f'-j{number_of_build_processes_to_launch}',
                                     'modules',
                                     f'SUBDIRS=drivers/net/wireless/realtek/{subdirectory}'])
        elif self.name == '8192cu':
            subprocess.check_output(['make',
                                     '-C',
                                     f'{self.src_dir}',
                                     'CC=ccache gcc',
                                     f'-j{number_of_build_processes_to_launch}',
                                     f'KSRC={self.linux_build_dir}',
                                     'CONFIG_PLATFORM_I386_PC=y'])

    def _append_version_to_ko_filename(self, kernel_module_filename: str):
        """Turn a plain "module.ko" filename in a versioned one"""
        return kernel_module_filename.replace('.ko', f'-{self.version_usable_on_filesystem}.ko')

    @property
    def versioned_driver_filename(self):
        return self._append_version_to_ko_filename(f'{self.name}.ko')

    def deploy(self, connection):
        if self.name == 'rtl8xxxu':
            connection.put(f'{self.linux_build_dir}/drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.ko',
                           remote=self.versioned_driver_filename)
        elif self.name == 'rtl8192cu':
            for local_file in ['rtlwifi.ko', 'rtl_usb.ko', 'rtl8192c/rtl8192c-common.ko', 'rtl8192cu/rtl8192cu.ko']:
                remote_file = self._append_version_to_ko_filename(local_file.split('/')[-1])
                connection.put(f'{self.linux_build_dir}/drivers/net/wireless/realtek/rtlwifi/{local_file}',
                               remote=remote_file)
        elif self.name == '8192cu':
            connection.put(f'{self.src_dir}/8192cu.ko', remote=self.versioned_driver_filename)

    def driver_dependencies(self):
        """Modules having to be loaded before insmod-ing a this driver"""
        return ['cfg80211'] if self.name == '8192cu' else ['mac80211']

    def driver_filenames(self):
        if self.name in ('rtl8xxxu', '8192cu'):
            return [self.versioned_driver_filename]

        return [self._append_version_to_ko_filename(file)
                for file in ['rtlwifi.ko', 'rtl_usb.ko', 'rtl8192c-common.ko', 'rtl8192cu.ko']]


def ipv4_tcp_port_is_open(host, port):
    """Test if a given IPv4 TCP port is in use"""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex((host, port)) == 0


def linux_src_from_build_directory(linux_build_directory):
    with open(f'{linux_build_directory}/Makefile') as makefile:
        include_line = makefile.readlines()[1]
        m = re.match('^include (.+)/Makefile$', include_line)
        return m[1]


def run_and_save(cmd, dut, filename, timeout=30) -> str:
    log.info(f'Execute on {dut.hostname}: {cmd}')
    output = dut.connection.run(cmd, timeout=timeout, hide=hide_ssh_output).stdout
    with open(filename, 'w') as f:
        f.write(output)
    return output.strip()


def dump_registers(dut, driver, filename_prefix, state):
    registers = ['bb_reg_dump', 'mac_reg_dump', 'rf_reg_dump']
    for reg in registers:
        if driver.name == '8192cu':
            reg_file = f'/proc/1/net/8192cu/{dut.wlan_interface}/{reg}'
        elif driver.name == 'rtl8xxxu':
            reg_file = f'/sys/kernel/debug/ieee80211/phy{dut.phy_index}/rtl8xxxu/{reg}'
        elif driver.name == 'rtl8192cu':
            reg_file = f'/sys/kernel/debug/ieee80211/phy{dut.phy_index}/rtlwifi/{reg}'
        log.info(f'Dumping register {reg} from {reg_file}')
        dut.connection.get(reg_file, f'{filename_prefix}-{state}-{reg}')


def terminate_process(proc, proc_name, acceptable_return_codes: [int] = None):
    if acceptable_return_codes is None:
        acceptable_return_codes = [0]
    log.info(f'Terminate {proc_name} instance')
    proc.terminate()
    outs, errs = proc.communicate()
    if proc.returncode not in acceptable_return_codes:
        log.error(f'Execution of "{" ".join(proc.args)}" failed with code {proc.returncode}: {errs.decode()}')
        if outs:
            log.info(f'{proc_name} stdout: {outs.decode()}')
        if errs:
            log.warning(f'{proc_name} stderr: {errs.decode()}')
        sys.exit(-1)


def main():
    parser = argparse.ArgumentParser(description='Benchmark rtl8xxxu/8192cu/rtl8192cu drivers')
    parser.add_argument('-l', '--log-level',
                        default='WARNING',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Minimum priority for log messages to be printed.')
    parser.add_argument('--dut',
                        required=True,
                        metavar='hostname',
                        help='Machine to log into via SSH as root, run drivers on',
                        type=str)
    parser.add_argument('--directions',
                        required=True,
                        choices=['rx', 'tx'],
                        nargs='+',
                        help='Main traffic flow direction: DUT to AP (tx), AP to DUT (rx)',
                        dest='directions',
                        action='extend')
    parser.add_argument('--driver',
                        choices=['rtl8xxxu', '8192cu', 'rtl8192cu'],
                        default=['rtl8xxxu', '8192cu', 'rtl8192cu'],
                        type=str,
                        nargs='+',
                        dest='drivers',
                        action='store')
    parser.add_argument('--mon-interface',
                        required=True,
                        type=str,
                        help="Local 802.11 capture interface. Must be listening on APs channel!",
                        action='store'
                        )
    parser.add_argument('--network-ssid',
                        type=str,
                        action='store',
                        default='rtl8xxxu-testwifi'
                        )
    parser.add_argument('--network-psk',
                        required=True,
                        type=str,
                        action='store'
                        )
    parser.add_argument('--linux-build-directory',
                        required=True,
                        type=str,
                        action='store',
                        )
    parser.add_argument('--realtek-8192cu-directory',
                        type=str,
                        action='store',
                        help="Needed when testing 8192cu driver",
                        )
    parser.add_argument('--iperf3-port',
                        type=int,
                        action='store',
                        default=5202,  # Non default value to minimize collisions
                        help="Port to have iperf3 communicate on",
                        )
    parser.add_argument('--iperf3-host',
                        type=str,
                        action='store',
                        default='10.42.0.1',
                        help="Hostname or IP address of Iperf3 server",
                        )
    parser.add_argument('--save-to',
                        type=str,
                        action='store',
                        default='.',
                        help="Location to store the results",
                        )
    args = parser.parse_args()

    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {args.log_level}')
    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', stream=sys.stderr)
    log.setLevel(numeric_level)
    global hide_ssh_output
    hide_ssh_output = args.log_level.upper() != 'DEBUG'
    log.info(f'Setting logging level to {numeric_level}')
    log.info(
        f'Testing on {args.dut}: directions {{{", ".join(args.directions)}}}, drivers {{{", ".join(args.drivers)}}}')
    log.info(f'sniffing interface: {args.mon_interface}')

    dirname = f'{args.dut}-{datetime.datetime.now().replace(microsecond=0).isoformat()}'
    log.info(f'Saving data in directory {args.save_to}/{dirname}')

    # Sanitize arguments
    if '8192cu' in args.drivers and not args.realtek_8192cu_directory:
        log.fatal('Argument --realtek-8192cu-directory needed when testing 8192cu')
        sys.exit(-1)
    # Check if IPerf3 server port is still available, produce descriptive error message if not
    if ipv4_tcp_port_is_open('localhost', args.iperf3_port):
        log.fatal(f'IPerf3 port ({args.iperf3_port}) is already in use!')
        sys.exit(-1)

    # Ensure drivers are built
    drivers = {}
    for driver_name in list(set(args.drivers)):
        src_dir = args.realtek_8192cu_directory if driver_name == '8192cu' else linux_src_from_build_directory(
            args.linux_build_directory)
        driver = Driver(driver_name, src_dir, args.linux_build_directory)
        if not driver.sources_are_clean():
            log.fatal('Refusing to work on dirty source directory!')
            sys.exit(-1)
        driver.build()
        drivers[driver_name] = driver

    # Setup DUT
    dut = DUT(args.dut)
    log.info(f'802.11 interface to run tests on: {dut.wlan_interface}')
    for driver in drivers.values():
        driver.deploy(dut.connection)
    dut.setup_wpa_supplicant(args.network_ssid, args.network_psk)

    # Create directories locally
    Path(f'{args.save_to}/{dirname}').mkdir(parents=True)
    symlink_name = Path(f'{args.save_to}/latest')
    symlink_name.unlink(missing_ok=True)
    symlink_name.symlink_to(dirname)

    # Run test with all driver and direction combinations
    run_and_save('journalctl', dut, f'{args.save_to}/{dirname}/initial-journalctl')
    for direction, driver in itertools.product(args.directions, drivers.values()):
        log.info(f'Testing driver {driver} in direction {direction}')
        log_filename_prefix = f'{args.save_to}/{dirname}/{driver.versioned_driver_filename}-{direction}'
        dut.wpa_supplicant_stop()
        dut.unload_all_drivers()
        dut.flush_logs()
        with (subprocess.Popen(['tcpdump', '-i', args.mon_interface, '-U', '-w', f'{log_filename_prefix}.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as tcpdump, subprocess.Popen(['iperf3', '-s', '-1', '--port', str(args.iperf3_port)], stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE) as iperf3_server):
            try:
                dut.load_driver(driver)
                time.sleep(1)  # 8192cu drivers needs some time to initialize
                # dump_registers(dut, driver, log_filename_prefix, "00-driver-loaded")
                time.sleep(3)  # 8192cu drivers needs some time to initialize
                dut.set_link_up()
                dump_registers(dut, driver, log_filename_prefix, "01-link-up")
                run_and_save('iw list', dut, f'{log_filename_prefix}.iw-list')
                run_and_save(f'iw dev {dut.wlan_interface} scan', dut, f'{log_filename_prefix}.iw-scan')
                dump_registers(dut, driver, log_filename_prefix, "02-scan-done")
                dut.wpa_supplicant_start()
                dut.dhclient_request()
                dump_registers(dut, driver, log_filename_prefix, "04-ip-address-received")
                iperf_direction_arg = '--reverse' if direction == 'rx' else ''
                iperf_result = run_and_save(
                    f'iperf3 {iperf_direction_arg} -c {args.iperf3_host} --port {args.iperf3_port}', dut,
                    f'{log_filename_prefix}.iperf3')
                lines = iperf_result.splitlines()

                dump_registers(dut, driver, log_filename_prefix, "05-iperf-completed")
            except Exception as e:
                log.fatal(e)
                sys.exit(-1)
            finally:
                terminate_process(tcpdump, 'tcpdump')
                terminate_process(iperf3_server, 'iperf3 server', [0, 1])
                run_and_save('journalctl', dut, f'{log_filename_prefix}.journalctl')

        run_and_save(f'iw dev {dut.wlan_interface} station dump', dut, f'{log_filename_prefix}.iw-station-dump')
        dut.dhclient_release()
        dut.wpa_supplicant_stop()
        dump_registers(dut, driver, log_filename_prefix, "06-wpa-supplicant-stopped")


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as e:
        log.fatal(f'Failed to execute command "{e.cmd}"')
        sys.exit(-1)
    except CommandTimedOut as e:
        log.fatal(f'Command "{e.result.command}" timed out after {e.timeout} seconds')
        sys.exit(-1)
    except Exception as e:
        log.fatal(e)
        sys.exit(-1)
