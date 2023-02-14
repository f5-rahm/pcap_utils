'''
### This script will: ###
1. Enable the database key on BIG-IP to inject tls session keys into packet captures
2. Run tcpdump with the --f5 ssl:v flags to capture traffic WITH session keys
3. Disable the tls session keys database key
4. Download tcpdump capture from BIG-IP
5. Delete tcpdump capture on BIG-IP
6. Extract session keys from tcpdump capture
7. Create a decrypted tcpdump capture from the encrypted capture + session keys file
'''

import os
import subprocess
from datetime import datetime
from time import sleep

from bigrest.bigip import BIGIP
from bigrest.common.exceptions import RESTAPIError


TCPDUMP_BASH_STRING = """timeout -s SIGKILL CAP_SECS tcpdump  -s0 -nni 0.0:nnnp --f5 ssl:v VIRTUAL_IP -w /shared/images/autocap_DATESTRING.pcap"""


def get_credentials():
    return os.getenv('F5_HOST'), os.getenv('F5_USER'), os.getenv('F5_PASS')


def instantiate_bigip(duration):
    host, user, pw = get_credentials()
    br = BIGIP(host, user, pw, request_token=True, session_verify=False, timeout=duration+5)
    br.modify(f"/mgmt/shared/authz/tokens/{br.session.headers._store.get('x-f5-auth-token')[1]}", {'timeout': '300'})
    return br


def download_file(bigip, file_name, msg):
    bigip.download('/mgmt/cm/autodeploy/software-image-downloads/', file_name)
    if os.sys.platform == 'win32':
        os.rename(file_name, f'{file_name}')
    else:
        os.rename(file_name, f'{file_name}')
    print(f'{msg}')


def prompt_user(msg: str) -> str:
    return str(input(f'\t{msg}'))


def toggle_sslprovider(bigip, state):
    data = {'value': state}
    bigip.modify('/mgmt/tm/sys/db/tcpdump.sslprovider', data)
    print(f'\tDatabase key tcpdump.sslprovider has been {state}d...continuing.')


def run_tcpdump(bigip, duration, virtual_name, filters):
    datestring = datetime.now().strftime('%Y%m%d-%H%M%S')
    vip = bigip.load(f'/mgmt/tm/ltm/virtual/{virtual_name}')
    virtual_ip = vip.properties.get('destination').split('/')[-1].split(':')[0]

    dump_string = TCPDUMP_BASH_STRING.replace('CAP_SECS', duration)
    if filters == '':
        dump_string = dump_string.replace('VIRTUAL_IP', f'host {virtual_ip}')
    else:
        dump_string = dump_string.replace('VIRTUAL_IP', f'host {virtual_ip} {filters} ')
        print(dump_string)
    dump_string = dump_string.replace('DATESTRING', datestring)

    try:
        print(f'\tStarting tcpdump...please reproduce your issue now.')
        data = {'command': 'run', 'utilCmdArgs': f'-c "{dump_string}"'}
        bigip.command('/mgmt/tm/util/bash', data)
    except RESTAPIError:
        pass
    sleep(5)
    print(f'\ttcpdump complete...continuing.')
    return f'autocap_{datestring}.pcap'


def delete_file(bigip, file_name, msg):
    data = {'command': 'run', 'utilCmdArgs': f'/shared/images/{file_name}'}
    bigip.command('/mgmt/tm/util/unix-rm', data)
    print(f'{msg}')


def user_responses():
    vip_name = prompt_user('Virtual name: ')
    duration = prompt_user('Duration in seconds for capture: ')
    filters = prompt_user('Capture filters in addition to vip [ex. "and (port 80 or port 443)" ]: ')
    return vip_name, duration, filters


def download_files(bigip, tcpdump_file):
    print(f'\tDownloading capture and key files from BIG-IP.')
    download_file(bigip, tcpdump_file, f'\t\t{tcpdump_file} downloaded.')
    print(f'\tAll files downloaded...continuing.')


def delete_files(bigip, tcpdump_file):
    print(f'\tCleaning up capture and key files on BIG-IP.')
    delete_file(bigip, tcpdump_file, f'\t\t{tcpdump_file} deleted.')
    print('\tAll files cleaned up on BIG-IP...continuing.')


def extract_keys(tcpdump_file):
    tshark_process = subprocess.run(["tshark",
                                     "-r", f"{tcpdump_file}",
                                     "-Y", "f5ethtrailer.tls.keylog",
                                     "-Tfields",
                                     "-e", "f5ethtrailer.tls.keylog"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    keyfile = open('session_keys.pms', 'w')
    subprocess.run(["sed",
                    "s/,/\\n/g"],
                   input=tshark_process.stdout,
                   stdout=keyfile,
                   stderr=subprocess.STDOUT)
    keyfile.close()
    print('\tExtracted keys file: session_keys.pms...continuing.')


def decrypt_capture(tcpdump_file):
    print(f'\tDecrypting capture {tcpdump_file} with session keys in session_keys.pms.')
    subprocess.run(['editcap',
                    '--inject-secrets',
                    f'tls,session_keys.pms',
                    f'{tcpdump_file}',
                    f'decrypted_{tcpdump_file}'],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.STDOUT)
    print(f'\tDecrypted file: decrypted_{tcpdump_file}...continuing.')


if __name__ == '__main__':

    print('\n\n\t#################################################')
    print('\t### BIG-IP tcpdump capture collection utility ###')
    print('\t#################################################\n')

    vip_name, duration, filters = user_responses()

    print('\n\t-------------------------------------------------\n')
    br = instantiate_bigip(int(duration))

    toggle_sslprovider(br, 'enable')
    tcpdump_file = run_tcpdump(br, duration, vip_name, filters)
    toggle_sslprovider(br, 'disable')

    download_files(br, tcpdump_file)
    delete_files(br, tcpdump_file)

    extract_keys(tcpdump_file)
    decrypt_capture(tcpdump_file)
    print('\t\n-------------------------------------------------\n')
    print('Process complete...now go analyze some packets!')
