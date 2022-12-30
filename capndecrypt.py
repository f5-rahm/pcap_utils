# This tool will in order:
# - Apply iRule to capture appropriate session keys
# - Kick off a tcpdump session on BIG-IP for N seconds with supplied capture filter arguments
# - Save keys from log entries into a file
# - Remove the iRule for key capture
# - Download capture and key files
# - Delete the capture and key files from BIG-IP
# - Use keyfile to decrypt the capture and save a decrypted copy

import os
import subprocess
import sys
from datetime import datetime
from time import sleep

from bigrest.bigip import BIGIP
from bigrest.common.exceptions import RESTAPIError

IRULE_CACHE_ENABLED = """when CLIENTSSL_HANDSHAKE {
  if { [IP::addr [getfield [IP::client_addr] "%" 1] equals CLIENT_IP_PLACEHOLDER] } {
    log local0. "[TCP::client_port] :: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
  }
}"""

IRULE_CACHE_DISABLED = """when CLIENTSSL_HANDSHAKE {
 if {[IP::addr [getfield [IP::client_addr] "%" 1] equals CLIENT_IP_PLACEHOLDER] } {
   log local0. "CLIENT_Side_IP:TCP source port: [IP::client_addr]:[TCP::remote_port]"
   log local0. "CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
   log local0. "RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
 }
}"""

TCPDUMP_BASH_STRING = """timeout -s SIGKILL CAP_SECS tcpdump -ni 0.0:nnn -s0 VIRTUAL_IP -vvv -w /shared/images/autocap_DATESTRING.pcap"""


def get_credentials():
    return os.getenv('F5_HOST'), os.getenv('F5_USER'), os.getenv('F5_PASS')


def instantiate_bigip(duration):
    host, user, pw = get_credentials()
    br = BIGIP(host, user, pw, request_token=True, session_verify=False, timeout=duration+5)
    # br = BIGIP('ltm3.test.local', 'admin', 'admin', request_token=True, session_verify=False, timeout=90)
    data = {'timeout': '300'}
    br.modify(f"/mgmt/shared/authz/tokens/{br.session.headers._store.get('x-f5-auth-token')[1]}", data)
    return br


def create_irule(bigip, profile_name, client_ip):
    if session_cache_enabled(bigip, profile_name):
        irule = IRULE_CACHE_ENABLED.replace('CLIENT_IP_PLACEHOLDER', client_ip)
        cache_val = 'enabled'
    else:
        irule = IRULE_CACHE_DISABLED.replace('CLIENT_IP_PLACEHOLDER', client_ip)
        cache_val = 'disabled'

    if br.exist(f'/mgmt/tm/ltm/rule/keylogger'):
        rule = br.load('/mgmt/tm/ltm/rule/keylogger')
        rule.properties['apiAnonymous'] = irule
        br.save(rule)
    else:
        data = {'name': 'keylogger', 'apiAnonymous': irule}
        br.create('/mgmt/tm/ltm/rule', data)
    print(f'\tSession keylogger iRule (cache {cache_val} version) created...continuing.')


def apply_irule(bigip, virtual_name):
    vip = bigip.load(f'/mgmt/tm/ltm/virtual/{virtual_name}')
    if vip.properties.get('rules') is None:
        vip.properties['rules'] = ['keylogger']
    else:
        vip.properties['rules'].append('keylogger')
    bigip.save(vip)
    print(f'\tSession keylogger iRule applied to {virtual_name}...continuing.')


def remove_irule(bigip, virtual_name):
    vip = bigip.load(f'/mgmt/tm/ltm/virtual/{virtual_name}')
    vip.properties['rules'].remove('/Common/keylogger')
    bigip.save(vip)
    print(f'\tSession keylogger iRule removed from {virtual_name}...continuing.')


def delete_irule(bigip):
    bigip.delete('/mgmt/tm/ltm/rule/~Common~keylogger')
    print('\tkeylogger iRule deleted...continuing.')


def download_file(bigip, file_name, msg):
    bigip.download('/mgmt/cm/autodeploy/software-image-downloads/', file_name)
    if os.sys.platform == 'win32':
        os.rename(file_name, f'outputfiles\{file_name}')
    else:
        os.rename(file_name, f'output_files/{file_name}')
    print(f'{msg}')


def prompt_user(msg: str) -> str:
    return str(input(f'\t{msg}'))


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


def session_cache_enabled(bigip, profile_name):
    cssl_profile = bigip.load(f'/mgmt/tm/ltm/profile/client-ssl/{profile_name}')
    if cssl_profile.properties.get('cacheSize') == 0:
        return False
    elif cssl_profile.properties.get('cacheSize') > 0:
        return True


def user_responses():
    vip_name = prompt_user('Virtual name: ')
    client_ip = prompt_user('Client IP for test traffic (type what is my IP in browser): ')
    duration = prompt_user('Duration in seconds for capture: ')
    filters = prompt_user('Capture filters in addition to vip [ex. "and (port 80 or port 443)" ]: ')
    return vip_name, client_ip, duration, filters


def create_keyfile(bigip, profile_name):
    if session_cache_enabled(bigip, profile_name):
        cmd = f"sed -e 's/^.*\(RSA Session-ID\)/\\1/;tx;d;:x' /var/log/ltm > /shared/images/autocap_sessionsecrets.pms"
        cache_val = 'enabled'
    else:
        cmd = f"grep -h -o 'CLIENT_RANDOM.*' /var/log/ltm* > /shared/images/autocap_sessionsecrets.pms"
        cache_val = 'disabled'
    data = {'command': 'run', 'utilCmdArgs': f'-c "{cmd}"'}
    bigip.command('/mgmt/tm/util/bash', data)
    print(f'\tSecrets key file created (with cache {cache_val} command)...continuing.')
    return f'autocap_sessionsecrets.pms'


def download_files(bigip, tcpdump_file, sessionkey_file):
    print(f'\tDownloading capture and key files from BIG-IP.')
    download_file(bigip, tcpdump_file, f'\t\t{tcpdump_file} downloaded.')
    download_file(bigip, sessionkey_file, f'\t\t{sessionkey_file} downloaded.')
    print(f'\tAll files downloaded...continuing.')


def delete_files(bigip, tcpdump_file, sessionkey_file):
    print(f'\tCleaning up capture and key files on BIG-IP.')
    delete_file(bigip, tcpdump_file, f'\t\t{tcpdump_file} deleted.')
    delete_file(bigip, sessionkey_file, f'\t\t{sessionkey_file} deleted.')
    print('\tAll files cleaned up on BIG-IP...continuing.')


def get_cssl_profile(bigip, vip_name):
    vip_profiles = bigip.load(f'/mgmt/tm/ltm/virtual/{vip_name}/profiles')
    cssl_profile = ''
    for profile in vip_profiles:
        if bigip.exist(f'/mgmt/tm/ltm/profile/client-ssl/{profile.properties.get("name")}'):
            cssl_profile = profile.properties.get('name')
    if cssl_profile != '':
        print(f'\tVirtual {vip_name} has associated client-ssl profile {cssl_profile}...continuing.')
        return cssl_profile
    else:
        sys.exit(f'\tVirtual {vip_name} has no associated client-ssl profile...exiting.')


def decrypt_capture(tcpdump_file, sessionkey_file):
    print(f'\tDecrypting capture {tcpdump_file} with session keys in {sessionkey_file}.')
    dir = 'output_files'
    cmd = f'editcap --inject-secrets tls,{dir}/{sessionkey_file} {dir}/{tcpdump_file} {dir}/decrypted_{tcpdump_file}'
    decrypt_file = subprocess.run(['editcap',
                                   '--inject-secrets',
                                   f'tls,{dir}/{sessionkey_file}',
                                   f'{dir}/{tcpdump_file}',
                                   f'{dir}/decrypted_{tcpdump_file}'],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.STDOUT)
    print(f'\tDecrypted file: {dir}/decrypted_{tcpdump_file}...continuing.')


if __name__ == '__main__':

    print('\n\n\t#################################################')
    print('\t### BIG-IP tcpdump capture collection utility ###')
    print('\t#################################################\n')

    vip_name, client_ip, duration, filters = user_responses()

    print('\n\t-------------------------------------------------\n')
    br = instantiate_bigip(int(duration))
    profile_name = get_cssl_profile(br, vip_name)
    create_irule(br, profile_name, client_ip)
    apply_irule(br, vip_name)
    tcpdump_file = run_tcpdump(br, duration, vip_name, filters)
    remove_irule(br, vip_name)
    delete_irule(br)
    sessionkey_file = create_keyfile(br, profile_name)
    download_files(br, tcpdump_file, sessionkey_file)
    delete_files(br, tcpdump_file, sessionkey_file)

    decrypt_capture(tcpdump_file, sessionkey_file)
    print('\t\n-------------------------------------------------\n')
    print('Process complete...now go analyze some packets!')
