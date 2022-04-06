import os
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

TCPDUMP_BASH_STRING = """timeout -s SIGKILL 55s tcpdump -ni 0.0:nnn -s0 host VIRTUAL_IP -vvv -w /shared/images/CASENUMBER_DATESTRING.pcap"""


def get_credentials():
    return {'host': os.getenv('F5_HOST'), 'user': os.getenv('F5_USER'), 'pass': os.getenv('F5_PASS')}


def instantiate_bigip():
    credentials = get_credentials()
    br = BIGIP(credentials.get('host'), credentials.get('user'), credentials.get('pass'), request_token=True)
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
    print(f'\t{msg}')


def prompt_user(msg: str) -> str:
    return str(input(f'\t{msg}'))


def run_tcpdump(bigip, virtual_name, case_number):
    datestring = datetime.now().strftime('%Y-%m-%d')
    vip = bigip.load(f'/mgmt/tm/ltm/virtual/{virtual_name}')
    virtual_ip = vip.properties.get('destination').split('/')[-1].split(':')[0]

    dump_string = TCPDUMP_BASH_STRING.replace('VIRTUAL_IP', virtual_ip)
    dump_string = dump_string.replace('CASENUMBER', case_number)
    dump_string = dump_string.replace('DATESTRING', datestring)
    print(f'\ttcpdump running, please reproduce your issue (waiting 55 sec)...')

    data = {'command': 'run', 'utilCmdArgs': f'-c "{dump_string}"'}
    # try:
    bigip.command('/mgmt/tm/util/bash', data)
    # except RESTAPIError as e:
    #     print(e, e.get('code'))
    sleep(56)
    return f'{case_number}_{datestring}.pcap'


def delete_bigip_file(bigip, file_name, msg):
    data = {'command': 'run', 'utilCmdArgs': f'/shared/images/{file_name}'}
    bigip.command('/mgmt/tm/util/unix-rm', data)
    print(f'\t{msg}')


def session_cache_enabled(bigip, profile_name):
    cssl_profile = bigip.load(f'/mgmt/tm/ltm/profile/client-ssl/{profile_name}')
    if cssl_profile.properties.get('cacheSize') == 0:
        return False
    elif cssl_profile.properties.get('cacheSize') > 0:
        return True


def user_responses():
    vip_name = prompt_user('Virtual name: ')
    client_ip = prompt_user('Client IP for test traffic: ')
    case_number = prompt_user('Case number: ')
    return vip_name, client_ip, case_number


def create_keyfile(bigip, profile_name, case_number):
    if session_cache_enabled(bigip, profile_name):
        cmd = f"sed -e 's/^.*\(RSA Session-ID\)/\\1/;tx;d;:x' /var/log/ltm > /shared/images/{case_number}_sessionsecrets.pms"
        cache_val = 'enabled'
    else:
        cmd = f"grep -h -o 'CLIENT_RANDOM.*' /var/log/ltm* > /shared/images/{case_number}_sessionsecrets.pms"
        cache_val = 'disabled'
    data = {'command': 'run', 'utilCmdArgs': f'-c "{cmd}"'}
    bigip.command('/mgmt/tm/util/bash', data)
    print(f'\tSecrets key file created (with cache {cache_val} command)...continuing.')
    return f'{case_number}_sessionsecrets.pms'


def download_support_files(bigip, tcpdump_file, sessionkey_file, qkview_file):
    download_file(bigip, tcpdump_file, f'{tcpdump_file} downloaded.')
    download_file(bigip, sessionkey_file, f'{sessionkey_file} downloaded.')
    download_file(bigip, qkview_file, f'{qkview_file} downloaded.')
    print(f'\tAll support files downloaded from /shared/images...continuing.')


def delete_support_files(bigip, tcpdump_file, sessionkey_file, qkview_file):
    delete_bigip_file(bigip, tcpdump_file, f'{tcpdump_file} deleted from BIG-IP.')
    delete_bigip_file(bigip, sessionkey_file, f'{sessionkey_file} deleted from BIG-IP.')
    delete_bigip_file(bigip, qkview_file, f'{qkview_file} deleted from BIG-IP.')
    print('\tAll support files cleaned up on BIG-IP...continuing.')


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


def generate_qkview(bigip, case_number):
    global_settings = bigip.load('/mgmt/tm/sys/global-settings')
    hostname = global_settings.properties.get('hostname')
    try:
        print('\tStarting qkview...standby.')
        data = {'command': 'run', 'utilCmdArgs': '-c "qkview"'}
        bigip.command('/mgmt/tm/util/bash', data)
    except RESTAPIError:
        pass
    while True:
        data = {'command': 'run', 'utilCmdArgs': f'-c "ps aux | grep qkview | wc -l"'}
        process_check = int(bigip.command('/mgmt/tm/util/bash', data))
        if process_check > 2:
            print('\tQkview still running...sleeping 10 seconds.')
            sleep(10)
            continue
        else:
            data = {'command': 'run', 'utilCmdArgs': f'/shared/tmp/{hostname}.qkview /shared/images/{case_number}_{hostname}.qkview'}
            bigip.command('/mgmt/tm/util/unix-mv', data)
            print('\tQkview complete...continuing.')
            break
    return f'{hostname}.qkview'


if __name__ == '__main__':

    print('\n\n\t#################################################')
    print('\t### BIG-IP tcpdump capture collection utility ###')
    print('\t#################################################\n\n')

    vip_name, client_ip, case_number = user_responses()
    br = instantiate_bigip()
    profile_name = get_cssl_profile(br, vip_name)
    create_irule(br, profile_name, client_ip)
    apply_irule(br, vip_name)
    tcpdump_file = run_tcpdump(br, vip_name, case_number)
    remove_irule(br, vip_name)
    delete_irule(br)
    sessionkey_file = create_keyfile(br, profile_name, case_number)
    qkview_file = generate_qkview(br, case_number)
    download_support_files(br, tcpdump_file, sessionkey_file, qkview_file)
    delete_support_files(br, tcpdump_file, sessionkey_file, qkview_file)

    # TODO - Apply sessionkeys file to capture file, save filtered output to new capture
    # TODO - Display to user: original pcap, session keys file, modified pcap
    # TODO - Test Cache Disabled
    # TODO - ERROR CHECKING
