"""Restore missing gateway plumbing using the installed MOH network config."""
import ipaddress,json,os,re,subprocess
from pathlib import Path

def run(args, check=True):
    result=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[:300])
    return result

def ensure_gateway():
    lan=os.environ.get('KNP_LAN','eth0')
    wan=os.environ.get('KNP_WAN','wlan0')
    if lan==wan or not all(re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',i) for i in (lan,wan)):
        raise ValueError('Invalid network interfaces')
    interfaces=json.loads(run(['ip','-j','address','show']).stdout)
    interface=next((i for i in interfaces if i['ifname']==lan),None)
    if not interface:
        raise RuntimeError('LAN interface missing; retry on next timer tick')
    run(['ip','link','set',lan,'up'])
    current={a.get('local') for a in interface.get('addr_info',[])}
    # Do not relocate an address already assigned to another interface.
    for address,prefix in [('192.168.5.1','24'),('192.168.100.1','32')]:
        if address not in current:
            for other in interfaces:
                if other['ifname']!=lan and any(a.get('local')==address for a in other.get('addr_info',[])):
                    raise RuntimeError('Gateway address belongs to another interface')
            for route in json.loads(run(['ip','-j','-4','route','show','table','all']).stdout):
                dst=route.get('dst','default')
                if dst!='default' and route.get('dev')!=lan and ipaddress.ip_address(address) in ipaddress.ip_network(dst,strict=False):
                    raise RuntimeError('Gateway address overlaps another interface route')
            run(['ip','address','add',address+'/'+prefix,'dev',lan])
    # Fail closed: restore saved authorization policy before enabling forwarding.
    if run(['nft','list','table','inet','kali_net_panel'],False).returncode:
        run(['sysctl','-w','net.ipv4.ip_forward=0'])
        run(['python3','/usr/local/lib/kali-net-panel/panel.py','--init'])
    run(['sysctl','-w','net.ipv4.ip_forward=1'])
    rules=[['-t','nat','POSTROUTING','-s','192.168.5.0/24','-o',wan,'-j','MASQUERADE'],
           ['FORWARD','-i',lan,'-o',wan,'-s','192.168.5.0/24','-j','ACCEPT'],
           ['FORWARD','-i',wan,'-o',lan,'-d','192.168.5.0/24','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT']]
    for rule in rules:
        prefix=rule[:2] if rule[0]=='-t' else []
        rest=rule[2:] if prefix else rule
        if run(['iptables','-w','3',*prefix,'-C',*rest],False).returncode:
            run(['iptables','-w','3',*prefix,'-A',*rest])
            print('Restored missing MOH gateway rule',flush=True)
    if run(['systemctl','is-active','--quiet','dnsmasq'],False).returncode:
        run(['systemctl','start','dnsmasq'])

if __name__=='__main__':
    ensure_gateway()
