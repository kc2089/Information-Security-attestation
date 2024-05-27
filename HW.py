import nmap

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 1-65535 -sV -T4')
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            ports = nm[host][proto].keys()
            ports = sorted(ports)
            for port in ports:
                print('port : %s\tstate : %s\tname : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))

if __name__ == '__main__':
    target = input("Введите целевую сеть для сканирования (например, '192.168.1.0/24'): ")
    scan_network(target)
