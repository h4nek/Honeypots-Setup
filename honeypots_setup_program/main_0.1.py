''' A Python 3 script to set up & run honeypots on LAN.
	Must be ran with root privileges.
'''
import json
from pprint import pprint #for debugging
import subprocess
from subprocess import call, Popen, run, DEVNULL, STDOUT
import re
from time import sleep

class Tarpit:
    def __init__(self, ips : "list of strings", ports : "list of strings"):
        self.ips = ips
        self.ports = ports
    def port_opening_without_redirection(self):
        for ip in self.ips:
            for port in self.ports:
                proc = Popen("nc -lvkd " + ip + " " + str(port) + " &> ./testfiles/simple_tarpit_log.out &", shell=True)
                print(proc.pid)
                proc.kill()
                proc.communicate() #killing the whole shell and finishing communication

if __name__ == "__main__":
    with open("./testfiles/test.json") as f:
        config = json.load(f)
    pprint(config)#testing
    
    ips = ["192.168.1.100", "192.168.1.101"]
    ports = [22, 80, 150]
    honeyIP = "192.168.1.157"
    
    n = 0
    for ip in ips:
        retCode = run(["ping", "-c", "1", ip], stdout=DEVNULL, stderr=STDOUT)
        if retCode: # is not equal to 0
            run(["ip", "addr", "add", ip + "/24", "brd", "+", "dev", "enp2s0", "label", "enp2s0:" + str(n)], stdout=DEVNULL, stderr=STDOUT)
            n += 1
    #nullFile = open(os.devnull, 'w')
    #call(["nmap", "192.168.1.0/24", "-oG", "./testfiles/hosts-ports.out"])
    #call("nmap 192.168.1.0/24 -oG ./testfiles/hosts-ports.out > /dev/null", shell=True)
    run(["nmap", "192.168.1.0/24", "-oG", "./testfiles/hosts-ports.out"], stdout=DEVNULL, stderr=STDOUT)

    '''Get the current configuration of LAN'''
    with open("./testfiles/hosts-ports.out", 'r') as f:
        first = True
        for line in f:
            if line.startswith("Host:"):
                if first:
                    first = False
                    continue
                words = [w.strip(',') for w in line.split()]
                print(words[1]) #host IP
                if words[3] == "Ports:":
                    i = 4
                    while not i == len(words) and words[i][0].isdigit():
                        port = words[i].split('/') # want to disect the port information
                        for x in port: # port num. / (open/closed) / transport protocol / service /...
                            print(x)
                        i += 1 
                first = True
                
    '''Run honeypots'''
    
    """Tarpit without Honeycomb"""
    """
    for ip in ips:
        for port in ports:
            honeyPort = re.findall(r'\d+', ip)[-1] + str(port)
            call("iptables -t nat -A PREROUTING -p tcp -d " + ip + " --dport " + str(port) + " -j DNAT --to-destination " + honeyIP + ":" + honeyPort, shell=True)
            call("iptables -t nat -A POSTROUTING -p tcp -d " + honeyIP + " --dport " + honeyPort + " -m conntrack --ctstate DNAT -j SNAT --to-source " + ip, shell=True)
            #pid = call("nc -lvkd " + honeyIP + " " + honeyPort + " &> ./testfiles/simple_tarpit_log.out &", shell=True)
            proc = Popen("nc -lvkd " + honeyIP + " " + honeyPort + " &> ./testfiles/simple_tarpit_log.out &", shell=True)
            print("nc pid: " + str(proc.pid))
            proc.kill()
            proc.communicate() #killing the whole shell and finishing communication
            #call("kill " + str(proc.pid), shell=True)
    """
    #strPorts = list(map(str, ports)) # an alternate conversion with map
    tarpit = Tarpit(ips, [str(port) for port in ports])
    tarpit.port_opening_without_redirection()
    
    """Cleanup"""
    #nullFile.close()
