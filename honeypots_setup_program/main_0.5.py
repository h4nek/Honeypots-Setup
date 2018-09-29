''' A Python 3 script to set up & run honeypots on LAN.
	Must be ran with root privileges.
'''
import json
from pprint import pprint #for debugging
import subprocess
from subprocess import call, Popen, run, DEVNULL, STDOUT, PIPE
import re
from time import sleep
import copy
import random

"""
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
"""

'''Compare two lists of atomic elements.'''
def cmp_lists(l1, l2):
    return sorted(l1) == sorted(l2)

'''Compare two states. State is a list of lists, each list element represents an interface, each integer inside represents an open port'''
def cmp_states(state1, state2):
    state2_rest = copy.deepcopy(state2) # we don't want to match one interface in the second state to several in the first state
    for iface in state1:
        ifaces_equal = False
        for iface2 in state2_rest:
            if cmp_lists(iface, iface2):
                ifaces_equal = True
                state2_rest.remove(iface2)
                break;
        if not ifaces_equal:
            return False
    return True

'''Get the current state of LAN. Returns it as list of interfaces, each interface being a list of ports.'''
def get_my_state():
    #run(["nmap", "192.168.1.0/24", "-oG", "./testfiles/hosts-ports.out"], stdout=DEVNULL, stderr=STDOUT) # comment out for faster testing
    
    with open("./testfiles/hosts-ports.out", 'r') as f:
        first = True
        ifaces = []
        for line in f:
            if line.startswith("Host:"):
                if first:
                    first = False
                    continue
                words = [w.strip(',') for w in line.split()]
                print(words[1]) #host IP
                if words[3] == "Ports:":
                    i = 4
                    iface = []
                    while not i == len(words) and words[i][0].isdigit():
                        port = words[i].split('/') # disect the port information
                        #for x in port: # port num. / (open/closed) / transport protocol / service /...
                        #    print(x)
                        iface.append(port[0])
                        i += 1
                    ifaces.append(iface)
                first = True
        return ifaces

'''Get a random number between 0 and 1 (inclusive), then use it to choose the concrete configuration.
Return a concrete configuration,= chosen based on the given probabilities.'''
def throw_a_dice(config):
   rand_num = random.random()
   acc = 0
   for concrete in config:
       print("prob: " + concrete[0])
       acc += float(concrete[0]) # add the current probability to the accumulator and see if the number fits under the new "threshold"
       if rand_num < acc:
           print("chosen conf: ", concrete[1])
           return concrete[1]

'''Create new IP adresses on the given interface (if not already assigned).'''
def create_ips(ips, iface):
    n = 0
    for ip in ips:
        ret_code = run(["ping", "-c", "1", ip], stdout=DEVNULL, stderr=STDOUT)
        if ret_code: # is not equal to 0
            run(["ip", "addr", "add", ip + "/24", "brd", "+", "dev", iface, "label", iface + ":" + str(n)], stdout=DEVNULL, stderr=STDOUT)
            n += 1

'''Start a concrete honeypot service on a given interface and port. Uses Honeycomb Framework. More parameters/options might be added in the future.'''
def start_honeypot(name, ip, port):
    return Popen(["honeycomb", "--iamroot", "service", "run", name, "ip=" + ip, "port=" + str(port)], stdout=PIPE, stderr=PIPE)

'''Start all honeypot services on given addresses and ports.'''
def start_services(config, ips):
    i = 0
    services = []
    for iface in config:
        for service in iface:
            honeypot = start_honeypot(service[0], ips[i], service[1])
            print("hp pid: " + str(honeypot.pid))
            services.append(honeypot)
        i += 1
    return services

'''Apply the concrete configuration on LAN. Sample values are used for now.'''
def apply_config(config):
    ips = ["192.168.1.105", "192.168.1.110"] #testing
    pprint(config) #testing
    run(["modprobe", "dummy"], stdout=DEVNULL, stderr=STDOUT)# load dummy kernel module if it's not loaded
    run(["ip", "li", "add", "eth10", "type", "dummy"], stdout=DEVNULL, stderr=STDOUT)#create sample interface
    create_ips(ips, "eth10")
    #return ("eth10", ips)
    return start_services(config, ips)
    
'''Stop all given honeypot services.'''
def stop_services(services):
    for honeypot in services:
        honeypot.kill()
        log = honeypot.communicate()
        print("first part: ", log[0])
        print("\n\n\n second part: ", log[1])

'''Deletes the supplied interface from local device.
ALL ASSOCIATED IPS WILL BE DELETED.'''
def delete_interface(iface):
    run(["ip", "li", "del", iface, "type", "dummy"], stdout=DEVNULL, stderr=STDOUT)


if __name__ == "__main__":
    with open("./testfiles/example.json") as f:
        configs = json.load(f)
        print(configs[0][0][0]) # [22, 88]
        my_state = get_my_state()
        print(my_state)
        services = None
        for config in configs[:-1]: # last config is expected to be the DEFAULT
            if cmp_states(my_state, config[0]):
                print("config: " + config[0])
                print("probs and confs: " + config[1])
                concrete_config = throw_a_dice(config[1])
                print("concrete config: " + concrete_config)
                services = apply_config(concrete_config)
                break
        else:
            print("config: " + configs[-1][0])
            print("probs and confs: ", configs[-1][1])
            concrete_config = throw_a_dice(configs[-1][1])
            print("concrete config: ", concrete_config)
            services = apply_config(concrete_config)
    
    print("going to sleep...")
    sleep(5)
    print("finished sleeping")
    stop_services(services)
    
    #pprint(configs)#testing
    
    ports = [22, 80, 150]
    honeyIP = "192.168.1.157"
    #exit()#testing

    #nullFile = open(os.devnull, 'w')
    #call(["nmap", "192.168.1.0/24", "-oG", "./testfiles/hosts-ports.out"])
    #call("nmap 192.168.1.0/24 -oG ./testfiles/hosts-ports.out > /dev/null", shell=True)
                
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
    #tarpit = Tarpit(ips, [str(port) for port in ports])
    #tarpit.port_opening_without_redirection()
    
    """Cleanup"""
    #nullFile.close()
