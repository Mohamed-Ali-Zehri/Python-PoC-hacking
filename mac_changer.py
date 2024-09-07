import subprocess
import pyfiglet
import optparse
import re

def get_banner():
    banner = pyfiglet.figlet_format("Mac Changer", font="slant")
    print(banner)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its mac address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New mac address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify the interface, use help for more info ")
    elif not options.new_mac:
        parser.error("[-] Please specify the new mac address, use help for more info ")
    return options

def change_mac(interface, new_mac):
    print(f"[+] Changing mac address for {interface} to {new_mac}")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface]).decode('utf-8')
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read mac address")
        return None

get_banner()
options = get_arguments()
change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac:
    print(f"Current MAC = {current_mac}")
    change_mac(options.interface, options.new_mac)

    updated_mac = get_current_mac(options.interface)
    if updated_mac == options.new_mac:
        print(f"[+] MAC address successfully changed to {updated_mac}")
    else:
        print("[-] MAC address did not change")
