#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
from termcolor import colored
from manuf import manuf
import argparse
from tabulate import tabulate
import threading
import time
import os

def display_banner():
    """
    Displays a decorative banner at the start of the script.
    """
    banner = r"""
 
 _ __ ___  __ _ _ __   ___ _ __ 
| '__/ _ \/ _` | '_ \ / _ \ '__|
| | |  __/ (_| | |_) |  __/ |   
|_|  \___|\__,_| .__/ \___|_|   
               | |              
               |_|              

        Advanced ARP Network Scanner by Hikari
    """
    print(colored(banner, "cyan"))


def save_results(results, filename):
    """
    Save scan results to a file.
    """
    with open(filename, 'w') as file:
        for result in results:
            file.write(f"{result['IP']}\t{result['MAC']}\t{result['Brand']}\n")
    print(colored(f"Results saved to {filename}", "green"))

def scan(target, interface=None):
    """
    Perform an ARP scan on the specified target IP.
    """
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request

    answered, _ = scapy.srp(arp_packet, timeout=1, verbose=False, iface=interface)
    parser = manuf.MacParser()
    results = []

    for sent, received in answered:
        brand = parser.get_manuf(received.hwsrc)
        results.append({"IP": received.psrc, "MAC": received.hwsrc, "Brand": brand})
    
    return results

def display_results(results):
    """
    Display scan results in a table format.
    """
    if results:
        print(colored("Scan Results:", "cyan"))
        table = [[result["IP"], result["MAC"], result["Brand"]] for result in results]
        headers = ["IP Address", "MAC Address", "Brand"]
        print(tabulate(table, headers, tablefmt="grid"))
    else:
        print(colored("No devices found.", "red"))

def continuous_scan(target, interval, interface=None):
    """
    Continuously scan the target IP range at a specified interval.
    """
    try:
        while True:
            results = scan(target, interface)
            display_results(results)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nContinuous scan stopped.")

def detect_duplicates(results):
    """
    Detect IP or MAC duplicates in the scan results.
    """
    ip_seen = {}
    mac_seen = {}

    duplicates = {"IP": [], "MAC": []}
    for device in results:
        ip = device["IP"]
        mac = device["MAC"]
        
        if ip in ip_seen:
            duplicates["IP"].append(ip)
        else:
            ip_seen[ip] = 1

        if mac in mac_seen:
            duplicates["MAC"].append(mac)
        else:
            mac_seen[mac] = 1

    if duplicates["IP"] or duplicates["MAC"]:
        print(colored("Duplicate IPs or MACs detected:", "yellow"))
        for ip in duplicates["IP"]:
            print(f"Duplicate IP: {ip}")
        for mac in duplicates["MAC"]:
            print(f"Duplicate MAC: {mac}")
    else:
        print(colored("No duplicate IPs or MACs detected.", "green"))

def network_summary(results):
    """
    Show a summary of the scanned network with device counts by manufacturer.
    """
    manufacturer_count = {}
    for device in results:
        brand = device["Brand"] or "Unknown"
        manufacturer_count[brand] = manufacturer_count.get(brand, 0) + 1

    print(colored("\nNetwork Summary:", "cyan"))
    for brand, count in manufacturer_count.items():
        print(f"{brand}: {count} devices")

def get_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Advanced ARP Network Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP or IP range to scan", required=True)
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to use", required=False)
    parser.add_argument("-s", "--save", dest="save", help="Filename to save the scan results", required=False)
    parser.add_argument("-c", "--continuous", dest="continuous", help="Perform continuous scan with interval", type=int, required=False)
    args = parser.parse_args()
    return args

def main():
    """
    Main function that handles the program flow.
    """
    display_banner()
    print(colored("Welcome to the Advanced ARP Scanner", "cyan", attrs=["bold"]))
    print(colored("Starting scan...", "cyan"))
    args = get_arguments()

    if args.continuous:
        continuous_scan(args.target, args.continuous, args.interface)
    else:
        results = scan(args.target, args.interface)
        display_results(results)
        detect_duplicates(results)
        network_summary(results)

        if args.save:
            save_results(results, args.save)

if __name__ == "__main__":
    main()



    
    


