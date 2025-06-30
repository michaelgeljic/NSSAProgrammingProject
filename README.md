Python Packet Sniffer GUI
This project is a simple, Python-based graphical packet sniffer inspired by Wireshark. It leverages Scapy for packet capture and Tkinter for a modern, dark-themed user interface. This tool allows users to capture, inspect, filter, and save packets from their network in real time.
Features

    Live packet sniffing using Scapy

    Real-time statistics for TCP, UDP, ICMP, HTTP, and Other protocols

    Filtering by protocol, source IP, and destination IP

    Save captured packets to .pcap files

    Load and analyze packets from existing .pcap files

    Detailed packet views including:

        Ethernet, IP, TCP, UDP, and ICMP headers

        Raw payload in both hexadecimal and ASCII

    Modern dark-themed GUI built with Tkinter and ttk

    Multithreaded packet capture to prevent GUI freezing

How It Works

    Packet Capture: Uses Scapy's sniff() function in a background thread

    Filtering: Applies filters dynamically to both live and loaded packets

    UI: Displays packets in a table and detailed views in side-by-side panes

Installation

    git clone https://github.com/michaelgeljic/WiresharkRemake.git
    cd WiresharkRemake
    pip install scapy
    python wireshark_remake.py

Note: You may need to run the script with administrative/root privileges to allow packet sniffing.
Usage

    Click "Start Sniffing" to begin capturing packets

    Use the filter inputs to narrow the displayed results

    Click on any row in the packet table to view its details

    Use "Save Packets" to export to a .pcap file

    Use "Load Packets" to import and analyze a .pcap file
