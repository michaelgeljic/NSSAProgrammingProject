# Import necessary modules
from tkinter import Tk, Label, Button, Frame, Text, Scrollbar, ttk, filedialog, StringVar, Entry
from threading import Thread
from scapy.all import sniff, Ether, IP, ICMP, TCP, UDP, wrpcap, rdpcap  # Scapy for packet manipulation
from time import time
import binascii  # For converting packet payloads to hexadecimal

# Global variables to store packet information and states
captured_packets = []  # List to store all captured packets
displayed_packets = []  # List to store packets matching filters
sniffing_active = False  # Flag to control packet sniffing
start_time = None  # To track when sniffing starts
packet_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "Other": 0}  # Packet statistics

# Function to process captured packets
def process_packet(packet):
    global captured_packets, packet_stats
    # Ensure the packet has Ethernet and IP layers
    if Ether in packet and IP in packet:
        captured_packets.append(packet)  # Add packet to the captured list

        # Determine protocol type and update statistics
        protocol = "Other"
        if ICMP in packet:
            protocol = "ICMP"
            packet_stats["ICMP"] += 1
        elif TCP in packet:
            if packet[TCP].dport in [80, 443] or packet[TCP].sport in [80, 443]:  # Check for HTTP/HTTPS
                protocol = "HTTP"
                packet_stats["HTTP"] += 1
            else:
                protocol = "TCP"
                packet_stats["TCP"] += 1
        elif UDP in packet:
            protocol = "UDP"
            packet_stats["UDP"] += 1
        else:
            packet_stats["Other"] += 1

        # Extract source and destination IPs
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if packet matches active filters
        if matches_filters(protocol, src_ip, dst_ip):
            displayed_packets.append(packet)  # Add packet to displayed list
            # Add packet to the table with protocol, source, destination, and length
            packet_table.insert("", "end", values=(protocol, src_ip, dst_ip, len(packet)))

        update_stats()  # Update the statistics display

    # Stop sniffing if 5000 packets have been captured
    if len(captured_packets) >= 5000:
        stop_sniffing()

# Start packet sniffing in a separate thread
def start_sniffing():
    global sniffing_active, start_time, displayed_packets
    sniffing_active = True  # Enable sniffing
    start_time = time()  # Record start time
    captured_packets.clear()  # Clear previous packets
    displayed_packets.clear()  # Clear displayed packets
    packet_table.delete(*packet_table.get_children())  # Clear table
    # Run sniffing in a thread to avoid freezing the GUI
    Thread(target=lambda: sniff(prn=process_packet, stop_filter=lambda x: not sniffing_active), daemon=True).start()

# Stop packet sniffing
def stop_sniffing():
    global sniffing_active
    sniffing_active = False  # Disable sniffing

# Save captured packets to a file
def save_packets():
    filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if filename:
        wrpcap(filename, captured_packets)  # Write packets to file

# Display packet details when a row in the table is selected
def display_packet_details(event):
    selected_item = packet_table.focus()  # Get the selected row
    if not selected_item:
        return

    index = packet_table.index(selected_item)  # Get row index
    packet = displayed_packets[index]  # Fetch corresponding packet

    # Collect packet details for the left section
    details = []
    if Ether in packet:
        details.append(f"Ethernet Frame:\n  Source MAC: {packet[Ether].src}\n  Destination MAC: {packet[Ether].dst}\n")
    if IP in packet:
        details.append(f"IP Header:\n  Source IP: {packet[IP].src}\n  Destination IP: {packet[IP].dst}\n"
                       f"  Protocol: {packet[IP].proto}\n  Length: {packet[IP].len}\n  TTL: {packet[IP].ttl}\n")
    if TCP in packet:
        details.append(f"TCP Header:\n  Source Port: {packet[TCP].sport}\n  Destination Port: {packet[TCP].dport}\n"
                       f"  Sequence Number: {packet[TCP].seq}\n  Acknowledgment: {packet[TCP].ack}\n")
    if UDP in packet:
        details.append(f"UDP Header:\n  Source Port: {packet[UDP].sport}\n  Destination Port: {packet[UDP].dport}\n"
                       f"  Length: {packet[UDP].len}\n")
    if ICMP in packet:
        details.append(f"ICMP Header:\n  Type: {packet[ICMP].type}\n  Code: {packet[ICMP].code}\n")
    details.append(f"Raw Data Summary:\n{packet.summary()}\n")

    # Format payload for the right section
    payload_hex = binascii.hexlify(bytes(packet)).decode("utf-8")
    payload_ascii = bytes(packet).decode("ascii", errors="replace")
    payload_formatted = "\n".join([payload_hex[i:i + 32] for i in range(0, len(payload_hex), 32)])
    ascii_formatted = "\n".join([payload_ascii[i:i + 16] for i in range(0, len(payload_ascii), 16)])

    # Display details in text widgets
    details_text_left.delete(1.0, "end")
    details_text_left.insert("end", "\n".join(details))
    details_text_right.delete(1.0, "end")
    details_text_right.insert("end", f"Hexadecimal:\n{payload_formatted}\n\nASCII:\n{ascii_formatted}")

# Update statistics displayed on the GUI
def update_stats():
    total_packets = sum(packet_stats.values())
    elapsed_time = time() - start_time if start_time else 0
    traffic_rate = total_packets / elapsed_time if elapsed_time > 0 else 0

    stats_label.config(
        text=f"TCP: {packet_stats['TCP']}  |  UDP: {packet_stats['UDP']}  |  ICMP: {packet_stats['ICMP']}  |  HTTP: {packet_stats['HTTP']}  |  Other: {packet_stats['Other']}\n"
             f"Total Packets: {total_packets}  |  Traffic Rate: {traffic_rate:.2f} packets/sec"
    )

# Filter packets based on protocol, source IP, and destination IP
def matches_filters(protocol, src_ip, dst_ip):
    protocol_filter_value = protocol_filter.get()
    src_ip_filter_value = src_ip_entry.get()
    dst_ip_filter_value = dst_ip_entry.get()

    # Check each filter condition
    if protocol_filter_value != "All" and protocol != protocol_filter_value:
        return False
    if src_ip_filter_value and src_ip_filter_value not in src_ip:
        return False
    if dst_ip_filter_value and dst_ip_filter_value not in dst_ip:
        return False
    return True

# Apply active filters and refresh the displayed packets
def apply_filters():
    global displayed_packets
    displayed_packets.clear()
    packet_table.delete(*packet_table.get_children())  # Clear table

    # Reapply filters to all captured packets
    for packet in captured_packets:
        protocol = "Other"
        if ICMP in packet:
            protocol = "ICMP"
        elif TCP in packet:
            if packet[TCP].dport in [80, 443] or packet[TCP].sport in [80, 443]:
                protocol = "HTTP"
            else:
                protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if matches_filters(protocol, src_ip, dst_ip):
            displayed_packets.append(packet)
            packet_table.insert("", "end", values=(protocol, src_ip, dst_ip, len(packet)))

# Load packets from a PCAP file
def load_pcap_file():
    global captured_packets, displayed_packets
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        packets = rdpcap(file_path)  # Read packets from file
        captured_packets.extend(packets)  # Add to captured packets
        apply_filters()  # Apply filters to the newly loaded packets

# GUI Setup
root = Tk()  # Initialize the main window
root.title("Packet Sniffer")

# Styling the GUI with a dark theme
background_color = "black"
text_color = "white"

# ttk style customization for modern aesthetics
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview.Heading", background="#5D3FD3", foreground="white", font=("Arial", 10, "bold"))
style.configure("Treeview", background="#2F3136", foreground="white", rowheight=25, fieldbackground="#2F3136")
style.map("Treeview", background=[("selected", "#4B0082")], foreground=[("selected", "white")])

# Setting up the main layout and controls
root.configure(bg=background_color)

# Packet Capture Controls - Buttons for user actions
controls_frame = Frame(root, bg=background_color)  # Frame to hold control buttons
controls_frame.pack(pady=10)  # Add padding to the frame

# Add buttons to control packet sniffing, saving, loading, and filtering
Button(controls_frame, text="Start Sniffing", bg="#5D3FD3", fg="white", command=start_sniffing).grid(row=0, column=0, padx=10, pady=5)
Button(controls_frame, text="Stop Sniffing", bg="#5D3FD3", fg="white", command=stop_sniffing).grid(row=0, column=1, padx=10, pady=5)
Button(controls_frame, text="Save Packets", bg="#5D3FD3", fg="white", command=save_packets).grid(row=0, column=2, padx=10, pady=5)
Button(controls_frame, text="Load Packets", bg="#5D3FD3", fg="white", command=load_pcap_file).grid(row=0, column=3, padx=10, pady=5)
Button(controls_frame, text="Apply Filters", bg="#5D3FD3", fg="white", command=apply_filters).grid(row=0, column=4, padx=10, pady=5)

# Filter Options - Dropdowns and Entry fields for filtering packets
filters_frame = Frame(root, bg=background_color)  # Frame to hold filter options
filters_frame.pack(pady=10)  # Add padding for spacing

# Dropdown for selecting protocol filter
Label(filters_frame, text="Protocol:", bg=background_color, fg=text_color).grid(row=0, column=0, padx=5)
protocol_filter = StringVar(value="All")  # Default value is "All"
protocol_dropdown = ttk.Combobox(filters_frame, textvariable=protocol_filter, values=["All", "TCP", "UDP", "ICMP", "HTTP"])
protocol_dropdown.grid(row=0, column=1, padx=5)

# Entry field for filtering by source IP
Label(filters_frame, text="Source IP:", bg=background_color, fg=text_color).grid(row=0, column=2, padx=5)
src_ip_entry = ttk.Entry(filters_frame)
src_ip_entry.grid(row=0, column=3, padx=5)

# Entry field for filtering by destination IP
Label(filters_frame, text="Destination IP:", bg=background_color, fg=text_color).grid(row=0, column=4, padx=5)
dst_ip_entry = ttk.Entry(filters_frame)
dst_ip_entry.grid(row=0, column=5, padx=5)

# Packet Table - Displays captured packets in a tabular format
table_frame = Frame(root, bg=background_color)  # Frame to hold the table
table_frame.pack(pady=10)  # Add padding around the table

# Define table columns and create the Treeview widget
columns = ("Protocol", "Source IP", "Destination IP", "Length")
packet_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)

# Configure each column with a header and alignment
for col in columns:
    packet_table.heading(col, text=col, anchor="center")
    packet_table.column(col, anchor="center", width=120)

packet_table.pack(side="left")  # Place table on the left side of the frame

# Add a vertical scrollbar for the table
scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=packet_table.yview)
scrollbar.pack(side="right", fill="y")  # Attach scrollbar to the right side of the frame
packet_table.configure(yscrollcommand=scrollbar.set)  # Link scrollbar to the table

# Bind the packet selection event to display detailed information
packet_table.bind("<ButtonRelease-1>", display_packet_details)

# Details Panel - Two text widgets to display detailed packet information
details_frame = Frame(root, bg=background_color)  # Frame for the details panel
details_frame.pack(pady=5, fill="x")  # Add padding and make it stretch horizontally

# Scrollbar for both text widgets in the details panel
details_scrollbar = Scrollbar(details_frame)
details_scrollbar.pack(side="right", fill="y")

# Left Text Widget - Displays packet headers and general details
details_text_left = Text(details_frame, height=15, width=60, wrap="none", bg="#2F3136", fg="white", font=("Courier", 10), yscrollcommand=details_scrollbar.set)
details_text_left.pack(side="left", padx=5, pady=5, fill="y", expand=True)

# Right Text Widget - Displays packet payload in Hex and ASCII
details_text_right = Text(details_frame, height=15, width=60, wrap="none", bg="#2F3136", fg="white", font=("Courier", 10), yscrollcommand=details_scrollbar.set)
details_text_right.pack(side="left", padx=5, pady=5, fill="y", expand=True)

# Configure the scrollbar to control both text widgets
details_scrollbar.config(command=lambda *args: [details_text_left.yview(*args), details_text_right.yview(*args)])

# Statistics Panel - Displays live statistics about captured packets
stats_label = Label(root, text="TCP: 0  |  UDP: 0  |  ICMP: 0  |  HTTP: 0  |  Other: 0\nTotal Packets: 0  |  Traffic Rate: 0.00 packets/sec", 
                    bg=background_color, fg=text_color)
stats_label.pack(pady=10)  # Add padding below the statistics label

# Run the GUI application
root.mainloop()  # Start the main event loop
