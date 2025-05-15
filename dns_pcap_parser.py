# Description: Extracts DNS queries from a .pcap file using Scapy
# This version is optimized for large files using PcapReader (streams one packet at a time)

from scapy.all import PcapReader, DNS, DNSQR
import time
import os

def extract_dns_queries_from_pcap(pcap_file_path):
    # Set to store unique DNS query names
    dns_queries = set()
    packet_count = 0
    dns_query_count = 0

    try:
        print(f"Opening PCAP file: {pcap_file_path}")
        with PcapReader(pcap_file_path) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1

                # Check if packet has a DNS layer and it's a query (qr = 0)
                if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                    for i in range(packet[DNS].qdcount):
                        try:
                            # Extract the query name
                            query_record = packet[DNS].qd[i]
                            qname = query_record.qname.decode('utf-8', errors='ignore').rstrip('.')
                            dns_queries.add(qname)
                            dns_query_count += 1
                        except Exception:
                            # If there's an error with decoding or indexing, skip that record
                            continue

                # Print progress every 100,000 packets
                if packet_count % 100000 == 0:
                    print(f"Processed {packet_count} packets...")

    except FileNotFoundError:
        print(f"Error: PCAP file not found at {pcap_file_path}")
        return []
    except Exception as e:
        print(f"An error occurred while processing the PCAP: {e}")
        return []

    print(f"Done. Processed {packet_count} packets.")
    print(f"Found {len(dns_queries)} unique DNS queries from {dns_query_count} DNS query records.")

    return list(dns_queries)


if __name__ == '__main__':
    test_pcap_path = 'C:/Users/aaara/Documents/Deakin/Deakin cybersec T1 2025/sit 327/HD1/benign.pcap'

    if os.path.exists(test_pcap_path):
        print(f"\nStarting DNS query extraction from:\n{test_pcap_path}\n")

        start_time = time.time()
        queries = extract_dns_queries_from_pcap(test_pcap_path)
        end_time = time.time()

        print(f"\nTotal time taken: {end_time - start_time:.2f} seconds")

        if queries:
            print(f"\nSample of first {min(10, len(queries))} unique DNS queries:")
            for i, q in enumerate(queries[:10]):
                print(f"{i + 1}. {q}")
        else:
            print("No DNS queries found.")
    else:
        print(f"Error: PCAP file not found at '{test_pcap_path}'")

    print("\ndns_pcap_parser.py finished running.")
