# Description: This is my main script for analyzing DNS queries.
# It uses the parser from 'dns_pcap_parser.py' and then applies
# character frequency and bigram analysis techniques inspired by my research papers.

import collections # For frequency counting (Counter)
import math      # For Shannon entropy calculation (log)
import re        # Regular expressions, though I might not use them heavily here
import csv       # For outputting my results to a CSV file
import os        # For handling file paths

# I need to import my parser function from the other file.
try:
    from dns_pcap_parser import extract_dns_queries_from_pcap
except ImportError:
    print("Error: I can't find dns_pcap_parser.py. I need to make sure it's in the same directory as this script.")
    exit()

# --- Helper Functions ---

def get_relevant_hostname_part(fqdn):
    """
    This function is my attempt to extract the part of the FQDN that's most likely
    to contain the tunneled data. Usually, this is the subdomain part to the left
    of the registered domain (e.g., 'attacker.com').
    I know this is a simplification; a truly robust solution would use a Public Suffix List.
    For my report, I'll acknowledge this heuristic.
    """
    parts = fqdn.lower().split('.') # Work with lowercase for consistency
    
    # My heuristic: if there are many subdomains, they are likely part of the payload.
    # e.g., for "data1.data2.data3.attacker.com", I'm interested in "data1.data2.data3".
    # For "www.google.com", I might look at "www".
    # Tunneling tools often put the payload in the leftmost labels.
    
    if len(parts) > 2: # This suggests something like payload.domain.tld or p1.p2.domain.tld
        # I'm assuming the actual registered domain is often 2 parts (e.g., domain.com)
        # or 3 parts for ccSLDs (e.g., domain.co.uk). This is a heuristic.
        # So, I'll try to get the labels before these.
        if len(parts) > 3 and len(parts[-2]) <= 3 and parts[-2] != "com": # Trying to catch .co.uk, .org.au etc. but not misinterpret something.com.au
            # This condition for `parts[-2] != "com"` is a bit of a hack to avoid cutting off ".com" in ".com.au" type domains.
            # A proper PSL is really needed for accuracy here.
            return ".".join(parts[:-3]) 
        elif len(parts) > 2 : # Likely .com, .net, or other TLDs that are single parts after the domain.
            return ".".join(parts[:-2])
        else: # Fallback for cases like domain.tld
             return parts[0]
    elif parts: # If only one or two parts (e.g., "localhost", or "domain" from "domain.com")
        return parts[0]
    return "" # Should ideally not happen for valid FQDNs passed here.

# --- Character Frequency Analysis (Inspired by Born and Gustafson [2]) ---

def calculate_char_frequencies_normalized(text):
    """
    I wrote this to calculate the normalized frequency of each character.
    It might be useful if I want to compare distributions more formally later.
    """
    if not text: # Handle empty strings
        return collections.Counter()
    counts = collections.Counter(text)
    total_chars = len(text)
    # Normalize by dividing each count by the total number of characters.
    frequencies = {char: count / total_chars for char, count in counts.items()}
    return frequencies

def calculate_shannon_entropy(text):
    """
    This calculates the Shannon entropy of a string.
    Higher entropy can suggest randomness or encoding, common in tunneled data.
    """
    if not text: # Handle empty strings to avoid errors
        return 0.0
    
    # Calculate probability of each unique character
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    # Shannon entropy formula
    entropy = -sum([p * math.log(p, 2.0) for p in prob if p > 0]) # Use log base 2, ensure p > 0
    return entropy

def analyze_domain_char_freq(fqdn, benign_char_profile=None):
    """
    This is where I analyze a domain based on character frequencies
    of its 'relevant hostname part'.
    The benign_char_profile isn't used for complex comparison in this simplified version,
    but I've kept it as a placeholder for potential future enhancements.
    It returns: (is_suspicious_boolean, reason_string, entropy_float)
    """
    hostname = get_relevant_hostname_part(fqdn) # Get the part I want to analyze
    
    if not hostname:
        return False, "No relevant hostname part to analyze", 0.0

    # 1. Shannon Entropy:
    # I know that typical English text has entropy around 3.5-5 bits/char.
    # Highly random or compressed data will have higher entropy.
    # Normal domain names are often structured and might have lower entropy.
    # This threshold is something I'll need to tune based on my benign dataset.
    entropy = calculate_shannon_entropy(hostname)
    entropy_threshold_suspicious = 3.8 # My initial guess for a threshold, needs testing!
    if entropy > entropy_threshold_suspicious:
        return True, f"High entropy ({entropy:.2f})", entropy

    # 2. Hexadecimal Character Dominance:
    # Some tunneling tools encode data using hex.
    hex_chars = "0123456789abcdef" # Only lowercase as I convert hostname to lowercase
    hex_count = sum(1 for char_val in hostname if char_val in hex_chars)
    if len(hostname) > 0: # Avoid division by zero for empty hostnames
        hex_ratio = hex_count / len(hostname)
        # If more than 75% hex characters and the hostname is reasonably long.
        if hex_ratio > 0.75 and len(hostname) > 10: 
            return True, f"Hex dominant (ratio: {hex_ratio:.2f})", entropy

    # 3. Numeric Character Dominance:
    # Similar to hex, some encodings might result in mostly numbers.
    numeric_count = sum(1 for char_val in hostname if char_val.isdigit())
    if len(hostname) > 0:
        numeric_ratio = numeric_count / len(hostname)
        # If more than 80% numeric and reasonably long.
        if numeric_ratio > 0.8 and len(hostname) > 10: 
            return True, f"Numeric dominant (ratio: {numeric_ratio:.2f})", entropy
            
    # 4. Low Variety of Characters for Length:
    # This might indicate simple base encodings or limited character sets used in some tunneling.
    unique_chars = len(set(hostname))
    # Example: if a long hostname part has very few unique characters.
    if len(hostname) > 15 and unique_chars < 5: 
        return True, f"Low unique chars ({unique_chars}) for length {len(hostname)}", entropy

    # 5. Length of the Relevant Hostname Part:
    # DNS tunneling often uses very long subdomains to carry data.
    # The maximum length for a single DNS label is 63 characters.
    # Here, I'm checking the combined length of the extracted 'relevant part'.
    # This threshold also needs careful tuning against my benign data.
    if len(hostname) > 60: # Slightly less than max label length as a starting point.
        return True, f"Very long hostname part (length: {len(hostname)})", entropy

    # If none of my heuristics trigger, I'll consider it normal for now.
    return False, "Passes character heuristics", entropy

# --- Bigram Analysis (Inspired by Qi et al. [4]) ---

def get_bigrams(text):
    """A simple function to generate a list of bigrams (2-character sequences) from a string."""
    if not text or len(text) < 2:
        return []
    return [text[i:i+2] for i in range(len(text) - 1)]

def build_benign_bigram_profile(fqdn_list):
    """
    I'll use this to build a frequency map (profile) of bigrams
    from my list of known benign FQDNs.
    """
    all_benign_bigrams = collections.Counter() # Using Counter for easy frequency tallying
    for fqdn in fqdn_list:
        hostname = get_relevant_hostname_part(fqdn) # Analyze the relevant part
        if hostname: # Ensure there's a hostname part
            bigrams_in_hostname = get_bigrams(hostname)
            all_benign_bigrams.update(bigrams_in_hostname)
    return all_benign_bigrams

def analyze_domain_bigram(fqdn, benign_bigram_profile, benign_total_bigrams):
    """
    This function analyzes a domain based on its bigram frequencies,
    comparing them against the profile I built from benign traffic.
    It returns: (is_suspicious_boolean, reason_string)
    """
    hostname = get_relevant_hostname_part(fqdn) # Get the relevant part
    
    if not hostname or len(hostname) < 2: # Need at least 2 chars for a bigram
        return False, "Hostname too short for bigram analysis"

    current_bigrams = get_bigrams(hostname)
    if not current_bigrams: # Should not happen if len(hostname) >= 2, but good check.
        return False, "No bigrams found in hostname"

    # Heuristic 1: Presence of bigrams that are very rare or non-existent in my benign set.
    # I need to define what "very rare" means. This threshold factor is a starting point.
    rare_threshold_factor = 0.00001 # e.g., a bigram appearing less than 0.001% of the time in benign set.
    
    # For illustration and as per some research, certain bigrams are inherently uncommon in typical language/hostnames.
    # This list is just an example; a real system would learn these or use more sophisticated linguistic models.
    # I'll use this as one of my checks.
    illustrative_odd_bigrams = {"xq", "z$", "qj", "zx", "j$", "$j", "kq", "vq", "vx", "$$", "qg", "qk", "qf", "jc", "q"} 
    # (Note: 'q' as a bigram is impossible, but if get_bigrams was modified for single chars, it could be relevant. Keeping list as is for now.)


    unseen_in_benign_count = 0
    rare_in_benign_count = 0
    odd_pattern_count = 0
    suspicious_bigrams_details = [] # To store reasons

    for bg in current_bigrams:
        is_rare_or_odd = False # Flag to check if current bigram is suspicious by any rule
        temp_reason = "" # Temporary reason for this specific bigram

        if bg not in benign_bigram_profile:
            unseen_in_benign_count += 1
            is_rare_or_odd = True
            temp_reason = bg + "(unseen)"
        elif benign_total_bigrams > 0 and \
             (benign_bigram_profile[bg] / benign_total_bigrams) < rare_threshold_factor:
            rare_in_benign_count += 1
            is_rare_or_odd = True
            temp_reason = bg + "(rare)"
        
        if bg in illustrative_odd_bigrams:
            odd_pattern_count +=1
            is_rare_or_odd = True # It's an odd pattern regardless of its benign frequency for this heuristic
            # If already marked as unseen/rare, append known_odd, else create new reason
            if temp_reason and "(known_odd)" not in temp_reason :
                 temp_reason += "/known_odd"
            elif not temp_reason:
                 temp_reason = bg + "(known_odd)"
        
        if is_rare_or_odd and temp_reason not in suspicious_bigrams_details:
            suspicious_bigrams_details.append(temp_reason)

    
    # Decision Heuristics (these thresholds will need tuning):
    # If a significant portion of bigrams are unseen in my benign data:
    if len(current_bigrams) > 3 and unseen_in_benign_count / len(current_bigrams) > 0.4: # Over 40% unseen
        return True, f"High proportion ({unseen_in_benign_count/len(current_bigrams):.2f}) of bigrams unseen in benign. Details: {set(suspicious_bigrams_details)}"
    
    # If a significant portion are from my 'illustrative_odd_bigrams' list:
    if len(current_bigrams) > 2 and odd_pattern_count / len(current_bigrams) > 0.2: # Over 20% are "odd"
         return True, f"High proportion ({odd_pattern_count/len(current_bigrams):.2f}) of 'illustrative odd' bigrams. Details: {set(suspicious_bigrams_details)}"

    # If many bigrams are individually rare in the benign set:
    if len(current_bigrams) > 3 and rare_in_benign_count / len(current_bigrams) > 0.3: # Over 30% are rare
        return True, f"High proportion of bigrams rare in benign. Details: {set(suspicious_bigrams_details)}"
            
    # Heuristic 2: Repetitiveness (e.g., "aaaaa..." -> many "aa" bigrams)
    # If one specific bigram makes up a large portion of all bigrams in *this* hostname.
    bigram_counts_for_this_hostname = collections.Counter(current_bigrams)
    for bg, count in bigram_counts_for_this_hostname.items():
        # If a single bigram is more than 50% of all bigrams in this (reasonably long) hostname part.
        if len(current_bigrams) > 3 and count / len(current_bigrams) > 0.5: 
            return True, f"Highly repetitive bigram '{bg}' (makes up {count/len(current_bigrams):.2f} of this hostname's bigrams)"

    return False, "Passes bigram heuristics"

# --- Main Processing Logic ---
def main():
    # I need to define the paths to my PCAP files.
    
    pcap_files = {
        "benign": 'C:/Users/aaara/Documents/Deakin/Deakin cybersec T1 2025/sit 327/HD1/benign.pcap',
        "dns2tcp": 'C:/Users/aaara/Documents/Deakin/Deakin cybersec T1 2025/sit 327/HD1/dns2tcp.pcap',
        "dnscat2": 'C:/Users/aaara/Documents/Deakin/Deakin cybersec T1 2025/sit 327/HD1/dnscat2.pcap',
        "iodine": 'C:/Users/aaara/Documents/Deakin/Deakin cybersec T1 2025/sit 327/HD1/dns-tunnel-iodine.pcap'
    }

    # First, I'll check if all my PCAP files actually exist.
    all_files_found = True
    for name, path in pcap_files.items():
        if not os.path.exists(path):
            print(f"CRITICAL ERROR: My PCAP file for '{name}' is missing at '{path}'. Please check the path.")
            all_files_found = False
    if not all_files_found:
        print("Exiting because one or more PCAP files were not found.")
        return # Stop execution if files are missing
    print("-" * 30)

    # 1. Process my Benign PCAP to build necessary profiles.
    # This is crucial for the bigram analysis later.
    print(f"Processing my benign PCAP: {pcap_files['benign']}")
    benign_queries = extract_dns_queries_from_pcap(pcap_files['benign'])
    
    if not benign_queries:
        print("Warning: I couldn't extract any queries from the benign PCAP. Bigram analysis might be less effective or fail.")
        # I'll create empty profiles to avoid errors, but this isn't ideal.
        benign_bigram_counts = collections.Counter()
        total_benign_bigrams = 0
    else:
        print(f"I extracted {len(benign_queries)} unique queries from my benign PCAP.")
        # Build the bigram profile from these benign queries.
        benign_bigram_counts = build_benign_bigram_profile(benign_queries)
        total_benign_bigrams = sum(benign_bigram_counts.values())
        if total_benign_bigrams > 0:
            print(f"I've built a benign bigram profile with {len(benign_bigram_counts)} unique bigrams and {total_benign_bigrams} total bigram occurrences.")
        else:
            print("Benign bigram profile is empty (no bigrams found in benign queries). Bigram analysis will be limited.")
    print("-" * 30)
    
    # I'll prepare a CSV file to store all my detailed analysis results.
    output_csv_file = "dns_tunnel_analysis_results.csv"
    # These are the columns I want in my CSV.
    csv_fieldnames = ["pcap_source", "fqdn", 
                      "char_freq_suspicious", "char_freq_reason", "hostname_entropy",
                      "bigram_suspicious", "bigram_reason", "relevant_hostname_part"]

    # Open the CSV file for writing.
    with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
        writer.writeheader() # Write the column headers first.

        # 2. Now, I'll process each of my DNS tunneling PCAP files.
        for pcap_name, pcap_path in pcap_files.items():
            # I'll also analyze the benign.pcap with the detection heuristics
            # to see if I get any false positives from my own benign data.
            # if pcap_name == "benign": 
            #     continue 

            print(f"Now processing the '{pcap_name}' PCAP from: {pcap_path}")
            
            current_pcap_queries = extract_dns_queries_from_pcap(pcap_path)
            if not current_pcap_queries:
                print(f"I didn't find any queries in {pcap_name}. Skipping analysis for this file.")
                continue
            
            # For console readability, I'll print details for a few queries, but I'll process all for the CSV.
            # For the benign pcap, I'll also limit console output.
            queries_to_show_in_console = 20 if pcap_name != "benign" else 5
            print(f"I extracted {len(current_pcap_queries)} unique queries from {pcap_name}. I'll show analysis for the first {queries_to_show_in_console} (or all if fewer)...")
            
            # Counters for summarizing how many were flagged by each method for this PCAP.
            flagged_by_char_freq = 0
            flagged_by_bigram = 0

            for i, fqdn in enumerate(current_pcap_queries):
                hostname_part = get_relevant_hostname_part(fqdn)

                # Perform Character Frequency Analysis
                is_susp_char, reason_char, entropy_val = analyze_domain_char_freq(fqdn) # No benign profile needed for current char_freq logic
                if is_susp_char:
                    flagged_by_char_freq +=1
                
                # Perform Bigram Analysis (needs the benign profile I built earlier)
                # Handle case where total_benign_bigrams might be 0
                if total_benign_bigrams > 0:
                    is_susp_bigram, reason_bigram = analyze_domain_bigram(fqdn, benign_bigram_counts, total_benign_bigrams)
                else:
                    is_susp_bigram, reason_bigram = False, "Skipped (no benign bigram profile)"

                if is_susp_bigram and reason_bigram != "Skipped (no benign bigram profile)":
                    flagged_by_bigram +=1

                # Write all results to my CSV file.
                writer.writerow({
                    "pcap_source": pcap_name, "fqdn": fqdn,
                    "char_freq_suspicious": is_susp_char, "char_freq_reason": reason_char, "hostname_entropy": f"{entropy_val:.2f}",
                    "bigram_suspicious": is_susp_bigram, "bigram_reason": reason_bigram,
                    "relevant_hostname_part": hostname_part
                })

                # Print details for the first few queries to the console.
                if i < queries_to_show_in_console : 
                    print(f"\n  FQDN ({i+1}): {fqdn}")
                    print(f"    Relevant Hostname: {hostname_part}")
                    print(f"    Char Freq Analysis: Suspicious={is_susp_char}, Reason='{reason_char}', Entropy={entropy_val:.2f}")
                    print(f"    Bigram Analysis:    Suspicious={is_susp_bigram}, Reason='{reason_bigram}'")
            
            # Print a summary for the current tunneling PCAP.
            print(f"\n  Summary for '{pcap_name}' PCAP:")
            print(f"    Total unique queries analyzed: {len(current_pcap_queries)}")
            print(f"    Flagged as suspicious by Character Frequency: {flagged_by_char_freq}")
            print(f"    Flagged as suspicious by Bigram Analysis:    {flagged_by_bigram}")
            print("-" * 30)
            
    print(f"\nMy analysis is complete! I've saved the detailed results to: {output_csv_file}")

if __name__ == '__main__':
    main()
