#!/usr/bin/env python3
import sqlite3
import argparse
import re
from tabulate import tabulate
import matplotlib.pyplot as plt

def analyze_welcome_messages(db_file, limit=10):
    """Analyze and display most common FTP welcome messages"""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Execute the query to get most common welcome messages
        query = """
        SELECT welcome, COUNT(*) AS count
        FROM ftp
        WHERE welcome IS NOT NULL
        GROUP BY welcome
        ORDER BY count DESC
        LIMIT ?;
        """
        cursor.execute(query, (limit,))
        results = cursor.fetchall()

        # Format and display the results
        if results:
            headers = ["Welcome Message", "Count"]
            print("\nMost Common Welcome Messages:")
            print(tabulate(results, headers=headers, tablefmt="pretty"))
        else:
            print("No welcome messages found in the database.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def load_ip2location_db(ip2location_file):
    """Load IP2Location database into memory"""
    ip_ranges = {}
    with open(ip2location_file, 'r') as f:
        for line in f:
            # Remove quotes and split
            cleaned_line = line.strip().replace('"', '')
            parts = cleaned_line.split(',')
            
            # We need at least start_ip, end_ip, and country_name
            if len(parts) >= 4:
                start_ip = parts[0]
                end_ip = parts[1]
                # Country name is typically the last column
                country_name = parts[-1]
                
                try:
                    ip_ranges[(int(start_ip), int(end_ip))] = country_name
                except (ValueError, IndexError):
                    continue  # Skip malformed lines
    return ip_ranges

def analyze_geographical_distribution(db_file, ip2location_file, limit=10):
    """Analyze and display geographical distribution using IP2Location"""
    conn = None
    try:
        # Load IP2Location database
        ip_ranges = load_ip2location_db(ip2location_file)
        # Convert to sorted list of tuples for efficient searching
        sorted_ranges = sorted(ip_ranges.items())
        range_keys = [r[0] for r in sorted_ranges]
        range_values = [r[1] for r in sorted_ranges]
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get sorted IPs directly from database
        cursor.execute("SELECT ip FROM ftp ORDER BY ip")
        ips = cursor.fetchall()

        # Count countries using optimized search
        country_counts = {}
        range_idx = 0  # Track our position in the ranges
        
        for (ip,) in ips:
            ip_int = ip  # IP is already in integer form
            # Find the matching range using linear search optimized for sorted data
            while range_idx < len(range_keys):
                start, end = range_keys[range_idx]
                if ip_int < start:
                    # IP is before current range, no match
                    country = "Unknown"
                    break
                elif ip_int <= end:
                    # IP is within current range
                    country = range_values[range_idx]
                    break
                else:
                    # IP is after current range, move to next range
                    range_idx += 1
            else:
                # Exhausted all ranges
                country = "Unknown"
            
            country_counts[country] = country_counts.get(country, 0) + 1

        # Get top countries
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        
        # If we have more countries than limit, group the rest under "Others"
        if len(sorted_countries) > limit:
            others_count = sum(count for _, count in sorted_countries[limit:])
            sorted_countries = sorted_countries[:limit]
            sorted_countries.append(('Others', others_count))
            # Re-sort with Others included
            sorted_countries = sorted(sorted_countries, key=lambda x: x[1], reverse=True)

        # Format and display the results
        if sorted_countries:
            headers = ["Country", "Host Count"]
            print(f"\nGeographical Distribution (Top {limit} Countries):")
            print(tabulate(sorted_countries, headers=headers, tablefmt="pretty"))

            # Generate pie chart with distinct colors
            countries, counts = zip(*sorted_countries)
            plt.figure(figsize=(10, 8))
            
            # Use a colormap with enough distinct colors
            colors = plt.cm.tab20.colors  # tab20 colormap has 20 distinct colors
            if len(countries) > 20:
                # If more than 20 categories, cycle through the colors
                colors = [colors[i % 20] for i in range(len(countries))]
            else:
                colors = colors[:len(countries)]
            
            plt.pie(counts, labels=countries, autopct='%1.1f%%', startangle=140, colors=colors,
                   textprops={'fontsize': 10}, pctdistance=0.85)  # Move percentages closer to edge
            plt.title(f'Geographical Distribution of FTP Servers (Top {limit} Countries)',
                    fontsize=14, fontweight='bold', pad=20)  # Bigger and bolder title with padding
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
            plt.subplots_adjust(top=0.85)  # Add more space above the chart
            plt.tight_layout()
            
            # Save and show the plot
            plt.savefig('geo_distribution.png')
            plt.show()
        else:
            print("No IP data found in the database.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

def analyze_server_software(db_file, limit=10):
    """Analyze and display server software breakdown"""
    try:
        # Common FTP server patterns
        server_patterns = {
            'Pure-FTPd': re.compile(r'(Pure-FTPd)|(220-You\sare\suser\snumber\s\d+\sof\s\d+\sallowed\.)', re.IGNORECASE),
            'ProFTPD': re.compile(r'ProFTPD', re.IGNORECASE),
            'vsFTPd': re.compile(r'(vsFTPd)|(blah FTP service\.)|(https://hub\.docker\.com/r/delfer/alpine-ftp-server/)', re.IGNORECASE),
            'Microsoft FTP': re.compile(r'Microsoft FTP Service', re.IGNORECASE),
            'FileZilla': re.compile(r'FileZilla\s+Server', re.IGNORECASE),
            'Idea FTP Server': re.compile(r'Idea\s+FTP\s+Server', re.IGNORECASE),
            'MikroTik': re.compile(r'MikroTik\s\d+\.\d+', re.IGNORECASE),
            'net.cn': re.compile(r'www\.net\.cn', re.IGNORECASE),
            'GNU inetutils': re.compile(r'(?:GNU\s+inetutils|inetutils-ftpd)\s+\d+\.\d+', re.IGNORECASE),
            'ipTIME': re.compile(r'ipTIME_FTPD\s+\d+\.\d+', re.IGNORECASE),
            'DreamHost': re.compile(r'^220 DreamHost FTP Server$', re.IGNORECASE),
            'Serv-U': re.compile(r'Serv-U\s+FTP\s+Server', re.IGNORECASE),
            'Firmware Update Utility': re.compile(r'^220 Ftp firmware update utility$', re.IGNORECASE),
            'Virtual FTP Service': re.compile(r'^220 Welcome to virtual FTP service\.$', re.IGNORECASE),
            'Asus': re.compile(r'^220 Welcome to ASUS', re.IGNORECASE),
            'TP-Link': re.compile(r'TP-L(INK)|(ink) FTP', re.IGNORECASE),
            'Multicraft': re.compile(r'Multicraft\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Firewall\'d': re.compile(r'^220 Firewall Authentication required before proceeding with service$', re.IGNORECASE),
            'Titan FTP': re.compile(r'Titan\s+FTP\s+Server\s\d+\.\d+', re.IGNORECASE),
            'Cerberus FTP': re.compile(r'Cerberus\s+FTP\s+Server', re.IGNORECASE),
            'CrushFTP': re.compile(r'CrushFTP Server Ready!', re.IGNORECASE),
            'Bftpd': re.compile(r'(bftpd\s\d+\.\d+)|(\(bftpd\))', re.IGNORECASE),
            'zFTPServer': re.compile(r'zFTPServer', re.IGNORECASE),
            'Rumpus': re.compile(r'(Rumpus\s+FTP\s+Server)|(Welcome To Rumpus!)', re.IGNORECASE),
            'SlimFTPd': re.compile(r'SlimFTPd\s+\d+\.\d+', re.IGNORECASE),
            'Xlight FTP': re.compile(r'Xlight\s+FTP\s+Server', re.IGNORECASE),
            'WS_FTP': re.compile(r'WS_FTP\s+Server', re.IGNORECASE),
            'Gene6 FTP': re.compile(r'Gene6\s+FTP\s+Server', re.IGNORECASE),
            'Core FTP': re.compile(r'Core\s+FTP\s+Server', re.IGNORECASE),
            'Nucleus': re.compile(r'Nucleus FTP Server', re.IGNORECASE),
            'BulletProof': re.compile(r'BulletProof FTP Server', re.IGNORECASE),
            'Wing': re.compile(r'Wing FTP Server', re.IGNORECASE),
            'Hostgator': re.compile(r'Hostgator', re.IGNORECASE),
            'A7Emailing': re.compile(r'A7Emailing', re.IGNORECASE),
            'Cafe24': re.compile(r'(Cafe24 FTP Server Ready)|(Welcome to CAFE24 FTP Server)', re.IGNORECASE),
            'IServ': re.compile(r'^220 IServ$', re.IGNORECASE),
            'Arvixe': re.compile(r'^220 Arvixe$', re.IGNORECASE),
            'ZXR10': re.compile(r'^220 ZXR10 ftp service ready for new user\.$', re.IGNORECASE),
            'Quick \'n Easy FTP Server': re.compile(r'Quick \'n Easy FTP Server', re.IGNORECASE),
            #'Generic': re.compile(r'(^220 FTP service ready\.$)|(^220 FTP S|server R|ready(\.)?$)|(^220 FTP Server$)|(^220 FTP-Server$)|(^220 Welcome! Please note that all activity is logged.$)|(^220 \.$)|(^220 Welcome to FTP service\.$)|(^220 FTP (OK)$)|(^220 Operation successful$)', re.IGNORECASE),
        }
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get all welcome messages
        cursor.execute("SELECT welcome FROM ftp WHERE welcome IS NOT NULL")
        messages = cursor.fetchall()

        # Count server software
        server_counts = {}
        unknown_count = 0
        
        for (message,) in messages:
            if not message:
                continue
                
            detected = False
            for name, pattern in server_patterns.items():
                if pattern.search(message):
                    server_counts[name] = server_counts.get(name, 0) + 1
                    detected = True
                    break
            
            if not detected:
                unknown_count += 1
                #print(f"Unknown server banner: {message}")

        # Sort all servers by count
        sorted_servers = sorted(server_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Calculate combined Others/Unknown count
        others_unknown_count = unknown_count
        
        # If we have more servers than limit, group the rest under Others/Unknown
        if len(sorted_servers) > limit:
            others_unknown_count += sum(count for _, count in sorted_servers[limit:])
            sorted_servers = sorted_servers[:limit]
        
        # Add combined Others/Unknown category if there are any
        if others_unknown_count > 0:
            sorted_servers.append(('Others/Unknown', others_unknown_count))
            # Re-sort with Others/Unknown included
            sorted_servers = sorted(sorted_servers, key=lambda x: x[1], reverse=True)

        # Format and display the results
        if sorted_servers:
            headers = ["Server Software", "Count"]
            print(f"\nServer Software Breakdown (Top {limit}):")
            print(tabulate(sorted_servers, headers=headers, tablefmt="pretty"))

            # Generate pie chart with distinct colors
            servers, counts = zip(*sorted_servers)
            plt.figure(figsize=(10, 8))
            
            # Use a colormap with enough distinct colors
            colors = plt.cm.tab20.colors  # tab20 colormap has 20 distinct colors
            if len(servers) > 20:
                # If more than 20 categories, cycle through the colors
                colors = [colors[i % 20] for i in range(len(servers))]
            else:
                colors = colors[:len(servers)]
            
            # Create pie chart with labels
            plt.pie(counts, labels=servers, autopct='%1.1f%%', startangle=140, colors=colors,
                   textprops={'fontsize': 10}, pctdistance=0.85)  # Move percentages closer to edge
            plt.title(f'Server Software Breakdown (Top {limit})',
                    fontsize=14, fontweight='bold', pad=20)  # Bigger and bolder title with padding
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
            plt.subplots_adjust(top=0.85)  # Add more space above the chart
            plt.tight_layout()
            
            # Save and show the plot
            plt.savefig('server_software.png')
            plt.show()
        else:
            print("No server software information found.")

    except Exception as e:
        print(f"Error analyzing server software: {e}")
    finally:
        if conn:
            conn.close()

def detect_worm_infections(db_file):
    """Detect and display statistics about potential worm infections"""
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Check for worm infection files using pattern matching
        query = """
        SELECT 
            SUM(CASE WHEN anon = 1 THEN 1 ELSE 0 END) AS anon_hosts,
            SUM(CASE WHEN anon = 1 AND (
                        listing LIKE '%AV.scr%' OR 
                        listing LIKE '%Photo.scr%' OR 
                        listing LIKE '%Video.scr%' OR
                        listing LIKE '%AV.%.scr%' OR
                        listing LIKE '%Photo.%.scr%' OR
                        listing LIKE '%Video.%.scr%') THEN 1 ELSE 0 END) AS infected_hosts,
            ROUND(100.0 * SUM(CASE WHEN anon = 1 AND (
                        listing LIKE '%AV.scr%' OR 
                        listing LIKE '%Photo.scr%' OR 
                        listing LIKE '%Video.scr%' OR
                        listing LIKE '%AV.%.scr%' OR
                        listing LIKE '%Photo.%.scr%' OR
                        listing LIKE '%Video.%.scr%') THEN 1 ELSE 0 END) / 
                  SUM(CASE WHEN anon = 1 THEN 1 ELSE 0 END), 2) AS infection_percent
        FROM ftp;
        """
        cursor.execute(query)
        result = cursor.fetchone()

        # Format and display the results
        if result:
            headers = ["Anonymous Hosts", "Infected Hosts", "Percentage"]
            data = [result]
            print("\nWorm Infection Statistics:")
            print(tabulate(data, headers=headers, tablefmt="pretty"))
        else:
            print("No data found in the database.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def calculate_anonymous_access(db_file):
    """Calculate and display anonymous access statistics"""
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Execute the query to get statistics
        query = """
        SELECT 
            COUNT(*) AS total_hosts,
            SUM(CASE WHEN anon = 1 THEN 1 ELSE 0 END) AS anon_hosts,
            ROUND(100.0 * SUM(CASE WHEN anon = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) AS anon_percent
        FROM ftp;
        """
        cursor.execute(query)
        result = cursor.fetchone()

        # Format and display the results
        if result:
            headers = ["Total Hosts", "Anonymous Hosts", "Percentage"]
            data = [result]
            print("\nAnonymous Access Statistics:")
            print(tabulate(data, headers=headers, tablefmt="pretty"))
        else:
            print("No data found in the database.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Analyze FTP server statistics")
    parser.add_argument("database", help="Path to SQLite database file")
    parser.add_argument("--welcome-limit", type=int, default=10,
                       help="Number of top welcome messages to display (default: 10)")
    parser.add_argument("--geo-limit", type=int, default=10,
                       help="Number of top countries to display (default: 10)")
    parser.add_argument("--ip2location", required=True,
                       help="Path to IP2Location LITE DB1 CSV file")
    parser.add_argument("--software-limit", type=int, default=10,
                       help="Number of top server software to display (default: 10)")
    args = parser.parse_args()

    # Calculate and display statistics
    #calculate_anonymous_access(args.database)
    #detect_worm_infections(args.database)
    #analyze_welcome_messages(args.database, args.welcome_limit)
    analyze_geographical_distribution(args.database, args.ip2location, args.geo_limit)
    analyze_server_software(args.database, args.software_limit)

if __name__ == "__main__":
    main()
