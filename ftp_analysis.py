#!/usr/bin/env python3
import sqlite3
import argparse
import re
from tabulate import tabulate

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
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

        # Format and display the results
        if sorted_countries:
            headers = ["Country", "Host Count"]
            print("\nGeographical Distribution (Top Countries):")
            print(tabulate(sorted_countries, headers=headers, tablefmt="pretty"))
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
            'vsFTPd': re.compile(r'vsFTPd\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'ProFTPD': re.compile(r'ProFTPD\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Pure-FTPd': re.compile(r'Pure-FTPd\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'FileZilla': re.compile(r'FileZilla\s+Server\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Microsoft FTP': re.compile(r'Microsoft FTP Service', re.IGNORECASE),
            'Wu-ftpd': re.compile(r'(?:wu-ftpd|wuftpd)\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Titan FTP': re.compile(r'Titan\s+FTP\s+Server', re.IGNORECASE),
            'Serv-U': re.compile(r'Serv-U\s+FTP\s+Server', re.IGNORECASE),
            'Cerberus FTP': re.compile(r'Cerberus\s+FTP\s+Server', re.IGNORECASE),
            'GlFTPd': re.compile(r'glFTPd\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'CrushFTP': re.compile(r'CrushFTP\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'pyftpdlib': re.compile(r'pyftpdlib\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Bftpd': re.compile(r'bftpd\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'zFTPServer': re.compile(r'zFTPServer\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Rumpus': re.compile(r'Rumpus\s+FTP\s+Server', re.IGNORECASE),
            'Xlight FTP': re.compile(r'Xlight\s+FTP\s+Server', re.IGNORECASE),
            'IIS FTP': re.compile(r'Microsoft-IIS/\d+\.\d+', re.IGNORECASE),
            'WS_FTP': re.compile(r'WS_FTP\s+Server', re.IGNORECASE),
            'Gene6 FTP': re.compile(r'Gene6\s+FTP\s+Server', re.IGNORECASE),
            'RaidenFTPD': re.compile(r'RaidenFTPD\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'BlackMoon FTP': re.compile(r'BlackMoon\s+FTP\s+Server', re.IGNORECASE),
            'CompleteFTP': re.compile(r'CompleteFTP\s+\d+\.\d+\.\d+', re.IGNORECASE),
            'Core FTP': re.compile(r'Core\s+FTP\s+Server', re.IGNORECASE),
            'GNU inetutils': re.compile(r'(?:GNU\s+inetutils|inetutils-ftpd)\s+\d+\.\d+', re.IGNORECASE),
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

        # Add unknown count if any
        if unknown_count > 0:
            server_counts['Unknown'] = unknown_count

        # Get top servers
        sorted_servers = sorted(server_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

        # Format and display the results
        if sorted_servers:
            headers = ["Server Software", "Count"]
            print("\nServer Software Breakdown:")
            print(tabulate(sorted_servers, headers=headers, tablefmt="pretty"))
        else:
            print("No server software information found.")

    except Exception as e:
        print(f"Error analyzing server software: {e}")
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
    #analyze_welcome_messages(args.database, args.welcome_limit)
    #analyze_geographical_distribution(args.database, args.ip2location, args.geo_limit)
    analyze_server_software(args.database, args.software_limit)

if __name__ == "__main__":
    main()
