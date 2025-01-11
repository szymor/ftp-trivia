#!/usr/bin/env python3
import sqlite3
import argparse
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
            start_ip, end_ip, country_code, country_name = line.strip().split(',')
            ip_ranges[(int(start_ip), int(end_ip))] = country_name
    return ip_ranges

def ip_to_int(ip):
    """Convert IP address to integer"""
    octets = list(map(int, ip.split('.')))
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]

def find_country_for_ip(ip, ip_ranges):
    """Find country for given IP using binary search"""
    ip_int = ip_to_int(ip)
    # Binary search through sorted ranges
    low, high = 0, len(ip_ranges) - 1
    while low <= high:
        mid = (low + high) // 2
        start, end = list(ip_ranges.keys())[mid]
        if start <= ip_int <= end:
            return ip_ranges[(start, end)]
        elif ip_int < start:
            high = mid - 1
        else:
            low = mid + 1
    return "Unknown"

def analyze_geographical_distribution(db_file, ip2location_file, limit=10):
    """Analyze and display geographical distribution using IP2Location"""
    try:
        # Load IP2Location database
        ip_ranges = load_ip2location_db(ip2location_file)
        # Sort ranges for binary search
        ip_ranges = dict(sorted(ip_ranges.items()))
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get all IPs
        cursor.execute("SELECT ip FROM ftp")
        ips = cursor.fetchall()

        # Count countries
        country_counts = {}
        for (ip,) in ips:
            country = find_country_for_ip(ip, ip_ranges)
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
    args = parser.parse_args()

    # Calculate and display statistics
    calculate_anonymous_access(args.database)
    analyze_welcome_messages(args.database, args.welcome_limit)
    analyze_geographical_distribution(args.database, args.ip2location, args.geo_limit)

if __name__ == "__main__":
    main()
