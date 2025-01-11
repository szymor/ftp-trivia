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
    args = parser.parse_args()

    # Calculate and display statistics
    calculate_anonymous_access(args.database)
    analyze_welcome_messages(args.database, args.welcome_limit)

if __name__ == "__main__":
    main()
