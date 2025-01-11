#!/usr/bin/env python3
import sqlite3
import argparse
from tabulate import tabulate

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
    parser = argparse.ArgumentParser(description="Analyze FTP server anonymous access statistics")
    parser.add_argument("database", help="Path to SQLite database file")
    args = parser.parse_args()

    # Calculate and display statistics
    calculate_anonymous_access(args.database)

if __name__ == "__main__":
    main()
