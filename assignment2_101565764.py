"""
Author: Affan Telek
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# This dictionary stores common port numbers and their matching service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = ""
        self.target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using a property lets the class control how the target value is accessed and changed without exposing the
    # private attribute directly. The setter adds validation so invalid data, such as an empty string, can be rejected
    # before it affects the object. This keeps the object in a safer and more consistent state.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it can reuse the target storage, property methods, and validation logic
# instead of rewriting them. For example, the PortScanner constructor calls super().__init__(target), which lets the
# parent class handle setting the private target value. This reduces duplicate code and keeps shared behavior in one place.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None
        # Q4: What would happen without try-except here?
        # Without try-except, a socket failure such as an unreachable host or connection error could crash the program
        # or terminate the thread unexpectedly. That would stop the scan from finishing cleanly and could leave the user
        # with incomplete results. Exception handling lets the scanner report the problem and continue scanning other ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            try:
                self.scan_results.append((port, status, service_name))
            finally:
                self.lock.release()
        except socket.error as error:
            print(f"Error scanning port {port}: {error}")
        finally:
            if sock is not None:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows many port checks to happen at the same time, so the scan finishes much faster than a sequential
    # scan. If you scanned 1024 ports one by one, each timeout could add delay and make the program feel very slow.
    # By running multiple threads, the scanner can wait on several network operations in parallel.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
            """
        )

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()
    except sqlite3.Error as error:
        print(f"Database error: {error}")


def load_past_scans():
    if not os.path.exists("scan_history.db"):
        print("No past scans found.")
        return

    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
            return

        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
    except sqlite3.Error:
        print("No past scans found.")
    finally:
        if conn is not None:
            conn.close()


def get_valid_port(prompt, minimum=1, maximum=1024):
    while True:
        try:
            port = int(input(prompt))
            if minimum <= port <= maximum:
                return port
            print("Port must be between 1 and 1024.")
        except ValueError:
            print("Invalid input. Please enter a valid integer.")


def main():
    try:
        target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"

        start_port = get_valid_port("Enter starting port (1-1024): ")

        while True:
            end_port = get_valid_port("Enter ending port (1-1024): ")
            if end_port >= start_port:
                break
            print("Ending port must be greater than or equal to start port.")

        scanner = PortScanner(target)
        print(f"Scanning {target} from port {start_port} to {end_port}...")
        scanner.scan_range(start_port, end_port)

        open_ports = scanner.get_open_ports()
        print(f"--- Scan Results for {target} ---")
        for port, status, service_name in open_ports:
            print(f"Port {port}: {status} ({service_name})")
        print("------")
        print(f"Total open ports found: {len(open_ports)}")

        save_results(target, scanner.scan_results)

        show_history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
        if show_history == "yes":
            load_past_scans()
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")


if __name__ == "__main__":
    main()

# Q5: New Feature Proposal
# One useful feature I would add is a quick summary filter that groups results into well-known services,
# such as web, remote access, and email ports, after the scan completes. A list comprehension could build
# each category by selecting matching tuples from scan_results, which would make the final output easier to read.
# Diagram: See diagram_101565764.png in the repository root
