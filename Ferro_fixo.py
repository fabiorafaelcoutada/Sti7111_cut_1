#!/usr/bin/env python3
import serial
import time
import argparse
import sys
import os

def parse_payload(filepath):
    """
    Parses a payload file containing lines like:
    sleep 1.0
    poke ADDRESS VALUE
    display ADDRESS
    """
    commands = []
    if not os.path.exists(filepath):
        print(f"Error: Payload file '{filepath}' not found.")
        sys.exit(1)

    with open(filepath, 'r') as f:
        for line in f:
            # Remove newline characters from the right
            # We want to preserve trailing spaces if they are part of the command
            clean_line = line.rstrip('\n').rstrip('\r')

            # Check for empty lines or comments (ignoring leading whitespace)
            if not clean_line.strip() or clean_line.strip().startswith('#'):
                continue

            # Check for sleep command
            # Sleep command is "sleep DURATION", spaces around it don't matter much
            if clean_line.strip().startswith('sleep '):
                try:
                    duration = float(clean_line.strip().split()[1])
                    commands.append(('sleep', duration))
                except (IndexError, ValueError):
                    print(f"Warning: Invalid sleep command: {line}")
            else:
                # Assume raw command to be sent (e.g., 'poke ...')
                # Remove leading whitespace as original code didn't have indentation in strings
                # But preserve trailing whitespace as some commands like 'poke ... ecwpk  ' have it
                commands.append(('write', clean_line.lstrip()))
    return commands

def main():
    parser = argparse.ArgumentParser(description='Serial Exploit Tool')
    parser.add_argument('--port', default='/dev/ttyUSB1', help='Serial port to connect to (default: /dev/ttyUSB1)')
    parser.add_argument('--baud', type=int, default=115200, help='Baud rate (default: 115200)')
    parser.add_argument('--payload', default='payload.txt', help='Payload file containing commands (default: payload.txt)')

    args = parser.parse_args()

    # Locate payload file
    payload_path = args.payload
    if not os.path.exists(payload_path):
        # Try finding it in the script's directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, payload_path)
        if os.path.exists(alt_path):
            payload_path = alt_path
        else:
            print(f"Error: Payload file '{payload_path}' not found.")
            sys.exit(1)

    # Load payload first to validate before opening port
    commands = parse_payload(payload_path)
    print(f"Loaded {len(commands)} commands from {payload_path}")

    try:
        # Open serial port
        s = serial.Serial(args.port, args.baud, write_timeout=0.5)
        print(f"Connected to {args.port} at {args.baud} baud.")
    except serial.SerialException as e:
        print(f"Error opening serial port: {e}")
        sys.exit(1)

    print("Starting execution...")

    try:
        for cmd_type, value in commands:
            if cmd_type == 'sleep':
                print(f"Sleeping for {value}s...")
                time.sleep(value)
            elif cmd_type == 'write':
                # Original code sent b"cmd\n"
                # So we append \n and encode as utf-8 (which is compatible with ascii for these commands)
                data = value.encode('utf-8') + b'\n'
                try:
                    s.write(data)
                    # print(f"Sent: {value}") # Verbose output optional
                except serial.SerialTimeoutException:
                    print("Write timeout! Exiting...")
                    sys.exit(1) # Replicate original crashing behavior but cleaner
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred during execution: {e}")
        # Original script would crash on unexpected error, we print and exit
        sys.exit(1)
    finally:
        if 's' in locals() and s.is_open:
            s.close()
            print("Serial port closed.")

if __name__ == "__main__":
    main()
