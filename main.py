# Мелешин Демид КН-204(МЕН-200201) TCP/UDP Scanner.
from socket import *
import argparse


def scan_port(cur_ip, cur_port, port_type):
    print(f"Scanning port: {cur_port} for {cur_ip}")

    try:
        cur_socket = socket(
            AF_INET,
            port_type  # TCP = SOCK_STREAM, UDP = SOCK_DGRAM
        )
        cur_socket.settimeout(0.5)
        cur_socket.connect((cur_ip, int(cur_port)))
        print(f"Port: {str(cur_port)} is opened\n")

    except:
        print(f"Port: {str(cur_port)} is closed\n")

    finally:
        cur_socket.close()


def scan_for_port_type(ip, ports_range, port_type):
    start = int(ports_range[0])
    end = int(ports_range[len(ports_range)-1])
    for port in range(start, end + 1):
        if port_type == '-u':
            scan_port(ip, port, SOCK_DGRAM)
        else:
            scan_port(ip, port, SOCK_STREAM)


def get_args():
    args = argparse.ArgumentParser("TCP Scanner")
    args.add_argument("-i", "--ip", type=str, help="Enter ip to scan")
    args.add_argument("-p", "--port", type=str, help="Enter ports to scan")
    args.add_argument("-u", "--ports_type", action="store_true")
    return args


def main():
    print("TCP/UDP Scanner\n")
    try:
        args = get_args().parse_args()
        ip = args.ip
        ports = args.port.split(',')
        ports_type = args.ports_type
        scan_for_port_type(ip, ports, ports_type)

    except:
        print("Incorrect input\n example: python portscanner.py -i 192.168.43.211 -p 1,1000")


if __name__ == "__main__":
    main()
