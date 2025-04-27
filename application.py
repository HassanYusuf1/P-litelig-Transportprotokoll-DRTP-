# application.py

import socket
import argparse
import struct
import time
import os

# Konstanter
HEADER_STØRRELSE = 8  # 8 bytes header
DATA_STØRRELSE = 992  # 992 bytes data
PAKKE_STØRRELSE = HEADER_STØRRELSE + DATA_STØRRELSE
TIDSAVBRUDD = 0.4  # 400 millisekunder timeout
STANDARD_VINDU = 3

# Flaggverdier
FLAGG_FIN = 0b001
FLAGG_ACK = 0b010
FLAGG_SYN = 0b100
FLAGG_RST = 0b000  # Ikke brukt

# Lager DRTP-header
def lag_header(sekvensnummer, bekreftelsesnummer, flagg, vindusstørrelse):
    return struct.pack('!HHHH', sekvensnummer, bekreftelsesnummer, flagg, vindusstørrelse)

# Tolker DRTP-header
def tolk_header(data):
    return struct.unpack('!HHHH', data)

# Starter server
def start_server(ip_adresse, portnummer, hopp_over_sekvens):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip_adresse, portnummer))
    print(f"Server kjører på {ip_adresse}:{portnummer}")

    forventet_sekvens = 1
    fil = open('mottatt_fil.jpg', 'wb')
    start_tid = None
    totale_bytes = 0

    # Håndterer treveis handshake
    while True:
        data, adresse = server_socket.recvfrom(PAKKE_STØRRELSE)
        sekvens, bekreftelse, flagg, vindu = tolk_header(data[:HEADER_STØRRELSE])

        if flagg & FLAGG_SYN:
            print("SYN-pakke mottatt")
            syn_ack = lag_header(0, 0, FLAGG_SYN | FLAGG_ACK, 15)
            server_socket.sendto(syn_ack, adresse)
            print("SYN-ACK-pakke sendt")
        elif flagg & FLAGG_ACK:
            print("ACK-pakke mottatt")
            print("Tilkobling etablert")
            break

    server_socket.settimeout(TIDSAVBRUDD)

    # Mottar data
    while True:
        try:
            pakke, adresse = server_socket.recvfrom(PAKKE_STØRRELSE)
            sekvens, bekreftelse, flagg, vindu = tolk_header(pakke[:HEADER_STØRRELSE])

            if flagg & FLAGG_FIN:
                print("FIN-pakke mottatt")
                fin_ack = lag_header(0, 0, FLAGG_FIN | FLAGG_ACK, 0)
                server_socket.sendto(fin_ack, adresse)
                print("FIN-ACK-pakke sendt")
                break

            if start_tid is None:
                start_tid = time.time()

            if sekvens == forventet_sekvens:
                if sekvens == hopp_over_sekvens:
                    print(f"Kaster pakke {sekvens} for testing av retransmisjon")
                    hopp_over_sekvens = 999999  # Kaster kun én gang
                    continue
                data = pakke[HEADER_STØRRELSE:]
                fil.write(data)
                totale_bytes += len(data)
                print(f"{time.strftime('%H:%M:%S')} -- pakke {sekvens} mottatt")
                ack_pakke = lag_header(0, sekvens, FLAGG_ACK, 0)
                server_socket.sendto(ack_pakke, adresse)
                print(f"{time.strftime('%H:%M:%S')} -- sender ACK for {sekvens}")
                forventet_sekvens += 1
            else:
                print(f"{time.strftime('%H:%M:%S')} -- pakke utenfor rekkefølge {sekvens} mottatt")

        except socket.timeout:
            continue

    fil.close()
    slutt_tid = time.time()
    varighet = slutt_tid - start_tid
    gjennomstrømming = (totale_bytes * 8) / (varighet * 1000000)  # Mbps
    print(f"\nGjennomstrømming: {gjennomstrømming:.2f} Mbps")
    print("Tilkobling lukkes")

# Starter klient
def start_klient(ip_adresse, portnummer, filnavn, vindusstørrelse):
    klient_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_adresse = (ip_adresse, portnummer)
    klient_socket.settimeout(TIDSAVBRUDD)

    # Starter treveis handshake
    syn = lag_header(0, 0, FLAGG_SYN, 0)
    klient_socket.sendto(syn, server_adresse)
    print("SYN-pakke sendt")

    try:
        data, _ = klient_socket.recvfrom(PAKKE_STØRRELSE)
        _, _, flagg, mottaker_vindu = tolk_header(data[:HEADER_STØRRELSE])
        if flagg & FLAGG_SYN and flagg & FLAGG_ACK:
            print("SYN-ACK-pakke mottatt")
            ack = lag_header(0, 0, FLAGG_ACK, 0)
            klient_socket.sendto(ack, server_adresse)
            print("ACK-pakke sendt")
            print("Tilkobling etablert")
    except socket.timeout:
        print("Tilkobling feilet")
        return

    vindusstørrelse = min(vindusstørrelse, mottaker_vindu)

    # Leser fil og forbereder pakker
    pakker = []
    sekvens = 1
    with open(filnavn, 'rb') as f:
        while True:
            bit = f.read(DATA_STØRRELSE)
            if not bit:
                break
            header = lag_header(sekvens, 0, 0, 0)
            pakker.append(header + bit)
            sekvens += 1

    base = 1
    neste_sekvens = 1
    totalt_antall_pakker = len(pakker)
    timer_start = time.time()

    def start_timer():
        nonlocal timer_start
        timer_start = time.time()

    def har_timeout():
        return time.time() - timer_start > TIDSAVBRUDD

    start_timer()

    # Sender data
    while base <= totalt_antall_pakker:
        while neste_sekvens < base + vindusstørrelse and neste_sekvens <= totalt_antall_pakker:
            klient_socket.sendto(pakker[neste_sekvens - 1], server_adresse)
            print(f"{time.strftime('%H:%M:%S')} -- pakke med sekvens = {neste_sekvens} sendt, sliding window = {{{', '.join(str(i) for i in range(base, neste_sekvens + 1))}}}")
            neste_sekvens += 1

        try:
            ack_pakke, _ = klient_socket.recvfrom(PAKKE_STØRRELSE)
            _, ack_nummer, flagg, _ = tolk_header(ack_pakke[:HEADER_STØRRELSE])
            if flagg & FLAGG_ACK:
                print(f"{time.strftime('%H:%M:%S')} -- ACK for pakke = {ack_nummer} mottatt")
                if ack_nummer >= base:
                    base = ack_nummer + 1
                    start_timer()

        except socket.timeout:
            print(f"{time.strftime('%H:%M:%S')} -- Timeout, sender på nytt")
            for i in range(base, neste_sekvens):
                klient_socket.sendto(pakker[i - 1], server_adresse)
                print(f"{time.strftime('%H:%M:%S')} -- sender pakke på nytt med sekvens = {i}")
            start_timer()

    # Sender FIN-pakke
    fin = lag_header(0, 0, FLAGG_FIN, 0)
    klient_socket.sendto(fin, server_adresse)
    print("\nFIN-pakke sendt")

    try:
        data, _ = klient_socket.recvfrom(PAKKE_STØRRELSE)
        _, _, flagg, _ = tolk_header(data[:HEADER_STØRRELSE])
        if flagg & FLAGG_FIN and flagg & FLAGG_ACK:
            print("FIN-ACK-pakke mottatt")
    except socket.timeout:
        print("Ingen FIN-ACK mottatt")

    print("Tilkobling lukkes")

# Hovedprogram
def hovedprogram():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', action='store_true', help='Kjør som server')
    parser.add_argument('-c', '--client', action='store_true', help='Kjør som klient')
    parser.add_argument('-i', '--ip', type=str, default='127.0.0.1', help='IP-adresse')
    parser.add_argument('-p', '--port', type=int, default=8088, help='Portnummer')
    parser.add_argument('-f', '--file', type=str, help='Filnavn (for klient)')
    parser.add_argument('-w', '--window', type=int, default=STANDARD_VINDU, help='Sliding window størrelse')
    parser.add_argument('-d', '--discard', type=int, default=999999, help='Sekvensnummer å kaste (for server)')

    args = parser.parse_args()

    if args.server:
        start_server(args.ip, args.port, args.discard)
    elif args.client:
        if not args.file:
            print("Filnavn må oppgis for klient")
            return
        start_klient(args.ip, args.port, args.file, args.window)
    else:
        print("Spesifiser --server eller --client")

if __name__ == "__main__":
    hovedprogram()
