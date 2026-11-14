#!/usr/bin/env python3
# R5-D4 V8 — Panel de control local
# Reproduce las 16 tramas cifradas capturadas. No implementa horarios ni días.

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

ROBOT_PORT = 6668
PACKETS_FILE = Path("/sdcard/Download/PCAPdroid/grandes.txt")
CANDIDATE_IPS = ["192.168.43.186", "192.168.43.187"]

ORDERS = [
    ("Limpieza", "Limpieza automática"),
    ("Limpieza", "Limpieza completa"),
    ("Limpieza", "Fregado"),
    ("Limpieza", "Bordes"),
    ("Modos", "TWICE activar"),
    ("Modos", "TWICE desactivar"),
    ("Aspiración", "Potencia TURBO"),
    ("Aspiración", "Potencia MEDIA"),
    ("Aspiración", "Potencia ECO"),
    ("Aspiración", "Potencia apagada"),
    ("Agua", "Caudal MÁXIMO"),
    ("Agua", "Caudal MEDIO"),
    ("Agua", "Caudal MÍNIMO"),
    ("Agua", "Agua apagada"),
    ("Programador", "Encender programador"),
    ("Programador", "Desactivar programador"),
]

def line():
    print("  " + "─" * 54)

def title():
    os.system("clear")
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║                 R5-D4  ·  CONTROL V8                 ║")
    print("  ║              PANEL DE ÓRDENES LOCALES                ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()

def load_packets():
    if not PACKETS_FILE.exists():
        print("  ERROR: No encuentro el archivo de tramas:")
        print(f"  {PACKETS_FILE}")
        print("\n  Comprueba que grandes.txt sigue en la carpeta PCAPdroid.")
        input("\n  ENTER para salir...")
        sys.exit(1)

    packets = []
    for raw in PACKETS_FILE.read_text(errors="ignore").splitlines():
        parts = raw.strip().split()
        if len(parts) < 3:
            continue
        hexdata = re.sub(r"[^0-9a-fA-F]", "", parts[-1])
        try:
            data = bytes.fromhex(hexdata)
        except ValueError:
            continue

        # tshark entrega dos bytes 00 delante de la trama TCP útil.
        # La trama del protocolo empieza en 55 aa y termina en aa 55.
        if data.startswith(b"\x00\x00\x55\xaa"):
            data = data[2:]

        if data.startswith(b"\x55\xaa") and data.endswith(b"\xaa\x55"):
            if len(data) == 341:
                packets.append(data)

    if len(packets) != 16:
        print(f"  ERROR: Se esperaban 16 tramas válidas y he encontrado {len(packets)}.")
        print("  No se enviará nada. Revisa grandes.txt.")
        input("\n  ENTER para salir...")
        sys.exit(1)
    return packets

def find_robot():
    candidates = list(CANDIDATE_IPS)
    try:
        result = subprocess.run(
            ["ip", "neigh"], capture_output=True, text=True, timeout=3
        )
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout):
            if ip not in candidates and not ip.endswith(".1"):
                candidates.append(ip)
    except Exception:
        pass

    for ip in candidates:
        try:
            with socket.create_connection((ip, ROBOT_PORT), timeout=1.5):
                return ip
        except OSError:
            continue
    return None

def send_packet(ip, packet):
    try:
        with socket.create_connection((ip, ROBOT_PORT), timeout=3) as sock:
            sock.settimeout(2)
            sock.sendall(packet)
            try:
                response = sock.recv(2048)
            except socket.timeout:
                response = b""
        return True, bool(response), None
    except OSError as exc:
        return False, False, str(exc)

def main():
    packets = load_packets()
    selected = set()

    while True:
        title()
        print("  ROBOT")
        line()
        print("  Buscando R5-D4 en la red local (TCP 6668)...")
        ip = find_robot()
        if not ip:
            print("  Estado: SIN CONEXIÓN")
            print("\n  No encuentro el robot. Comprueba el punto de acceso")
            print("  y que R5-D4 esté encendido.")
            input("\n  ENTER para volver a intentar...")
            continue
        print(f"  Estado: CONECTADO     IP: {ip}:{ROBOT_PORT}")
        print()
        print("  ÓRDENES DISPONIBLES")
        line()

        last_group = None
        for i, (group, label) in enumerate(ORDERS):
            if group != last_group:
                print(f"\n  ┌─ {group.upper()}")
                last_group = group
            mark = "✓" if i in selected else " "
            print(f"  │  [{mark}] {i+1:02d}  {label}")
        print("  └" + "─" * 53)
        print()
        print(f"  Seleccionadas: {len(selected)} de 16")
        line()
        print("  INTRODUCE EL NÚMERO para marcar/desmarcar.")
        print("  *  = seleccionar todas       -  = desmarcar todas")
        print("  ENTER = EJECUTAR selección   q  = salir")
        print()

        choice = input("  Selección > ").strip().lower()
        if choice == "q":
            print("\n  Panel cerrado.")
            return
        if choice == "*":
            selected = set(range(16))
            continue
        if choice == "-":
            selected.clear()
            continue
        if choice == "":
            if not selected:
                print("\n  No has seleccionado ninguna orden.")
                input("  ENTER para continuar...")
                continue
            break
        if choice.isdigit():
            number = int(choice)
            if 1 <= number <= 16:
                idx = number - 1
                if idx in selected:
                    selected.remove(idx)
                else:
                    selected.add(idx)
            continue
        print("\n  Entrada no válida.")
        input("  ENTER para continuar...")

    # Enter en el panel inicia directamente el envío, sin palabra de confirmación.
    title()
    print("  EJECUTANDO ÓRDENES SELECCIONADAS")
    line()
    print(f"  Robot: {ip}:{ROBOT_PORT}")
    print(f"  Total: {len(selected)} órdenes")
    print("  Orden de envío: según la lista del panel")
    print()

    success = 0
    failures = 0
    for idx in sorted(selected):
        label = ORDERS[idx][1]
        print(f"  [{idx+1:02d}/16] {label:<25}", end="", flush=True)
        ok, replied, error = send_packet(ip, packets[idx])
        if ok:
            success += 1
            print("  ENVIADA" + (" · respuesta recibida" if replied else " · sin respuesta"))
        else:
            failures += 1
            print("  ERROR")
            print(f"         {error}")
            break
        time.sleep(0.35)

    print()
    line()
    print("  RESULTADO")
    print(f"  Tramas enviadas: {success}")
    print(f"  Errores:         {failures}")
    print()
    print("  Nota: envío TCP correcto no garantiza que el robot")
    print("  ejecute la orden. Las tramas cifradas podrían depender")
    print("  de la sesión original de la aplicación.")
    input("\n  ENTER para cerrar el panel...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Operación interrumpida.")
