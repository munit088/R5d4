#!/usr/bin/env python3
# R5-D4: reproduccion literal de tramas capturadas en PCAP.
# 1/2: tramas 0x0D ya probadas por el usuario.
# Controles confirmados: tareas horarias y potencia de aspiracion.
import socket
import sys
import ipaddress
import struct
import concurrent.futures
import fcntl
import os

HOST = None  # Se descubre automaticamente al iniciar.
PORT = 6668
LOCAL_IP = None


def detect_robot_ip():
    """Detecta R5-D4 mediante su puerto TCP 6668 en la subred local."""
    global LOCAL_IP
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 80))
        LOCAL_IP = probe.getsockname()[0]
        ip_local = LOCAL_IP
    except OSError as e:
        print("No se pudo detectar la IP local:", repr(e))
        print("No se enviara ninguna trama.")
        raise SystemExit(1)
    finally:
        probe.close()

    network = ipaddress.ip_network(ip_local + "/24", strict=False)
    print("IP del movil:", ip_local)
    print("Subred:", network)

    def comprobar(ip):
        try:
            with socket.create_connection((str(ip), PORT), timeout=1):
                return str(ip)
        except OSError:
            return None

    for numero in (186, 187):
        candidata = str(network.network_address + numero)
        if candidata == ip_local:
            continue
        print("Probando:", candidata)
        encontrada = comprobar(candidata)
        if encontrada:
            print("R5-D4 detectado:", encontrada)
            return encontrada

    print("No responde ninguna de las dos IP conocidas.")
    manual = input("Introduce la IP de R5-D4 manualmente: ").strip()

    try:
        direccion = ipaddress.ip_address(manual)
    except ValueError:
        print("IP no valida. No se transmitira ninguna trama.")
        raise SystemExit(1)

    if direccion.version != 4 or direccion not in network or manual == ip_local:
        print("IP fuera de la subred del movil o no valida.")
        print("No se transmitira ninguna trama.")
        raise SystemExit(1)

    print("Comprobando TCP 6668 en:", manual)
    encontrada = comprobar(manual)
    if encontrada:
        print("R5-D4 detectado manualmente:", encontrada)
        return encontrada

    print("La IP manual no responde en TCP 6668.")
    print("No se transmitira ninguna trama.")
    raise SystemExit(1)


FRAMES = {
    "1": ("Activar los horarios", "000055aa000005ce0000000d00000177332e3300000000000000170009e02666a4ef4921e089cb169061ac080603b44d83ddc4988d32d752de0387f7f23a08a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c701452c572a3878b8a4267b70f4a6b0c2c4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f64e2f86a5664a1f1a659eff8acc6dc77ccd0f0f710fa1eb37b7e817fe7da5cfb3a32ded54f3481b4a656a66f1d21d51e8844bae42f460514623352a4406e3304706195f10000aa55"),
    "2": ("Desactivar los horarios", "000055aa000005cf0000000d00000177332e3300000000000000180009e02666a4ef4921e089cb169061ac080603b44d83ddc4988d32d752de0387f7f23a08a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70558e45f2dd7feec5ed40e9e06c7837f74f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f64e2f86a5664a1f1a659eff8acc6dc77ccd0f0f710fa1eb37b7e817fe7da5cfb3a32ded54f3481b4a656a66f1d21d51eba365f289e8afc9954c4dd51100a28c1303c94410000aa55"),
    "3": ("Aspiracion fuerte", "000055aa0000063c0000000d00000147332e33000000000000000d000b298b66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c706405a0634009b55c4533ee67be18e8644f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fd478a27e18c2d35141c0cc0c99632471d875a94d0000aa55"),
    "4": ("Aspiracion NULL", "000055aa0000063d0000000d00000147332e33000000000000000e000b298b66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70fa345582006427308ad861c83cafccd64f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcb1a02bb51b259955546c7070b0d726c8da3f34f0000aa55"),

    "5": ("Aspiracion ECO", "000055aa0000042a0000000d00000147332e33000000000000000700029dad66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c709c487efd7394f4a075259d8719b203dc4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fb1522677a14342cec68a99d0d9e0b782bd4c3caa0000aa55"),
    "6": ("Aspiracion normal", "000055aa0000042b0000000d00000147332e33000000000000000800029dad66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c703496fd2c13e0bcf5485f353b7f59d4254f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f7a15d2d1cc27a6668eb352058405c242e7fcec4b0000aa55"),
    "7": ("SIN AGUA", "000055aa000003eb0000000d00000147332e33000000000000001d000549a866a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70f80eff70af81bcf8fc284fe32b5431bd4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f5f695539aac2a44ae8d98dda31c4ee911639ec2e0000aa55"),
    "10": ("Agua alta", "000055aa000003ea0000000d00000147332e33000000000000001c000549a866a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70d2f23ce7a20913d67b837c15b00a71b44f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f7a15d2d1cc27a6668eb352058405c242a46fb11b0000aa55"),
    "8": ('Agua baja', '000055aa000005f40000000d00000147332e33000000000000000d0007332266a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70c4994b0ba9d95aa859871fe99b5e680f4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcb1a02bb51b259955546c7070b0d726c6bc459870000aa55'),
    "9": ('Agua media', '000055aa000005f50000000d00000147332e33000000000000000e0007332266a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c709c487efd7394f4a075259d8719b203dc4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fb1522677a14342cec68a99d0d9e0b782a345eb840000aa55'),
}

HOST = detect_robot_ip()

print("R5-D4 — Ajustes de limpieza")
print("Robot detectado:", HOST, " puerto:", PORT)
print("1 = Activar los horarios | 2 = Desactivar los horarios")
print("3 = Aspiracion fuerte | 4 = Aspiracion NULL | 5 = Aspiracion ECO | 6 = Aspiracion normal")
print("7 = SIN AGUA | 8 = Agua baja | 9 = Agua media | 10 = Agua alta")
print("Puedes combinar ajustes, por ejemplo: 1,5,8")
print("Escribe los numeros separados por comas o espacios. q = salir")

raw = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else input("Que quieres cambiar? (ej. 1,5,8): ").strip()
if raw.lower() in ("q", "salir"):
    print("Cancelado.")
    raise SystemExit

import re
choices = [item for item in re.split(r"[,;\s]+", raw) if item]
if not choices or any(item not in FRAMES for item in choices):
    print("Seleccion no valida. Usa los numeros del menu.")
    raise SystemExit

# Quitar duplicados sin alterar el orden elegido.
choices = list(dict.fromkeys(choices))

# Solo se puede elegir un valor por cada grupo de ajustes.
groups = {
    "planes horarios": {"1", "2"},
    "aspiracion": {"3", "4", "5", "6"},
    "agua": {"7", "8", "9", "10"},
}
for group_name, members in groups.items():
    selected = [item for item in choices if item in members]
    if len(selected) > 1:
        print(f"Seleccion incompatible: elige solo una opcion de {group_name}.")
        raise SystemExit

selected_frames = [(item, *FRAMES[item]) for item in choices]
print("\nVas a aplicar estos cambios:")
for item, label, hexdata in selected_frames:
    payload = bytes.fromhex(hexdata)
    print(f"  {item} = {label} ({len(payload)} bytes)")

print("\nSe aplicaran por separado y en el orden elegido.")
if input("Escribe APLICAR para confirmar: ").strip() != "APLICAR":
    print("No se ha cambiado nada.")
    raise SystemExit

for item, label, hexdata in selected_frames:
    payload = bytes.fromhex(hexdata)
    print(f"\nAplicando: {label}")
    try:
        with socket.create_connection((HOST, PORT), timeout=5, source_address=(LOCAL_IP, 0)) as sock:
            sock.settimeout(3)
            sock.sendall(payload)
            try:
                response = sock.recv(2048)
                print("Respuesta:", response.hex() if response else "conexion cerrada sin datos")
                if response:
                    print("Bytes recibidos:", len(response))
            except socket.timeout:
                print("Sin respuesta dentro de 3 segundos; se continua con la siguiente opcion.")
    except OSError as e:
        print("Error de conexion/envio:", repr(e))
        print("Tanda detenida para no continuar con el estado de envio incierto.")
        break
