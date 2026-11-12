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


def _interfaces_ipv4():
    """Obtiene la red local sin enumerar interfaces restringidas por Android."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect solo consulta la ruta local; no envia datos.
        probe.connect(("192.168.43.186", 6668))
        address = probe.getsockname()[0]
        network = ipaddress.IPv4Network(f"{address}/24", strict=False)
        print(f"Red local detectada: {network}")
        return [network]
    except (OSError, ValueError) as e:
        print("No se pudo obtener la red local:", repr(e))
        return []
    finally:
        probe.close()


def _port_6668_open(address):
    """Comprueba solo el establecimiento TCP; no envia datos de aplicacion."""
    try:
        with socket.create_connection((str(address), PORT), timeout=5):
            return str(address)
    except OSError:
        return None


def detect_robot_ip():
    """Localiza el unico equipo de la red conectada que escucha en TCP 6668."""
    networks = _interfaces_ipv4()
    if not networks:
        print("No se pudo obtener la red local automaticamente.")
        print("No se enviara nada. Comprueba que el hotspot Wi-Fi esta activo.")
        raise SystemExit(1)

    # Priorizar la IP conocida de R5-D4; si no responde, buscar automaticamente.
    known_ip = "192.168.43.186"
    if _port_6668_open(known_ip):
        print("R5-D4 localizado en la IP conocida.")
        return known_ip

    candidates = []
    for network in networks:
        candidates.extend(network.hosts())

    print("Buscando R5-D4 en la red local (TCP 6668)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        results = list(pool.map(_port_6668_open, candidates))
    matches = sorted(set(item for item in results if item))

    if len(matches) == 1:
        print("R5-D4 localizado automaticamente.")
        return matches[0]
    if not matches:
        print("No se ha encontrado ningun equipo con TCP 6668 abierto.")
    else:
        print("Deteccion ambigua: varios equipos tienen TCP 6668 abierto:", ", ".join(matches))
    print("Por seguridad no se transmitira ninguna trama.")
    raise SystemExit(1)
FRAMES = {
    "1": ("Activar TAREAS", "000055aa000005ce0000000d00000177332e3300000000000000170009e02666a4ef4921e089cb169061ac080603b44d83ddc4988d32d752de0387f7f23a08a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c701452c572a3878b8a4267b70f4a6b0c2c4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f64e2f86a5664a1f1a659eff8acc6dc77ccd0f0f710fa1eb37b7e817fe7da5cfb3a32ded54f3481b4a656a66f1d21d51e8844bae42f460514623352a4406e3304706195f10000aa55"),
    "2": ("Desactivar TAREAS", "000055aa000005cf0000000d00000177332e3300000000000000180009e02666a4ef4921e089cb169061ac080603b44d83ddc4988d32d752de0387f7f23a08a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70558e45f2dd7feec5ed40e9e06c7837f74f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f64e2f86a5664a1f1a659eff8acc6dc77ccd0f0f710fa1eb37b7e817fe7da5cfb3a32ded54f3481b4a656a66f1d21d51eba365f289e8afc9954c4dd51100a28c1303c94410000aa55"),
    "3": ("Aspiracion fuerte", "000055aa0000063c0000000d00000147332e33000000000000000d000b298b66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c706405a0634009b55c4533ee67be18e8644f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fd478a27e18c2d35141c0cc0c99632471d875a94d0000aa55"),
    "4": ("Aspiracion NULL", "000055aa0000063d0000000d00000147332e33000000000000000e000b298b66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70fa345582006427308ad861c83cafccd64f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcb1a02bb51b259955546c7070b0d726c8da3f34f0000aa55"),

    "5": ("Aspiracion ECO", "000055aa0000042a0000000d00000147332e33000000000000000700029dad66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c709c487efd7394f4a075259d8719b203dc4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fb1522677a14342cec68a99d0d9e0b782bd4c3caa0000aa55"),
    "6": ("Aspiracion normal", "000055aa0000042b0000000d00000147332e33000000000000000800029dad66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c703496fd2c13e0bcf5485f353b7f59d4254f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f7a15d2d1cc27a6668eb352058405c242e7fcec4b0000aa55"),
    "7": ("SIN AGUA", "000055aa000003eb0000000d00000147332e33000000000000001d000549a866a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70f80eff70af81bcf8fc284fe32b5431bd4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f5f695539aac2a44ae8d98dda31c4ee911639ec2e0000aa55"),
    "10": ("Agua alta", "000055aa000003ea0000000d00000147332e33000000000000001c000549a866a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70d2f23ce7a20913d67b837c15b00a71b44f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f7a15d2d1cc27a6668eb352058405c242a46fb11b0000aa55"),
    "8": ('Agua baja', '000055aa000005f40000000d00000147332e33000000000000000d0007332266a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70c4994b0ba9d95aa859871fe99b5e680f4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcb1a02bb51b259955546c7070b0d726c6bc459870000aa55'),
    "9": ('Agua media', '000055aa000005f50000000d00000147332e33000000000000000e0007332266a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c709c487efd7394f4a075259d8719b203dc4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fb1522677a14342cec68a99d0d9e0b782a345eb840000aa55'),
    "11": ("Limpieza completa", "000055aa000005b80000000d00000147332e3300000000000000070001f4d366a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526651bc2398efcfba9fc2931471566c72a72911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c7023a3b30698ff7994fef1413d6f4ac0394f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcc125a7b0770aaac5c71ed00b9223343dc0c3e7b0000aa55"),
    "12": ("Modo auto", "000055aa000005930000000d00000147332e3300000000000000470001cc5d66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c7012b84850e90acc9e3ff16fbb9670f3394f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f2da1172f48744e7a2b33d5f17765c934b713dcd60000aa55"),
    "13": ("Limpieza bordes", "000055aa000005920000000d00000147332e3300000000000000460001cc5d66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526628dc778dc238963a026b74bcfb0faf8f2911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c70fa345582006427308ad861c83cafccd64f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcb1a02bb51b259955546c7070b0d726cfc83297e0000aa55"),
    "16": ("Desactivar PROGRAMAR (horarios y dias de la semana)", "000055aa0000052b0000000d00000147332e33000000000000001f00044dde66a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526651bc2398efcfba9fc2931471566c72a72911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c705c2766f79dbb29af9b471278024f4b33fd8765a3abeb4b82349206fbb4ca694a65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f464558c0c621e253462486a0e444760f00d505b70000aa55"),
    "14": ("Modo Fregado", "000055aa000006480000000d00000147332e33000000000000000c000c560966a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526651bc2398efcfba9fc2931471566c72a72911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c7000c258c8f61ab666bdc906703d201bed4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f2da1172f48744e7a2b33d5f17765c9345785ecc70000aa55"),

    "17": ("Encender TWICE", "000055aa000006ec0000000d00000147332e33000000000000000b000a613766a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526651bc2398efcfba9fc2931471566c72a72911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c7000c258c8f61ab666bdc906703d201bedfd8765a3abeb4b82349206fbb4ca694a65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7fcc125a7b0770aaac5c71ed00b9223343ccda8ea50000aa55"),
    "18": ("Apagar TWICE", "000055aa000004a10000000d00000147332e33000000000000001a000d27e666a4ef4921e089cb169061ac080603b42d914ca0165b600e9ed342a4b7d9f3f3a2b9afcdc3dc38e2bbf3cc997cb3371a3d270432b0712a17c30ddac3213aea4a17a8b98c64141a2045098f077058825e696e6876b12b046d135931c01c93cac16f3d2028ab8412d90b3331782ae0526651bc2398efcfba9fc2931471566c72a72911814d6ef8f57fd27f542d22a99519f94acb125fb4690d2bab426743ee2c1727256032d0a7b9e1e3ffc828979d260c4980afad03aeb46f1a10906d3998b7cc819ee573649e0b1f8199f044f62f4c7000c258c8f61ab666bdc906703d201bed4f0c170c9f439791f22b3144035149ec65e49ac21e469711f8e41aa6c6d86fa05327eda8f8a0c6d9864bd3761daa5f2fccf48f42219c57f3f9a29da999863f7f2da1172f48744e7a2b33d5f17765c9345b4c90440000aa55"),

}

HOST = detect_robot_ip()

print("R5-D4 — Ajustes de limpieza")
print("Robot detectado:", HOST, " puerto:", PORT)
print("1 = Activar TAREAS | 2 = Desactivar TAREAS")
print("3 = Aspiracion fuerte | 4 = Aspiracion NULL | 5 = Aspiracion ECO | 6 = Aspiracion normal")
print("7 = SIN AGUA | 8 = Agua baja | 9 = Agua media | 10 = Agua alta")
print("11 = Limpieza completa | 12 = Modo auto")
print("13 = Limpieza bordes | 14 = Modo Fregado")
print("15 = PROGRAMAR (hora, minutos y dias)")
print("16 = Desactivar PROGRAMAR")
print("17 = Encender TWICE | 18 = Apagar TWICE")
print("Puedes combinar ajustes, por ejemplo: 1,5,8")
print("Escribe los numeros separados por comas o espacios. q = salir")

raw = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else input("Que quieres cambiar? (ej. 1,5,8): ").strip()
if raw.lower() in ("q", "salir"):
    print("Cancelado.")
    raise SystemExit

import re
choices = [item for item in re.split(r"[,;\s]+", raw) if item]
visible = {str(n) for n in range(1, 19)}
if not choices or any(item not in visible for item in choices):
    print("Seleccion no valida. Usa las opciones visibles del menu.")
    raise SystemExit

programacion_frames = []

if "15" in choices:
    if "16" in choices:
        print("No puedes programar y desactivar a la vez.")
        raise SystemExit

    hora = input("Hora (00-23): ").strip()
    minuto = input("Minutos (00-59): ").strip()

    if not re.fullmatch(r"(?:[01]?[0-9]|2[0-3])", hora):
        print("Hora no valida.")
        raise SystemExit
    if not re.fullmatch(r"[0-5]?[0-9]", minuto):
        print("Minutos no validos.")
        raise SystemExit

    aliases = {
        "L": 0, "LU": 0, "LUN": 0, "LUNES": 0,
        "M": 1, "MA": 1, "MAR": 1, "MARTES": 1,
        "X": 2, "MI": 2, "MIE": 2, "MIERCOLES": 2,
        "J": 3, "JU": 3, "JUE": 3, "JUEVES": 3,
        "V": 4, "VI": 4, "VIE": 4, "VIERNES": 4,
        "S": 5, "SA": 5, "SAB": 5, "SABADO": 5,
        "D": 6, "DO": 6, "DOM": 6, "DOMINGO": 6
    }

    dias_raw = input("Dias (L,M,X,J,V,S,D): ").strip().upper()
    tokens = [x for x in re.split(r"[,;\s]+", dias_raw) if x]

    if not tokens or any(x not in aliases for x in tokens):
        print("Dias no validos.")
        raise SystemExit

    dias = list(dict.fromkeys(aliases[x] for x in tokens))

    archivo = Path("/sdcard/Download/R5D4_reloj_frames.txt")
    reloj = {}

    for linea in archivo.read_text().splitlines():
        partes = linea.split()
        if len(partes) != 2:
            raise SystemExit("Formato incorrecto en archivo de tramas.")
        reloj[partes[0].lower()] = partes[1]

    esperados = {f"{n:08x}" for n in range(0x5e9, 0x644)}
    if len(reloj) != 91 or set(reloj) != esperados:
        raise SystemExit("Las 91 tramas no coinciden con los identificadores esperados.")

    def obtener_trama(identificador, etiqueta):
        hexadecimal = reloj[identificador]
        datos = bytes.fromhex(hexadecimal)
        if (len(datos) != 341 or datos[:2] != bytes.fromhex("55aa")
                or datos[-2:] != bytes.fromhex("aa55")
                or datos[4:8].hex() != identificador):
            raise SystemExit("Trama incorrecta: " + identificador)
        return (etiqueta, etiqueta, hexadecimal)

    h = int(hora)
    m = int(minuto)
    minuto_trama = max(1, m)

    programacion_frames.append(
        obtener_trama(f"{0x5e9+h:08x}", f"Hora {h:02d}:00")
    )
    programacion_frames.append(
        obtener_trama(f"{0x601+minuto_trama-1:08x}", f"Minuto {m:02d}")
    )

    nombres = ["Lunes", "Martes", "Miercoles", "Jueves",
               "Viernes", "Sabado", "Domingo"]

    for dia in dias:
        programacion_frames.append(
            obtener_trama(f"{0x63c+dia:08x}", nombres[dia])
        )

    programacion_frames.append(
        obtener_trama("00000643", "Restaurar estado inicial")
    )

# Quitar duplicados sin alterar el orden elegido.

# Solo se puede elegir un valor por cada grupo de ajustes.
groups = {
    "tareas": {"1", "2"},
    "rutinas": {"11", "12", "13", "14"},
    "programar": {"15", "16"},
    "twice": {"17", "18"},
    "aspiracion": {"3", "4", "5", "6"},
    "agua": {"7", "8", "9", "10"},
}
for group_name, members in groups.items():
    if group_name in ("aspiracion", "agua"):
        continue
    selected = [item for item in choices if item in members]
    if len(selected) > 1:
        print(f"Seleccion incompatible: elige solo una opcion de {group_name}.")
        raise SystemExit

# Resolver interferencias entre aspiracion y agua.
asp = next((x for x in choices if x in {"3", "4", "5", "6"}), None)
agua = next((x for x in choices if x in {"7", "8", "9", "10"}), None)

effective_choices = choices.copy()

if asp and agua:
    if asp == "5":
        effective_choices.remove(asp)
        print("\nCombinacion compatible: ECO queda aplicado por la trama de agua.")
    elif agua == "9":
        effective_choices.remove(agua)
        print("\nCombinacion compatible: agua MEDIA queda aplicado por la trama de aspiracion.")
    else:
        print("\nCOMBINACION NO DISPONIBLE con las tramas actuales.")
        print("No se ha enviado ninguna trama.")
        raise SystemExit

# Activar PROGRAMAR siempre al final.
if "15" in effective_choices:
    effective_choices.remove("15")
    effective_choices.append("15")

selected_frames = []
for item in effective_choices:
    if item == "15":
        selected_frames.extend(programacion_frames)
    else:
        selected_frames.append((item, *FRAMES[item]))
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
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
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
