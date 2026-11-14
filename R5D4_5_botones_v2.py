#!/usr/bin/env python3
# R5-D4: localizar el robot por TCP/6668 y enviar las 5 tramas capturadas.
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

PUERTO = 6668
PREFIJO_RED = "192.168.43."  # Hotspot Android; se comprueba el puerto, no una IP fija.
TIMEOUT_DETECCION = 0.35
TIMEOUT_RESPUESTA = 2.0

TRAMAS = [
    bytes.fromhex("55aa000006de0000000d000001a7332e3300000000000000240003cd960da51172e11e6eb25a0c205d7ae964e112e74ee4d1dcb3950f2f81cf69784d09c90333f287a86d3df1e532a87bc6202af83a3a0877fcbaee7765bf7216a4c0fc15cd2719eb5a2d1c7d92c5f1be2e6bc77c2cb533aa702f9322573e3e818d7a69b3c6b12786aff6c82b6cf615de3e63414d4e6d6a8c69523aece015d00bbf0c0068533db48c29f0ff559740c6b24145e720257afb619aba0c66f141332486f40d5072b8ad2303c0662b5fe25d17df2831894e7c6a3f8d984fc0e741b248b806304e78a23c5b1bc21b3fbb3981586909300419e97c022cbe58f3e844df96825648d4ce6de01d049f5372a547159644015121ad1981047dbdfd88881e58d7783497018670d21ec5cd0579fe535878086dc9c9305f58f43a762490ca7632b3c09bcb2ac1e325118d55690c28fce363e82d03a3c5a857ed19061901c05df8b49a2c516aeb77e2fed3cb7e24d7896ff0bedf2e7e43701acd42f96bb2769156c03b416e0361791753e6fce759c7ab3ab93fa74821ad1981047dbdfd88881e58d778349796c480069f9b7bb585935aa5f8587c5c7ce89bcb0000aa55"),
    bytes.fromhex("55aa000006df0000000d000001a7332e3300000000000000250003cd960da51172e11e6eb25a0c205d7ae964e112e74ee4d1dcb3950f2f81cf69784d09c90333f287a86d3df1e532a87bc6202af83a3a0877fcbaee7765bf7216a4c0fc15cd2719eb5a2d1c7d92c5f1be2e6bc77c2cb533aa702f9322573e3e818d7a69b3c6b12786aff6c82b6cf615de3e63414d4e6d6a8c69523aece015d00bbf0c0068533db48c29f0ff559740c6b24145e720257afb619aba0c66f141332486f40d5072b8ad2303c0662b5fe25d17df2831894e7c6a3f8d984fc0e741b248b806304e78a23c5b1bc21b3fbb3981586909300419e97c022cbe58f3e844df96825648d4ce6de01d049f5372a547159644015121ad1981047dbdfd88881e58d7783497018670d21ec5cd0579fe535878086dc9c9305f58f43a762490ca7632b3c09bcb2ac1e325118d55690c28fce363e82d031694e3d520b3bf101fe65cf2982b25af6aeb77e2fed3cb7e24d7896ff0bedf2e7e43701acd42f96bb2769156c03b416e0361791753e6fce759c7ab3ab93fa74821ad1981047dbdfd88881e58d7783497dc1a636e8d4fb745f724dd722d40971da063d2820000aa55"),
    bytes.fromhex("55aa000006e00000000d000001a7332e3300000000000000260003cd960da51172e11e6eb25a0c205d7ae964e112e74ee4d1dcb3950f2f81cf69784d09c90333f287a86d3df1e532a87bc6202af83a3a0877fcbaee7765bf7216a4c0fc15cd2719eb5a2d1c7d92c5f1be2e6bc77c2cb533aa702f9322573e3e818d7a69b3c6b12786aff6c82b6cf615de3e63414d4e6d6a8c69523aece015d00bbf0c0068533db48c29f0ff559740c6b24145e720257afb619aba0c66f141332486f40d5072b8ad2303c0662b5fe25d17df2831894e7c6a3f8d984fc0e741b248b806304e78a23c5b1bc21b3fbb3981586909300419e97c022cbe58f3e844df96825648d4ce6de01d049f5372a547159644015121ad1981047dbdfd88881e58d7783497018670d21ec5cd0579fe535878086dc9c9305f58f43a762490ca7632b3c09bcb2ac1e325118d55690c28fce363e82d03a3c5a857ed19061901c05df8b49a2c516aeb77e2fed3cb7e24d7896ff0bedf2e7e43701acd42f96bb2769156c03b416e0361791753e6fce759c7ab3ab93fa74821ad1981047dbdfd88881e58d778349796c480069f9b7bb585935aa5f8587c5c090c11b80000aa55"),
    bytes.fromhex("55aa000006e10000000d000001a7332e3300000000000000270003cd960da51172e11e6eb25a0c205d7ae964e112e74ee4d1dcb3950f2f81cf69784d09c90333f287a86d3df1e532a87bc6202af83a3a0877fcbaee7765bf7216a4c0fc15cd2719eb5a2d1c7d92c5f1be2e6bc77c2cb533aa702f9322573e3e818d7a69b3c6b12786aff6c82b6cf615de3e63414d4e6d6a8c69523aece015d00bbf0c0068533db48c29f0ff559740c6b24145e720257afb619aba0c66f141332486f40d5072b8ad2303c0662b5fe25d17df2831894e7c6a3f8d984fc0e741b248b806304e78a23c5b1bc21b3fbb3981586909300419e97c022cbe58f3e844df96825648d4ce6de01d049f5372a547159644015121ad1981047dbdfd88881e58d7783497018670d21ec5cd0579fe535878086dc9c9305f58f43a762490ca7632b3c09bcb2ac1e325118d55690c28fce363e82d03a3c5a857ed19061901c05df8b49a2c516aeb77e2fed3cb7e24d7896ff0bedf2ed4d907cc394219cf0c7ea9057716412e0361791753e6fce759c7ab3ab93fa74821ad1981047dbdfd88881e58d7783497dc1a636e8d4fb745f724dd722d40971de8660b370000aa55"),
    bytes.fromhex("55aa000006e20000000d000001a7332e3300000000000000280003cd960da51172e11e6eb25a0c205d7ae964e112e74ee4d1dcb3950f2f81cf69784d09c90333f287a86d3df1e532a87bc6202af83a3a0877fcbaee7765bf7216a4c0fc15cd2719eb5a2d1c7d92c5f1be2e6bc77c2cb533aa702f9322573e3e818d7a69b3c6b12786aff6c82b6cf615de3e63414d4e6d6a8c69523aece015d00bbf0c0068533db48c29f0ff559740c6b24145e720257afb619aba0c66f141332486f40d5072b8ad2303c0662b5fe25d17df2831894e7c6a3f8d984fc0e741b248b806304e78a23c5b1bc21b3fbb3981586909300419e97c022cbe58f3e844df96825648d4ce6de01d049f5372a547159644015121ad1981047dbdfd88881e58d7783497018670d21ec5cd0579fe535878086dc9c9305f58f43a762490ca7632b3c09bcb2ac1e325118d55690c28fce363e82d03a3c5a857ed19061901c05df8b49a2c516aeb77e2fed3cb7e24d7896ff0bedf2e7e43701acd42f96bb2769156c03b416e0361791753e6fce759c7ab3ab93fa74821ad1981047dbdfd88881e58d778349796c480069f9b7bb585935aa5f8587c5c741a1fa00000aa55"),
]

def comprobar_ip(ip):
    try:
        with socket.create_connection((ip, PUERTO), timeout=TIMEOUT_DETECCION):
            return ip
    except OSError:
        return None

def detectar_r5():
    print(f"\nBuscando R5-D4 en {PREFIJO_RED}1-254, puerto TCP {PUERTO}...")
    encontradas = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        tareas = [pool.submit(comprobar_ip, f"{PREFIJO_RED}{n}") for n in range(1, 255)]
        for tarea in as_completed(tareas):
            ip = tarea.result()
            if ip:
                encontradas.append(ip)
    if not encontradas:
        return None
    # Si hay más de un equipo con el puerto abierto, se muestran todos.
    print("Equipo(s) con TCP/6668 abierto: " + ", ".join(sorted(encontradas)))
    return sorted(encontradas)[0]

def enviar(ip, numero, enviadas):
    if numero in enviadas:
        print("Esta trama ya se ha enviado en esta ejecución; no se repite.")
        return
    trama = TRAMAS[numero - 1]
    try:
        with socket.create_connection((ip, PUERTO), timeout=3) as sock:
            sock.settimeout(TIMEOUT_RESPUESTA)
            sock.sendall(trama)
            print(f"\nBotón {numero}: enviada trama de {len(trama)} bytes a {ip}:{PUERTO}.")
            try:
                respuesta = sock.recv(2048)
                if respuesta:
                    print(f"Respuesta de R5: {len(respuesta)} bytes: {respuesta.hex()}")
                else:
                    print("R5 cerró la conexión sin enviar datos.")
            except socket.timeout:
                print("Enviada; R5 no devolvió respuesta dentro de 2 segundos.")
        enviadas.add(numero)
    except OSError as e:
        print(f"Error enviando al robot: {e}")

def main():
    ip = detectar_r5()
    if not ip:
        print("\nNo se ha encontrado ningún equipo con TCP/6668 abierto.")
        print("Comprueba que R5 está encendido y conectado al hotspot AndroidAp.")
        return
    print(f"\nR5-D4 localizado en {ip}.")
    print("Cinco órdenes capturadas; todavía no se ha confirmado que sean órdenes de apagado.")
    enviadas = set()
    while True:
        print("\n========== R5-D4 ==========")
        for n in range(1, 6):
            estado = " (ya enviada)" if n in enviadas else ""
            print(f"{n} - ENVIAR TRAZA {n}{estado}")
        print("r - Buscar R5 otra vez")
        print("q - Salir")
        opcion = input("Elige: ").strip().lower()
        if opcion == "q":
            break
        if opcion == "r":
            nuevo = detectar_r5()
            if nuevo:
                ip = nuevo
                print(f"R5 localizado en {ip}.")
            else:
                print("No se ha encontrado R5.")
            continue
        if opcion in ("1", "2", "3", "4", "5"):
            enviar(ip, int(opcion), enviadas)
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()
