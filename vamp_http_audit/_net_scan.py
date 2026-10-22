# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_net_scan.py — Descubrimiento de servicios HTTP/HTTPS en rangos de red (CIDR).

Expande uno o varios rangos CIDR, prueba conexión TCP en puertos web comunes
y devuelve las URLs activas listas para pasar a HTTPAuditor.
Sin dependencias externas: solo asyncio y stdlib.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Iterable

# Puertos web que se comprueban por defecto
WEB_PORTS: list[int] = [
    80, 443, 8000, 8008, 8080, 8081, 8082, 8088, 8089,
    4443, 8443, 9443, 10000,
]

# Puertos que usan TLS → scheme https://
HTTPS_PORTS: frozenset[int] = frozenset([443, 4443, 8443, 9443])


def _url_para(ip: str, puerto: int) -> str:
    """Construye la URL con el esquema correcto para una IP y puerto."""
    scheme = "https" if puerto in HTTPS_PORTS else "http"
    if puerto in (80, 443):
        return f"{scheme}://{ip}"
    return f"{scheme}://{ip}:{puerto}"


async def _tcp_abierto(ip: str, puerto: int, timeout: float) -> bool:
    """Comprueba si un puerto TCP está abierto mediante connect asíncrono."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, puerto),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _escanear_host(
    ip: str,
    puertos: list[int],
    timeout: float,
    sem: asyncio.Semaphore,
) -> list[str]:
    """Prueba todos los puertos de un host y devuelve las URLs activas."""
    urls: list[str] = []
    async with sem:
        tareas = [_tcp_abierto(ip, p, timeout) for p in puertos]
        resultados = await asyncio.gather(*tareas)
        for puerto, abierto in zip(puertos, resultados):
            if abierto:
                urls.append(_url_para(ip, puerto))
    return urls


async def _escanear_red_async(
    cidrs: list[str],
    puertos: list[int],
    timeout: float,
    max_concurrencia: int,
) -> list[str]:
    """Núcleo asíncrono: expande los CIDRs y escanea todos los hosts."""
    ips: list[str] = []
    for cidr in cidrs:
        try:
            red = ipaddress.ip_network(cidr, strict=False)
            # Excluir dirección de red y broadcast en /24+; en /32 incluir el host
            if red.num_addresses <= 2:
                ips.extend(str(h) for h in red.hosts() or [str(red.network_address)])
            else:
                ips.extend(str(h) for h in red.hosts())
        except ValueError as exc:
            raise ValueError(f"CIDR inválido {cidr!r}: {exc}") from exc

    sem = asyncio.Semaphore(max_concurrencia)
    tareas = [_escanear_host(ip, puertos, timeout, sem) for ip in ips]
    grupos = await asyncio.gather(*tareas)

    urls: list[str] = []
    for grupo in grupos:
        urls.extend(grupo)
    return urls


def escanear_redes(
    cidrs: Iterable[str],
    puertos: list[int] | None = None,
    timeout: float = 1.5,
    max_concurrencia: int = 200,
) -> list[str]:
    """
    Punto de entrada síncrono: escanea los rangos CIDR y devuelve URLs activas.

    Parámetros
    ----------
    cidrs            : rangos en notación CIDR (ej. «192.168.1.0/24»)
    puertos          : lista de puertos TCP a probar (por defecto WEB_PORTS)
    timeout          : segundos de espera por intento TCP (default: 1.5)
    max_concurrencia : conexiones TCP simultáneas (default: 200)

    Devuelve
    --------
    Lista de URLs del tipo «http://10.0.0.5:8080» o «https://10.0.0.1».
    """
    if puertos is None:
        puertos = WEB_PORTS
    lista = list(cidrs)
    if not lista:
        return []
    return asyncio.run(
        _escanear_red_async(lista, puertos, timeout, max_concurrencia)
    )
