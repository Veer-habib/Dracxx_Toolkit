"""Nmap adapter - port/service/version enumeration. Safe detection scripts
only (e.g. -sV, default/safe NSE categories). No exploit/brute NSE scripts
are ever invoked.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List

from dracxx.integrations.base import ToolAdapter
from dracxx.models.schema import Port

SAFE_SCRIPT_CATEGORIES = "default,safe,version"


class NmapAdapter(ToolAdapter):
    binary_name = "nmap"
    display_name = "Nmap"

    async def scan(
        self,
        target: str,
        ports: str = "top-1000",
        deep: bool = False,
        fast: bool = False,
    ) -> List[Port]:
        args = ["-oX", "-", "-sV", "--script", SAFE_SCRIPT_CATEGORIES]
        if fast:
            # Top 100 ports, no heavy scripts beyond version
            args = ["-oX", "-", "-sV", "--top-ports", "100", "--open"]
            timeout = 60
        elif ports == "top-1000":
            args += ["--top-ports", "1000"]
            timeout = 180
        elif ports:
            args += ["-p", ports]
            timeout = 180
        else:
            timeout = 180
        if deep and not fast:
            args += ["-A"]
            timeout = 600
        args += [target]
        result = await self.run(args, timeout=timeout)
        if not result.ok or not result.stdout:
            return []
        return self._parse_xml(result.stdout, target)

    @staticmethod
    def _parse_xml(xml_text: str, target: str) -> List[Port]:
        out = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return out
        for host in root.findall("host"):
            for ports_el in host.findall("ports"):
                for port_el in ports_el.findall("port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    svc = port_el.find("service")
                    out.append(Port(
                        asset=target,
                        port=int(port_el.get("portid")),
                        protocol=port_el.get("protocol", "tcp"),
                        service=svc.get("name") if svc is not None else None,
                        product=svc.get("product") if svc is not None else None,
                        version=svc.get("version") if svc is not None else None,
                        tls="ssl" in (svc.get("tunnel", "") if svc is not None else ""),
                    ))
        return out
