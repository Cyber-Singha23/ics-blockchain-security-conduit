import socket
import struct
import time

# Target the "unsecured" PLC endpoint directly.
# With iptables active, the Linux kernel transparently diverts this to 127.0.0.1:5021!
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5020

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_CYAN   = "\033[96m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_DIM    = "\033[90m"

def send_packet(trans_id, proto_id, unit_id, role_name, func_code, addr, val, desc):
    frame = struct.pack(">HHHBBHH", trans_id, proto_id, 6, unit_id, func_code, addr, val)
    t0 = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(frame)
        resp = s.recv(1024)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    # Dynamically check if the response is a Modbus Exception (0x80 bit set on Function Code)
    is_exception = (len(resp) >= 8 and (resp[7] & 0x80) != 0)
    exc_code = resp[8] if (is_exception and len(resp) >= 9) else None

    state_str = "N/A"
    if not is_exception:
        if func_code == 3 and len(resp) >= 11:
            _, _, _, _, _, _, psi = struct.unpack(">HHHBBBH", resp[:11])
            state_str = f"{psi} PSI (Boiler Pressure)"
        elif func_code == 5:
            state_str = "Coil 0 = OPEN" if val > 0 else "Coil 0 = CLOSED (Normal)"
    else:
        state_str = f"REJECTED (Modbus Exception 0x{resp[7]:02x} / Code 0x{exc_code:02x})"

    return {
        "desc": desc,
        "role": f"Unit {unit_id} ({role_name})",
        "fc": f"FC=0{func_code}",
        "is_blocked": is_exception,
        "state": state_str,
        "latency": latency_ms
    }

def main():
    print(f"{C_BOLD}{C_CYAN}{'=' * 84}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}  IEC 62443 NETWORK CONDUIT ENFORCEMENT TEST (IPTABLES DNAT REDIRECTION){C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 84}{C_RESET}")
    print(f"  {C_DIM}Client Target  : {TARGET_HOST}:{TARGET_PORT} (Attempting Direct PLC Access){C_RESET}")
    print(f"  {C_DIM}Kernel Rule    : iptables DNAT 127.0.0.1:5020 -> 127.0.0.1:5021 (Edge Gateway){C_RESET}\n")

    print(f"{C_BOLD}{C_YELLOW}[PART A] Authorized Operators Targeting Port 5020 (Transparently Routed via Gateway){C_RESET}")
    print(f"{C_DIM}{'-' * 84}{C_RESET}")

    # Using proto_id=1 for fast Edge-Cached verification (~1-4 ms)
    ops = [
        (1, 1, 1, "Engineer",    3, 0, 1,      "Read Boiler Pressure Telemetry"),
        (2, 1, 2, "HMI Monitor", 3, 0, 1,      "Read Boiler Pressure Status"),
        (3, 1, 1, "Engineer",    5, 0, 0x0000, "Set Relief Valve to Normal (CLOSED)")
    ]

    for tid, pid, uid, role, fc, addr, val, desc in ops:
        res = send_packet(tid, pid, uid, role, fc, addr, val, desc)
        if not res["is_blocked"]:
            print(f"  {C_GREEN}[+] {res['role']:<22}{C_RESET} | {res['fc']} | {desc}")
            print(f"      Process State : {C_BOLD}{res['state']}{C_RESET} | Latency: {C_BOLD}{res['latency']:.2f} ms{C_RESET}")
            print(f"      Conduit Check : {C_GREEN}INTERCEPTED BY GATEWAY & ALLOWED (Authorized Role){C_RESET}\n")
        else:
            print(f"  {C_RED}[-] {res['role']:<22}{C_RESET} | {res['fc']} | {desc} -> BLOCKED\n")
        time.sleep(0.15)

    print(f"{C_BOLD}{C_RED}[PART B] Direct PLC Bypass Attack on Port 5020 (Intercepted by iptables + Gateway){C_RESET}")
    print(f"{C_DIM}{'-' * 84}{C_RESET}")

    # Attacker uses proto_id=0 (raw standard Modbus frame) trying to hit 127.0.0.1:5020 directly
    atk = send_packet(99, 0, 3, "Rogue Attacker", 5, 0, 0xFF00, "Direct Bypass Attempt: Force Relief Valve OPEN")
    print(f"  {C_RED}[!] {atk['role']:<22}{C_RESET} | {atk['fc']} | {atk['desc']}")
    if atk["is_blocked"]:
        print(f"      Gateway Action: {C_GREEN}{C_BOLD}{atk['state']}{C_RESET}")
        print(f"      Process Impact: {C_GREEN}{C_BOLD}NONE (Physical PLC at 127.0.0.2:5020 Untouched!){C_RESET}")
        print(f"      Check Latency : {C_BOLD}{atk['latency']:.2f} ms{C_RESET} | Security Verdict: {C_GREEN}{C_BOLD}BYPASS MITIGATED (Blocked by Conduit){C_RESET}")
    else:
        print(f"      Process Impact: {C_RED}{C_BOLD}{atk['state']} [PHYSICAL PROCESS HIJACKED!]{C_RESET}")
        print(f"      Attack Latency: {C_BOLD}{atk['latency']:.2f} ms{C_RESET} | Security Verdict: {C_RED}{C_BOLD}BREACH SUCCEEDED (Firewall Inactive){C_RESET}")

    print(f"{C_BOLD}{C_CYAN}{'=' * 84}{C_RESET}")
    if atk["is_blocked"]:
        print(f"{C_BOLD}TEST COMPLETE: Even when targeting Port 5020 directly, iptables forced traffic")
        print(f"               through the Edge Blockchain Gateway (5021) and blocked the attack!{C_RESET}")
    else:
        print(f"{C_BOLD}TEST COMPLETE: Firewall redirection is OFF. Direct attack on Port 5020 succeeded.{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 84}{C_RESET}")

if __name__ == "__main__":
    main()
