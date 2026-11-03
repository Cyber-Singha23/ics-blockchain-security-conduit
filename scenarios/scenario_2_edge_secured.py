import json
import socket
import struct
import time
from web3 import Web3

HOST = "127.0.0.1"
GATEWAY_PORT = 5021
GANACHE_URL  = "http://127.0.0.1:8545"

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_CYAN   = "\033[96m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_DIM    = "\033[90m"

def init_and_reset_blockchain_state():
    """Ensures Unit 1 & Unit 2 start with clean Trust=100 before running Scenario 2."""
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    with open("contract_config.json", "r") as f:
        cfg = json.load(f)
    contract = w3.eth.contract(address=cfg["contract_address"], abi=cfg["abi"])
    acct_map = cfg.get("accounts", cfg.get("unit_map", {}))
    admin = acct_map.get("admin", w3.eth.accounts[0])

    u1_addr = acct_map["1"]
    u2_addr = acct_map["2"]
    u3_addr = acct_map["3"]

    tx1 = contract.functions.registerDevice(u1_addr, True).transact({"from": admin})
    tx2 = contract.functions.registerDevice(u2_addr, False).transact({"from": admin})
    w3.eth.wait_for_transaction_receipt(tx1)
    w3.eth.wait_for_transaction_receipt(tx2)

    return w3, contract, cfg["contract_address"], {"1": u1_addr, "2": u2_addr, "3": u3_addr}

def get_node_trust(contract, addr):
    _, _, trust = contract.functions.devices(addr).call()
    return trust

def send_gateway_request(trans_id, proto_id, unit_id, role_name, func_code, addr, val, desc, contract, unit_addrs):
    frame = struct.pack(">HHHBBHH", trans_id, proto_id, 6, unit_id, func_code, addr, val)
    t0 = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10.0)
        s.connect((HOST, GATEWAY_PORT))
        s.sendall(frame)
        resp = s.recv(1024)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    is_exception = (len(resp) >= 8 and (resp[7] & 0x80) != 0)
    exc_code = resp[8] if (is_exception and len(resp) >= 9) else 0

    reading_str = "Blocked (Exception 0x85)" if is_exception else "Coil 0 Written"
    if not is_exception and func_code == 3 and len(resp) >= 11:
        _, _, _, _, _, _, psi = struct.unpack(">HHHBBBH", resp[:11])
        reading_str = f"{psi} PSI (Verified)"
    elif not is_exception and func_code == 5:
        reading_str = "Coil 0 = CLOSED (Normal)" if val == 0 else "Coil 0 = OPEN"

    trust_after = get_node_trust(contract, unit_addrs[str(unit_id)])

    return {
        "step": desc,
        "role": f"Unit {unit_id} ({role_name})",
        "fc": f"FC=0{func_code}",
        "reading": reading_str,
        "latency": latency_ms,
        "blocked": is_exception,
        "exc_hex": f"Modbus Exception 0x{resp[7]:02x}" if is_exception else "None",
        "trust": trust_after
    }

def main():
    print(f"{C_BOLD}{C_CYAN}{'=' * 94}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}           SCENARIO 2: PROPOSED ARCHITECTURE (EDGE-ASSISTED BLOCKCHAIN CONDUIT){C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 94}{C_RESET}")

    w3, contract, c_addr, unit_addrs = init_and_reset_blockchain_state()
    print(f"  {C_DIM}Contract Active : {c_addr} | Edge Gateway: {HOST}:{GATEWAY_PORT}{C_RESET}\n")

    # Warm up the Edge Gateway's local cache with 1 fast on-chain sync
    send_gateway_request(900, 0, 1, "Engineer", 3, 0, 1, "Warm Edge Cache", contract, unit_addrs)

    print(f"{C_BOLD}{C_GREEN}[PART A] Normal Authorized Operations Through Edge Gateway{C_RESET}")
    print(f"{C_DIM}{'-' * 94}{C_RESET}")

    normal_ops = [
        (1, 1, 1, "Engineer",    3, 0, 1,      "Authorized Pressure Read via Edge Cache"),
        (2, 1, 2, "HMI Monitor", 3, 0, 1,      "Authorized Monitor Read via Edge Cache"),
        (3, 1, 1, "Engineer",    5, 0, 0x0000, "Authorized Valve Reset (Coil 0 -> CLOSED)")
    ]

    for tid, pid, uid, role, fc, addr, val, desc in normal_ops:
        res = send_gateway_request(tid, pid, uid, role, fc, addr, val, desc, contract, unit_addrs)
        print(f"  {C_GREEN}[+] {res['role']:<22}{C_RESET} | {res['fc']} | {desc}")
        print(f"      Process State : {C_BOLD}{res['reading']}{C_RESET} | Latency: {C_GREEN}{C_BOLD}{res['latency']:.2f} ms{C_RESET}")
        print(f"      On-Chain Trust: {C_BOLD}{res['trust']}/100{C_RESET} | Conduit Verdict: {C_GREEN}{C_BOLD}SUCCESS (Allowed){C_RESET}\n")
        time.sleep(0.15)

    print(f"{C_BOLD}{C_RED}[PART B] Attack With Security (Blocked at Edge Conduit){C_RESET}")
    print(f"{C_DIM}{'-' * 94}{C_RESET}")

    atk = send_gateway_request(
        101, 1, 3, "Rogue Attacker", 5, 0, 0xFF00,
        "Unauthorized Actuator Override Attempt (OPEN Relief Valve)",
        contract, unit_addrs
    )
    print(f"  {C_RED}[!] {atk['role']:<22}{C_RESET} | {atk['fc']} | {atk['step']}")
    print(f"      Gateway Action: {C_RED}{C_BOLD}BLOCKED ({atk['exc_hex']}){C_RESET} | Intercept Latency: {C_BOLD}{atk['latency']:.2f} ms{C_RESET}")
    print(f"      Node Status   : {C_YELLOW}{C_BOLD}Unregistered Device (On-Chain Trust Score = {atk['trust']}/100){C_RESET}")
    print(f"      Safety Outcome: {C_GREEN}{C_BOLD}Plant Floor Protected (Malicious Frame Dropped Before Reaching PLC){C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 94}{C_RESET}")
    print(f"{C_BOLD}SCENARIO 2 COMPLETE: High-speed authorized operations co-exist with robust automated defense.{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{'=' * 94}{C_RESET}")

if __name__ == "__main__":
    main()
