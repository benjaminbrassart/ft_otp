#!/usr/bin/env python3

import base64
import hashlib
import hmac
import struct
import sys
import time

def hotp_dynamic_truncation(hash: bytes) -> int:
    assert len(hash) == 20

    last_byte = hash[19]
    offset = last_byte & 0x0F

    bin_code = (hash[offset] & 0x7F) << 24 \
        | (hash[offset + 1] & 0xFF) << 16 \
        | (hash[offset + 2] & 0xFF) << 8 \
        | (hash[offset + 3] & 0xFF) << 0

    return bin_code

    # print(type(bin_code))

    # return hash[offset:offset + 4]

#
# 5.3.   Generating an HOTP Value
#   Step 1: Generate an HMAC-SHA-1 value
#               Let HS = HMAC-SHA-1(K, C)   // HS is a 20-byte string
#
#   Step 2: Generate a 4-byte string (Dynamic Truncation)
#               Let Sbits = DT(HS)          // DT, defined below
#                                           // Sbits is a 31-bit string
#
#   DT(String) // String = String[0] ... String[19]
#
def hotp_generate(secret: bytes, mfactor: int, digits: int) -> str:
    """
    Generate an HOTP value

    ### Parameters
    - `secret` the decrypted bytes of the key (K in RFC 4226)
    - `mfactor` the moving factor (counter for HOTP, time / interval for TOTP) (C in RFC 4226)
    - `digits` the number of digits to output

    ### Reference
    - https://www.rfc-editor.org/rfc/rfc4226#section-5.3
    """
    assert mfactor < (1 << 64)

    # convert mfactor to a big-endian 8-byte buffer
    #   > = big endian
    #   Q = unsigned long long
    mfactor_bytes = struct.pack(">Q", mfactor)

    # Step 1: Generate an HMAC-SHA-1 value
    hash = hmac.digest(secret, mfactor_bytes, hashlib.sha1)

    # Step 2: Generate a 4-byte string (Dynamic Truncation)
    sbits = hotp_dynamic_truncation(hash)

    # Step 3: Compute an HOTP value
    otp_key = sbits % (10 ** digits)

    return f"{otp_key:0>{digits}}"

def totp_generate(secret: bytes, digits: int, interval: int) -> str:
    now = int(time.time() // interval)

    return hotp_generate(secret, now, digits)

def run_genkey(file_name: str):
    with open(file_name, "r") as file:
        content = file.read()

    if len(content) < 64 or not all(c in "0123456789ABCDEFabcdef" for c in content):
        raise Exception("key must be at least 64 hexadecimal characters")

    hex_secret = bytes.fromhex(content)

    # TODO encrypt key

    with open("ft_otp.key", "wb") as wf:
        wf.write(hex_secret)

def run_genpass(file_name: str):
    with open(file_name, "rb") as file:
        content = file.read()
        password = totp_generate(content, 6, 30)

        print(password)

def usage():
    print("Usage:")
    print("  ft_otp -g <file> -- Generate an encrypted key file from an hexadecimal file")
    print("  ft_otp -k <file> -- Generate a temporary password from an encrypted key file")

def main(argv: list[str]) -> int:
    args = argv[1:]

    if len(args) != 2:
        usage()
        return 1

    match args[0]:
        case "-g":
            run_function = run_genkey
        case "-k":
            run_function = run_genpass
        case _:
            usage()
            return 1

    try:
        run_function(args[1])
    except Exception as e:
        print(f"ft_otp: error: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main(sys.argv))
