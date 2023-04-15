import argparse
import re
import base64

def identify_hash(hash_string):
    """
    This function identifies different types of hashes using regular expressions.
    """
    # MD5
    if re.match(r'^[a-fA-F0-9]{32}$', hash_string):
        return "MD5"
    # SHA1
    elif re.match(r'^[a-fA-F0-9]{40}$', hash_string):
        return "SHA1"
    # SHA256
    elif re.match(r'^[a-fA-F0-9]{64}$', hash_string):
        return "SHA256"
    # SHA512
    elif re.match(r'^[a-fA-F0-9]{128}$', hash_string):
        return "SHA512"
    # NTLM
    elif re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$', hash_string):
        return "NTLM"
    # LM
    elif re.match(r'^[a-fA-F0-9]{14}:[a-fA-F0-9]{14}$', hash_string):
        return "LM"
    # MySQL 4.x
    elif re.match(r'^[a-fA-F0-9]{16}$', hash_string):
        return "MySQL 4.x"
    # MySQL 5.x
    elif re.match(r'^(\$mysql\$\d+\$[a-fA-F0-9]+\$)', hash_string):
        return "MySQL 5.x"
    # PostgreSQL MD5
    elif re.match(r'^md5[a-fA-F0-9]{32}$', hash_string):
        return "PostgreSQL MD5"
    # PostgreSQL SCRAM-SHA-256
    elif re.match(r'^SCRAM-SHA-256\$.*$', hash_string):
        return "PostgreSQL SCRAM-SHA-256"
    # LDAP {SHA}
    elif re.match(r'^\{SHA\}[a-zA-Z0-9+/]{27}=$', hash_string):
        return "LDAP {SHA}"
    # LDAP {SSHA}
    elif re.match(r'^\{SSHA\}[a-zA-Z0-9+/]{32,}=$', hash_string):
        return "LDAP {SSHA}"
    # Base64
    elif re.match(r'^[a-zA-Z0-9+/]+={0,2}$', hash_string):
        try:
            x = base64.b64decode(hash_string).decode()
            return f"Base64\nDecoded..: {x}"
        except:
            pass
    # Base32
    elif re.match(r'^[a-zA-Z2-7]+=*$', hash_string):
        try:
            x = base64.b32decode(hash_string).decode()
            return f"Base32\nDecoded..: {x}"
        except:
            pass
    # Base16
    elif re.match(r'^[a-fA-F0-9]+$', hash_string):
        try:
            x = base64.b16decode(hash_string).decode()
            return f"Base16\nDecoded..: {x}"
        except:
            pass
    # Unknown hash
    else:
        return "Unknown hash type"


# Create an argument parser
parser = argparse.ArgumentParser(description="Identify the type of a hash.")

# Add a hash argument
parser.add_argument("--hash", "--h", metavar="HASH",
                    required=True, help="The hash to identify.")

# Parse the arguments
args = parser.parse_args()

# Identify the hash type
hash_type = identify_hash(args.hash)

# Print the hash type
print(f"Hash.....: {args.hash}\nType.....: {hash_type}")
