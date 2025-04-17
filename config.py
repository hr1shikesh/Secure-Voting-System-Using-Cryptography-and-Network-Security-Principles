# ------------ config.py ------------
import ssl  # Added missing import

# Election Configuration
ELECTION = {
    "society_name": "Mumbai United Cooperative Housing Society",
    "election_date": "2025-04-15",
    "positions": ["Chairperson", "Secretary", "Treasurer"],
    "voter_eligibility": {
        "min_age": 18,
        "membership_days": 180
    },
    "allowed_attempts": 3,
    "session_timeout": 300
}

# Cryptographic Configuration
CRYPTO = {
    "hash_algorithm": "SHA-512",
    "hmac_digest_size": 32,
    "pbkdf2_iterations": 1000000,
    "ecc_curve": "secp521r1",
    "aes_mode": "GCM",
    "aes_key_size": 32
}

# Network Security (Fixed TLS Configuration)
TLS_CONFIG = {
    "ssl_version": ssl.PROTOCOL_TLS_SERVER,  # Now properly imported
    "cert_path": "certs/server.crt",
    "key_path": "certs/server.key"
}

# System Security Policies
SECURITY = {
    "password_policy": {
        "min_length": 12,
        "require_upper": True,
        "require_special_char": True
    },
    "firewall_rules": {
        "max_connections": 100,
        "rate_limit": "10/60"
    },
    "intrusion_detection": {
        "alert_threshold": 5
    }
}

# Audit Logging
LOGGING = {
    "vote_audit_log": "audit.log",
    "encrypt_logs": True
}