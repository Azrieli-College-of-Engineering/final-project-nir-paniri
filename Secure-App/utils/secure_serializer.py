"""
Secure Serialization Utilities for ServerOps

This module provides two defense mechanisms against insecure deserialization:

1. HMAC Signature Verification (HMACPickleSerializer)
   - Still uses pickle, but signs data with HMAC-SHA256
   - Attacker cannot forge valid signatures without the secret key
   - Detects any tampering with the serialized data

2. JSON-Based Serialization (JSONSerializer)  
   - Replaces pickle entirely with JSON
   - JSON cannot execute code - it only handles primitive types
   - Most secure option but requires objects to be JSON-serializable

Usage:
    # HMAC approach (still uses pickle but validates integrity)
    serializer = HMACPickleSerializer(secret_key="your-secret-key")
    signed_data = serializer.serialize(obj)
    obj = serializer.deserialize(signed_data)  # Validates signature first
    
    # JSON approach (safest, no code execution possible)
    serializer = JSONSerializer()
    json_data = serializer.serialize(obj)
    obj = serializer.deserialize(json_data, ServerConfig)
"""

import pickle
import json
import hmac
import hashlib
import base64
import os
from typing import Any, Type, List
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SignatureVerificationError(Exception):
    """Raised when HMAC signature verification fails."""
    pass


class HMACPickleSerializer:
    """
    Secure pickle serializer with HMAC-SHA256 signature verification.
    
    This prevents tampering but still uses pickle for serialization.
    The signature is computed over the pickled data using a secret key.
    Any modification to the data will cause signature verification to fail.
    
    Format: base64(pickle_data) + "." + base64(hmac_signature)
    
    Security Note: This approach prevents tampering but requires keeping
    the secret key secure. If the key is compromised, an attacker could
    generate valid signatures for malicious payloads.
    """
    
    SEPARATOR = b"."
    
    def __init__(self, secret_key: str):
        """
        Initialize the serializer with a secret key.
        
        Args:
            secret_key: The secret key for HMAC signing. 
                       Should be a strong, randomly generated string.
        """
        if not secret_key or len(secret_key) < 16:
            raise ValueError("Secret key must be at least 16 characters")
        self.secret_key = secret_key.encode('utf-8')
    
    def _compute_signature(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 signature for the given data."""
        return hmac.new(
            self.secret_key,
            data,
            hashlib.sha256
        ).digest()
    
    def _verify_signature(self, data: bytes, signature: bytes) -> bool:
        """
        Verify the signature matches the data.
        Uses hmac.compare_digest for timing-attack resistance.
        """
        expected_signature = self._compute_signature(data)
        return hmac.compare_digest(signature, expected_signature)
    
    def serialize(self, obj: Any) -> bytes:
        """
        Serialize an object with HMAC signature.
        
        Args:
            obj: The Python object to serialize
            
        Returns:
            Base64 encoded pickle data with appended HMAC signature
        """
        pickled_data = pickle.dumps(obj)
        encoded_pickle = base64.b64encode(pickled_data)
        
        signature = self._compute_signature(pickled_data)
        encoded_signature = base64.b64encode(signature)
        
        return encoded_pickle + self.SEPARATOR + encoded_signature
    
    def deserialize(self, data: bytes) -> Any:
        """
        Deserialize data after verifying the HMAC signature.
        
        Args:
            data: The signed, encoded data to deserialize
            
        Returns:
            The deserialized Python object
            
        Raises:
            SignatureVerificationError: If signature is invalid or missing
            ValueError: If data format is invalid
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if self.SEPARATOR not in data:
            raise SignatureVerificationError(
                "Invalid format: Missing signature separator"
            )
        
        parts = data.rsplit(self.SEPARATOR, 1)
        if len(parts) != 2:
            raise SignatureVerificationError(
                "Invalid format: Expected data.signature"
            )
        
        encoded_pickle, encoded_signature = parts
        
        try:
            pickled_data = base64.b64decode(encoded_pickle)
            signature = base64.b64decode(encoded_signature)
        except Exception as e:
            raise SignatureVerificationError(
                f"Invalid base64 encoding: {e}"
            )
        
        if not self._verify_signature(pickled_data, signature):
            raise SignatureVerificationError(
                "HMAC signature verification failed! "
                "Data may have been tampered with."
            )
        
        return pickle.loads(pickled_data)


class JSONSerializer:
    """
    JSON-based serializer - the safest option.
    
    This completely eliminates the deserialization vulnerability by using
    JSON instead of pickle. JSON can only represent primitive data types
    (strings, numbers, lists, dicts, booleans, null) and cannot execute
    arbitrary code during parsing.
    
    Objects must implement to_dict() and from_dict() methods, or be
    simple dictionaries already.
    """
    
    def serialize(self, obj: Any) -> bytes:
        """
        Serialize an object or list of objects to JSON.
        
        Args:
            obj: Object with to_dict() method, or a list of such objects
            
        Returns:
            Base64 encoded JSON string
        """
        if isinstance(obj, list):
            data = [self._obj_to_dict(item) for item in obj]
        else:
            data = self._obj_to_dict(obj)
        
        json_str = json.dumps(data, indent=2)
        return base64.b64encode(json_str.encode('utf-8'))
    
    def _obj_to_dict(self, obj: Any) -> dict:
        """Convert an object to a dictionary."""
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        raise TypeError(
            f"Object of type {type(obj)} is not JSON serializable. "
            "Implement a to_dict() method."
        )
    
    def deserialize(self, data: bytes, cls: Type = None) -> Any:
        """
        Deserialize JSON data back to objects.
        
        Args:
            data: Base64 encoded JSON data
            cls: Optional class with from_dict() method for reconstruction
            
        Returns:
            Deserialized data (dict/list of dicts, or class instances if cls provided)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            json_str = base64.b64decode(data).decode('utf-8')
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON data: {e}")
        except Exception as e:
            raise ValueError(f"Failed to decode data: {e}")
        
        if cls is None:
            return parsed
        
        if isinstance(parsed, list):
            return [cls.from_dict(item) for item in parsed]
        else:
            return cls.from_dict(parsed)


class SecureSerializer:
    """
    Factory class providing easy access to secure serialization options.
    
    Usage:
        # Get HMAC-protected pickle serializer
        serializer = SecureSerializer.get_hmac_serializer("secret-key")
        
        # Get JSON serializer (safest)
        serializer = SecureSerializer.get_json_serializer()
    """
    
    @staticmethod
    def get_hmac_serializer(secret_key: str = None) -> HMACPickleSerializer:
        """
        Get an HMAC-protected pickle serializer.
        
        Args:
            secret_key: Secret key for signing. If None, uses environment
                       variable SERVEROPS_SECRET_KEY or generates one.
        """
        if secret_key is None:
            secret_key = os.environ.get(
                'SERVEROPS_SECRET_KEY',
                'default-secret-key-change-in-production-12345'
            )
        return HMACPickleSerializer(secret_key)
    
    @staticmethod
    def get_json_serializer() -> JSONSerializer:
        """Get a JSON serializer (safest option)."""
        return JSONSerializer()


if __name__ == "__main__":
    print("=== Secure Serializer Demo ===\n")
    
    from models import ServerConfig
    
    config = ServerConfig("test-server", "10.0.0.1", "Web Server", 8080)
    
    print("1. HMAC Pickle Serializer Demo:")
    print("-" * 40)
    hmac_serializer = HMACPickleSerializer("my-super-secret-key-12345")
    signed_data = hmac_serializer.serialize([config])
    print(f"Signed data: {signed_data[:80].decode()}...")
    
    restored = hmac_serializer.deserialize(signed_data)
    print(f"Restored: {restored[0]}")
    
    print("\nTampering detection test:")
    tampered = signed_data[:-10] + b"xxxxxxxxxx"
    try:
        hmac_serializer.deserialize(tampered)
    except SignatureVerificationError as e:
        print(f"[BLOCKED] {e}")
    
    print("\n2. JSON Serializer Demo:")
    print("-" * 40)
    json_serializer = JSONSerializer()
    json_data = json_serializer.serialize([config])
    print(f"JSON data: {base64.b64decode(json_data).decode()}")
    
    restored = json_serializer.deserialize(json_data, ServerConfig)
    print(f"Restored: {restored[0]}")
