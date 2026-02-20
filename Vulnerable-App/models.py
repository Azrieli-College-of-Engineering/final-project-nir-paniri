"""
ServerConfig Model - Represents server configuration data.

This class is serialized using Python's pickle module, which is the 
source of the insecure deserialization vulnerability in this application.
"""


class ServerConfig:
    """
    Represents a server configuration profile.
    
    Attributes:
        hostname: The server's hostname
        ip: The server's IP address
        role: The server's role (e.g., "Web Server", "Database")
        port: The SSH/management port (default: 22)
    """
    
    def __init__(self, hostname: str, ip: str, role: str, port: int = 22):
        self.hostname = hostname
        self.ip = ip
        self.role = role
        self.port = port
    
    def __repr__(self):
        return f"ServerConfig(hostname='{self.hostname}', ip='{self.ip}', role='{self.role}', port={self.port})"
    
    def to_dict(self) -> dict:
        """Convert the config to a dictionary (used in secure version)."""
        return {
            'hostname': self.hostname,
            'ip': self.ip,
            'role': self.role,
            'port': self.port
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ServerConfig':
        """Create a ServerConfig from a dictionary (used in secure version)."""
        return cls(
            hostname=data.get('hostname', ''),
            ip=data.get('ip', ''),
            role=data.get('role', ''),
            port=data.get('port', 22)
        )
