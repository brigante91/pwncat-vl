"""
HTTP/HTTPS covert channel implementation.
Tunnels data through normal-looking HTTP requests/responses.
"""

import base64
import socket
import urllib.parse
from typing import Optional
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse

from pwncat.util import console
from pwncat.channel import Channel, ChannelError


class HTTPChannel(Channel):
    """
    HTTP/HTTPS covert channel that tunnels data through HTTP requests.
    Data is base64 encoded and sent via POST requests.
    """
    
    def __init__(
        self,
        host: str,
        port: int = 80,
        path: str = "/",
        ssl: bool = False,
        user_agent: str = "Mozilla/5.0",
        **kwargs
    ):
        if not host:
            raise ChannelError(self, "no host address provided")
        
        if port is None:
            port = 443 if ssl else 80
        
        self.host = host
        self.port = port
        self.path = path
        self.ssl = ssl
        self.user_agent = user_agent
        self._connected = False
        self._connection = None
        
        # Buffer for received data
        self._recv_buffer = b""
        
        super().__init__(host=host, port=port, **kwargs)
    
    @property
    def connected(self) -> bool:
        """Check if channel is connected"""
        return self._connected
    
    def connect(self):
        """Establish HTTP connection"""
        try:
            if self.ssl:
                self._connection = HTTPSConnection(self.host, self.port)
            else:
                self._connection = HTTPConnection(self.host, self.port)
            self._connected = True
        except Exception as e:
            raise ChannelError(self, f"failed to connect: {e}")
    
    def send(self, data: bytes) -> int:
        """Send data via HTTP POST"""
        if not self._connected or not self._connection:
            raise ChannelError(self, "not connected")
        
        try:
            # Encode data as base64
            encoded = base64.b64encode(data).decode('utf-8')
            
            # Send as POST request
            headers = {
                'User-Agent': self.user_agent,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': str(len(encoded))
            }
            
            self._connection.request('POST', self.path, encoded, headers)
            response = self._connection.getresponse()
            
            # Read response (may contain data)
            response_data = response.read()
            
            # Decode response if it contains data
            if response_data:
                try:
                    decoded = base64.b64decode(response_data)
                    self._recv_buffer += decoded
                except:
                    pass
            
            return len(data)
        except Exception as e:
            raise ChannelError(self, f"send failed: {e}")
    
    def recv(self, count: Optional[int] = None) -> bytes:
        """Receive data from HTTP responses"""
        if not self._connected:
            raise ChannelError(self, "not connected")
        
        # Return buffered data
        if self._recv_buffer:
            if count is None:
                data = self._recv_buffer
                self._recv_buffer = b""
                return data
            else:
                data = self._recv_buffer[:count]
                self._recv_buffer = self._recv_buffer[count:]
                return data
        
        # Request more data via GET
        try:
            headers = {'User-Agent': self.user_agent}
            self._connection.request('GET', self.path, headers=headers)
            response = self._connection.getresponse()
            response_data = response.read()
            
            if response_data:
                try:
                    decoded = base64.b64decode(response_data)
                    self._recv_buffer += decoded
                    
                    if count is None:
                        data = self._recv_buffer
                        self._recv_buffer = b""
                        return data
                    else:
                        data = self._recv_buffer[:count]
                        self._recv_buffer = self._recv_buffer[count:]
                        return data
                except:
                    return b""
        except Exception:
            pass
        
        return b""
    
    def recvinto(self, buffer) -> int:
        """Receive data into buffer"""
        data = self.recv(len(buffer))
        buffer[:len(data)] = data
        return len(data)
    
    def close(self):
        """Close the connection"""
        if self._connection:
            try:
                self._connection.close()
            except:
                pass
        self._connected = False
    
    def drain(self):
        """Drain any pending data"""
        pass
    
    @property
    def address(self):
        """Get connection address"""
        return (self.host, self.port)
