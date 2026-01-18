"""
SOCKS proxy command for pwncat-vl.
Implements SOCKS4 and SOCKS5 proxy server.
"""

import socket
import struct
import threading
import select
from typing import Dict, Optional

import pwncat
from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.util import console
from pwncat.platform import PlatformError


class SocksProxy:
    """SOCKS proxy server implementation"""
    
    SOCKS4 = 0x04
    SOCKS5 = 0x05
    
    def __init__(self, port: int, version: int = 5, session=None):
        self.port = port
        self.version = version
        self.session = session
        self.listener: Optional[socket.socket] = None
        self.running = False
        self.threads = []
    
    def start(self):
        """Start the SOCKS proxy server"""
        try:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(("127.0.0.1", self.port))
            self.listener.listen(5)
            self.listener.setblocking(False)
            
            self.running = True
            thread = threading.Thread(target=self._accept_connections, daemon=True)
            thread.start()
            self.threads.append(thread)
            
            version_str = "SOCKS5" if self.version == 5 else "SOCKS4"
            console.log(
                f"[green]{version_str} proxy[/green] listening on [cyan]127.0.0.1:{self.port}[/cyan]"
            )
            
        except Exception as e:
            raise PlatformError(f"Failed to start SOCKS proxy: {e}")
    
    def _accept_connections(self):
        """Accept incoming SOCKS connections"""
        while self.running:
            try:
                ready, _, _ = select.select([self.listener], [], [], 0.5)
                if not ready:
                    continue
                
                client_sock, addr = self.listener.accept()
                console.log(f"[yellow]New SOCKS connection[/yellow] from {addr[0]}:{addr[1]}")
                
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock,),
                    daemon=True
                )
                thread.start()
                self.threads.append(thread)
                
            except (OSError, socket.error) as e:
                if self.running:
                    console.log(f"[red]Error accepting connection[/red]: {e}")
                break
    
    def _handle_client(self, client_sock: socket.socket):
        """Handle a SOCKS client connection"""
        try:
            if self.version == 5:
                self._handle_socks5(client_sock)
            else:
                self._handle_socks4(client_sock)
        except Exception as e:
            console.log(f"[red]SOCKS error[/red]: {e}")
        finally:
            try:
                client_sock.close()
            except:
                pass
    
    def _handle_socks5(self, client_sock: socket.socket):
        """Handle SOCKS5 protocol"""
        # Receive authentication methods
        data = client_sock.recv(2)
        if len(data) < 2:
            return
        
        version, nmethods = struct.unpack("!BB", data)
        if version != 5:
            return
        
        methods = client_sock.recv(nmethods)
        
        # Send no authentication required
        client_sock.sendall(b"\x05\x00")
        
        # Receive connection request
        data = client_sock.recv(4)
        if len(data) < 4:
            return
        
        version, cmd, rsv, atyp = struct.unpack("!BBBB", data)
        if version != 5 or cmd != 1:  # Only CONNECT supported
            client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        
        # Parse address
        if atyp == 1:  # IPv4
            addr_data = client_sock.recv(4)
            host = socket.inet_ntoa(addr_data)
        elif atyp == 3:  # Domain name
            length = ord(client_sock.recv(1))
            host = client_sock.recv(length).decode('utf-8')
        elif atyp == 4:  # IPv6
            addr_data = client_sock.recv(16)
            host = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        
        # Get port
        port_data = client_sock.recv(2)
        port = struct.unpack("!H", port_data)[0]
        
        # Connect to target
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.connect((host, port))
            
            # Get bound address
            bound_addr = remote_sock.getsockname()
            bound_ip = socket.inet_aton(bound_addr[0])
            
            # Send success response
            response = b"\x05\x00\x00\x01" + bound_ip + struct.pack("!H", bound_addr[1])
            client_sock.sendall(response)
            
            # Forward data
            self._forward_data(client_sock, remote_sock)
            
        except Exception as e:
            # Send failure response
            client_sock.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
    
    def _handle_socks4(self, client_sock: socket.socket):
        """Handle SOCKS4 protocol"""
        # Receive connection request
        data = client_sock.recv(8)
        if len(data) < 8:
            return
        
        version, cmd, port, ip = struct.unpack("!BBHI", data)
        if version != 4 or cmd != 1:  # Only CONNECT supported
            client_sock.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
            return
        
        host = socket.inet_ntoa(struct.pack("!I", ip))
        
        # Read userid (null-terminated)
        userid = b""
        while True:
            byte = client_sock.recv(1)
            if byte == b"\x00":
                break
            userid += byte
        
        # Connect to target
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.connect((host, port))
            
            # Send success response
            bound_addr = remote_sock.getsockname()
            bound_ip = struct.unpack("!I", socket.inet_aton(bound_addr[0]))[0]
            response = b"\x00\x5a" + struct.pack("!H", bound_addr[1]) + struct.pack("!I", bound_ip)
            client_sock.sendall(response)
            
            # Forward data
            self._forward_data(client_sock, remote_sock)
            
        except Exception as e:
            # Send failure response
            client_sock.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
    
    def _forward_data(self, client_sock: socket.socket, remote_sock: socket.socket):
        """Forward data bidirectionally between client and remote"""
        client_sock.setblocking(False)
        remote_sock.setblocking(False)
        
        while self.running:
            try:
                ready, _, errors = select.select(
                    [client_sock, remote_sock], [], [client_sock, remote_sock], 0.1
                )
                
                if errors:
                    break
                
                if client_sock in ready:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    remote_sock.sendall(data)
                
                if remote_sock in ready:
                    data = remote_sock.recv(4096)
                    if not data:
                        break
                    client_sock.sendall(data)
                    
            except (socket.error, OSError):
                break
        
        try:
            remote_sock.close()
        except:
            pass
    
    def stop(self):
        """Stop the SOCKS proxy"""
        self.running = False
        if self.listener:
            try:
                self.listener.close()
            except:
                pass
        
        for thread in self.threads:
            thread.join(timeout=1.0)
        
        version_str = "SOCKS5" if self.version == 5 else "SOCKS4"
        console.log(f"[yellow]Stopped {version_str} proxy[/yellow] on port {self.port}")


class SocksManager:
    """Manages active SOCKS proxies"""
    
    def __init__(self):
        self.proxies: Dict[int, SocksProxy] = {}
        self.lock = threading.Lock()
    
    def add(self, proxy: SocksProxy):
        """Add a proxy"""
        with self.lock:
            self.proxies[proxy.port] = proxy
    
    def remove(self, port: int):
        """Remove a proxy"""
        with self.lock:
            if port in self.proxies:
                self.proxies[port].stop()
                del self.proxies[port]
    
    def list(self):
        """List all active proxies"""
        with self.lock:
            return list(self.proxies.values())
    
    def stop_all(self):
        """Stop all proxies"""
        with self.lock:
            for proxy in list(self.proxies.values()):
                proxy.stop()
            self.proxies.clear()


class Command(CommandDefinition):
    """
    Start a SOCKS proxy server for dynamic port forwarding.
    
    The SOCKS proxy allows tools to connect through the pwncat session
    to access remote networks.
    
    Examples:
        socks -p 1080              # Start SOCKS5 proxy on port 1080
        socks -p 1080 -v 4         # Start SOCKS4 proxy on port 1080
        socks -l                   # List active proxies
        socks -s 1080              # Stop proxy on port 1080
    """
    
    PROG = "socks"
    ARGS = {
        "--port,-p": Parameter(
            Complete.NONE,
            type=int,
            metavar="PORT",
            help="Local port to listen on"
        ),
        "--version,-v": Parameter(
            Complete.NONE,
            type=int,
            choices=[4, 5],
            default=5,
            help="SOCKS version (4 or 5, default: 5)"
        ),
        "--list,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="List all active SOCKS proxies"
        ),
        "--stop,-s": Parameter(
            Complete.NONE,
            type=int,
            metavar="PORT",
            help="Stop proxy on the specified port"
        ),
    }
    LOCAL = False
    
    def run(self, manager: "pwncat.manager.Manager", args):
        """Execute the socks command"""
        
        # Initialize socks manager if not exists
        if not hasattr(manager, "_socks_manager"):
            manager._socks_manager = SocksManager()
        
        socks_manager = manager._socks_manager
        
        # List proxies
        if args.list:
            proxies = socks_manager.list()
            if not proxies:
                console.log("[yellow]No active SOCKS proxies[/yellow]")
                return
            
            from rich.table import Table
            table = Table(title="Active SOCKS Proxies")
            table.add_column("Port", style="cyan")
            table.add_column("Version", style="yellow")
            table.add_column("Status", style="green")
            
            for proxy in proxies:
                version_str = f"SOCKS{proxy.version}"
                status = "running" if proxy.running else "stopped"
                table.add_row(str(proxy.port), version_str, status)
            
            console.print(table)
            return
        
        # Stop proxy
        if args.stop:
            socks_manager.remove(args.stop)
            console.log(f"[green]Stopped SOCKS proxy on port {args.stop}[/green]")
            return
        
        # Start proxy
        if args.port:
            if args.port in socks_manager.proxies:
                self.parser.error(f"Port {args.port} already has a SOCKS proxy")
            
            try:
                proxy = SocksProxy(
                    port=args.port,
                    version=args.version,
                    session=manager.target
                )
                proxy.start()
                socks_manager.add(proxy)
                
            except Exception as e:
                self.parser.error(f"Failed to start SOCKS proxy: {e}")
        else:
            self.parser.error("No action specified. Use --port, --list, or --stop")
