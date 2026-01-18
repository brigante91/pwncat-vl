"""
Port forwarding command for pwncat-vl.
Supports local and remote port forwarding.
"""

import socket
import threading
import select
from typing import Dict, Optional

import pwncat
from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.util import console
from pwncat.platform import PlatformError


class ForwardManager:
    """Manages active port forwarding connections"""
    
    def __init__(self):
        self.forwards: Dict[int, "PortForward"] = {}  # local_port -> forward
        self.remote_forwards: Dict[int, "RemotePortForward"] = {}  # remote_port -> forward
        self.lock = threading.Lock()
    
    def add(self, forward):
        """Add a forwarding rule"""
        with self.lock:
            if isinstance(forward, RemotePortForward):
                self.remote_forwards[forward.remote_port] = forward
            else:
                self.forwards[forward.local_port] = forward
    
    def remove(self, port: int, is_remote: bool = False):
        """Remove a forwarding rule"""
        with self.lock:
            if is_remote:
                if port in self.remote_forwards:
                    self.remote_forwards[port].stop()
                    del self.remote_forwards[port]
            else:
                if port in self.forwards:
                    self.forwards[port].stop()
                    del self.forwards[port]
    
    def list(self):
        """List all active forwards"""
        with self.lock:
            return list(self.forwards.values()) + list(self.remote_forwards.values())
    
    def stop_all(self):
        """Stop all forwards"""
        with self.lock:
            for forward in list(self.forwards.values()):
                forward.stop()
            self.forwards.clear()
            for forward in list(self.remote_forwards.values()):
                forward.stop()
            self.remote_forwards.clear()


class PortForward:
    """Manages a single port forward connection"""
    
    def __init__(self, local_port: int, remote_host: str, remote_port: int, 
                 forward_type: str = "local", session=None):
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.forward_type = forward_type
        self.session = session
        self.listener: Optional[socket.socket] = None
        self.running = False
        self.threads = []
    
    def start(self):
        """Start the port forward"""
        try:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(("127.0.0.1", self.local_port))
            self.listener.listen(5)
            self.listener.setblocking(False)
            
            self.running = True
            thread = threading.Thread(target=self._accept_connections, daemon=True)
            thread.start()
            self.threads.append(thread)
            
            console.log(
                f"[green]Forwarding[/green] [cyan]localhost:{self.local_port}[/cyan] "
                f"-> [cyan]{self.remote_host}:{self.remote_port}[/cyan]"
            )
            
        except Exception as e:
            raise PlatformError(f"Failed to start port forward: {e}")
    
    def _accept_connections(self):
        """Accept incoming connections and forward them"""
        while self.running:
            try:
                ready, _, _ = select.select([self.listener], [], [], 0.5)
                if not ready:
                    continue
                
                client_sock, addr = self.listener.accept()
                console.log(f"[yellow]New connection[/yellow] from {addr[0]}:{addr[1]}")
                
                # Start forwarding thread for this connection
                thread = threading.Thread(
                    target=self._forward_connection,
                    args=(client_sock,),
                    daemon=True
                )
                thread.start()
                self.threads.append(thread)
                
            except (OSError, socket.error) as e:
                if self.running:
                    console.log(f"[red]Error accepting connection[/red]: {e}")
                break
    
    def _forward_connection(self, client_sock: socket.socket):
        """Forward data between client and remote"""
        remote_sock = None
        try:
            # Connect to remote host
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.connect((self.remote_host, self.remote_port))
            remote_sock.setblocking(False)
            
            # Forward data bidirectionally
            while self.running:
                try:
                    ready, _, errors = select.select(
                        [client_sock, remote_sock], [], [client_sock, remote_sock], 0.1
                    )
                    
                    if errors:
                        break
                    
                    # Forward from client to remote
                    if client_sock in ready:
                        data = client_sock.recv(4096)
                        if not data:
                            break
                        remote_sock.sendall(data)
                    
                    # Forward from remote to client
                    if remote_sock in ready:
                        data = remote_sock.recv(4096)
                        if not data:
                            break
                        client_sock.sendall(data)
                        
                except (socket.error, OSError) as e:
                    if self.running:
                        break
        
        except Exception as e:
            console.log(f"[red]Forwarding error[/red]: {e}")
        
        finally:
            try:
                client_sock.close()
            except:
                pass
            try:
                if remote_sock:
                    remote_sock.close()
            except:
                pass
    
    def stop(self):
        """Stop the port forward"""
        self.running = False
        if self.listener:
            try:
                self.listener.close()
            except:
                pass
        
        # Wait for threads to finish (with timeout)
        for thread in self.threads:
            thread.join(timeout=1.0)
        
        console.log(f"[yellow]Stopped forwarding[/yellow] {self.local_port} -> {self.remote_host}:{self.remote_port}")


class RemotePortForward:
    """Manages a remote port forward (expose remote port locally)"""
    
    def __init__(self, remote_port: int, local_host: str, local_port: int, session=None):
        self.remote_port = remote_port
        self.local_host = local_host
        self.local_port = local_port
        self.session = session
        self.running = False
        self.threads = []
        self.remote_listener = None
    
    def start(self):
        """Start remote port forward by creating listener on remote host"""
        if not self.session or not self.session.platform:
            raise PlatformError("No active session for remote port forward")
        
        try:
            # Use socat or nc on remote to create listener
            platform = self.session.platform
            
            # Try socat first, then nc
            socat_path = platform.which("socat")
            nc_path = platform.which("nc") or platform.which("netcat")
            
            if socat_path:
                # Use socat for bidirectional forwarding
                command = f"{socat_path} TCP-LISTEN:{self.remote_port},fork,reuseaddr TCP:{self.local_host}:{self.local_port} &"
            elif nc_path:
                # Use nc (less ideal, unidirectional)
                command = f"while true; do {nc_path} -l -p {self.remote_port} -c '{nc_path} {self.local_host} {self.local_port}'; done &"
            else:
                # Fallback: use Python if available
                python_cmd = platform.which("python3") or platform.which("python")
                if python_cmd:
                    # Python-based port forwarder
                    script = f"""
import socket, threading
def forward(src, dst):
    while True:
        try:
            data = src.recv(4096)
            if not data: break
            dst.sendall(data)
        except: break
    src.close()
    dst.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', {self.remote_port}))
s.listen(5)
while True:
    client, _ = s.accept()
    server = socket.socket()
    server.connect(('{self.local_host}', {self.local_port}))
    threading.Thread(target=forward, args=(client, server), daemon=True).start()
    threading.Thread(target=forward, args=(server, client), daemon=True).start()
"""
                    command = f"{python_cmd} -c {repr(script)} &"
                else:
                    raise PlatformError("No suitable tool found for remote port forwarding (need socat, nc, or python)")
            
            # Execute command in background
            result = platform.run(command, shell=True, capture_output=True)
            
            self.running = True
            
            console.log(
                f"[green]Remote forwarding[/green] [cyan]remote:{self.remote_port}[/cyan] "
                f"-> [cyan]{self.local_host}:{self.local_port}[/cyan]"
            )
            
        except Exception as e:
            raise PlatformError(f"Failed to start remote port forward: {e}")
    
    def stop(self):
        """Stop the remote port forward"""
        self.running = False
        
        if self.session and self.session.platform:
            try:
                # Kill the background process
                platform = self.session.platform
                # Find and kill socat/nc/python processes for this port
                platform.run(f"pkill -f 'TCP-LISTEN:{self.remote_port}'", shell=True, capture_output=True)
            except:
                pass
        
        console.log(f"[yellow]Stopped remote forwarding[/yellow] {self.remote_port} -> {self.local_host}:{self.local_port}")


class Command(CommandDefinition):
    """
    Forward ports between local and remote hosts.
    
    Local port forwarding forwards connections from a local port to a remote host/port
    through the current pwncat session.
    
    Remote port forwarding exposes a remote port on the local machine.
    
    Examples:
        forward -L 8080 -H 10.10.10.10 -p 80    # Local 8080 -> Remote 10.10.10.10:80
        forward -R 9090 -H 127.0.0.1 -p 3306   # Remote 9090 -> Local 127.0.0.1:3306
        forward -l                                 # List active forwards
        forward -s 8080                           # Stop forward on port 8080
    """
    
    PROG = "forward"
    ARGS = {
        "--local,-L": Parameter(
            Complete.NONE,
            type=int,
            metavar="PORT",
            help="Local port to listen on (local port forwarding)"
        ),
        "--remote-forward,-R": Parameter(
            Complete.NONE,
            type=int,
            metavar="PORT",
            help="Remote port to listen on (remote port forwarding)"
        ),
        "--remote-host,-H": Parameter(
            Complete.NONE,
            type=str,
            metavar="HOST",
            help="Remote host to forward to (for local) or local host (for remote)"
        ),
        "--remote-port,-p": Parameter(
            Complete.NONE,
            type=int,
            metavar="PORT",
            help="Remote port to forward to (for local) or local port (for remote)"
        ),
        "--list,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="List all active port forwards"
        ),
        "--stop,-s": Parameter(
            Complete.NONE,
            type=int,
            metavar="PORT",
            help="Stop forwarding on the specified port"
        ),
    }
    LOCAL = False
    
    def run(self, manager: "pwncat.manager.Manager", args):
        """Execute the forward command"""
        
        # Initialize forward manager if not exists
        if not hasattr(manager, "_forward_manager"):
            manager._forward_manager = ForwardManager()
        
        forward_manager = manager._forward_manager
        
        # List forwards
        if args.list:
            forwards = forward_manager.list()
            if not forwards:
                console.log("[yellow]No active port forwards[/yellow]")
                return
            
            from rich.table import Table
            table = Table(title="Active Port Forwards")
            table.add_column("Local Port", style="cyan")
            table.add_column("Remote Host", style="yellow")
            table.add_column("Remote Port", style="yellow")
            table.add_column("Type", style="green")
            
            for forward in forwards:
                if isinstance(forward, RemotePortForward):
                    table.add_row(
                        f"remote:{forward.remote_port}",
                        forward.local_host,
                        str(forward.local_port),
                        "remote"
                    )
                else:
                    table.add_row(
                        str(forward.local_port),
                        forward.remote_host,
                        str(forward.remote_port),
                        forward.forward_type
                    )
            
            console.print(table)
            return
        
        # Stop forward
        if args.stop:
            # Try both local and remote
            found = False
            if args.stop in forward_manager.forwards:
                forward_manager.remove(args.stop, is_remote=False)
                found = True
            if args.stop in forward_manager.remote_forwards:
                forward_manager.remove(args.stop, is_remote=True)
                found = True
            
            if found:
                console.log(f"[green]Stopped forwarding on port {args.stop}[/green]")
            else:
                console.log(f"[yellow]No forwarding found on port {args.stop}[/yellow]")
            return
        
        # Start local forward
        if args.local:
            if not args.remote_host or not args.remote_port:
                self.parser.error("--local requires --remote-host and --remote-port")
            
            if args.local in forward_manager.forwards or args.local in forward_manager.remote_forwards:
                self.parser.error(f"Port {args.local} is already being forwarded")
            
            try:
                forward = PortForward(
                    local_port=args.local,
                    remote_host=args.remote_host,
                    remote_port=args.remote_port,
                    forward_type="local",
                    session=manager.target
                )
                forward.start()
                forward_manager.add(forward)
                
            except Exception as e:
                self.parser.error(f"Failed to start port forward: {e}")
        
        # Start remote forward
        elif args.remote_forward:
            if not args.remote_host or not args.remote_port:
                self.parser.error("--remote-forward requires --remote-host and --remote-port")
            
            if args.remote_forward in forward_manager.forwards or args.remote_forward in forward_manager.remote_forwards:
                self.parser.error(f"Port {args.remote_forward} is already being forwarded")
            
            try:
                forward = RemotePortForward(
                    remote_port=args.remote_forward,
                    local_host=args.remote_host,
                    local_port=args.remote_port,
                    session=manager.target
                )
                forward.start()
                forward_manager.add(forward)
                
            except Exception as e:
                self.parser.error(f"Failed to start remote port forward: {e}")
        else:
            self.parser.error("No action specified. Use --local, --remote-forward, --list, or --stop")
