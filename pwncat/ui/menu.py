"""
Interactive menu system for pwncat-vl.
Provides a user-friendly menu interface for common operations.
"""

from typing import Optional, Callable
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich import box

import pwncat
from pwncat.util import console


class InteractiveMenu:
    """Interactive menu system for pwncat-vl"""
    
    def __init__(self, manager: "pwncat.manager.Manager"):
        self.manager = manager
        self.running = True
    
    def show_main_menu(self):
        """Display main menu"""
        console.clear()
        
        menu_text = """
[bold cyan]pwncat-vl Interactive Menu[/bold cyan]

[1] Connect to target
[2] List sessions
[3] Manage sessions
[4] Run module
[5] File transfer
[6] Network methods
[7] Enter interactive shell
[8] Exit menu (return to CLI)

"""
        
        console.print(Panel(menu_text, title="Main Menu", border_style="cyan"))
    
    def run(self):
        """Run the interactive menu loop"""
        while self.running:
            self.show_main_menu()
            
            try:
                choice = Prompt.ask(
                    "[bold yellow]Select option[/bold yellow]",
                    choices=["1", "2", "3", "4", "5", "6", "7", "8"],
                    default="8"
                )
                
                if choice == "1":
                    self.connect_menu()
                elif choice == "2":
                    self.list_sessions()
                elif choice == "3":
                    self.manage_sessions()
                elif choice == "4":
                    self.run_module_menu()
                elif choice == "5":
                    self.file_transfer_menu()
                elif choice == "6":
                    self.network_methods_menu()
                elif choice == "7":
                    self.enter_shell()
                elif choice == "8":
                    self.running = False
                    break
            except KeyboardInterrupt:
                console.print("\n[yellow]Returning to main menu...[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
    
    def connect_menu(self):
        """Interactive connection menu"""
        console.print("\n[bold cyan]Connect to Target[/bold cyan]\n")
        
        host = Prompt.ask("Host", default="")
        if not host:
            return
        
        port = IntPrompt.ask("Port", default=4444)
        platform = Prompt.ask("Platform", choices=["linux", "windows"], default="linux")
        
        use_ssl = Prompt.ask("Use SSL?", choices=["y", "n"], default="n") == "y"
        
        try:
            console.print(f"\n[cyan]Connecting to {host}:{port}...[/cyan]\n")
            
            from pwncat.commands import connect
            connect.Command().run(self.manager, type(
                'args',
                (),
                {
                    'connection_string': f"{host}:{port}",
                    'platform': platform,
                    'ssl': use_ssl
                }
            )())
            
            console.print("\n[green]Connection established![/green]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
        except Exception as e:
            console.print(f"\n[red]Connection failed: {e}[/red]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
    
    def list_sessions(self):
        """List active sessions"""
        from pwncat.commands.sessions import Command
        cmd = Command()
        cmd.run(self.manager, type('args', (), {'list': True})())
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def manage_sessions(self):
        """Manage sessions menu"""
        console.print("\n[bold cyan]Manage Sessions[/bold cyan]\n")
        
        if not self.manager.sessions:
            console.print("[yellow]No active sessions[/yellow]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        from pwncat.commands.sessions import Command
        cmd = Command()
        cmd.run(self.manager, type('args', (), {'list': True})())
        
        session_id = IntPrompt.ask("\nSelect session ID", default=None)
        if session_id is None or session_id not in self.manager.sessions:
            return
        
        console.print("\n[1] Switch to session\n[2] Kill session\n[3] Name session\n[4] Tag session")
        action = Prompt.ask("Action", choices=["1", "2", "3", "4"], default="1")
        
        if action == "1":
            self.manager.target = self.manager.sessions[session_id]
            console.print(f"[green]Switched to session {session_id}[/green]")
        elif action == "2":
            cmd.run(self.manager, type('args', (), {'kill': True, 'session_id': session_id})())
        elif action == "3":
            name = Prompt.ask("Session name")
            cmd.run(self.manager, type('args', (), {'name': name, 'session_id': session_id})())
        elif action == "4":
            tag = Prompt.ask("Tag")
            cmd.run(self.manager, type('args', (), {'tag': tag, 'session_id': session_id})())
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def run_module_menu(self):
        """Run module menu"""
        console.print("\n[bold cyan]Run Module[/bold cyan]\n")
        
        if not self.manager.target:
            console.print("[yellow]No active session[/yellow]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        module_pattern = Prompt.ask("Module pattern (e.g., 'enumerate.*')", default="")
        if not module_pattern:
            return
        
        # Search modules
        matched = list(self.manager.match_modules(module_pattern, self.manager.target.platform))
        if not matched:
            console.print("[yellow]No modules found[/yellow]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        # Show modules
        table = Table(title="Matching Modules")
        table.add_column("ID", style="cyan")
        table.add_column("Module", style="yellow")
        
        for i, module in enumerate(matched[:10], 1):
            table.add_row(str(i), module.name)
        
        console.print(table)
        
        choice = IntPrompt.ask("\nSelect module number", default=1)
        if choice < 1 or choice > len(matched):
            return
        
        module = matched[choice - 1]
        console.print(f"\n[cyan]Running module: {module.name}[/cyan]\n")
        
        try:
            from pwncat.commands.run import Command
            cmd = Command()
            cmd.run(self.manager, type('args', (), {'module': module.name, 'args': []})())
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def file_transfer_menu(self):
        """File transfer menu"""
        console.print("\n[bold cyan]File Transfer[/bold cyan]\n")
        
        if not self.manager.target:
            console.print("[yellow]No active session[/yellow]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        direction = Prompt.ask("Direction", choices=["upload", "download"], default="upload")
        
        if direction == "upload":
            source = Prompt.ask("Local source path")
            dest = Prompt.ask("Remote destination path", default="")
            recursive = Prompt.ask("Recursive?", choices=["y", "n"], default="n") == "y"
            
            from pwncat.commands.upload import Command
            cmd = Command()
            args = type('args', (), {
                'source': source,
                'destination': dest if dest else None,
                'recursive': recursive,
                'compress': False,
                'resume': False,
                'rate_limit': None
            })()
            cmd.run(self.manager, args)
        else:
            source = Prompt.ask("Remote source path")
            dest = Prompt.ask("Local destination path", default="")
            recursive = Prompt.ask("Recursive?", choices=["y", "n"], default="n") == "y"
            
            from pwncat.commands.download import Command
            cmd = Command()
            args = type('args', (), {
                'source': source,
                'destination': dest if dest else None,
                'recursive': recursive
            })()
            cmd.run(self.manager, args)
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def network_methods_menu(self):
        """Network methods menu"""
        console.print("\n[bold cyan]Network Methods[/bold cyan]\n")
        
        if not self.manager.target:
            console.print("[yellow]No active session[/yellow]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        console.print("[1] Port Forward\n[2] SOCKS Proxy")
        choice = Prompt.ask("Action", choices=["1", "2"], default="1")
        
        if choice == "1":
            fwd_type = Prompt.ask("Type", choices=["local", "remote"], default="local")
            local_port = IntPrompt.ask("Local/Remote port")
            remote_host = Prompt.ask("Remote host")
            remote_port = IntPrompt.ask("Remote port")
            
            from pwncat.commands.forward import Command
            cmd = Command()
            if fwd_type == "local":
                args = type('args', (), {
                    'local': local_port,
                    'remote_host': remote_host,
                    'remote_port': remote_port,
                    'list': False,
                    'stop': None
                })()
            else:
                args = type('args', (), {
                    'remote_forward': local_port,
                    'remote_host': remote_host,
                    'remote_port': remote_port,
                    'list': False,
                    'stop': None
                })()
            cmd.run(self.manager, args)
        elif choice == "2":
            port = IntPrompt.ask("SOCKS port", default=1080)
            version = IntPrompt.ask("SOCKS version", choices=[4, 5], default=5)
            
            from pwncat.commands.socks import Command
            cmd = Command()
            args = type('args', (), {
                'port': port,
                'version': version,
                'list': False,
                'stop': None
            })()
            cmd.run(self.manager, args)
        
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")
    
    def enter_shell(self):
        """Enter interactive shell"""
        if not self.manager.target:
            console.print("[yellow]No active session[/yellow]")
            Prompt.ask("[yellow]Press Enter to continue[/yellow]", default="")
            return
        
        console.print("\n[yellow]Entering interactive shell. Type 'exit' to return.[/yellow]\n")
        # The interactive shell is already available via manager.interactive()
        # For now, just notify user
        console.print("[cyan]Use 'exit' command in pwncat to return to menu[/cyan]")
        Prompt.ask("\n[yellow]Press Enter to continue[/yellow]", default="")


def show_interactive_menu(manager: "pwncat.manager.Manager"):
    """Entry point for interactive menu"""
    menu = InteractiveMenu(manager)
    menu.run()
