"""
Theme management command for pwncat-vl.
Allows configuration of color themes.
"""

import pwncat
from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.util import console
from pygments.styles import get_all_styles


class Command(CommandDefinition):
    """
    Configure and manage color themes for pwncat-vl.
    
    List available themes or set a new theme.
    
    Examples:
        theme list                    # List all available themes
        theme set monokai             # Set theme to monokai
        theme                         # Show current theme
    """
    
    PROG = "theme"
    ARGS = {
        "action": Parameter(
            Complete.CHOICES,
            choices=["list", "set"],
            nargs="?",
            help="Action: list or set theme"
        ),
        "theme_name": Parameter(
            Complete.NONE,
            nargs="?",
            help="Theme name to set"
        ),
    }
    LOCAL = True
    
    def run(self, manager: "pwncat.manager.Manager", args):
        """Execute the theme command"""
        
        if args.action == "list":
            # List all available themes
            themes = sorted(get_all_styles())
            current_theme = manager.config.get("color_theme", "monokai")
            
            from rich.table import Table
            table = Table(title="Available Color Themes")
            table.add_column("Theme Name", style="cyan")
            table.add_column("Status", style="yellow")
            
            for theme in themes:
                status = "[green]active[/green]" if theme == current_theme else ""
                table.add_row(theme, status)
            
            console.print(table)
            console.log(f"\n[cyan]Current theme:[/cyan] [yellow]{current_theme}[/yellow]")
            console.log(f"[yellow]To change:[/yellow] theme set <theme_name>")
            return
        
        if args.action == "set":
            if not args.theme_name:
                self.parser.error("theme name required")
            
            # Verify theme exists
            try:
                from pygments.styles import get_style_by_name
                get_style_by_name(args.theme_name)
            except:
                console.log(f"[red]Error:[/red] Theme '{args.theme_name}' not found")
                console.log("[yellow]Use 'theme list' to see available themes[/yellow]")
                return
            
            # Set theme
            manager.config.set("color_theme", args.theme_name, glob=True)
            console.log(f"[green]Theme set to:[/green] [cyan]{args.theme_name}[/cyan]")
            console.log("[yellow]Note: Theme will be applied to the next prompt session[/yellow]")
            return
        
        # Show current theme
        current_theme = manager.config.get("color_theme", "monokai")
        console.log(f"[cyan]Current theme:[/cyan] [yellow]{current_theme}[/yellow]")
        console.log(f"[yellow]Use 'theme list' to see all themes[/yellow]")
        console.log(f"[yellow]Use 'theme set <name>' to change theme[/yellow]")
