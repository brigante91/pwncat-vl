"""
Module pattern matching command for pwncat-vl.
Allows finding modules by pattern (like IDEAS.md suggestion).
"""

import pwncat
from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.util import console


class Command(CommandDefinition):
    """
    Match modules by pattern (glob or regex).
    
    This command provides programmatic access to modules similar to
    the IDEAS.md suggestion: `manager.modules.match(r"escalate/.*")`
    
    Examples:
        match escalate.*          # Find all escalation modules
        match enumerate.*         # Find all enumeration modules
        match linux.enumerate.*   # Find Linux enumeration modules
    """
    
    PROG = "match"
    ARGS = {
        "pattern": Parameter(
            Complete.NONE,
            metavar="PATTERN",
            help="Pattern to match (supports glob: *, ?)"
        ),
        "--platform,-p": Parameter(
            Complete.NONE,
            type=str,
            metavar="PLATFORM",
            help="Filter by platform (linux, windows)"
        ),
    }
    LOCAL = False
    
    def run(self, manager: "pwncat.manager.Manager", args):
        """Execute the match command"""
        
        if not args.pattern:
            self.parser.error("pattern is required")
        
        # Get platform filter if specified
        platform = None
        if args.platform:
            if args.platform.lower() == "linux":
                from pwncat.platform import Linux
                platform = Linux
            elif args.platform.lower() == "windows":
                from pwncat.platform import Windows
                platform = Windows
            else:
                console.log(f"[red]error[/red]: unknown platform: {args.platform}")
                return
        
        # Use target platform if available
        if platform is None and manager.target:
            platform = manager.target.platform
        
        # Match modules
        matched = list(manager.match_modules(args.pattern, platform))
        
        if not matched:
            console.log(f"[yellow]No modules found matching pattern: {args.pattern}[/yellow]")
            return
        
        # Display results
        from rich.table import Table
        table = Table(title=f"Modules matching '{args.pattern}'")
        table.add_column("Module Name", style="cyan")
        table.add_column("Platform", style="yellow")
        table.add_column("Description", style="white")
        
        for module in matched:
            platform_str = ", ".join([p.name for p in module.PLATFORM]) if module.PLATFORM else "agnostic"
            desc = module.__doc__.split("\n")[0] if module.__doc__ else "No description"
            table.add_row(module.name, platform_str, desc)
        
        console.print(table)
        console.log(f"[green]Found {len(matched)} module(s)[/green]")
