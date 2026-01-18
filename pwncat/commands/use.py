#!/usr/bin/env python3

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition, get_module_choices


class Command(CommandDefinition):
    """
    Set the currently used module in the config handler.
    
    This enters a module context where `set` commands apply to the module
    arguments, and `run` can be executed without specifying the module name.
    
    Examples:
        use linux.enumerate.system.distro    # Enter distro enumeration module context
        set                                  # Show module arguments
        run                                  # Run the module
        back                                 # Exit module context
    """

    PROG = "use"
    ARGS = {
        "module": Parameter(
            Complete.CHOICES,
            choices=get_module_choices,
            metavar="MODULE",
            help="the module to use",
        )
    }
    LOCAL = False

    def run(self, manager: "pwncat.manager.Manager", args):

        try:
            module = list(manager.target.find_module(args.module, exact=True))[0]
        except IndexError:
            console.log(f"[red]error[/red]: {args.module}: no such module")
            return

        manager.target.config.use(module)
        console.log(f"[green]Using module:[/green] [cyan]{module.name}[/cyan]")
        
        # Show module info
        if module.__doc__:
            doc_lines = module.__doc__.strip().split("\n")
            console.log(f"[yellow]Description:[/yellow] {doc_lines[0]}")
        
        # Show available arguments
        if module.ARGUMENTS:
            from rich.table import Table
            table = Table(title="Module Arguments", show_header=True, header_style="bold magenta")
            table.add_column("Argument", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Default", style="green")
            table.add_column("Help", style="white")
            
            for arg_name, arg_def in module.ARGUMENTS.items():
                arg_type = str(arg_def.type).split("'")[1] if "'" in str(arg_def.type) else str(arg_def.type)
                default = str(arg_def.default) if arg_def.default is not pwncat.modules.NoValue else "required"
                help_text = arg_def.help or "No description"
                table.add_row(arg_name, arg_type, default, help_text)
            
            console.print(table)