#!/usr/bin/env python3
from rich import box
from rich.table import Table

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Interact and control active remote sessions. This command can be used
    to change context between sessions or kill active sessions which were
    established with the `connect` command.
    
    Enhanced with session tagging and naming support.
    """

    PROG = "sessions"
    ARGS = {
        "--list,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="List active connections",
        ),
        "--kill,-k": Parameter(
            Complete.NONE,
            action="store_true",
            help="Kill an active session",
        ),
        "--name,-n": Parameter(
            Complete.NONE,
            type=str,
            metavar="NAME",
            help="Set a name/tag for a session",
        ),
        "--tag,-t": Parameter(
            Complete.NONE,
            type=str,
            metavar="TAG",
            help="Add a tag to a session",
        ),
        "session_id": Parameter(
            Complete.NONE,
            type=int,
            help="Interact with the given session",
            nargs="?",
        ),
    }
    LOCAL = True

    def run(self, manager: "pwncat.manager.Manager", args):

        # Initialize session metadata if not exists
        if not hasattr(manager, "_session_metadata"):
            manager._session_metadata = {}
        
        metadata = manager._session_metadata

        if args.list or (not args.kill and args.session_id is None and not args.name and not args.tag):
            table = Table(title="Active Sessions", box=box.MINIMAL_DOUBLE_HEAD)

            table.add_column("ID")
            table.add_column("Name/Tags")
            table.add_column("User")
            table.add_column("Host ID")
            table.add_column("Platform")
            table.add_column("Type")
            table.add_column("Address")

            for session_id, session in manager.sessions.items():
                ident = str(session_id)
                kwargs = {"style": ""}
                if session is manager.target:
                    ident = "*" + ident
                    kwargs["style"] = "underline"
                
                # Get session name and tags
                session_meta = metadata.get(session_id, {})
                name_tags = ""
                if session_meta.get("name"):
                    name_tags = f"[cyan]{session_meta['name']}[/cyan]"
                if session_meta.get("tags"):
                    tags_str = " ".join([f"[yellow]#{tag}[/yellow]" for tag in session_meta["tags"]])
                    if name_tags:
                        name_tags += " " + tags_str
                    else:
                        name_tags = tags_str
                if not name_tags:
                    name_tags = "-"
                
                table.add_row(
                    str(ident),
                    name_tags,
                    session.current_user().name,
                    str(session.hash),
                    session.platform.name,
                    str(type(session.platform.channel).__name__),
                    str(session.platform.channel),
                    **kwargs,
                )

            console.print(table)

            return

        if args.session_id is None:
            if args.name or args.tag:
                console.log("[red]error[/red]: session id required for --name or --tag")
            else:
                console.log("[red]error[/red]: no session id specified")
            return

        # check if a session with the provided ``session_id`` exists or not
        if args.session_id not in manager.sessions:
            console.log(f"[red]error[/red]: {args.session_id}: no such session!")
            return

        session = manager.sessions[args.session_id]

        # Handle naming
        if args.name:
            if args.session_id not in metadata:
                metadata[args.session_id] = {}
            metadata[args.session_id]["name"] = args.name
            console.log(f"[green]Named session {args.session_id}: {args.name}[/green]")
            return

        # Handle tagging
        if args.tag:
            if args.session_id not in metadata:
                metadata[args.session_id] = {"tags": []}
            elif "tags" not in metadata[args.session_id]:
                metadata[args.session_id]["tags"] = []
            
            if args.tag not in metadata[args.session_id]["tags"]:
                metadata[args.session_id]["tags"].append(args.tag)
                console.log(f"[green]Tagged session {args.session_id} with: #{args.tag}[/green]")
            else:
                console.log(f"[yellow]Session {args.session_id} already has tag: #{args.tag}[/yellow]")
            return

        if args.kill:
            channel = str(session.platform.channel)
            session.close()
            if args.session_id in metadata:
                del metadata[args.session_id]
            console.log(f"session-{args.session_id} ({channel}) closed")
            return

        manager.target = session
        session_meta = metadata.get(args.session_id, {})
        name_info = f" [{session_meta.get('name', '')}]" if session_meta.get('name') else ""
        console.log(f"targeting session-{args.session_id}{name_info} ({session.platform.channel})")
