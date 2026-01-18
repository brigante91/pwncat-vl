#!/usr/bin/env python3
"""
LinPEAS-style enumeration module for comprehensive privilege escalation checks.

This module performs a comprehensive enumeration similar to LinPEAS by running
all relevant enumeration modules and organizing the results.

LinPEAS (Linux Privilege Escalation Awesome Script) is a script that checks 
Linux systems for privilege escalation vectors. This module replicates that
functionality using pwncat's native enumeration modules.
"""

import fnmatch
from io import IOBase

import pwncat.modules
from pwncat.modules import Status, ModuleFailed
from pwncat.modules.enumerate import EnumerateModule, Schedule


def FileType(mode: str = "r"):
    """Helper to handle file output arguments"""
    def _file_type(path: str):
        if path is None:
            return None
        if isinstance(path, IOBase):
            return path
        try:
            return open(path, mode)
        except (FileNotFoundError, PermissionError):
            raise ValueError(f"{path}: unable to open with mode: {mode}")
    return _file_type


class Module(pwncat.modules.BaseModule):
    """
    Perform LinPEAS-style comprehensive enumeration for privilege escalation.
    
    This module runs all relevant enumeration modules to identify potential
    privilege escalation vectors, similar to the LinPEAS script.
    
    It organizes checks into categories:
    - System Information (kernel, distro, users)
    - Sudo/Suid checks
    - File permissions and capabilities
    - Cron jobs and scheduled tasks
    - Process and service enumeration
    - Network configuration
    - Credential hunting
    - Software vulnerabilities
    
    The output can be written to a file or displayed directly.
    """

    ARGUMENTS = {
        "output": pwncat.modules.Argument(
            FileType("w"),
            default=None,
            help="File to write the report to (default: stdout)",
        ),
        "quiet": pwncat.modules.Argument(
            bool,
            default=False,
            help="Only show findings, not status messages",
        ),
        "categories": pwncat.modules.Argument(
            pwncat.modules.List(str),
            default=["*"],
            help="Categories to check (default: all). Options: system, sudo, suid, caps, cron, processes, network, creds, software",
        ),
    }

    PLATFORM = None  # Agnostic, but mainly useful on Linux

    # Define LinPEAS-style categories and their corresponding fact types
    CATEGORY_MAPPING = {
        "system": [
            "system.distro",
            "system.uname",
            "system.init",
            "system.container",
            "system.network",
            "system.process",
            "user.*",
        ],
        "sudo": [
            "software.sudo.*",
        ],
        "suid": [
            "file.suid",
            "ability.execute",
        ],
        "caps": [
            "file.caps",
        ],
        "cron": [
            "software.cron.*",
        ],
        "processes": [
            "system.process",
            "system.services",
        ],
        "network": [
            "system.network",
        ],
        "creds": [
            "creds.*",
            "ability.file.read",  # May reveal credentials
        ],
        "software": [
            "software.*",
        ],
        "escalate": [
            "escalate.*",
        ],
        "files": [
            "file.*",
            "misc.writable_path",
        ],
    }

    def _format_category_header(self, category: str) -> str:
        """Format a category header for output"""
        headers = {
            "system": "═══════════════════════════ SYSTEM INFORMATION ════════════════════════════",
            "sudo": "═══════════════════════════════════ SUDO ══════════════════════════════════",
            "suid": "═══════════════════════════════ SUID BINARIES ═══════════════════════════════",
            "caps": "═════════════════════════════ CAPABILITIES ═════════════════════════════════",
            "cron": "═════════════════════════════ CRON JOBS ═══════════════════════════════════",
            "processes": "═══════════════════════════ PROCESSES ════════════════════════════════════",
            "network": "══════════════════════════════ NETWORK ══════════════════════════════════",
            "creds": "══════════════════════════════ CREDENTIALS ══════════════════════════════════",
            "software": "════════════════════════════ SOFTWARE ═══════════════════════════════════",
            "escalate": "══════════════════════════ ESCALATION METHODS ═══════════════════════════",
            "files": "════════════════════════════ FILES & PERMISSIONS ════════════════════════════",
        }
        return headers.get(category, f"═══════════════════════════ {category.upper()} ════════════════════════════")

    def run(self, session, output, quiet, categories):
        """
        Execute LinPEAS-style enumeration.
        
        This method runs enumeration modules organized by category and formats
        the output similar to LinPEAS.
        """
        
        # Determine which categories to check
        if "*" in categories or not categories:
            categories_to_check = list(self.CATEGORY_MAPPING.keys())
        else:
            categories_to_check = categories
        
        # Find all enumeration modules
        all_modules = set(session.find_module(f"enumerate.*", base=EnumerateModule))
        
        # Collect facts by category
        facts_by_category = {cat: [] for cat in categories_to_check}
        modules_run = set()
        
        if output:
            # Write header to file
            output.write("=" * 75 + "\n")
            output.write(" " * 20 + "LINPEAS-STYLE ENUMERATION\n")
            output.write("=" * 75 + "\n\n")
            output.write(f"Target: {session.platform.hostname}\n")
            output.write(f"User: {session.current_user().name}\n")
            output.write(f"Platform: {session.platform.name}\n\n")
            output.flush()
        
        # Run enumeration modules for each category
        for category in categories_to_check:
            if category not in self.CATEGORY_MAPPING:
                if not quiet:
                    yield Status(f"[yellow]Unknown category: {category}[/yellow]")
                continue
            
            type_patterns = self.CATEGORY_MAPPING[category]
            
            if not quiet:
                yield Status(f"Checking [cyan]{category}[/cyan]...")
            
            # Find modules that provide facts matching this category
            category_modules = []
            for module in all_modules:
                for pattern in type_patterns:
                    for provided_type in module.PROVIDES:
                        if fnmatch.fnmatch(provided_type, pattern):
                            category_modules.append(module)
                            break
                    else:
                        continue
                    break
            
            # Run modules for this category
            for module in category_modules:
                if module in modules_run:
                    continue
                    
                try:
                    if not quiet:
                        yield Status(f"  Running [dim]{module.name}[/dim]...")
                    
                    # Run the module and collect facts
                    for item in module.run(session, types=type_patterns, cache=True):
                        if isinstance(item, Status):
                            if not quiet and not output:
                                yield item
                            continue
                        
                        # Add fact to appropriate category
                        facts_by_category[category].append(item)
                        
                        # Also yield for output
                        if not output:
                            yield item
                            
                except ModuleFailed as exc:
                    if not quiet:
                        session.log(f"[red]{module.name}[/red]: {str(exc)}")
                
                modules_run.add(module)
        
        # Format and write output
        if output:
            for category in categories_to_check:
                facts = facts_by_category[category]
                if not facts:
                    continue
                
                # Write category header
                output.write("\n" + self._format_category_header(category) + "\n\n")
                
                # Write facts for this category
                for fact in facts:
                    try:
                        title = fact.title(session)
                        output.write(f"  • {title}\n")
                        
                        # Add description if available
                        if hasattr(fact, 'description'):
                            desc = fact.description(session)
                            if desc:
                                output.write(f"    {desc}\n")
                    except Exception:
                        # Skip facts that can't be formatted
                        pass
                
                output.write("\n")
            
            # Write summary
            output.write("\n" + "=" * 75 + "\n")
            output.write(" " * 25 + "SUMMARY\n")
            output.write("=" * 75 + "\n\n")
            
            total_facts = sum(len(facts) for facts in facts_by_category.values())
            output.write(f"Total findings: {total_facts}\n\n")
            
            for category in categories_to_check:
                count = len(facts_by_category[category])
                if count > 0:
                    output.write(f"  {category:15} {count:3} findings\n")
            
            output.flush()
            yield Status(f"[green]Report written to file[/green]")
        else:
            # Summary for interactive output
            if not quiet:
                yield Status("\n[bold cyan]Enumeration Summary:[/bold cyan]")
                for category in categories_to_check:
                    count = len(facts_by_category[category])
                    if count > 0:
                        yield Status(f"  {category}: {count} findings")
