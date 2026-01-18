"""
Centralized error handling and recovery system for pwncat-vl.
Provides automatic error recovery and better error messages.
"""

import traceback
import functools
from typing import Callable, Optional, Type, Tuple, Any
from enum import Enum

import pwncat
from pwncat.util import console
from pwncat.channel import ChannelError, ChannelClosed, ChannelTimeout
from pwncat.platform import PlatformError


class ErrorSeverity(Enum):
    """Error severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ErrorContext:
    """Context information for error handling"""
    
    def __init__(self, operation: str, component: str = None, recoverable: bool = True):
        self.operation = operation
        self.component = component
        self.recoverable = recoverable
        self.retry_count = 0
        self.max_retries = 3


class ErrorHandler:
    """Centralized error handler with recovery capabilities"""
    
    def __init__(self):
        self.error_history = []
        self.recovery_strategies = {}
        self._register_default_strategies()
    
    def _register_default_strategies(self):
        """Register default recovery strategies"""
        
        # Channel errors
        self.recovery_strategies[ChannelClosed] = self._recover_channel_closed
        self.recovery_strategies[ChannelTimeout] = self._recover_channel_timeout
        self.recovery_strategies[ChannelError] = self._recover_channel_error
        
        # Platform errors
        self.recovery_strategies[PlatformError] = self._recover_platform_error
    
    def handle_error(
        self,
        error: Exception,
        context: ErrorContext,
        severity: ErrorSeverity = ErrorSeverity.ERROR
    ) -> Tuple[bool, Optional[Any]]:
        """
        Handle an error with automatic recovery if possible.
        
        Returns:
            (recovered, result) - True if recovered, False otherwise. Result if recovered.
        """
        
        error_type = type(error)
        error_info = {
            "type": error_type.__name__,
            "message": str(error),
            "context": context.operation,
            "component": context.component,
            "severity": severity.value,
            "traceback": traceback.format_exc()
        }
        self.error_history.append(error_info)
        
        # Log error
        self._log_error(error, context, severity)
        
        # Try recovery
        if context.recoverable and error_type in self.recovery_strategies:
            recovery_func = self.recovery_strategies[error_type]
            try:
                result = recovery_func(error, context)
                if result:
                    console.log(f"[green]Recovered from {error_type.__name__}[/green]")
                    return True, result
            except Exception as recovery_error:
                console.log(f"[red]Recovery failed[/red]: {recovery_error}")
        
        return False, None
    
    def _log_error(self, error: Exception, context: ErrorContext, severity: ErrorSeverity):
        """Log error with appropriate formatting"""
        
        error_msg = f"[{severity.value}] {context.operation}"
        if context.component:
            error_msg += f" ({context.component})"
        error_msg += f": {str(error)}"
        
        if severity == ErrorSeverity.CRITICAL:
            console.log(f"[red]{error_msg}[/red]")
            console.print_exception()
        elif severity == ErrorSeverity.ERROR:
            console.log(f"[red]{error_msg}[/red]")
        elif severity == ErrorSeverity.WARNING:
            console.log(f"[yellow]{error_msg}[/yellow]")
        else:
            console.log(f"[cyan]{error_msg}[/cyan]")
    
    def _recover_channel_closed(self, error: ChannelClosed, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for closed channels"""
        
        if context.retry_count >= context.max_retries:
            return None
        
        context.retry_count += 1
        
        # Try to cleanup and reconnect if possible
        if hasattr(error, 'cleanup'):
            try:
                # Get manager from context if available
                if hasattr(context, 'manager'):
                    error.cleanup(context.manager)
            except:
                pass
        
        # Suggest reconnection
        console.log("[yellow]Channel closed. Attempting recovery...[/yellow]")
        return None
    
    def _recover_channel_timeout(self, error: ChannelTimeout, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for channel timeouts"""
        
        if context.retry_count >= context.max_retries:
            return None
        
        context.retry_count += 1
        
        # Timeouts are often recoverable by retrying
        console.log(f"[yellow]Timeout occurred. Retrying ({context.retry_count}/{context.max_retries})...[/yellow]")
        return "retry"
    
    def _recover_channel_error(self, error: ChannelError, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for generic channel errors"""
        
        # Most channel errors are not easily recoverable
        return None
    
    def _recover_platform_error(self, error: PlatformError, context: ErrorContext) -> Optional[Any]:
        """Recovery strategy for platform errors"""
        
        # Platform errors often indicate missing tools or permissions
        # Provide helpful suggestions
        error_msg = str(error).lower()
        
        if "not found" in error_msg or "no such" in error_msg:
            console.log("[yellow]Suggestion: Check if required tools are available on target[/yellow]")
        elif "permission" in error_msg or "denied" in error_msg:
            console.log("[yellow]Suggestion: Check permissions or try with different user[/yellow]")
        
        return None
    
    def get_error_history(self, limit: int = 10):
        """Get recent error history"""
        return self.error_history[-limit:]
    
    def clear_history(self):
        """Clear error history"""
        self.error_history.clear()


# Global error handler instance
_error_handler = ErrorHandler()


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance"""
    return _error_handler


def with_error_handling(
    operation: str = None,
    component: str = None,
    recoverable: bool = True,
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    reraise: bool = True
):
    """
    Decorator for automatic error handling and recovery.
    
    Args:
        operation: Description of the operation
        component: Component name (e.g., 'channel', 'platform')
        recoverable: Whether errors can be recovered
        severity: Error severity level
        reraise: Whether to re-raise exception if not recovered
    """
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            handler = get_error_handler()
            context = ErrorContext(
                operation=operation or func.__name__,
                component=component,
                recoverable=recoverable
            )
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                recovered, result = handler.handle_error(e, context, severity)
                
                if recovered and result:
                    if result == "retry" and context.retry_count < context.max_retries:
                        # Retry the operation
                        return wrapper(*args, **kwargs)
                    return result
                
                if reraise:
                    raise
                return None
        
        return wrapper
    return decorator


def handle_error(
    error: Exception,
    operation: str,
    component: str = None,
    recoverable: bool = True,
    severity: ErrorSeverity = ErrorSeverity.ERROR
) -> Tuple[bool, Optional[Any]]:
    """
    Handle an error manually.
    
    Returns:
        (recovered, result) - True if recovered, False otherwise
    """
    handler = get_error_handler()
    context = ErrorContext(operation, component, recoverable)
    return handler.handle_error(error, context, severity)
