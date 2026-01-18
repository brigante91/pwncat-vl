Error Handling
==============

pwncat-vl includes a comprehensive error handling and recovery system.

Error Handler
-------------

The error handler provides automatic error recovery and better error messages.

Error Severity Levels
---------------------

- **INFO**: Informational messages
- **WARNING**: Warning messages that don't stop execution
- **ERROR**: Errors that may be recoverable
- **CRITICAL**: Critical errors that require attention

Using Error Handling
--------------------

The error handler is automatically used in critical components:

- Channel operations (send/recv)
- Module execution
- Platform operations

Error Recovery
--------------

The error handler attempts automatic recovery for:

- Channel timeouts (retries)
- Channel closed errors (cleanup)
- Platform errors (suggestions)

Error History
-------------

Error history is maintained and can be accessed programmatically:

.. code-block:: python

    from pwncat.error_handler import get_error_handler
    
    handler = get_error_handler()
    history = handler.get_error_history(limit=10)

Decorator Usage
---------------

You can use the error handling decorator in your modules:

.. code-block:: python

    from pwncat.error_handler import with_error_handling, ErrorSeverity
    
    @with_error_handling(operation="my operation", component="module", 
                       recoverable=True, severity=ErrorSeverity.ERROR)
    def my_function():
        # Your code here
        pass

Manual Error Handling
---------------------

Handle errors manually:

.. code-block:: python

    from pwncat.error_handler import handle_error, ErrorSeverity
    
    try:
        # Your code
        pass
    except Exception as e:
        recovered, result = handle_error(e, "operation name", 
                                        component="component",
                                        recoverable=True,
                                        severity=ErrorSeverity.ERROR)
