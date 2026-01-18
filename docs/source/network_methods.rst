Network Methods
===============

pwncat-vl now includes advanced network methods for port forwarding and SOCKS proxy support.

Port Forwarding
---------------

Port forwarding allows you to forward network connections through your pwncat session.

Local Port Forwarding
~~~~~~~~~~~~~~~~~~~~~

Local port forwarding forwards connections from a local port to a remote host/port.

.. code-block:: bash

    forward -L 8080 -h 10.10.10.10 -p 80

This will listen on localhost:8080 and forward all connections to 10.10.10.10:80 through the current session.

Remote Port Forwarding
~~~~~~~~~~~~~~~~~~~~~~

Remote port forwarding exposes a remote port on the local machine.

.. code-block:: bash

    forward -R 9090 -h 127.0.0.1 -p 3306

This will listen on the remote host on port 9090 and forward connections to localhost:3306.

Managing Forwards
~~~~~~~~~~~~~~~~~

List all active port forwards:

.. code-block:: bash

    forward -l

Stop a specific forward:

.. code-block:: bash

    forward -s 8080

SOCKS Proxy
-----------

pwncat-vl supports dynamic port forwarding via SOCKS proxy (SOCKS4 and SOCKS5).

Starting a SOCKS Proxy
~~~~~~~~~~~~~~~~~~~~~~

Start a SOCKS5 proxy (default):

.. code-block:: bash

    socks -p 1080

Start a SOCKS4 proxy:

.. code-block:: bash

    socks -p 1080 -v 4

Managing Proxies
~~~~~~~~~~~~~~~~

List all active SOCKS proxies:

.. code-block:: bash

    socks -l

Stop a proxy:

.. code-block:: bash

    socks -s 1080

Usage Examples
--------------

Using SOCKS proxy with other tools:

.. code-block:: bash

    # Start SOCKS proxy in pwncat
    socks -p 1080
    
    # Use with curl
    curl --socks5-hostname 127.0.0.1:1080 http://internal-server.local
    
    # Use with proxychains
    proxychains nmap -sT -Pn 10.10.10.0/24
