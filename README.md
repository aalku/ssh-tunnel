# ssh-tunnel
python scripts that creates an outgoing-incoming ssh tunnel that can bypass some firewalls

Sometimes you want to access a system that is behind a firewall or NAT and you can't open a port on them.
With this kind of tunnel you can make it "call home" and wait for your connection on your local computer or somewhere else.

This is what you get:

    +----------------+          +-----+   +---------------+          +-------------+
    |                |          |     |   |               |          |             |
    |                >------------------------------------------------>            |
    |        <-----------------------------------------------------------+         |
    |                >------------------------------------------------>  |  SSH    |
    |  Remote site   |          |     |   |               |          |   |  Server |
    |                |          |  F  |   |            +-----------------+         |
    |                |          |  i  |   |            |  |          |             |
    |                |          |  r  |   |  Internet  |  |          +-------------+
    +----------------+          |  e  |   |            |  |
                                |  w  |   |            |  |
                                |  a  |   |            |  |          +--------------+
                                |  l  |   |            |  |          |              |
                                |  l  |   |            +-----------------< You      |
                                |     |   |               |          |              |
                                +-----+   +---------------+          +--------------+


You access a remote site bypassing a firewall with the help of a SSH server.
You can see the tunnel going out from the remote site to the SSH server and how your connection can get there through it. From the firewall point of view there is just an output SSH connection. Most firewalls will allow it. The firewall can't see there is an incomming connection hidden inside it.

You can create the tunnel with this command:
  python autossh.py -tp 22 -sh <external-ssh-server> -lp <port-to-listen-on> -su <user> -sq <password> "$@" >> /var/log/autossh.log 2>&1 &

This will make autossh.py make an ssh connection to <external-ssh-server> with user <user> and listen there on <port-to-listen-on> tcp port. Any collection there (on the SSH server) to the local <port-to-listen-on> port will be driven through the tunnel to the port 22 (as commanded by the -tp 22 argument) of the system you run autossh on. You can use a different port if you want to "share" another service.

SSH itself can do this kind of tunnels but in my experience it fails a lot because it will not reconnect when needed and have a lot of troubles with zombie connections keeping the ports busy. autossh.py handles that problems for you by running python code on the ssh server too.
It uses random ports and then check if the wanted port is held by a zombie instance of the process, kills it, and takes the port.
The tunnel connection is very stable. The connections through it are closed when there is no activity for some time but the tunnel keeps connected or reconnects in case of any network error.

Python is needed to be installed on the SSH server but you don't need to place or run any script there. autossh.py will start a python console there and will send the needed python commands, all through the SSH connection.

autossh.py depends on pexpect. I included the version I used to develop and test. I don't know if it works with any other.

I only tested it with Python 2.7.x

Any contribution to documentation or code is welcome.
