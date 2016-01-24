# ssh-tunnel
python scripts that creates an outgoing-incoming ssh tunnel that can bypass some firewalls

Sometimes you want to access a system that is behind a firewall or NAT and you can't open a port on them.
With this kind of tunnel you can make it "call home" and wait for your connection on your local computer or somewhere else.

TODO: Explanations, diagrams, etc.

It depends on pexpect. I included the version I used to develop and test. I don't know if it works with any other.

You can create a tunnel with this command:
  pyton autossh.py -tp 22 -sh <external-ssh-server> -lp <port-to-listen-on> -su <user> "$@" >> /var/log/autossh.log 2>&1 &
