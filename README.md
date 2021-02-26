# Automatic Peer System

An automatic peer system using WireGuard and Bird2 for DN42.

## Usage

First, clone this project on your server and create some folders.
```shell
git clone https://github.com/lss233/fuzzy-bassoon
cd fuzzy-bassoon
mkdir data/{wireguard, bird} .ssh
```
Next, create a file named `node.json`:
```json
{
    "name": "The node name here",
    "asn": "Your ASN",
    "mpbgp": true, // Is MP-BGP Supported ?
    "wireguard": {
        "publickey": "Your WireGuard Public Key",
        "privatekey": "Yourr WireGuard Private Key",
        "ipv4": "The DN42 IPv4 Address on this machine",
        "ipv6": "The DN42 IPv6 Address on this machine",
        "linkLocal": "The Link-Local Address on this machine"
    }
}
```

Generate a ssh keypair for incoming connection.
```shell
ssh-keygen -t rsa -f ./.ssh/privkey
```

Open your bird.conf, and add following:
```toml
include "/path/to/fuzzy-bassoon/data/bird/*";
```

Start the server, you can write a supervisord configuration file,
or systemd or tmux and something else. whatever.

```
node index.js
```
