# Raw Ethernet Frame
Create a raw IEEE 802.3 Ethernet frame to send udp/tcp packets.

## Restriction
* The operation check is confirmed only on Linux.
* VLAN is not supported.
* Only IPv4 is supported.
* IP header is not include the `option` and the `frag_off`.

## Usage
### Build
Run the following commands.

```sh
make
```

