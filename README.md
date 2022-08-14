# Raw Ethernet Frame
Create a raw IEEE 802.3 Ethernet frame to send udp/tcp packets.

## Restriction
* The operation check is confirmed only on Linux.
* VLAN is **not** supported.
* Only IPv4 is supported.
* The IP header does not contain an `option` field.
* The `option` field of TCP header is not checked.

## Usage
### Build
Run the following command.

```sh
make
```

### Execute
Execute the following command.

```sh
./target
```