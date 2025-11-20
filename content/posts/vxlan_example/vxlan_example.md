---
title: "a practical example of linux vxlans"
date: 2025-11-19T12:56:10+10:00
draft: false
toc: false
Summary: "a vxlan demo with containerlabs, frr and linux"
images:
tags:
  - networking
---

VXLANs are used to carry traffic over an existing network. This is going to be a practical tour of a network built with ContainerLab. Our underlay network is going to be built using FRR. Our overlay VXLAN interfaces are going to be using flood and learn, instead of static assignments. Feel free to clone the container labs setup [here](https://github.com/fliqqs/containerlab-vxlan-example) and follow along.

```
 PC1 --- R1 --- R2 --- R3 --- PC2
           \     |     /
            \----|----/
             Underlay
```


Our VXLAN virtual tunnel endpoints (VTEPs) will be constructed on R1 and R3 with the following:

```bash
ip link add vxlan100 type vxlan id 100 group 239.1.1.1 dev r1-r2 dstport 4789 ttl 16
ip link add br0 type bridge
ip link set vxlan100 master br0
ip link set r1-pc1 master br0
ip link set br0 up
ip link set vxlan100 up
```

This creates the endpoint on router R1 which will use multicast group `239.1.1.1`. This VTEP device is attached to a bridge along with another interface `r1-pc1` which is the incoming traffic from `pc1`.

Let's log into PC1 with:
```bash
sudo docker exec -it clab-vxlan-lab-pc1 sh
```

And attempt to ping the other endpoint. In this lab, PC1 has the address `192.168.1.10/24` and PC2 has `192.168.1.20/24`. When attempting to ping PC2, we initially get no reply.

Looking on R2, we can see the encapsulation of the packets. The ARP is wrapped in the VXLAN multicast group and is being flooded to `239.1.1.1`.

```
    [Protocols in frame: eth:ethertype:ip:udp:vxlan:eth:ethertype:arp]
Ethernet II, Src: aa:c1:ab:1c:5d:93 (aa:c1:ab:1c:5d:93), Dst: IPv4mcast_01:01:01 (01:00:5e:01:01:01)
    Destination: IPv4mcast_01:01:01 (01:00:5e:01:01:01)
        Address: IPv4mcast_01:01:01 (01:00:5e:01:01:01)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: aa:c1:ab:1c:5d:93 (aa:c1:ab:1c:5d:93)
        Address: aa:c1:ab:1c:5d:93 (aa:c1:ab:1c:5d:93)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IPv4 (0x0800)
Internet Protocol Version 4, Src: 10.0.23.3, Dst: 239.1.1.1
```

The same behavior happens on the interface towards R3, but this is expected as we need to configure multicast routing with PIM. If we had static entries in the FDB bridge, this wouldn't happen, but we need R2 in the middle to forward the traffic. We can do this by setting up PIM. We will set R2 as the rendezvous point (RP) and it will now forward the traffic between the `r2-r1` and the `r2-r3` interfaces.

We are now able to ping the PC2 VTEP address. If we look at the R1 forwarding database entry, we can see the MAC address of the PC2 interface `aa:c1:ab:c6:a7:e6`: is reachable via the underlay network address.

```
bash-5.1# bridge fdb
00:00:00:00:00:00 dev vxlan100 dst 239.1.1.1 via r2-r1 self permanent
2a:2d:de:09:55:92 dev vxlan100 dst 10.0.12.1 self
aa:c1:ab:26:b4:a6 dev vxlan100 dst 10.0.12.1 self
6e:25:57:ab:31:99 dev vxlan100 dst 10.0.23.3 self
aa:c1:ab:c6:a7:e6 dev vxlan100 dst 10.0.23.3 self
```


```
87: eth0@if88: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 9500 qdisc noqueue state UP
    link/ether aa:c1:ab:c6:a7:e6 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.20/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::a8c1:abff:fec6:a7e6/64 scope link
       valid_lft forever preferred_lft forever
```

You can additionally watch it happen in real time with `bridge monitor fdb`.

On the wire we can now see that when we send traffic such as ICMP, the outer layer is set to the VTEP address instead of a multicast group as it has been learnt by the kernel.

```
    [Protocols in frame: eth:ethertype:ip:udp:vxlan:eth:ethertype:ip:icmp:data]
Ethernet II, Src: aa:c1:ab:80:55:0d (aa:c1:ab:80:55:0d), Dst: aa:c1:ab:e5:4e:94 (aa:c1:ab:e5:4e:94)
    Destination: aa:c1:ab:e5:4e:94 (aa:c1:ab:e5:4e:94)
        Address: aa:c1:ab:e5:4e:94 (aa:c1:ab:e5:4e:94)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: aa:c1:ab:80:55:0d (aa:c1:ab:80:55:0d)
        Address: aa:c1:ab:80:55:0d (aa:c1:ab:80:55:0d)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IPv4 (0x0800)
Internet Protocol Version 4, Src: 10.0.23.3, Dst: 10.0.12.1
```

Hopefully this gives you a little insight into linux networking.