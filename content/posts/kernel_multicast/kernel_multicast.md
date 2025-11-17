---
title: "Kernel multicast and IGMP"
date: 2025-11-01T12:56:10+10:00
draft: false
toc: false
Summary: "lessons learned about contributing to Holo routing"
images:
tags:
  - networking
---

In my free time I have been contributing to an opensource project called holo routing, which is a linux based routing software build in Rust. Feel free to learn more [here](https://www.github.com/holo-routing/holo).

I had been implementing a few RFC's that extended the funcitonality of OSPF but decided I wanted a bit of a challenge, so there is no better pain than multicast. Multicast is a bit of an overloaded term and can encompass many protocols but for my case I wanted to start with IGMP and look at PIM later down the track.

Both IGMP version one and three have well defined multicast groups but version two allows for its "group join requests" to be addressed to any multicast group so how do we listen to all of these arbitrary groups?.


My inital reaction was to just set up a `RAW` socket and that was it... oh how wrong was I.
```rust
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(IGMP_IP_PROTO)),
            )
        })?;
        socket.set_nonblocking(true)?;
```

I used a wicked tool called [`mcjoin`](https://github.com/troglobit/mcjoin) to send IGMP joins to random group address and found myself scratching my head as nothing happend. I confirmed with wireshark that the packets arrived on the interface but were just being eaten by the kernel. Recall that normally if we were writting a multicast application we would tell the kernel that we were interested in a group such as `239.2.3.10` by setting a `sockopt`. But doing that for every group would be silly.

We can actually interact with the kernel multicast routing table ourself by opening a control socket, we take our raw socket and set the `MRT_INIT` options. Its important to note you can only have one socket at a time marked with this option.

This did raise to me an interesting quesiton what if you needed to listen for traffic from another multicast protocol, what happens because the raw socket has protocol `IGMP_IP_PROTO` but thats for another time I guess..


```rust
    fn set_mrt_init(&self, value: bool) -> Result<()> {
        let optval = value as c_int;
        setsockopt(
            self,
            libc::IPPROTO_IP,
            MRT_INIT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
```

Now we can interact with the kernel we need to create `virtual interfaces` (VIF's) these can be based on real interfaces or other deives such as tunnels. We use these VIF's to perform multicast magic. As I writing router software I am building them based on real devices so lets do that.

```rust
    fn start_vif(&self, ifindex: u32, vifid: u16) -> Result<()> {
        let vif = vifctl {
            vifc_vifi: vifid,
            vifc_flags: VIFF_USE_IFINDEX,
            vifc_threshold: 0,
            vifc_rate_limit: 0,
            addr_index_union: __vif_union {
                vifc_lcl_ifindex: ifindex as i32,
            },
            vifc_rmt_addr: libc::in_addr { s_addr: 0 },
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            MRT_ADD_VIF,
            &vif as *const _ as *const libc::c_void,
            std::mem::size_of_val(&vif) as libc::socklen_t,
        )
    }
```

Excellent now the kernel will provide our socket with multicast traffic it receives on our VIF's build on real interfaces, now this raises an interesting question how do we know where this arrived from? The kernel can actually provide us more detail about the incoming packet with `IP_PKTINFO` we can toggle a socket option to include this extra info with incoming packets it reports.

```c
struct in_pktinfo {
	int		ipi_ifindex;
	struct in_addr	ipi_spec_dst;
	struct in_addr	ipi_addr;
};
```

We can then use this to both learn which interface we received the packet on and the content itself. These were some of the things I have learnt in my ongoing journey of linux networking. If you also enjoy open source routing I encourage you to again checkout Holo Routing.