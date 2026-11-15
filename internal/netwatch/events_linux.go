package netwatch

import (
	"context"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// watch subscribes to rtnetlink: links, IPv4/IPv6 addresses and routes.
func watch(ctx context.Context, notify, _ func(func() Change), fail func(error)) (string, func() string) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		fail(err)
		return "", nil
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		fail(err)
		return "", nil
	}
	go func() {
		<-ctx.Done()
		unix.Close(fd)
	}()
	go func() {
		buf := make([]byte, 8192)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == unix.ENOBUFS {
					notify(func() Change { return Change{Source: "rtnetlink", Kind: "notifications-lost"} })
					continue
				} // dropped notifications require revalidation
				if err == unix.EINTR {
					continue
				}
				fail(err)
				return
			}
			notify(func() Change { return linuxChange(buf[:n]) })
		}
	}()
	return "", nil
}

func linuxChange(buf []byte) Change {
	c := Change{Source: "rtnetlink", Kind: "message"}
	msgs, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		c.Kind = "unparsed-message"
		return c
	}
	// One datagram can contain several notifications. Retain all message types.
	for i, m := range msgs {
		if i > 0 {
			c.Kind += ","
		} else {
			c.Kind = ""
		}
		switch m.Header.Type {
		case unix.RTM_NEWLINK:
			c.Kind += "interface-new"
		case unix.RTM_DELLINK:
			c.Kind += "interface-delete"
		case unix.RTM_NEWADDR:
			c.Kind += "address-new"
		case unix.RTM_DELADDR:
			c.Kind += "address-delete"
		case unix.RTM_NEWROUTE:
			c.Kind += "route-new"
		case unix.RTM_DELROUTE:
			c.Kind += "route-delete"
		default:
			c.Kind += fmt.Sprintf("message-%d", m.Header.Type)
		}
	}
	return c
}
