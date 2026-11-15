package netwatch

import (
	"context"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// watch reads the routing socket: the kernel writes a message to it on every
// route, address and interface change.
func watch(ctx context.Context, notify, _ func(func() Change), fail func(error)) (string, func() string) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		fail(err)
		return "", nil
	}
	go func() {
		<-ctx.Done()
		unix.Close(fd)
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				fail(err)
				return
			}
			notify(func() Change { return darwinChange(buf[:n]) })
		}
	}()
	return "", nil
}

func darwinChange(buf []byte) Change {
	c := Change{Source: "routing-socket", Kind: "message"}
	msgs, err := syscall.ParseRoutingMessage(buf)
	if err != nil {
		c.Kind = "unparsed-message"
		return c
	}
	for i, msg := range msgs {
		if i > 0 {
			c.Kind += ","
		} else {
			c.Kind = ""
		}
		var kind uint8
		switch m := msg.(type) {
		case *syscall.RouteMessage:
			kind = m.Header.Type
			c.Interface = uint32(m.Header.Index)
		case *syscall.InterfaceMessage:
			kind = m.Header.Type
			c.Interface = uint32(m.Header.Index)
		case *syscall.InterfaceAddrMessage:
			kind = m.Header.Type
			c.Interface = uint32(m.Header.Index)
		}
		switch kind {
		case unix.RTM_ADD:
			c.Kind += "route-add"
		case unix.RTM_DELETE:
			c.Kind += "route-delete"
		case unix.RTM_CHANGE:
			c.Kind += "route-change"
		case unix.RTM_NEWADDR:
			c.Kind += "address-new"
		case unix.RTM_DELADDR:
			c.Kind += "address-delete"
		case unix.RTM_IFINFO:
			c.Kind += "interface-change"
		default:
			c.Kind += fmt.Sprintf("message-%d", kind)
		}
	}
	return c
}
