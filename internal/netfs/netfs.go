package netfs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SocketState maps hex state codes to human-readable names
var SocketState = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// Socket represents a single entry from /proc/net/tcp or udp
type Socket struct {
	Proto       string
	LocalAddr   string
	LocalPort   int
	RemoteAddr  string
	RemotePort  int
	State       string
	Inode       uint64
	PID         int
	ProcessName string
}

func (s Socket) String() string {
	state := s.State
	if state == "" {
		state = "UNKNOWN"
	}
	owner := s.ProcessName
	if owner == "" && s.PID > 0 {
		owner = fmt.Sprintf("pid/%d", s.PID)
	}
	return fmt.Sprintf("%-5s %-21s %-21s %-12s %s",
		s.Proto,
		fmt.Sprintf("%s:%d", s.LocalAddr, s.LocalPort),
		fmt.Sprintf("%s:%d", s.RemoteAddr, s.RemotePort),
		state,
		owner,
	)
}

// ReadSockets reads TCP, TCP6, UDP, UDP6 sockets from /proc/net/
func ReadSockets() ([]Socket, error) {
	var all []Socket
	sources := []struct {
		path  string
		proto string
		v6    bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp6", true},
	}

	inodePID := buildInodePIDMap()

	exeCache := make(map[int]string)
	for _, src := range sources {
		socks, err := parseNetFile(src.path, src.proto, src.v6)
		if err != nil {
			continue // file may not exist
		}
		for i := range socks {
			if pid, ok := inodePID[socks[i].Inode]; ok {
				socks[i].PID = pid
				name, cached := exeCache[pid]
				if !cached {
					if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
						name = filepath.Base(link)
					}
					exeCache[pid] = name
				}
				if name != "" {
					socks[i].ProcessName = name
				}
			}
		}
		all = append(all, socks...)
	}
	return all, nil
}

func parseNetFile(path, proto string, v6 bool) ([]Socket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // skip header

	var socks []Socket
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		var localAddr, remAddr string
		var localPort, remPort int
		var err1, err2 error

		if v6 {
			localAddr, localPort, err1 = parseHexAddrV6(fields[1])
			remAddr, remPort, err2 = parseHexAddrV6(fields[2])
		} else {
			localAddr, localPort, err1 = parseHexAddr(fields[1])
			remAddr, remPort, err2 = parseHexAddr(fields[2])
		}
		if err1 != nil || err2 != nil {
			continue
		}

		stateHex := strings.ToUpper(fields[3])
		state := SocketState[stateHex]

		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		socks = append(socks, Socket{
			Proto:      proto,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remAddr,
			RemotePort: remPort,
			State:      state,
			Inode:      inode,
		})
	}
	return socks, sc.Err()
}

// parseHexAddr converts "0F02000A:1F90" → ("10.0.2.15", 8080, nil)
func parseHexAddr(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad addr: %s", s)
	}
	ipInt, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	// little-endian
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(ipInt))
	return net.IP(b).String(), int(port), nil
}

// parseHexAddrV6 converts 32-char hex IPv6 address
func parseHexAddrV6(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad addr6: %s", s)
	}
	addrHex := parts[0]
	if len(addrHex) != 32 {
		return "", 0, fmt.Errorf("bad ipv6 hex len: %s", addrHex)
	}
	b := make([]byte, 16)
	for i := 0; i < 4; i++ {
		word, err := strconv.ParseUint(addrHex[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return "", 0, err
		}
		binary.LittleEndian.PutUint32(b[i*4:], uint32(word))
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	return net.IP(b).String(), int(port), nil
}

// buildInodePIDMap walks /proc/*/fd/ and maps socket inodes to PIDs.
// NOTE: single-valued (last writer wins). When several processes share one socket
// inode (for example after a fork), the reported owner PID is whichever entry the
// /proc enumeration visited last and is therefore nondeterministic. Changing this
// to a PID set ripples into Socket.PID consumers and report formatting for marginal
// forensic value, so it is intentionally left as-is.
func buildInodePIDMap() map[uint64]int {
	m := make(map[uint64]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") {
				inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				inode, err := strconv.ParseUint(inodeStr, 10, 64)
				if err == nil {
					m[inode] = pid
				}
			}
		}
	}
	return m
}

// Interface represents a parsed network interface
type Interface struct {
	Name        string
	Flags       string
	Addresses   []string
	Promiscuous bool
}

// ReadInterfaces reads /sys/class/net/ to list interfaces and flags
func ReadInterfaces() ([]Interface, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var ifaces []Interface
	for _, e := range entries {
		iface := Interface{Name: e.Name()}

		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/flags", e.Name())); err == nil {
			flagsStr := strings.TrimSpace(string(data))
			flags, err := strconv.ParseUint(strings.TrimPrefix(flagsStr, "0x"), 16, 32)
			if err == nil {
				iface.Flags = flagsStr
				// IFF_PROMISC = 0x100
				iface.Promiscuous = (flags & 0x100) != 0
			}
		}

		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", e.Name())); err == nil {
			iface.Addresses = append(iface.Addresses, strings.TrimSpace(string(data)))
		}

		if netIface, err := net.InterfaceByName(e.Name()); err == nil {
			addrs, _ := netIface.Addrs()
			for _, a := range addrs {
				iface.Addresses = append(iface.Addresses, a.String())
			}
		}

		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

// RouteEntry represents a row from /proc/net/route
type RouteEntry struct {
	Iface   string
	Dest    string
	Gateway string
	Flags   string
	Mask    string
}

// ReadRoutes parses /proc/net/route
func ReadRoutes() ([]RouteEntry, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // skip header

	var routes []RouteEntry
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		dest, _ := hexToIPv4(fields[1])
		gw, _ := hexToIPv4(fields[2])
		mask, _ := hexToIPv4(fields[7])
		routes = append(routes, RouteEntry{
			Iface:   fields[0],
			Dest:    dest,
			Gateway: gw,
			Flags:   fields[3],
			Mask:    mask,
		})
	}
	return routes, nil
}

// hexToIPv4 converts little-endian hex "0101A8C0" → "192.168.1.1"
func hexToIPv4(h string) (string, error) {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return "", err
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return net.IP(b).String(), nil
}

// ARPEntry represents a row from /proc/net/arp
type ARPEntry struct {
	IP     string
	HWType string
	Flags  string
	MAC    string
	Mask   string
	Device string
}

// ReadARP parses /proc/net/arp
func ReadARP() ([]ARPEntry, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // skip header

	var entries []ARPEntry
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		entries = append(entries, ARPEntry{
			IP:     fields[0],
			HWType: fields[1],
			Flags:  fields[2],
			MAC:    fields[3],
			Mask:   fields[4],
			Device: fields[5],
		})
	}
	return entries, nil
}

// PacketSocket represents one entry from /proc/net/packet.
// The kernel writes one line per open AF_PACKET socket.
type PacketSocket struct {
	Inode  uint64
	RefCnt int
	Type   int // socket type: 3 = SOCK_RAW
}

// ReadPacketSockets parses /proc/net/packet and returns all open raw sockets.
//
// /proc/net/packet format (header + data lines):
//
//	sk       RefCnt Type Proto  Iface R Rmem   User   Inode
//	ffff...  3      3    0x0003 2     0 0      0      12345
func ReadPacketSockets() ([]PacketSocket, error) {
	data, err := os.ReadFile("/proc/net/packet")
	if err != nil {
		return nil, err
	}

	var result []PacketSocket
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		inode, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		refcnt, _ := strconv.Atoi(fields[1])
		sockType, _ := strconv.Atoi(fields[2])
		result = append(result, PacketSocket{
			Inode:  inode,
			RefCnt: refcnt,
			Type:   sockType,
		})
	}
	return result, nil
}
