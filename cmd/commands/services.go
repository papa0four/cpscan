// cmd/commands/services.go
package cmd

import (
    "fmt"
    "net"
    "strconv"
    "time"
    "github.com/spf13/cobra"
    "path/filepath"
    "github.com/papa0four/cpscan/internal/dataloader"
)

// Command flags for protocol and port
var port int
var portServiceMap map[int]dataloader.PortService

// servicesCmd represents the services command
var servicesCmd = &cobra.Command{
    Use: "services",
    Short: "Scan open ports and running services on the host",
    Long: `The services command scans open TCP/UDP ports and attempts to guess the running protocol. The scan can be run in full mode (all ports) or target a specific port/protocol`,
    Run: func(cmd *cobra.Command, args []string) {
        // Load JSON data before running the scan
        jsonPath := filepath.Join("data", "port_services.json")
        var err error
        portServiceMap, err = dataloader.LoadPortServiceMap(jsonPath)
        if err != nil {
            fmt.Printf("Error loading JSON data: %v\n", err)
            return
        }

        if port > 0 {
            scanSinglePort(port)
        } else {
            scanAllPorts()
        }
    },
}

func init() {
    servicesCmd.Flags().IntVarP(&port, "port", "p", 0, "Specify a specific port to scan")
    RootCmd.AddCommand(servicesCmd)
}

func scanSinglePort(port int) {
    tcpOpen, udpOpen := false, false

    // Try TCP connection
    address := "localhost:" + strconv.Itoa(port)
    conn, err := net.DialTimeout("tcp", address, 2*time.Second)
    if err == nil {
        tcpOpen = true
        conn.Close()
    }

    // Try UDP connection
    conn, err = net.DialTimeout("udp", address, 2*time.Second)
    if err == nil {
        udpOpen = true
        conn.Close()
    }

    // Determin protocol and output
    if tcpOpen && udpOpen {
        printPortInfo(port, "TCP/UDP")
    } else if tcpOpen {
        printPortInfo(port, "TCP")
    } else if udpOpen {
        printPortInfo(port, "UDP")
    } else {
        fmt.Printf("Port %d: close\n", port)
    }
}

// scanAllPorts scans all ports for TCP and UDP services
func scanAllPorts() {
    totalPorts := 65535
    closedPorts := 0

    for port := 1; port <= totalPorts; port++ {
        tcpOpen, udpOpen := false, false
        address := "localhost:" + strconv.Itoa(port)

        // Try TCP
        conn, err := net.DialTimeout("tcp", address, 2*time.Second)
        if err == nil {
            tcpOpen = true
            conn.Close()
        }

        // Try UDP
        conn, err = net.DialTimeout("udp", address, 2*time.Second)
        if err == nil {
            udpOpen = true
            conn.Close()
        }

        // Determine protocol and output or mark as closed
        if tcpOpen && udpOpen {
            printPortInfo(port, "TCP/UDP")
        } else if tcpOpen {
            printPortInfo(port, "TCP")
        } else if udpOpen {
            printPortInfo(port, "UDP")
        } else {
            closedPorts++
        }
    }

    fmt.Printf("%d port(s) closed\n", closedPorts)
}

func printPortInfo(port int, protocol string) {
    service, exists := portServiceMap[port]
    if exists {
        fmt.Printf("Port %d: %s \"%s\" - open\n", port, protocol, service.Service)
    } else {
        fmt.Printf("Port %d: %s \"unknown\" - open\n", port, protocol)
    }
}
