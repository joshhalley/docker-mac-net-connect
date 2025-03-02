package networkmanager

import (
        "bytes"
        "fmt"
        "os/exec"
        "strings"

        "github.com/docker/docker/api/types"
)

type NetworkManager struct {
        DockerNetworks map[string]types.NetworkResource
}

func New() NetworkManager {
        return NetworkManager{
                DockerNetworks: map[string]types.NetworkResource{},
        }
}

// Set the point-to-point IP address configuration on a network interface.
func (manager *NetworkManager) SetInterfaceAddress(ip string, peerIp string, iface string) (string, string, error) {
        ipVersion := determineIPVersion(ip)
        var cmd *exec.Cmd

        if ipVersion == "inet" {
                cmd = exec.Command("ifconfig", iface, ipVersion, ip+"/32", peerIp)
        } else {
                cmd = exec.Command("ifconfig", iface, ipVersion, ip, peerIp)
        }

        var stdout bytes.Buffer
        var stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        err := cmd.Run()

        return stdout.String(), stderr.String(), err
}

// Add a route to the macOS routing table.
func (manager *NetworkManager) AddRoute(net string, iface string) (string, string, error) {
        ipVersion := determineIPVersion(net)
        cmd := exec.Command("route", "-q", "-n", "add", ipVersion, net, "-interface", iface)

        var stdout bytes.Buffer
        var stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        err := cmd.Run()

        return stdout.String(), stderr.String(), err
}

// Delete a route from the macOS routing table.
func (manager *NetworkManager) DeleteRoute(net string) (string, string, error) {
        ipVersion := determineIPVersion(net)
        cmd := exec.Command("route", "-q", "-n", "delete", ipVersion, net)

        var stdout bytes.Buffer
        var stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        err := cmd.Run()

        return stdout.String(), stderr.String(), err
}

func (manager *NetworkManager) ProcessDockerNetworkCreate(network types.NetworkResource, iface string) {
        manager.DockerNetworks[network.ID] = network

        for _, config := range network.IPAM.Config {
                if network.Scope == "local" {
                        fmt.Printf("Adding route for %s -> %s (%s)\n", config.Subnet, iface, network.Name)

                        _, stderr, err := manager.AddRoute(config.Subnet, iface)

                        if err != nil {
                                fmt.Errorf("Failed to add route: %v. %v\n", err, stderr)
                        }
                }
        }
}

func (manager *NetworkManager) ProcessDockerNetworkDestroy(network types.NetworkResource) {
        for _, config := range network.IPAM.Config {
                if network.Scope == "local" {
                        fmt.Printf("Deleting route for %s (%s)\n", config.Subnet, network.Name)

                        _, stderr, err := manager.DeleteRoute(config.Subnet)

                        if err != nil {
                                fmt.Errorf("Failed to delete route: %v. %v\n", err, stderr)
                        }
                }
        }
        delete(manager.DockerNetworks, network.ID)
}

// Helper function to determine if the IP address is IPv4 or IPv6.
func determineIPVersion(ip string) string {
        if strings.Contains(ip, ":") {
                return "-inet6"
        }
        return "-inet"
}