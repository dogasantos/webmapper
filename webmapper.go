package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Ullaakut/nmap/v2"
)

type Host struct {
	IPAddress string
	Hostnames []string
}

// Remove duplicated elements from slice
func RemoveDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == false {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
func fixDefaultPorts(webServices []string) []string {
	var fixedServices []string

	for _, service := range webServices {
		// Parse the URL
		u, err := url.Parse(service)
		if err != nil {
			// If parsing fails for any reason, keep the original
			fixedServices = append(fixedServices, service)
			continue
		}

		// Split the host into hostname and port (if present)
		hostParts := strings.Split(u.Host, ":")
		if len(hostParts) == 2 {
			// if we have "host:port"
			port := hostParts[1]

			// Check if it's "http" with port 80
			// or "https" with port 443
			if (u.Scheme == "http" && port == "80") ||
				(u.Scheme == "https" && port == "443") {
				// Remove the port
				u.Host = hostParts[0]
			}
		}

		fixedServices = append(fixedServices, u.String())
	}

	return fixedServices
}

func parseMassdns(lines []string) []Host {
	var hosts []Host
	for _, line := range lines {
		parts := strings.Split(line, " ")
		if len(parts) < 3 {
			continue
		}
		// parts[0] is the hostname, parts[2] is the IP
		host := strings.TrimSuffix(parts[0], ".") // remove trailing '.'
		ip := parts[len(parts)-1]

		hosts = append(hosts, Host{
			IPAddress: ip,
			Hostnames: []string{host},
		})
	}
	return hosts
}

func parseDnsx(lines []string) []Host {
	var hosts []Host
	for _, line := range lines {
		parts := strings.Split(line, " [A] [")
		if len(parts) != 2 {
			continue
		}
		host := parts[0]
		ip := strings.TrimSuffix(parts[1], "]")
		hosts = append(hosts, Host{IPAddress: ip, Hostnames: []string{host}})
	}
	return hosts
}

func getHostnamesFromIP(hosts []Host, ip string) []string {
	var hostnames []string
	for _, host := range hosts {
		if host.IPAddress == ip {
			hostnames = append(hostnames, host.Hostnames...)
		}
	}
	return hostnames
}

func parseNmap(filename string) (*nmap.Run, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	var result nmap.Run
	err = decoder.Decode(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func findWebServices(nmapResult *nmap.Run, hosts []Host) []string {
	var webServices []string
	webServiceNames := []string{"http", "http-proxy", "https", "https-alt", "ssl"}

	for _, host := range nmapResult.Hosts {
		ip := host.Addresses[0].Addr
		hostnames := getHostnamesFromIP(hosts, ip)
		for _, port := range host.Ports {
			if port.State.State == "open" {
				for _, serviceName := range webServiceNames {
					if strings.Contains(port.Service.Name, serviceName) {
						proto := "http"
						if serviceName == "https" || serviceName == "ssl" || strings.Contains(port.Service.Name, "https") {
							proto = "https"
						}
						for _, hostname := range hostnames {
							webServices = append(webServices, fmt.Sprintf("%s://%s:%d", proto, hostname, port.ID))
						}
						if len(hostnames) == 0 {
							webServices = append(webServices, fmt.Sprintf("%s://%s:%d", proto, ip, port.ID))
						}
					}
				}
			}
		}
	}

	return webServices
}

func saveFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	nmapReport := flag.String("nmapreport", "", "nmap xml report file")
	massdnsReport := flag.String("massdns", "", "massdns or dnsx report file (ip - hostname) so we can get the proper hostname for each ip address")
	output := flag.String("output", "", "Output is a text file containing hosts in the format proto://ip-or-host:port (with a .web suffix)")
	flag.Parse()

	if *nmapReport == "" {
		fmt.Println("Usage: go run main.go -nmapreport <nmap report file> -massdns <massdns report file> -output <output file>")
		return
	}

	fmt.Println("webmapper 1.0 @ dogasantos")
	fmt.Println("-------------------------------------------------------")
	fmt.Println("parse nmap xml report and get all web services running ")
	fmt.Println("-------------------------------------------------------")

	nmapResult, err := parseNmap(*nmapReport)
	if err != nil {
		fmt.Printf("Error reading nmap report: %v\n", err)
		return
	}
	fmt.Println("  + Nmap report successfully loaded")

	var hosts []Host
	if *massdnsReport != "" {
		lines, err := readLines(*massdnsReport)
		if err != nil {
			fmt.Printf("Error reading massdns/dnsx report: %v\n", err)
			return
		}
		if strings.Contains(lines[0], "[") && strings.Contains(lines[0], "]") {
			hosts = parseDnsx(lines)
		} else {
			hosts = parseMassdns(lines)
		}
	}

	webServices := findWebServices(nmapResult, hosts)
	webServices = RemoveDuplicates(fixDefaultPorts(webServices))

	if *output != "" {
		err := saveFile(*output, webServices)
		if err != nil {
			fmt.Printf("Error saving output file: %v\n", err)
		}
	} else {
		for _, service := range webServices {
			fmt.Println(service)
		}
	}

	fmt.Println("[*] Done.")
}
