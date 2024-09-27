package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var topPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	25,    // SMTP
	26,    // SMTP
	465,   // SMTPS
	80,    // HTTP
	443,   // HTTPS
	8080,  // HTTP Proxy
	8443,  // HTTPS Proxy
	1080,  // SOCKS Proxy
	3306,  // MySQL
	33060, // MySQL (Docker)
	5432,  // PostgreSQL
	54320, // PostgreSQL (Docker)
	6379,  // Redis
	6380,  // Redis (TLS/SSL)
	5672,  // RabbitMQ
	27017, // MongoDB
	27018, // MongoDB
	27019, // MongoDB
	5000,  // Docker Registry
	9000,  // PHP-FPM
}

type Endpoint struct {
	Addr string
	Port int
}

var logger = logrus.New()

func main() {
	inputFile, outputFile, logLevel, workerLimit, timeout, ports := parseFlags()
	setupLogger(logLevel)

	addresses, err := readLines(inputFile)
	if err != nil {
		logger.Fatalf("❌ Error reading addresses: %v", err)
	}

	output := getOutputFile(outputFile)
	defer output.Close()

	services, err := readServicesFile("/etc/services")
	if err != nil {
		logger.Error("❗ Can't read service names")
	}

	logger.Debug("🚩 Port scanning started")
	scanPorts(addresses, output, workerLimit, timeout, ports, services)
	logger.Debug("🏁 Finished!")
}

func parseFlags() (string, string, string, int, time.Duration, []int) {
	inputFile := flag.String("i", "-", "File with a list of addresses to check (default is stdin)")
	outputFile := flag.String("o", "-", "File to output results (default is stdout)")
	logLevel := flag.String("log", "info", "Logging level (debug, info, warn, error, fatal, panic)")
	workerLimit := flag.Int("w", 50, "Number of concurrent workers for scanning ports")
	timeout := flag.Duration("t", 2*time.Second, "Timeout for port scanning")
	ports := flag.String("p", "", "Ports to scan (comma-separated or ranges, e.g., 80,443,1000-2000)")
	flag.Parse()

	portList := parsePorts(*ports)
	if len(portList) == 0 {
		portList = topPorts
	}
	return *inputFile, *outputFile, *logLevel, *workerLimit, *timeout, portList
}

func setupLogger(logLevel string) {
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Fatalf("❌ Invalid log level: %v", err)
	}
	logger.SetLevel(level)
}

func readLines(path string) ([]string, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func openFile(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}

func getOutputFile(outputFile string) *os.File {
	if outputFile == "-" {
		return os.Stdout
	}

	output, err := os.Create(outputFile)
	if err != nil {
		logger.Fatalf("❌ Can't open file: %s", outputFile)
	}

	return output
}

func scanPort(endpoint Endpoint, results chan Endpoint, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", endpoint.Addr, endpoint.Port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		logger.Debugf("⛔ Port %s is closed: %v", address, err)
		return
	}
	defer conn.Close()

	logger.Infof("✅ Port %s is open", address)
	results <- endpoint
}

func expandIPRange(ipRange string) []string {
	if !strings.Contains(ipRange, "-") {
		return []string{ipRange}
	}

	parts := strings.Split(ipRange, "-")
	startIP := net.ParseIP(parts[0])
	endIP := net.ParseIP(parts[1])

	if startIP == nil || endIP == nil {
		logger.Errorf("❗ Invalid IP range: %s", ipRange)
		return nil
	}

	var ips []string
	for ip := startIP.Mask(net.CIDRMask(32, 32)); ip.String() != endIP.String(); inc(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanPorts(addresses []string, output *os.File, workerLimit int, timeout time.Duration, ports []int, services map[int]string) {
	endpoints := make(chan Endpoint)
	results := make(chan Endpoint)
	var wg sync.WaitGroup

	for i := 1; i <= workerLimit; i++ {
		wg.Add(1)
		logger.Debugf("🚀 Starting worker #%d", i)
		go func(id int) {
			defer func() {
				logger.Debugf("🎉 Worker #%d finished", id)
				wg.Done()
			}()
			for endpoint := range endpoints {
				logger.Debugf("Worker #%d scanning port for %s:%d", id, endpoint.Addr, endpoint.Port)
				scanPort(endpoint, results, timeout)
			}
		}(i)
	}

	go func() {
		for result := range results {
			name, ok := services[result.Port]
			if !ok {
				name = "unknown"
			}
			fmt.Fprintf(output, "%s %d (%s)\n", result.Addr, result.Port, name)
		}
	}()

	for _, address := range addresses {
		for _, endpoint := range generateEndpoints(address, ports) {
			endpoints <- endpoint
		}
	}

	close(endpoints)
	wg.Wait()
	close(results)
}

func generateEndpoints(address string, ports []int) []Endpoint {
	if strings.Contains(address, "/") {
		return generateCIDREndpoints(address, ports)
	} else if strings.Contains(address, "-") {
		return generateRangeEndpoints(address, ports)
	}
	return generateSingleHostEndpoints(address, ports)
}

func generateCIDREndpoints(address string, ports []int) []Endpoint {
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		logger.Errorf("❗ Invalid CIDR: %s", address)
		return nil
	}

	var endpoints []Endpoint
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		for _, port := range ports {
			endpoints = append(endpoints, Endpoint{Addr: ip.String(), Port: port})
		}
	}
	return endpoints
}

func generateRangeEndpoints(address string, ports []int) []Endpoint {
	var endpoints []Endpoint
	for _, ip := range expandIPRange(address) {
		for _, port := range ports {
			endpoints = append(endpoints, Endpoint{Addr: ip, Port: port})
		}
	}
	return endpoints
}

func generateSingleHostEndpoints(address string, ports []int) []Endpoint {
	var endpoints []Endpoint
	address = extractHost(address)
	for _, port := range ports {
		endpoints = append(endpoints, Endpoint{Addr: address, Port: port})
	}
	return endpoints
}

func extractHost(address string) string {
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil {
			logger.Errorf("❗ Invalid URL: %s", address)
			return address
		}
		address = u.Hostname()
	}
	return address
}

func parsePorts(ports string) []int {
	var portList []int
	if ports == "" {
		return portList
	}

	portRanges := strings.Split(ports, ",")
	for _, portRange := range portRanges {
		portRange = strings.TrimSpace(portRange)
		if strings.Contains(portRange, "-") {
			portList = append(portList, parsePortRange(portRange)...)
		} else {
			port, err := strconv.Atoi(portRange)
			if err != nil {
				logger.Errorf("❗ Invalid port: %s", portRange)
				continue
			}
			portList = append(portList, port)
		}
	}
	return portList
}

func parsePortRange(portRange string) []int {
	parts := strings.Split(portRange, "-")
	startPort, err := strconv.Atoi(parts[0])
	if err != nil {
		startPort = 1
	}
	endPort, err := strconv.Atoi(parts[1])
	if err != nil {
		endPort = 65535
	}

	var portList []int
	for port := startPort; port <= endPort; port++ {
		portList = append(portList, port)
	}
	return portList
}

func readServicesFile(path string) (map[int]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	services := make(map[int]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		serviceName := parts[0]
		portProto := strings.Split(parts[1], "/")
		if len(portProto) != 2 {
			continue
		}
		port, err := strconv.Atoi(portProto[0])
		if err != nil {
			continue
		}
		services[port] = serviceName
	}
	return services, scanner.Err()
}
