package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type NetworkPolicy struct {
	AllowDomains []string `yaml:"allow_domains"`
	DenyIps      []string `yaml:"deny_ips"`
	AllowAll     bool     `yaml:"allow_all"`
	// computed
	denyIpSet    map[string]struct{}
	exactDomains map[string]struct{}
	regexDomains []*regexp.Regexp
}

type Policy struct {
	ToolsWhitelist   []string       `yaml:"tools_whitelist"`
	TimeLimitSeconds uint64         `yaml:"time_limit_seconds"`
	CpuLimitPercent  uint8          `yaml:"cpu_limit_percent"`
	RamLimitMb       uint64         `yaml:"ram_limit_mb"`
	Network          NetworkPolicy  `yaml:"network"`
	// computed
	toolsSet         map[string]struct{}
}

func LoadPolicy(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var p Policy
	err = yaml.Unmarshal(data, &p)
	if err != nil {
		return nil, err
	}
	// Validate
	if p.CpuLimitPercent > 100 {
		return nil, fmt.Errorf("cpu_limit_percent must be between 0 and 100")
	}
	// Init tools set
	p.toolsSet = make(map[string]struct{})
	for _, t := range p.ToolsWhitelist {
		p.toolsSet[t] = struct{}{}
	}
	// Init network
	p.Network.denyIpSet = make(map[string]struct{})
	for _, ips := range p.Network.DenyIps {
		ip := net.ParseIP(ips)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", ips)
		}
		p.Network.denyIpSet[ip.String()] = struct{}{}
	}
	p.Network.exactDomains = make(map[string]struct{})
	p.Network.regexDomains = make([]*regexp.Regexp, 0)
	for _, d := range p.Network.AllowDomains {
		re, err := regexp.Compile(d)
		if err != nil {
			p.Network.exactDomains[d] = struct{}{}
		} else {
			p.Network.regexDomains = append(p.Network.regexDomains, re)
		}
	}
	return &p, nil
}

func (p *Policy) IsToolAllowed(tool string) bool {
	_, ok := p.toolsSet[tool]
	return ok
}

func (p *Policy) CpuLimit() uint8 {
	return p.CpuLimitPercent
}

func (p *Policy) RamLimit() uint64 {
	return p.RamLimitMb
}

func (p *Policy) IsNetworkAllowed(domain *string, ip *net.IP) bool {
	np := &p.Network
	if np.AllowAll {
		if ip != nil {
			if _, ok := np.denyIpSet[ip.String()]; ok {
				return false
			}
		}
		return true
	}
	// Check denies first
	if ip != nil {
		if _, ok := np.denyIpSet[ip.String()]; ok {
			return false
		}
	}
	// Check allows
	if domain != nil {
		dom := *domain
		if _, ok := np.exactDomains[dom]; ok {
			return true
		}
		for _, re := range np.regexDomains {
			if re.MatchString(dom) {
				return true
			}
		}
	}
	return false
}

func usage() {
	fmt.Println(`policy-engine - Central Policy Validator for HackerOS Security Mode

Usage: policy-engine <command> [options]

Commands:
  validate <file>                    Validate a policy YAML file
  check-tool <policy> <tool>         Check if a tool is allowed
  check-network <policy> [--domain <domain>] [--ip <ip>]  Check network access for domain/IP
  get-limits <policy>                Get resource limits from policy
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	switch cmd {
	case "validate":
		if len(os.Args) != 3 {
			usage()
			os.Exit(1)
		}
		file := os.Args[2]
		_, err := LoadPolicy(file)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Policy is valid.")
	case "check-tool":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		policyFile := os.Args[2]
		tool := os.Args[3]
		p, err := LoadPolicy(policyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if p.IsToolAllowed(tool) {
			fmt.Printf("Tool '%s' is allowed.\n", tool)
		} else {
			fmt.Printf("Tool '%s' is NOT allowed.\n", tool)
			os.Exit(1)
		}
	case "check-network":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		policyFile := os.Args[2]
		fs := flag.NewFlagSet("check-network", flag.ExitOnError)
		domain := fs.String("domain", "", "Domain to check")
		ipStr := fs.String("ip", "", "IP to check")
		err := fs.Parse(os.Args[3:])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		p, err := LoadPolicy(policyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		var ip *net.IP
		if *ipStr != "" {
			parsed := net.ParseIP(*ipStr)
			if parsed == nil {
				fmt.Printf("Invalid IP: %s\n", *ipStr)
				os.Exit(1)
			}
			ip = &parsed
		}
		var domPtr *string
		if *domain != "" {
			domPtr = domain
		}
		if p.IsNetworkAllowed(domPtr, ip) {
			fmt.Println("Network access is allowed.")
		} else {
			fmt.Println("Network access is NOT allowed.")
			os.Exit(1)
		}
	case "get-limits":
		if len(os.Args) != 3 {
			usage()
			os.Exit(1)
		}
		policyFile := os.Args[2]
		p, err := LoadPolicy(policyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("Time limit: %d seconds\n", p.TimeLimitSeconds)
		fmt.Printf("CPU limit: %d%%\n", p.CpuLimitPercent)
		fmt.Printf("RAM limit: %d MB\n", p.RamLimitMb)
	default:
		usage()
		os.Exit(1)
	}
}
