package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	pkg_errors "github.com/pkg/errors"
	"golang.org/x/exp/slog"
)

func exitOnError(err error, msg string) {
	if err != nil {
		slog.Error(msg, err)
		fmt.Printf("%v: %+v\n", msg, err)
	}
	os.Exit(1)
}

var domains []map[string]bool

const domFilepath = "/tmp/hosts-blacklist"

func readDomains() error {
	domainsMap := make(map[string]map[string]bool)
	f, err := os.Open(domFilepath)
	if err != nil {
		return pkg_errors.Errorf("Could not open domains file “%v”", domFilepath)
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		domain := scanner.Text()
		components := strings.Split(domain, ".")
		length := len(components)
		tld := components[length-2] + "." + components[length-1]
		if _, exists := domainsMap[tld]; !exists {
			domainsMap[tld] = make(map[string]bool)
		}
		domainsMap[tld][domain] = true
	}
	for _, subdomains := range domainsMap {
		domains = append(domains, subdomains)
	}
	return nil
}

func checkDomain(subdomains map[string]bool, domain string, minimal chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for otherDomain := range subdomains {
		if domain != otherDomain && strings.HasSuffix(domain, otherDomain) {
			break
		}
	}
	minimal <- domain
}

func checkSDs(subdomains map[string]bool, minimal chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range subdomains {
		wg.Add(1)
		go checkDomain(subdomains, domain, minimal, wg)
	}
}

func main() {
	slog.Info("Reading domains")
	if err := readDomains(); err != nil {
		exitOnError(err, "Could not read domains")
	}
	slog.Info("End reading domains", "numberTLDs", len(domains))
	minimal := make(chan string)
	var wg sync.WaitGroup
	for _, subdomains := range domains {
		wg.Add(1)
		go checkSDs(subdomains, minimal, &wg)
	}
	minimalSet := make(map[string]bool)
	var wgCollect sync.WaitGroup
	wgCollect.Add(1)
	go func() {
		defer wgCollect.Done()
		for domain := range minimal {
			minimalSet[domain] = true
		}
	}()
	wg.Wait()
	close(minimal)
	wgCollect.Wait()
	fmt.Println(len(domains), len(minimalSet))
	slog.Info("Finished")
}
