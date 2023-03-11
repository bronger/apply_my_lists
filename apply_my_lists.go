package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	pkg_errors "github.com/pkg/errors"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slog"
)

func init() {
	opts := slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == "time" {
				return slog.String(a.Key, a.Value.Time().Format("2006/01/02 15:04:05"))
			}
			return a
		},
	}
	textHandler := opts.NewTextHandler(os.Stderr)
	logger := slog.New(textHandler)
	slog.SetDefault(logger)
}

func exitOnError(err error, msg string) {
	if err != nil {
		slog.Error(msg, err)
		fmt.Printf("%v: %+v\n", msg, err)
	}
	os.Exit(1)
}

var domains = make(map[string][]string)

const domFilepath = "/tmp/hosts-blacklist"

func getTLD(domain string) string {
	components := strings.Split(domain, ".")
	length := len(components)
	return components[length-2] + "." + components[length-1]
}

func readDomains() error {
	slog.Info("Reading domains")
	domainsRaw := make(map[string]map[string]bool)
	f, err := os.Open(domFilepath)
	if err != nil {
		return pkg_errors.Errorf("Could not open domains file “%v”", domFilepath)
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var numberDomains int
	for scanner.Scan() {
		domain := "." + scanner.Text()
		numberDomains++
		tld := getTLD(domain)
		if _, exists := domainsRaw[tld]; !exists {
			domainsRaw[tld] = make(map[string]bool)
		}
		domainsRaw[tld][domain] = true
	}
	if err := scanner.Err(); err != nil {
		return pkg_errors.Wrap(err, fmt.Sprintf("Error while reading domains file “%v”", domFilepath))
	}
	for tld, subdomains := range domainsRaw {
		domains[tld] = maps.Keys(subdomains)
	}
	slog.Info("Finished reading domains", "number", numberDomains, "numberTLDs", len(domains))
	return nil
}

func checkDomain(subdomains []string, domain string, minimal chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, otherDomain := range subdomains {
		if domain != otherDomain && strings.HasSuffix(domain, otherDomain) {
			slog.Debug("Domain is shadowed", "domain", domain, "by", otherDomain)
			return
		}
	}
	minimal <- domain
}

func main() {
	if err := readDomains(); err != nil {
		exitOnError(err, "Could not read domains")
	}
	minimal := make(chan string)
	var wg sync.WaitGroup
	for tld := range domains {
		subdomains := domains[tld]
		for _, domain := range subdomains {
			wg.Add(1)
			go checkDomain(subdomains, domain, minimal, &wg)
		}
	}
	minimalSet := make(map[string]bool)
	var wgCollect sync.WaitGroup
	wgCollect.Add(1)
	go func() {
		defer wgCollect.Done()
		for domain := range minimal {
			minimalSet[domain[1:]] = true
		}
	}()
	wg.Wait()
	close(minimal)
	wgCollect.Wait()
	slog.Info("Minimal domains collected", "number", len(minimalSet))
	slog.Info("Finished")
}
