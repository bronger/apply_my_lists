package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	pkg_errors "github.com/pkg/errors"
	"go4.org/must"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
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
		os.Exit(1)
	}
}

const domFilepath = "/tmp/hosts-blacklist"

func readList(path string) (entries []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("Could not find file; assumed empty", "path", path)
			return nil, nil
		}
		return nil, pkg_errors.Errorf("Could not open list file “%v”", path)
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, pkg_errors.Wrap(err, fmt.Sprintf("Error while reading list file “%v”", path))
	}
	return
}

func getTLD(domain string) string {
	components := strings.Split(domain, ".")
	length := len(components)
	return components[length-2] + "." + components[length-1]
}

func readDomains() (domainsRaw map[string]map[string]bool, err error) {
	domainsRaw = make(map[string]map[string]bool)
	slog.Info("Reading domains")
	f, err := os.Open(domFilepath)
	if err != nil {
		return nil, pkg_errors.Errorf("Could not open domains file “%v”", domFilepath)
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
		return nil, pkg_errors.Wrap(err, fmt.Sprintf("Error while reading domains file “%v”", domFilepath))
	}
	slog.Info("Finished reading domains", "number", numberDomains, "numberTLDs", len(domainsRaw))
	return
}

func cookDomains(domainsRaw map[string]map[string]bool) (domains [][]string) {
	for _, subdomains := range domainsRaw {
		cookedSDs := maps.Keys(subdomains)
		slices.SortFunc(cookedSDs, func(a, b string) bool {
			return len(a) < len(b)
		})
		domains = append(domains, cookedSDs)
	}
	return
}

func checkDomain(subdomains []string, domain string, minimal chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	lenDomain := len(domain)
	for _, otherDomain := range subdomains {
		if len(otherDomain) > lenDomain {
			break
		}
		if strings.HasSuffix(domain, otherDomain) && domain != otherDomain {
			return
		}
	}
	minimal <- domain
}

func applyBlacklist(path string, domainsRaw map[string]map[string]bool) error {
	blackDomains, err := readList("my_blacklist")
	if err != nil {
		return fmt.Errorf("Error while reading blacklist: %w", err)
	}
	exitOnError(err, "Error while reading blacklist")
	for _, domain := range blackDomains {
		tld := getTLD(domain)
		domainsRaw[tld][domain] = true
	}
	return nil
}

func main() {
	var domains [][]string
	if domainsRaw, err := readDomains(); err != nil {
		exitOnError(err, "Could not read domains")
	} else {
		applyBlacklist("my_blacklist", domainsRaw)
		domains = cookDomains(domainsRaw)
	}
	minimal := make(chan string)
	var wgCollect sync.WaitGroup
	var numberMinimal int
	wgCollect.Add(1)
	go func() {
		defer wgCollect.Done()
		f, err := os.Create("servers-blacklist")
		exitOnError(err, "Error creating file “servers-blacklist”")
		defer must.Close(f)
		w := bufio.NewWriter(f)
		defer must.Do(w.Flush)
		for domain := range minimal {
			numberMinimal++
			_, err := w.WriteString(fmt.Sprintf("%s\n", domain[1:]))
			exitOnError(err, "Error writing to file “servers-blacklist”")
		}
	}()
	var wg sync.WaitGroup
	for _, subdomains := range domains {
		for _, domain := range subdomains {
			wg.Add(1)
			go checkDomain(subdomains, domain, minimal, &wg)
		}
	}
	slog.Info("Created all workers")
	wg.Wait()
	close(minimal)
	wgCollect.Wait()
	slog.Info("Minimal domains collected", "number", numberMinimal)
	slog.Info("Finished")
}
