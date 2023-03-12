/*
	apply_my_lists creates input for the --servers-file option of dnsmasq.

It takes a list of malicious domains and makes it useful for dnsmasq.  It
applies black and whitelists along the way.  See README.rst for further
details.
*/
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	pkg_errors "github.com/pkg/errors"
	"go4.org/must"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
)

// init sets up logging.
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

// exitOnError aborts the program if a non-nil error value is passed.  It is
// supposed to be called in “init”, “main”, and Go routines, where it is
// impossible to escalate an error to a caller.
func exitOnError(err error, msg string) {
	if err != nil {
		slog.Error(msg, err)
		fmt.Printf("%v: %+v\n", msg, err)
		os.Exit(1)
	}
}

const domFilepath = "/etc/hosts-blacklist"

// readList reads the black or whitelist and returns its domain names.  See
// README.rst for the file format.  As with the rest of this programm, all
// domain names are prepended with a “.”, so that subdomain matching can be
// realised with a simple HasSuffix.
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
		entries = append(entries, "."+line)
	}
	if err := scanner.Err(); err != nil {
		return nil, pkg_errors.Wrap(err, fmt.Sprintf("Error while reading list file “%v”", path))
	}
	return
}

// getTLD extracts the top level domain from the given domain.  It panics if
// there is none to extract.
func getTLD(domain string) string {
	components := strings.Split(domain, ".")
	length := len(components)
	return components[length-2] + "." + components[length-1]
}

var hostRegexp = regexp.MustCompile(`0\.0\.0\.0 (.*)`)

// readDomains reads the large blacklist file and returns a mapping from top
// level domains to a set of domains that belong to this TLD.  (This may
// include the TLD itself.)  A “set” is a mapping to bool which is never false.
// All domain names are prepended with a “.”, so that subdomain matching can be
// realised with a simple HasSuffix.
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
		line := scanner.Text()
		domain := "." + hostRegexp.FindStringSubmatch(line)[1]
		if domain == "." {
			return nil, pkg_errors.Errorf("Invalid line in domains file: “%s”", line)
		}
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

// cookDomains simplfies the nested maps into nested slices.  This makes some
// operations faster.   It is called after the maps have served their purpose
// to ensure fast lookups and ensure uniqueness.  The domain slices are sorted by
// length in order to have a reliable breaking condition when looking for
// subdomains.  (A domain can never be longer than its subdomain.)
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

// checkDomain sends domains which are not subdomains of any other blacklisted
// domain to the “minimal” channel.  This channel is the result of the program.
// The loop here is the hot loop of the program which has to be as performant
// as possible.  For instance, we make use of the fact that the items in the
// subdomains slice become longer and longer.
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

// applyBlacklist adds the entries in the personal blacklist to the set of
// domains.
func applyBlacklist(path string, domainsRaw map[string]map[string]bool) error {
	blackDomains, err := readList(path)
	if err != nil {
		return fmt.Errorf("Error while reading blacklist: %w", err)
	}
	exitOnError(err, "Error while reading blacklist")
	for _, domain := range blackDomains {
		tld := getTLD(domain)
		if _, exists := domainsRaw[tld]; !exists {
			domainsRaw[tld] = make(map[string]bool)
		}
		domainsRaw[tld][domain] = true
	}
	return nil
}

var tldLocks = make(map[string]*sync.RWMutex)
var tldLocksLock sync.RWMutex

// whitelist holds all domains that need to be whitelisted explicitly because
// they are subsomains of blacklisted domains.
var whitelist = make(map[string]bool)
var whitelistLock sync.RWMutex

// applyWhitelistEntry does the parallisable work for applyWhitelist.  It
// removed the domain gives as “entry” and all of its subdomains from the
// blacklist.  Moreover, it adds domains to “whitelist” if they are subdomains
// of blacklisted domains.
func applyWhitelistEntry(entry string, domainsRaw map[string]map[string]bool, wg *sync.WaitGroup) {
	defer wg.Done()
	tld := getTLD(entry)
	tldLocksLock.Lock()
	lock, exists := tldLocks[tld]
	if !exists {
		lock = new(sync.RWMutex)
		tldLocks[tld] = lock
	}
	tldLocksLock.Unlock()
	lock.RLock()
	subdomains := domainsRaw[tld]
	lock.RUnlock()
	var needsOnWhitelist bool
	for subdomain := range subdomains {
		if strings.HasSuffix(subdomain, entry) {
			lock.Lock()
			delete(domainsRaw[tld], subdomain)
			lock.Unlock()
			slog.Debug("Remove domain because of whitelisting", "entry", entry, "domain", subdomain)
		} else if !needsOnWhitelist && strings.HasSuffix(entry, subdomain) {
			needsOnWhitelist = true
			slog.Debug("Add domain to explicit whitelisting", "entry", entry, "shadower", subdomain)
		}
	}
	if needsOnWhitelist {
		whitelistLock.Lock()
		whitelist[entry] = true
		whitelistLock.Unlock()
	}
}

// applyWhitelist removes domains of the personal whitelist (and their
// subdomains) from the set of domains.  Moreover, it adds whitelisted domains
// that are subdomains to other blacklisted domains to the “whitelist” map so
// that they can be whitelisted explicitly in the output.
func applyWhitelist(path string, domainsRaw map[string]map[string]bool) error {
	whiteDomains, err := readList(path)
	if err != nil {
		return fmt.Errorf("Error while reading whitelist: %w", err)
	}
	exitOnError(err, "Error while reading whitelist")
	var wg sync.WaitGroup
	for _, domain := range whiteDomains {
		wg.Add(1)
		go applyWhitelistEntry(domain, domainsRaw, &wg)
	}
	wg.Wait()
	return nil
}

func main() {
	var domains [][]string
	if domainsRaw, err := readDomains(); err != nil {
		exitOnError(err, "Could not read domains")
	} else {
		applyBlacklist("/tmp/my_blacklist", domainsRaw)
		applyWhitelist("/tmp/my_whitelist", domainsRaw)
		domains = cookDomains(domainsRaw)
	}
	minimal := make(chan string)
	var wgCollect sync.WaitGroup
	var numberMinimal int
	wgCollect.Add(1)
	go func() {
		defer wgCollect.Done()
		f, err := os.Create("/etc/servers-blacklist")
		exitOnError(err, "Error creating file “servers-blacklist”")
		defer must.Close(f)
		w := bufio.NewWriter(f)
		defer must.Do(w.Flush)
		for domain := range minimal {
			numberMinimal++
			_, err := w.WriteString(fmt.Sprintf("server=/%s/\n", domain[1:]))
			exitOnError(err, "Error writing to file “servers-blacklist”")
		}
		for domain := range whitelist {
			_, err := w.WriteString(fmt.Sprintf("server=/%s/#\n", domain[1:]))
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
