package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var blacklistSources = []string{
	"http://sysctl.org/cameleon/hosts",
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"http://mirror1.malwaredomains.com/files/justdomains",
	"https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
	"https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
	"https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
	"https://www.stephanpringle.com/hosts/crackle.txt",
	"http://winhelp2002.mvps.org/hosts.txt",
	"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
	"https://adaway.org/hosts.txt",
	"https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt",
	"https://raw.githubusercontent.com/w13d/adblockListABP-PiHole/master/list.txt",
	"https://raw.githubusercontent.com/EnergizedProtection/block/master/assets/sources/filter/abpindo.txt",
}

var blacklist = []string{
	"5fd74.v.fwmrm.net",
	"tracking.miui.com",
	"connect.rom.miui.com",
	"adv.sec.miui.com",
	"sdkconfig.ad.xiaomi.com",
	"data.mistat.xiaomi.com",
	"api.ad.xiaomi.com",
	"asp.animelab.com",
	"sdk.adincube.com",
	"bl-1.com",
	"eqx148.switchmedia.asia",
}

var whitelist = []string{
	"bit.ly",
	"code.jquery.com",
	"imgur.com",
}

const fileName = "hosts.txt"

var hostEntries = []string{}
var seenHostEntries = map[string]bool{}

func fetchHostFile(urls <-chan string, results chan<- []string) {
	for url := range urls {
		hosts := []string{}
		resp, err := http.Get(url)
		if err != nil {
			log.Fatal(err)
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			results <- []string{}
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			hosts = append(hosts, scanner.Text())
		}
		results <- hosts
	}
}

func isValidHostEntry(hostName string) bool {
	hostName = strings.TrimSpace(hostName)

	if len(hostName) == 0 {
		return false
	}

	if hostName[0] == '#' || hostName[0] == '!' {
		return false
	}

	if strings.Contains(hostName, ":") {
		return false
	}

	return true
}

func isInWhitelist(hostName string) bool {
	for _, whiteHost := range whitelist {
		if whiteHost == hostName {
			return true
		}
	}

	return false
}

func cleanHostName(hostName string) string {
	hostName = strings.ReplaceAll(hostName, "\t", " ")
	hostName = strings.ReplaceAll(hostName, "  ", " ")
	hostName = strings.ReplaceAll(hostName, "127.0.0.1 ", "")
	hostName = strings.ReplaceAll(hostName, "0.0.0.0 ", "")
	hostName = strings.Split(hostName, " ")[0]
	return hostName
}

func addToHostEntries(hostName string) {
	if !seenHostEntries[hostName] {
		hostEntries = append(hostEntries, hostName)
		seenHostEntries[hostName] = true
	}
}

func writeHostEntriesToFile(fileName string) {
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for _, hostEntry := range hostEntries {
		fmt.Fprintln(w, "0.0.0.0", hostEntry)
	}
}

func validateAndAddtoHostEntries(hosts []string) {
	for _, hostname := range hosts {
		if !isValidHostEntry(hostname) {
			continue
		}
		cleanHostName := cleanHostName(hostname)

		if !isInWhitelist(cleanHostName) {
			addToHostEntries(cleanHostName)
		}
	}
}

func main() {
	urls := make(chan string, len(blacklistSources))
	results := make(chan []string, len(blacklistSources))
	numWorkers := 5

	for w := 0; w < numWorkers; w++ {
		go fetchHostFile(urls, results)
	}

	for _, url := range blacklistSources {
		urls <- url
	}

	close(urls)

	for r := 0; r < len(blacklistSources); r++ {
		validateAndAddtoHostEntries(<-results)
	}

	validateAndAddtoHostEntries(blacklist)
	writeHostEntriesToFile(fileName)
}
