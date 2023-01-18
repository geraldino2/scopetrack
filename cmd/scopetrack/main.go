package main

import (
	"os"
	"os/signal"
	"syscall"
	"errors"
	"fmt"
	"bufio"
	"time"
	"context"
	"io"
	"io/ioutil"
	"encoding/json"
	"regexp"
	"net"

	"github.com/geraldino2/scopetrack/internal/config"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"github.com/corpix/uarand"
	"github.com/schollz/progressbar/v3"
	"github.com/k0kubun/go-ansi"
	"github.com/asaskevich/govalidator"
	"github.com/domainr/whois"
	"github.com/likexian/whois-parser"
)

type Template struct {
	Identifier            string   `json:"Identifier"`
	StatusCodeDNS         []string `json:"StatusCodeDNS"`
	RecordType            string   `json:"RecordType"`
	RecordFingerprint     []string `json:"RecordFingerprint"`
	AdditionalFingerprint []string `json:"AdditionalFingerprint"`
	Status                string   `json:"Status"`
}

type Result struct {
	FQDN                  string `json:"FQDN"`
	StatusCodeDNS         string `json:"StatusCodeDNS"`
	AdditionalInfo        string `json:"AdditionalInfo"`
	Source                string `json:"Source"`
	Status                string `json:"Status"`
}

var (
	options *config.Options
	noerrorTemplatesA = []Template{}
	noerrorTemplatesCNAME = []Template{}
	noerrorTemplatesNS = []Template{}
	nxdomainTemplates = []Template{}
	servfailTemplates = []Template{}
	bar = progressbar.NewOptions(
		0,
		progressbar.OptionSetWriter(ansi.NewAnsiStderr()),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetWidth(15),
		progressbar.OptionShowCount(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetDescription("[[cyan]STATS[reset]] Querying..."),
		progressbar.OptionShowIts(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
)

func LoadTemplates() {
	files, err := ioutil.ReadDir(options.TemplatePath)
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	for _, file := range files {
		if !file.IsDir() {
			data, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", options.TemplatePath, file.Name()))
			if err != nil {
				gologger.Warning().Str("template", fmt.Sprintf("%s/%s", options.TemplatePath, file.Name())).Msgf("%s\n",err)
				continue
			}

			buffer := []Template{}
			json.Unmarshal([]byte(data), &buffer)

			for i := 0; i < len(buffer); i++ {
				if buffer[i].StatusCodeDNS[0] == "NOERROR" {
					if buffer[i].RecordType == "A" {
						noerrorTemplatesA = append(noerrorTemplatesA, buffer[i])
					}
					if buffer[i].RecordType == "CNAME" {
						noerrorTemplatesCNAME = append(noerrorTemplatesCNAME, buffer[i])
					}
					if buffer[i].RecordType == "NS" {
						noerrorTemplatesNS = append(noerrorTemplatesNS, buffer[i])
					}
				}

				if buffer[i].StatusCodeDNS[0] == "NXDOMAIN" {
					nxdomainTemplates = append(nxdomainTemplates, buffer[i])
				}

				if buffer[i].StatusCodeDNS[0] == "SERVFAIL" || buffer[i].StatusCodeDNS[0] == "REFUSED" {
					servfailTemplates = append(servfailTemplates, buffer[i])
				}
			}
		}
	}
}

func main() {
	chansig := make(chan os.Signal, 1)
	signal.Notify(chansig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<- chansig
		gologger.Info().Msgf("exiting...")
		os.Exit(1)
	}()

	options = config.ParseOptions(bar)

	LoadTemplates()

	chanfqdn := make(chan string)
	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			_ = options.FileFqdn.Set(scanner.Text())
		}
	}

	if options.Stats {
		bar.ChangeMax(len(options.FileFqdn))
	} else {
		bar.Finish()
	}

	go func() {
		defer close(chanfqdn)
		if options.FileFqdn != nil {
			for _, item := range options.FileFqdn {
				chanfqdn <- item
			}
		}
	}()

	wg := sizedwaitgroup.New(options.BulkSize)
	wgoutput := sizedwaitgroup.New(1)
	wgoutput.Add()
	outputchan := make(chan Result)
	go output(&wgoutput, outputchan)

	limiter := ratelimit.New(context.Background(), uint(options.RequestsPerSec)*3, time.Duration(3*time.Second))//rate limit amortized to bursts within 3 seconds

	retries := options.RetriesDNS
	dnsClient, _ := retryabledns.New(options.FileResolver, retries)

	for item := range chanfqdn {
		wg.Add()
		go query(&wg, limiter, item, dnsClient, outputchan, 0)
	}

	wg.Wait()
	close(outputchan)
	wgoutput.Wait()
}


func query(wg *sizedwaitgroup.SizedWaitGroup, limiter *ratelimit.Limiter, fqdn string, dnsClient *retryabledns.Client, outputchan chan Result, currIt int) {
	gologger.Debug().Str("fqdn", fqdn).Msgf("query")
	if currIt == 0 {
		defer bar.Add(1)
	}
	defer wg.Done()

	if !govalidator.IsDNSName(fqdn) {
		return
	}

	gologger.Debug().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("DNS request\n")
	dnsResponses, err := dnsClient.Query(fqdn, dns.TypeA)
	if err != nil {
		gologger.Warning().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("%s\n", err)
		retryQuery(wg, limiter, fqdn, dnsClient, outputchan, 1)
		return
	}

	if dnsResponses.StatusCode == "NOERROR" {
		if options.NoHTTP {
			return
		}

		if len(dnsResponses.A) == 0 && len(dnsResponses.CNAME) == 0 {
			return
		}

		publicAddress := false
		for _, record := range dnsResponses.A {
			if net.ParseIP(record) != nil && !net.ParseIP(record).IsPrivate() {
				publicAddress = true
			}
		}

		if !publicAddress {
			return
		}

		var dnsRecords = [][]string{dnsResponses.A, dnsResponses.CNAME}

		gologger.Debug().Str("fqdn", fqdn).Str("question", "NS").Str("flags", "").Msgf("DNS request\n")
		dnsResponsesNS, dnsErrNS := dnsClient.Query(fqdn, dns.TypeNS)
		if dnsErrNS != nil {
			gologger.Warning().Str("fqdn", fqdn).Str("question", "NS").Str("flags", "").Msgf("%s\n", dnsErrNS)
			retryQuery(wg, limiter, fqdn, dnsClient, outputchan, 1)
			return
		} else {
			dnsRecords = append(dnsRecords, dnsResponsesNS.NS)
		}

		var httpProbe bool = false

		for _, templateGroup := range [][]Template{noerrorTemplatesA, noerrorTemplatesCNAME, noerrorTemplatesNS} {
			for _, template := range templateGroup {
				for _, recordFingerprint := range template.RecordFingerprint {
					for _, recordGroup := range dnsRecords {
						for _, record := range recordGroup {
							match, _ := regexp.MatchString(recordFingerprint, record)
							httpProbe = httpProbe || match
						}
					}
				}
			}
		}

		var httpTxt string = ""
		var httpErr error = nil

		gologger.Debug().Str("fqdn", fqdn).Msgf("HTTP request\n")
		if httpProbe {
			httpTxt, httpErr = download(limiter, fmt.Sprintf("http://%s", fqdn))
		}

		if httpErr != nil {
			gologger.Warning().Str("url", fmt.Sprintf("http://%s", fqdn)).Msgf("%s\n", httpErr)
			outputchan <- Result{
				FQDN: fqdn,
				StatusCodeDNS: "",
				AdditionalInfo: "",
				Source: "",
				Status: "HTTP_ERROR",
			}
		} else {
			for _, templateGroup := range [][]Template{noerrorTemplatesA, noerrorTemplatesCNAME, noerrorTemplatesNS} {
				for _, template := range templateGroup {
					for _, recordFingerprint := range template.RecordFingerprint {
						probeTemplateMatch(template, recordFingerprint, dnsResponses.A, httpTxt, fqdn, outputchan)

						probeTemplateMatch(template, recordFingerprint, dnsResponses.CNAME, httpTxt, fqdn, outputchan)

						if dnsErrNS == nil {
							probeTemplateMatch(template, recordFingerprint, dnsResponses.NS, httpTxt, fqdn, outputchan)
						}
					}
				}
			}
		}
	}

	if dnsResponses.StatusCode == "NXDOMAIN" {
		gologger.Debug().Str("fqdn", fqdn).Str("question", "CNAME").Str("flags", "").Msgf("DNS request\n")
		dnsResponses, err = dnsClient.Query(fqdn, dns.TypeCNAME)
		if err != nil {
			gologger.Warning().Str("fqdn", fqdn).Str("question", "CNAME").Str("flags", "").Msgf("%s\n", err)
			
		}

		if len(dnsResponses.CNAME) > 0 {
			var templateMatch = false
			for _, template := range nxdomainTemplates {
				for _, recordFingerprintCNAME := range template.RecordFingerprint {
					match, _ := regexp.MatchString(recordFingerprintCNAME, dnsResponses.CNAME[0])
					if match {
						templateMatch = true
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: "NXDOMAIN",
							AdditionalInfo: "",
							Source: template.Identifier,
							Status: template.Status,
						}
						break
					}
				}
			}

			fqdnApex, parseErr1 := extractApex(fqdn)
			cnameApex, parseErr2 := extractApex(dnsResponses.CNAME[0])
			if parseErr1 != nil || parseErr2 != nil {
				gologger.Warning().Str("fqdn", fqdn).Msgf("%s\n", err)
				return
			}

			if !templateMatch && fqdnApex != cnameApex {
				available, err := isDomainAvailable(cnameApex)
				if available {
					if err == nil {
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: "NXDOMAIN",
							AdditionalInfo: dnsResponses.CNAME[0],
							Source: "NXDOMAIN with available CNAME apex",
							Status: "CONFIRMED_TAKEOVER",
						}
					} else {
						gologger.Warning().Str("fqdn", cnameApex).Msgf("%s\n", err)
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: "NXDOMAIN",
							AdditionalInfo: dnsResponses.CNAME[0],
							Source: "NXDOMAIN with CNAME",
							Status: "POTENTIAL_TAKEOVER",
						}
					}
				}
			}
		} else {
			apex, parseErr := extractApex(fqdn)
			if parseErr != nil {
				gologger.Warning().Str("fqdn", fqdn).Msgf("%s\n", err)
				return
			}

			apexStatus, err := queryStatus(apex, dnsClient)
			if err != nil {
				gologger.Warning().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("%s\n", err)
				retryQuery(wg, limiter, fqdn, dnsClient, outputchan, 1)
				return
			}

			if apexStatus == "NXDOMAIN" {
				available, err := isDomainAvailable(apex)
				if available {
					if err == nil {
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: "NXDOMAIN",
							AdditionalInfo: apex,
							Source: "Available apex",
							Status: "CONFIRMED_TAKEOVER",
						}
					} else {
						gologger.Warning().Str("fqdn", apex).Msgf("%s\n", err)
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: "NXDOMAIN",
							AdditionalInfo: apex,
							Source: "Potential available apex (NXDOMAIN)",
							Status: "POTENTIAL_TAKEOVER",
						}
					}
				}
			}
		}
	}

	if dnsResponses.StatusCode == "SERVFAIL" || dnsResponses.StatusCode == "REFUSED" {
		gologger.Debug().Str("fqdn", fqdn).Str("question", "NS").Str("flags", "+trace").Msgf("DNS request\n")
		traceResponse, err := dnsClient.Trace(fqdn, dns.TypeNS, options.TraceDepth)
		if err != nil {
			gologger.Warning().Str("fqdn", fqdn).Str("question", "NS").Str("flags", "+trace").Msgf("%s\n", err)
			retryQuery(wg, limiter, fqdn, dnsClient, outputchan, 1)
			return
		}

		ns_records := []string{}
		for i := 0; i < len(traceResponse.DNSData); i++ {
			if len(traceResponse.DNSData[i].NS) > 0 {
				ns_records = traceResponse.DNSData[i].NS
			}
		}

		for _, template := range servfailTemplates {
			var skipTemplate bool = false
			for _, recordFingerprintNS := range template.RecordFingerprint {
				for _, dnsTraceRecordNS := range ns_records {
					match, _ := regexp.MatchString(recordFingerprintNS, dnsTraceRecordNS)
					if match {
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: dnsResponses.StatusCode,
							AdditionalInfo: dnsTraceRecordNS,
							Source: template.Identifier,
							Status: template.Status,
						}
						skipTemplate = true
						break
					}
				}
				if skipTemplate {
					break
				}
			}
		}

		for _, dnsTraceRecordNS := range ns_records {
			apex, err := extractApex(dnsTraceRecordNS)
			if err != nil {
				gologger.Warning().Str("fqdn", fqdn).Msgf("%s\n", err)
				return
			}

			apexStatus, err := queryStatus(apex, dnsClient)
			if err != nil {
				gologger.Warning().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("%s\n", err)
				wg.Add()
				return
			}

			if apexStatus == "NXDOMAIN" {
				available, err := isDomainAvailable(apex)
				if available {
					if err == nil {
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: dnsResponses.StatusCode,
							AdditionalInfo: dnsTraceRecordNS,
							Source: "Available NS apex",
							Status: "CONFIRMED_TAKEOVER",
						}
					} else {
						gologger.Warning().Str("fqdn", apex).Msgf("%s\n", err)
						outputchan <- Result{
							FQDN: fqdn,
							StatusCodeDNS: dnsResponses.StatusCode,
							AdditionalInfo: dnsTraceRecordNS,
							Source: "Potential available NS apex (NXDOMAIN)",
							Status: "POTENTIAL_TAKEOVER",
						}
					}
				}
			}
		}
	}
}

func retryQuery(wg *sizedwaitgroup.SizedWaitGroup, limiter *ratelimit.Limiter, fqdn string, dnsClient *retryabledns.Client, outputchan chan Result, currIt int) {
	if currIt > options.RetriesTarget {
		outputchan <- Result{
			FQDN: fqdn,
			StatusCodeDNS: "",
			AdditionalInfo: "",
			Source: "",
			Status: "DNS_ERROR",
		}
		return
	}

	time.Sleep(time.Duration(options.TargetRetryDelay) * time.Second)

	wg.Add()
	query(wg, limiter, fqdn, dnsClient, outputchan, currIt + 1)
}

func queryStatus(fqdn string, dnsClient *retryabledns.Client) (string, error) {
	gologger.Debug().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("DNS request\n")
	dnsResponses, err := dnsClient.Query(fqdn, dns.TypeA)
	if err != nil {
		gologger.Warning().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("%s\n", err)
		return "", err
	}
	return dnsResponses.StatusCode, nil
}

func output(wgoutput *sizedwaitgroup.SizedWaitGroup, outputchan chan Result) {
	defer wgoutput.Done()

	var f *os.File
	if options.Output != "" {
		var err error
		f, err = os.Create(options.Output)
		if err != nil {
			gologger.Fatal().Msgf("Could not create output file '%s': %s\n", options.Output, err)
		}
		defer f.Close()
	}

	for o := range outputchan {
		outputItems(f, o)
	}
}

func outputItems(f *os.File, items ...Result) {
	for _, item := range items {
		data, _ := json.Marshal(&item)
		if item.Status == "DNS_ERROR" {
			gologger.Info().Msgf("skipping %s due to DNS errors", item.FQDN)
		} else if item.Status == "HTTP_ERROR" {
			gologger.Info().Msgf("skipping %s due to HTTP errors", item.FQDN)
		} else {
			gologger.Silent().Msgf("%s\n", string(data))
		}

		if f != nil {
			_, _ = f.WriteString(string(data) + "\n")
		}
	}
}

func extractApex(hostname string) (string, error) {
	if hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	if !govalidator.IsDNSName(hostname) {
		return "", errors.New("invalid fqdn")
	}

	eTLD, _ := publicsuffix.PublicSuffix(hostname)

	if len(eTLD)+1 >= len(hostname) {
		return "", errors.New("hostname is a public suffix")
	}

	i := len(hostname)-len(eTLD)-2
	for ; i > 0; i -= 1 {
		if hostname[i] == '.' {
			i += 1
			break
		}
	}

	return hostname[i:], nil
}

func download(limiter *ratelimit.Limiter, url string) (string, error) {
	httpOptions := retryablehttp.Options {
		RetryWaitMin:  time.Duration(options.MinWaitRetryHTTP) * time.Second,
		RetryWaitMax:  time.Duration(options.MaxWaitRetryHTTP) * time.Second,
		Timeout:       time.Duration(options.TimeoutHTTP) * time.Second,
		RetryMax:      options.RetriesHTTP,
		RespReadLimit: int64(options.MaxSizeHTTP),
		KillIdleConn:  true,
	}
	client := retryablehttp.NewClient(httpOptions)

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Warning().Str("url", url).Msgf("%s\n", err)
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8") 
	req.Header.Set("User-Agent", uarand.GetRandom())

	limiter.Take()
	resp, err := client.Do(req)
	if err != nil {
		gologger.Warning().Str("url", url).Msgf("%s\n", err)
		return "", err
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Warning().Str("url", url).Msgf("%s\n", err)
		return "", err
	}

	return string(data), err
}

func probeTemplateMatch(template Template, recordFingerprint string, records []string, httpTxt string, fqdn string, outputchan chan Result) {
	for _, record := range records {
		recordMatch, _ := regexp.MatchString(recordFingerprint, record)
		if recordMatch {
			for _, recordAdditionalFingerprint := range template.AdditionalFingerprint {
				textMatch, _ := regexp.MatchString(recordAdditionalFingerprint, httpTxt)
				if textMatch {
					outputchan <- Result{
						FQDN: fqdn,
						StatusCodeDNS: "NOERROR",
						AdditionalInfo: recordAdditionalFingerprint,
						Source: template.Identifier,
						Status: template.Status,
					}
					return
				}
			}
		}
	}
}

func isDomainAvailable(fqdn string) (bool, error) {
	request, err := whois.NewRequest(fqdn)
	if err != nil {
		return true, errors.New(fmt.Sprintf("%s: whois request error", fqdn))
	}

	response, err := whois.DefaultClient.Fetch(request)
	if err != nil {
		return true, errors.New(fmt.Sprintf("%s: whois fetch error", fqdn))
	}

	_, err = whoisparser.Parse(string(response.Body[:]))
	if err != nil {
		if errors.Is(err, whoisparser.ErrNotFoundDomain) {
			return true, nil
		} else {
			return true, err
		}
	} else {
		return false, nil
	}
}