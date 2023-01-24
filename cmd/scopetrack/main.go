package main

import (
	"os"
	"os/signal"
	"syscall"
	"fmt"
	"bufio"
	"time"
	"context"
	"io/ioutil"
	"encoding/json"
	"regexp"
	"net"
	"errors"

	"github.com/geraldino2/scopetrack/internal/config"
	"github.com/geraldino2/scopetrack/internal/utils"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/miekg/dns"
	"github.com/schollz/progressbar/v3"
	"github.com/k0kubun/go-ansi"
	"github.com/asaskevich/govalidator"
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
	FQDN                  string   `json:"FQDN"`
	StatusCodeDNS         string   `json:"StatusCodeDNS"`
	AdditionalInfo        string   `json:"AdditionalInfo"`
	Source                string   `json:"Source"`
	Status                string   `json:"Status"`
	BaseResolver          []string `json:"BaseResolver"`
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
				gologger.Warning().Str("template", fmt.Sprintf("%s/%s", options.TemplatePath, file.Name())).Msgf("%s\n", err)
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

	utils.Limiter = ratelimit.New(context.Background(), uint(options.RequestsPerSec)*3, time.Duration(3*time.Second))//rate limit amortized to bursts within 3 seconds

	retries := options.RetriesDNS
	dnsClient, err := retryabledns.New(options.FileResolver, retries)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}

	for item := range chanfqdn {
		wg.Add()
		go query(&wg, item, dnsClient, outputchan)
	}

	wg.Wait()
	close(outputchan)
	wgoutput.Wait()
}

func query(wg *sizedwaitgroup.SizedWaitGroup, fqdn string, dnsClient *retryabledns.Client, outputchan chan Result) {
	gologger.Debug().Str("fqdn", fqdn).Msgf("query")
	defer bar.Add(1)
	defer wg.Done()

	if !govalidator.IsDNSName(fqdn) {
		gologger.Debug().Str("fqdn", fqdn).Msgf("invalid DNS name")
		return
	}

	gologger.Debug().Str("fqdn", fqdn).Str("question", "A").Str("flags", "").Msgf("DNS request\n")
	var dnsResponses *retryabledns.DNSData
	var err error
	var baseResolvers []string
	for i := 0; i < options.RetriesTarget; i++ {
		dnsResponses, err = dnsClient.Query(fqdn, dns.TypeA)
		baseResolvers = dnsResponses.Resolver
		if err != nil {
			time.Sleep(time.Duration(options.TargetRetryDelay) * time.Second)
			continue
		}

		if dnsResponses.StatusCode == "NOERROR" {
			probeNOERROR(fqdn, dnsResponses, dnsClient, outputchan)
		} else if dnsResponses.StatusCode == "NXDOMAIN" {
			probeNXDOMAIN(fqdn, dnsResponses, dnsClient, baseResolvers, outputchan)
		} else if dnsResponses.StatusCode == "SERVFAIL" || dnsResponses.StatusCode == "REFUSED" {
			probeSERVFAIL(fqdn, dnsResponses, dnsClient, baseResolvers, outputchan)
		} else {
			raiseErrDNS(fqdn, outputchan, errors.New(fmt.Sprintf("unexpected status: %s", dnsResponses.StatusCode)), baseResolvers)
		}
		return
	}

	raiseErrDNS(fqdn, outputchan, err, baseResolvers)
}

func probeNOERROR(fqdn string, dnsResponses *retryabledns.DNSData, dnsClient *retryabledns.Client, outputchan chan Result) {
	var publicAddresses = []string{}
	for _, record := range dnsResponses.A {
		if net.ParseIP(record) != nil && !net.ParseIP(record).IsPrivate() {
			publicAddresses = append(publicAddresses, record)
		}
	}

	if options.NoHTTP || (len(publicAddresses) == 0 && len(dnsResponses.CNAME) == 0) {
		return
	}

	gologger.Debug().Str("fqdn", fqdn).Str("question", "NS").Str("flags", "").Msgf("DNS request\n")
	dnsResponsesNS, dnsErrNS := dnsClient.Query(fqdn, dns.TypeNS)
	if dnsErrNS != nil {
		raiseErrDNS(fqdn, outputchan, dnsErrNS, dnsResponsesNS.Resolver)
		return
	}

	var matchedTemplates = []Template{}
	var matchPairs = []utils.Pair[[]Template, []string] {
		{noerrorTemplatesA, publicAddresses},
		{noerrorTemplatesCNAME, dnsResponses.CNAME},
		{noerrorTemplatesNS, dnsResponsesNS.NS},
	}

	for _, templateRecordPair := range matchPairs {
		for _, template := range templateRecordPair.First {
			for _, recordFingerprint := range template.RecordFingerprint {
				for _, record := range templateRecordPair.Second {
					match, _ := regexp.MatchString(recordFingerprint, record)
					if match {
						matchedTemplates = append(matchedTemplates, template)
					}
				}
			}
		}
	}

	if len(matchedTemplates) > 0 {
		gologger.Debug().Str("fqdn", fqdn).Msgf("HTTP request\n")
		httpTxt, httpErr := utils.Download(options, fmt.Sprintf("http://%s", fqdn))

		if httpErr != nil {
			gologger.Warning().Str("url", fmt.Sprintf("http://%s", fqdn)).Msgf("%s\n", httpErr)
			outputchan <- Result{
				FQDN: fqdn,
				StatusCodeDNS: "NOERROR",
				AdditionalInfo: fmt.Sprintf("%s", httpErr),
				Source: fmt.Sprintf("%+v", matchedTemplates),
				Status: "HTTP_ERROR",
			}
		} else {
			for _, template := range matchedTemplates {
				verifyHttpTemplateMatch(template, fqdn, httpTxt, publicAddresses, dnsResponses.CNAME, dnsResponsesNS.NS, outputchan)
			}
		}
	}
}

func probeNXDOMAIN(fqdn string, dnsResponses *retryabledns.DNSData, dnsClient *retryabledns.Client, baseResolvers []string, outputchan chan Result) {
	gologger.Debug().Str("fqdn", fqdn).Str("question", "CNAME").Str("flags", "").Msgf("DNS request\n")
	dnsResponses, err := dnsClient.Query(fqdn, dns.TypeCNAME)
	if err != nil {
		raiseErrDNS(fqdn, outputchan, err, dnsResponses.Resolver)
		return
	}

	if len(dnsResponses.CNAME) > 0 {
		var cname = dnsResponses.CNAME[len(dnsResponses.CNAME)-1]
		var templateMatch = false

		for _, template := range nxdomainTemplates {
			for _, recordFingerprintCNAME := range template.RecordFingerprint {
				match, _ := regexp.MatchString(recordFingerprintCNAME, cname)
				if match {
					templateMatch = true
					outputchan <- Result{
						FQDN: fqdn,
						StatusCodeDNS: "NXDOMAIN",
						AdditionalInfo: cname,
						Source: template.Identifier,
						Status: template.Status,
						BaseResolver: baseResolvers,
					}
				}
			}
		}

		fqdnApex, parseErr1 := utils.ExtractApex(fqdn)
		cnameApex, parseErr2 := utils.ExtractApex(cname)
		if parseErr1 != nil || parseErr2 != nil {
			gologger.Warning().Str("fqdn", fqdn).Msgf("%s\n", err)
			return
		}

		if !templateMatch && fqdnApex != cnameApex {
			outputchan <- Result{
				FQDN: fqdn,
				StatusCodeDNS: "NXDOMAIN",
				AdditionalInfo: cname,
				Source: "NXDOMAIN with external CNAME",
				Status: "POTENTIAL_TAKEOVER",
				BaseResolver: baseResolvers,
			}
		}
	} else {
		outputchan <- Result{
			FQDN: fqdn,
			StatusCodeDNS: "NXDOMAIN",
			AdditionalInfo: fqdn,
			Source: "Potential available apex",
			Status: "INFORMATIONAL",
			BaseResolver: baseResolvers,
		}
	}
}

func probeSERVFAIL(fqdn string, dnsResponses *retryabledns.DNSData, dnsClient *retryabledns.Client, baseResolvers []string, outputchan chan Result) {
	gologger.Debug().Str("fqdn", fqdn).Str("question", "NS").Str("flags", "+trace").Msgf("DNS request\n")
	traceResponse, err := dnsClient.Trace(fqdn, dns.TypeNS, options.TraceDepth)
	if err != nil {
		raiseErrDNS(fqdn, outputchan, err, nil)
		return
	}

	ns_records := []string{}
	for i := 0; i < len(traceResponse.DNSData); i++ {
		if len(traceResponse.DNSData[i].NS) > 0 {
			ns_records = traceResponse.DNSData[i].NS
		}
	}

	var templateMatch = false
	for _, template := range servfailTemplates {
		for _, recordFingerprintNS := range template.RecordFingerprint {
			for _, dnsTraceRecordNS := range ns_records {
				match, _ := regexp.MatchString(recordFingerprintNS, dnsTraceRecordNS)
				if match {
					templateMatch = true
					outputchan <- Result{
						FQDN: fqdn,
						StatusCodeDNS: dnsResponses.StatusCode,
						AdditionalInfo: dnsTraceRecordNS,
						Source: template.Identifier,
						Status: template.Status,
						BaseResolver: baseResolvers,
					}
				}
			}
		}
	}

	for _, dnsTraceRecordNS := range ns_records {
		fqdnApex, parseErr1 := utils.ExtractApex(fqdn)
		cnameApex, parseErr2 := utils.ExtractApex(dnsTraceRecordNS)
		if parseErr1 != nil || parseErr2 != nil {
			gologger.Warning().Str("fqdn", fqdn).Msgf("%s\n", err)
			return
		}

		if !templateMatch && fqdnApex != cnameApex {
			outputchan <- Result{
				FQDN: fqdn,
				StatusCodeDNS: dnsResponses.StatusCode,
				AdditionalInfo: dnsTraceRecordNS,
				Source: fmt.Sprintf("%s with external NS", dnsResponses.StatusCode),
				Status: "POTENTIAL_TAKEOVER",
				BaseResolver: baseResolvers,
			}
		}
	}
}

func verifyHttpTemplateMatch(template Template, fqdn string, httpTxt string, aRecords []string, cnameRecords []string, nsRecords []string, outputchan chan Result) {
	var records []string

	if template.RecordType == "A" {
		records = aRecords
	} else if template.RecordType == "CNAME" {
		records = cnameRecords
	} else if template.RecordType == "NS" {
		records = nsRecords
	}

	for _, record := range records {
		for _, recordFingerprint := range template.RecordFingerprint {
			recordMatch, _ := regexp.MatchString(recordFingerprint, record)
			if recordMatch {
				for _, recordAdditionalFingerprint := range template.AdditionalFingerprint {
					textMatch, err := regexp.MatchString(recordAdditionalFingerprint, httpTxt)
					if err != nil {
						gologger.Warning().Str("template", template.Identifier).Str("additionalfingerprint", recordAdditionalFingerprint).Msgf("%s\n", err)
						return
					}

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

	outputchan <- Result{
		FQDN: fqdn,
		StatusCodeDNS: "NOERROR",
		Source: template.Identifier,
		Status: "INFORMATIONAL",
	}
}

func raiseErrDNS(fqdn string, outputchan chan Result, err error, resolvers []string) {
	outputchan <- Result{
		FQDN: fqdn,
		AdditionalInfo: fmt.Sprintf("%s", err),
		Status: "DNS_ERROR",
		BaseResolver: resolvers,
	}
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
		if !options.ResultValidation && item.Status != "HTTP_ERROR" && item.Status != "DNS_ERROR" {
			dnsClient, _ := retryabledns.New(options.FileResolver, options.RetriesValidation)
			validationStatus, err := queryStatus(item.FQDN, dnsClient)
			if err == nil && item.StatusCodeDNS != validationStatus {
				item.Status = "VALIDATION_ERROR"
				item.AdditionalInfo = fmt.Sprintf("status=%s", validationStatus)
			}
		}

		data, _ := json.Marshal(&item)
		if item.Status == "DNS_ERROR" {
			gologger.Info().Msgf("skipping %s due to DNS errors", item.FQDN)
		} else if item.Status == "HTTP_ERROR" {
			gologger.Info().Msgf("skipping %s due to HTTP errors", item.FQDN)
		} else {
			gologger.Silent().Msgf("%s", string(data))
		}

		if f != nil {
			_, _ = f.WriteString(string(data) + "\n")
		}
	}
}