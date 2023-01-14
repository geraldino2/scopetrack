package main

import (
	"os"
	"errors"
	"fmt"
	"bufio"
	"time"
	"context"
	"io"
	"math/rand"
	"hash/maphash"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"crypto/tls"
	"regexp"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"github.com/corpix/uarand"
)

const banner = `
                                _                       _    
                               | |                     | |   
 ___   ___   ___   _ __    ___ | |_  _ __   __ _   ___ | | __
/ __| / __| / _ \ | '_ \  / _ \| __|| '__| / _' | / __|| |/ /
\__ \| (__ | (_) || |_) ||  __/| |_ | |   | (_| || (__ |   < 
|___/ \___| \___/ | .__/  \___| \__||_|    \__,_| \___||_|\_\
                  | |                                  v0.0.3
                  |_|                                        
`
const Version = `v0.0.3`
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

type Options struct {
	FileFqdn              goflags.StringSlice
	/* HealthUpdate          bool
	ProbeTakeover         bool
	SkipValidation        bool */
	ListTemplates         bool
	TemplatePath          string
	FileConfig            string
	FileResolver          goflags.StringSlice
	TimeoutHTTP           int
	RetriesHTTP           int
	RetriesDNS            int
	TraceDepth            int
	BulkSize              int
	RequestsPerSec        int
	Output                string
	Debug                 bool
	Verbose               bool
	Silent                bool
	Version               bool
}

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
	Resolver              string `json:"Resolver"`
	StatusCodeDNS         string `json:"StatusCodeDNS"`
	AdditionalInfo        string `json:"AdditionalInfo"`
	Source                string `json:"Source"`
	Status                string `json:"Status"`
}

var options *Options
var resolvers = []string{}
var noerrorTemplatesA = []Template{}
var noerrorTemplatesCNAME = []Template{}
var noerrorTemplatesNS = []Template{}
var nxdomainTemplates = []Template{}
var servfailTemplates = []Template{}

func homePath() string {
	path, err := os.UserHomeDir()

    if err != nil {
        gologger.Fatal().Msgf("%s\n", err)
    }

    return path
}

func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`scopetrack is developed track FQDNs and DNS records.`)

	// Input
	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.FileFqdn, "fqdn", "l", nil, "files containing list of FQDNs to process", goflags.FileNormalizedStringSliceOptions),
	)

	// Database
	/* flagSet.CreateGroup("database", "Database",
		flagSet.BoolVarP(&options.HealthUpdate, "health-update", "hu", false, "filter dead FQDNs in the database"),
		flagSet.BoolVarP(&options.ProbeTakeover, "probe-takeover", "p", false, "template based search for FQDN takeovers"),
		flagSet.BoolVar(&options.SkipValidation, "skip-validation", false, "skip validation of FQDNs"),
	) */

	// Templates
	flagSet.CreateGroup("templates", "Templates",
		flagSet.BoolVar(&options.ListTemplates, "tl", false, "list all available templates"),
		flagSet.StringVar(&options.TemplatePath, "template-path", fmt.Sprintf("%s/.scopetrack/templates", homePath()), "path where templates are located"),
	)

	// Configurations
	flagSet.CreateGroup("configurations", "Configurations",
		flagSet.StringVar(&options.FileConfig, "config-file", "", "yaml configuration file to be loaded"),
		flagSet.StringSliceVarP(&options.FileResolver, "resolvers", "rl", []string{fmt.Sprintf("%s/resolvers.txt", homePath())}, "files containing list of resolvers to use", goflags.FileNormalizedStringSliceOptions),
		flagSet.IntVar(&options.TimeoutHTTP, "http-timeout", 10, "time to wait in seconds before a HTTP timeout"),
		flagSet.IntVar(&options.RetriesHTTP, "http-retries", 2, "number of times to retry a failed HTTP request"),
		flagSet.IntVar(&options.RetriesDNS, "dns-retries", 3, "number of times to retry a failed DNS request"),
		flagSet.IntVar(&options.TraceDepth, "dns-trace-depth", 31, "maximum number of hops in a trace recursion"),
	)

	// Optimizations
	flagSet.CreateGroup("optimizations", "Optimizations",
		flagSet.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "maximum number of hosts to be analyzed in parallel"),
		flagSet.IntVar(&options.RequestsPerSec, "rps", 150, "maximum number of requests per sec"),
	)

	// Output
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to"),
		flagSet.BoolVar(&options.Debug, "debug", false, "debug mode"),
		flagSet.BoolVar(&options.Verbose, "verbose", false, "verbose mode"),
		flagSet.BoolVar(&options.Silent, "silent", false, "silent mode"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of the project"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	if options.FileConfig != "" {
		if err := flagSet.MergeConfigFile(options.FileConfig); err != nil {
			gologger.Fatal().Msgf("Could not merge config file: %s\n", err)
		}
	}

	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	if options.ListTemplates {
		file, err := os.Open(options.TemplatePath)
		if err != nil {
			gologger.Fatal().Msgf("Failed opening templates path: %s", err)
		}
		defer file.Close()
		list, _ := file.Readdirnames(0)
		for _, name := range list {
			gologger.Info().Msgf(name)
		}
		os.Exit(0)
	}

	return options
}

func (options *Options) validateOptions() error {
	if options.FileFqdn == nil && !fileutil.HasStdin() /* && !options.HealthUpdate && !options.ProbeTakeover */ && !options.ListTemplates {
		return errors.New("no input provided and nothing to do")
	}

	return nil
}

func (options *Options) configureOutput() {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
}

func LoadTemplates() {
	files, err := ioutil.ReadDir(options.TemplatePath)
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	for _, file := range files {
		if !file.IsDir() {
			data, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", options.TemplatePath, file.Name()))
			if err != nil {
				gologger.Warning().Msgf("couldn't load template %s: err\n", fmt.Sprintf("%s/%s", options.TemplatePath, file.Name()), err)
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
	options = ParseOptions()

	LoadTemplates()

	chanfqdn := make(chan string)
	go func() {
		defer close(chanfqdn)
		if fileutil.HasStdin() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				_ = options.FileFqdn.Set(scanner.Text())
			}
		}
		if options.FileFqdn != nil {
			for _, item := range options.FileFqdn {
				chanfqdn <- item
			}
		}
	}()

	wg := sizedwaitgroup.New(options.BulkSize)
	wgoutput := sizedwaitgroup.New(1)
	wgoutput.Add()
	outputchan := make(chan string)
	go output(&wgoutput, outputchan)

	limiter := ratelimit.New(context.Background(), uint(options.RequestsPerSec)*3, time.Duration(3*time.Second))//rate limit amortized to bursts within 3 seconds

	for _, item := range options.FileResolver {
		resolvers = append(resolvers, item)
	}

	for item := range chanfqdn {
		wg.Add()
		go query(&wg, limiter, item, outputchan)
	}

	wg.Wait()
	close(outputchan)
	wgoutput.Wait()
}


func query(wg *sizedwaitgroup.SizedWaitGroup, limiter *ratelimit.Limiter, fqdn string, outputchan chan string) {
	defer wg.Done()
	retries := options.RetriesDNS
	rng := rand.New(rand.NewSource(int64(new(maphash.Hash).Sum64())))
	resolver := resolvers[rng.Intn(len(resolvers))]
	dnsClient, _ := retryabledns.New([]string{resolver}, retries)

	gologger.Debug().Msgf("FQDN=%s RESOLVER=%s QUESTION=A FLAGS=\n", fqdn, resolver)
	dnsResponses, err := dnsClient.Query(fqdn, dns.TypeA)
	if err != nil {
		gologger.Debug().Msgf("%s\n", err)
		return
	}

	if dnsResponses.StatusCode == "NOERROR" {
		var dnsRecords [][]string

		gologger.Debug().Msgf("FQDN=%s RESOLVER=%s QUESTION=CNAME FLAGS=\n", fqdn, resolver)
		dnsResponsesCNAME, dnsErrCNAME := dnsClient.Query(fqdn, dns.TypeCNAME)
		if dnsErrCNAME != nil {
			gologger.Debug().Msgf("%s\n", dnsErrCNAME)
		} else {
			dnsRecords = append(dnsRecords, dnsResponsesCNAME.CNAME)
		}

		gologger.Debug().Msgf("FQDN=%s RESOLVER=%s QUESTION=NS FLAGS=\n", fqdn, resolver)
		dnsResponsesNS, dnsErrNS := dnsClient.Query(fqdn, dns.TypeNS)
		if dnsErrNS != nil {
			gologger.Debug().Msgf("%s\n", dnsErrNS)
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

		if httpProbe {
			httpTxt, httpErr = download(limiter, fmt.Sprintf("http://%s", fqdn))
		}

		if httpErr != nil {
			gologger.Debug().Msgf("couldn't send HTTP GET to %s: %s\n", fqdn, httpErr)
		} else {
			for _, templateGroup := range [][]Template{noerrorTemplatesA, noerrorTemplatesCNAME, noerrorTemplatesNS} {
				for _, template := range templateGroup {
					for _, recordFingerprint := range template.RecordFingerprint {
						probeTemplateMatch(template, recordFingerprint, dnsResponses.A, httpTxt, fqdn, outputchan)

						if dnsErrCNAME == nil {
							probeTemplateMatch(template, recordFingerprint, dnsResponses.CNAME, httpTxt, fqdn, outputchan)
						}

						if dnsErrNS == nil {
							probeTemplateMatch(template, recordFingerprint, dnsResponses.NS, httpTxt, fqdn, outputchan)
						}
					}
				}
			}
		}
	}

	if dnsResponses.StatusCode == "NXDOMAIN" {
		gologger.Debug().Msgf("FQDN=%s RESOLVER=%s QUESTION=CNAME FLAGS=\n", fqdn, resolver)
		dnsResponses, err = dnsClient.Query(fqdn, dns.TypeCNAME)
		if err != nil {
			gologger.Debug().Msgf("%s\n", err)
		}

		if len(dnsResponses.CNAME) > 0 {
			gologger.Info().Msgf("%s responded with NXDOMAIN, CNAME=%s", fqdn, dnsResponses.CNAME[0])
			for _, template := range nxdomainTemplates {
				for _, recordFingerprintCNAME := range template.RecordFingerprint {
					match, _ := regexp.MatchString(recordFingerprintCNAME, dnsResponses.CNAME[0])
					if match {
						outputchan <- fqdn
						break
					}
				}
			}
		} else {
			apex, parseErr := extractApex(fqdn)
			if parseErr != nil {
				apexStatus, err := queryStatus(apex, resolver)
				if err != nil {
					if apexStatus == "NXDOMAIN" {
						outputchan <- fqdn
					}
				}
			}
		}
	}

	if dnsResponses.StatusCode == "SERVFAIL" || dnsResponses.StatusCode == "REFUSED" {
		gologger.Debug().Msgf("FQDN=%s RESOLVER=%s QUESTION=NS FLAGS=+trace\n", fqdn, resolver)
		traceResponse, err := dnsClient.Trace(fqdn, dns.TypeNS, options.TraceDepth)
		if err != nil {
			gologger.Debug().Msgf("%s\n", err)
		}

		ns_records := []string{}
		for i := 0; i < len(traceResponse.DNSData); i++ {
			if len(traceResponse.DNSData[i].NS) > 0 {
				ns_records = traceResponse.DNSData[i].NS
			}
		}

		for _, dnsTraceRecordNS := range ns_records {
			apex, err := extractApex(dnsTraceRecordNS)
			if err != nil {
				apexStatus, _ := queryStatus(apex, resolver)
				if apexStatus == "NXDOMAIN" {
					outputchan <- fqdn
				}
			}
		}

		for _, template := range servfailTemplates {
			var skipTemplate bool = false
			for _, recordFingerprintNS := range template.RecordFingerprint {
				for _, dnsTraceRecordNS := range ns_records {
					match, _ := regexp.MatchString(recordFingerprintNS, dnsTraceRecordNS)
					if match {
						outputchan <- fqdn
						skipTemplate = true
						break
					}
				}
				if skipTemplate {
					break
				}
			}
		}
	}
}

func queryStatus(fqdn string, resolver string) (string, error) {
	retries := options.RetriesDNS
	dnsClient, _ := retryabledns.New([]string{resolver}, retries)

	gologger.Debug().Msgf("FQDN=%s RESOLVER=%s QUESTION=A FLAGS=\n", fqdn, resolver)
	dnsResponses, err := dnsClient.Query(fqdn, dns.TypeA)
	if err != nil {
		gologger.Debug().Msgf("%s\n", err)
		return "", err
	}
	return dnsResponses.StatusCode, nil
}

func output(wgoutput *sizedwaitgroup.SizedWaitGroup, outputchan chan string) {
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

func outputItems(f *os.File, items ...string) {
	for _, item := range items {
		gologger.Silent().Msgf("%s\n", item)
		if f != nil {
			_, _ = f.WriteString(item + "\n")
		}
	}
}

func extractApex(hostname string) (string, error) {
	if hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
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
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8") 
	req.Header.Set("User-Agent", uarand.GetRandom())
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client {
		Transport: customTransport,
		Timeout: time.Duration(options.TimeoutHTTP) * time.Second,
	}

	var txt string = ""
	var resp *http.Response = nil
	var bodyBytes []byte = nil
	var err error = nil

	for i := 0; i < options.RetriesHTTP; i++ {
		gologger.Debug().Msgf("URL=%s HTTP GET /\n", url)
		resp, err = client.Do(req)
		limiter.Take()
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		txt = string(bodyBytes)
	}

	return txt, err
}

func probeTemplateMatch(template Template, recordFingerprint string, records []string, httpTxt string, fqdn string, outputchan chan string) {
	for _, record := range records {
		recordMatch, _ := regexp.MatchString(recordFingerprint, record)
		if recordMatch {
			for _, recordAdditionalFingerprint := range template.AdditionalFingerprint {
				textMatch, _ := regexp.MatchString(recordAdditionalFingerprint, httpTxt)
				if textMatch {
					outputchan <- fqdn
					return
				}
			}
		}
	}
}