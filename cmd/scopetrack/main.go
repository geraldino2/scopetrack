package main

import (
	"os"
	"errors"
	"fmt"
	"bufio"
	"sync"
	"time"
	"context"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/miekg/dns"
)

const banner = `
                                _                       _    
                               | |                     | |   
 ___   ___   ___   _ __    ___ | |_  _ __   __ _   ___ | | __
/ __| / __| / _ \ | '_ \  / _ \| __|| '__| / _' | / __|| |/ /
\__ \| (__ | (_) || |_) ||  __/| |_ | |   | (_| || (__ |   < 
|___/ \___| \___/ | .__/  \___| \__||_|    \__,_| \___||_|\_\
                  | |                                  v0.0.1
                  |_|                                        
`
const Version = `v0.0.1`

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
	BulkSize              int
	RequestsPerSec        int
	Output                string
	Debug                 bool
	Verbose               bool
	Silent                bool
	Version               bool
}

var options *Options
var limiter *ratelimit.Limiter
var resolvers = []string{}

func homePath() string {
	path, err := os.UserHomeDir()

    if err != nil {
        gologger.Fatal().Msgf("%s\n", err)
    }

    return path
}

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
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

func main() {
	options = ParseOptions()
	
	limiter = ratelimit.New(context.Background(), uint(options.RequestsPerSec)*3, time.Duration(3*time.Second))//rate limit amortized to bursts within 3 seconds
	for _, item := range options.FileResolver {
		resolvers=append(resolvers,item)
	}

	chanfqdn := make(chan string)
	outputchan := make(chan string)
	var wg sync.WaitGroup

	wg.Add(1)
	go process(&wg, chanfqdn, outputchan)
	wg.Add(1)
	go output(&wg, outputchan)

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

	close(chanfqdn)
	wg.Wait()
}

func process(wg *sync.WaitGroup, chanfqdn, outputchan chan string) {
	swg := sizedwaitgroup.New(options.BulkSize)

	for fqdn := range chanfqdn {
		swg.Add()
		go func() {
			defer swg.Done()
			query(fqdn, outputchan)
		}()
	}

	swg.Wait()
	close(outputchan)
}


func query(fqdn string, outputchan chan string) {
	retries := 2
	dnsClient, _ := retryabledns.New(resolvers, retries)
	dnsResponses, err := dnsClient.Query(fqdn, dns.TypeA)
	limiter.Take()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	outputchan <- dnsResponses.StatusCode
}

func output(wg *sync.WaitGroup, outputchan chan string) {
	defer wg.Done()

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
