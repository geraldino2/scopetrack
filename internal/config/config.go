package config

import (
	"fmt"
	"os"
	"errors"

	"github.com/geraldino2/scopetrack/internal/formatter"
	//"github.com/projectdiscovery/gologger/formatter"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/schollz/progressbar/v3"
)

const banner = `
                                _                       _    
                               | |                     | |   
 ___   ___   ___   _ __    ___ | |_  _ __   __ _   ___ | | __
/ __| / __| / _ \ | '_ \  / _ \| __|| '__| / _' | / __|| |/ /
\__ \| (__ | (_) || |_) ||  __/| |_ | |   | (_| || (__ |   < 
|___/ \___| \___/ | .__/  \___| \__||_|    \__,_| \___||_|\_\
                  | |                                  v0.0.4
                  |_|                                        
`
const Version = `v0.0.4`
func ShowBanner() {
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
	ProgressBar           *progressbar.ProgressBar
}

func ParseOptions(bar *progressbar.ProgressBar) *Options {
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

	options.ProgressBar = bar

	options.configureOutput()

	ShowBanner()

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
	gologger.DefaultLogger.SetFormatter(&formatter.PbarCLI{ProgressBar: options.ProgressBar})
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
}

func homePath() string {
	path, err := os.UserHomeDir()

    if err != nil {
        gologger.Fatal().Msgf("%s\n", err)
    }

    return path
}