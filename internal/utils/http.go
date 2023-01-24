package utils

import (
	"io"
	"time"
	"net/http"
	"crypto/tls"

	"github.com/geraldino2/scopetrack/internal/config"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/gologger"
	"github.com/corpix/uarand"
)

var Limiter *ratelimit.Limiter

func Download(options *config.Options, url string) (string, error) {
	httpOptions := retryablehttp.Options {
		RetryWaitMin:           time.Duration(options.MinWaitRetryHTTP) * time.Second,
		RetryWaitMax:           time.Duration(options.MaxWaitRetryHTTP) * time.Second,
		Timeout:                time.Duration(options.TimeoutHTTP) * time.Second,
		RetryMax:               options.RetriesHTTP,
		RespReadLimit:          int64(options.MaxSizeHTTP),
		KillIdleConn:           true,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
		MaxResponseHeaderBytes: int64(options.MaxHeaderSizeHTTP),
	}

	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport: transport,
		Timeout: time.Duration(options.TimeoutHTTP) * time.Second,
	}, httpOptions)

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Warning().Str("url", url).Msgf("%s\n", err)
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8") 
	req.Header.Set("User-Agent", uarand.GetRandom())

	Limiter.Take()
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