package formatter

import (
	"bytes"

	"github.com/schollz/progressbar/v3"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

type PbarCLI struct{
	ProgressBar      *progressbar.ProgressBar
}

var _ formatter.Formatter = &PbarCLI{}

func (j *PbarCLI) Format(event *formatter.LogEvent) ([]byte, error) {
	j.ProgressBar.Clear()
	
	var aurora = aurora.NewAurora(true)

	label := event.Metadata["label"]
	if label != "" {
		switch event.Level {
			case levels.LevelInfo, levels.LevelVerbose:
				event.Metadata["label"] = aurora.Blue(label).String()
			case levels.LevelFatal:
				event.Metadata["label"] = aurora.Bold(aurora.Red(label)).String()
			case levels.LevelError:
				event.Metadata["label"] = aurora.Red(label).String()
			case levels.LevelDebug:
				event.Metadata["label"] = aurora.Magenta(label).String()
			case levels.LevelWarning:
				event.Metadata["label"] = aurora.Yellow(label).String()
		}
	}

	buffer := &bytes.Buffer{}
	buffer.Grow(len(event.Message))

	label, ok := event.Metadata["label"]
	if label != "" && ok {
		buffer.WriteRune('[')
		buffer.WriteString(label)
		buffer.WriteRune(']')
		buffer.WriteRune(' ')
		delete(event.Metadata, "label")
	}
	timestamp, ok := event.Metadata["timestamp"]
	if timestamp != "" && ok {
		buffer.WriteRune('[')
		buffer.WriteString(timestamp)
		buffer.WriteRune(']')
		buffer.WriteRune(' ')
		delete(event.Metadata, "timestamp")
	}
	buffer.WriteString(event.Message)

	for k, v := range event.Metadata {
		if v != "" {
			buffer.WriteRune(' ')
			buffer.WriteString(aurora.Bold(k).String())
			buffer.WriteRune('=')
			buffer.WriteString(v)
		}
	}
	
	data := buffer.Bytes()
	return data, nil
}