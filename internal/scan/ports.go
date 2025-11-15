package scan

import (
	"bufio"
	"context"
	"strconv"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

type PortScanner struct{}

func NewPortScanner() *PortScanner { return &PortScanner{} }

type NaabuOptions struct {
	Ports string // e.g. "80,443,8000-8100" or ""
	Rate  int
}

func (s *PortScanner) ScanNaabu(ctx context.Context, hosts []string, opts NaabuOptions) ([]model.Port, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	args := []string{"-silent", "-json"}

	if opts.Ports != "" {
		args = append(args, "-p", opts.Ports)
	}
	if opts.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(opts.Rate))
	}

	stdin := strings.Join(hosts, "\n") + "\n"

	res := executil.RunWithStdin(ctx, stdin, "naabu", args...)
	if res.Err != nil {
		return nil, res.Err
	}

	type naabuOut struct {
		Host string `json:"host"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
		Proto string `json:"protocol"`
	}

	scanner := bufio.NewScanner(strings.NewReader(string(res.Stdout)))
	var out []model.Port

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var o naabuOut
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			continue
		}
		out = append(out, model.Port{
			Host:     o.Host,
			Port:     o.Port,
			Protocol: o.Proto,
		})
	}
	return out, scanner.Err()
}
