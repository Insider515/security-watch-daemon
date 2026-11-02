// Deriving thresholds from real traffic: how many requests, denials and errors
// ordinary visitors produce on this particular server.
package watch

import (
	"bufio"
	"fmt"
	"os"
	"sort"
)

// tuneCounters - what one address accumulated within one minute.
type tuneCounters struct {
	total    int
	notFound int
	denied   int
	failed   int
}

// Tune reads the web server log and prints thresholds computed from it: the
// distribution of requests per minute and per address is taken, and the
// threshold is placed above the 99.9th value but below rare outliers.
func Tune(path string) error {
	// #nosec G304 -- the log path is named by the operator on the command line.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer file.Close()

	buckets := map[string]*tuneCounters{}
	lines, parsed := 0, 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines++
		entry := parseCombined(scanner.Text())
		if !entry.Valid {
			continue
		}
		parsed++
		minute := entry.At.Unix() / 60
		key := fmt.Sprintf("%s|%d", entry.IP, minute)
		bucket, has := buckets[key]
		if !has {
			bucket = &tuneCounters{}
			buckets[key] = bucket
		}
		bucket.total++
		switch {
		case entry.Status == 404:
			bucket.notFound++
		case entry.Status == 401 || entry.Status == 403:
			bucket.denied++
		case entry.Status >= 500:
			bucket.failed++
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if parsed == 0 {
		return fmt.Errorf("not a single line parsed: the log format differs from combined")
	}

	totals := make([]int, 0, len(buckets))
	notFounds := make([]int, 0, len(buckets))
	denieds := make([]int, 0, len(buckets))
	faileds := make([]int, 0, len(buckets))
	for _, bucket := range buckets {
		totals = append(totals, bucket.total)
		notFounds = append(notFounds, bucket.notFound)
		denieds = append(denieds, bucket.denied)
		faileds = append(faileds, bucket.failed)
	}

	fmt.Printf("lines parsed: %d of %d, \"address+minute\" pairs: %d\n\n", parsed, lines, len(buckets))
	fmt.Printf("%-22s %8s %8s %8s %10s\n", "measure", "median", "99th", "max", "threshold")
	report := func(name string, values []int, floor int) int {
		sort.Ints(values)
		suggested := percentile(values, 0.999) * 2
		if suggested < floor {
			suggested = floor
		}
		fmt.Printf("%-22s %8d %8d %8d %10d\n", name,
			percentile(values, 0.5), percentile(values, 0.99), values[len(values)-1], suggested)
		return suggested
	}
	requests := report("requests per minute", totals, 60)
	notFound := report("404 responses", notFounds, 20)
	denied := report("401/403 responses", denieds, 10)
	failed := report("5xx responses", faileds, 5)

	fmt.Printf("\nput this into the configuration:\n")
	fmt.Printf("  \"requests_per_minute\": %d,\n", requests)
	fmt.Printf("  \"not_found_per_minute\": %d,\n", notFound)
	fmt.Printf("  \"denied_per_minute\": %d,\n", denied)
	fmt.Printf("  \"errors_per_minute\": %d\n", failed)
	fmt.Printf("\nThresholds are set to twice the 99.9th value: an ordinary visitor\n")
	fmt.Printf("never reaches them, while scanning and flooding do.\n")
	return nil
}

// percentile returns the value below which the given share of values lies. The
// slice must be sorted.
func percentile(sorted []int, share float64) int {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * share)
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
