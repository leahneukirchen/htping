// htping - periodically send HTTP requests and keep statistics
//
// To the extent possible under law, Leah Neukirchen <leah@vuxu.org>
// has waived all copyright and related or neighboring rights to this work.
// http://creativecommons.org/publicdomain/zero/1.0/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const version = "0.1"

var (
	sizeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "htpingd",
			Name:      "responses_size_bytes",
			Help:      "Size of HTTP response.",
		},
		[]string{
			"url",
			"addr",
			"code",
		},
	)
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "htpingd",
			Name:      "requests_total",
			Help:      "Number of HTTP requests.",
		},
		[]string{
			"url",
		},
	)
	responseCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "htpingd",
			Name:      "responses_total",
			Help:      "Number of HTTP responses.",
		},
		[]string{
			"url",
			"addr",
			"code",
		},
	)
	durSummary = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace:  "htpingd",
			Name:       "duration_seconds",
			Help:       "Request duration in seconds.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{
			"url",
			"addr",
		},
	)
)

var ntotal int32

var flag4 bool
var flag6 bool
var network = "tcp"
var quiet bool
var myHeaders headers
var method string

var insecure bool

var http11 bool
var keepalive bool

type transport struct {
	http.RoundTripper
	addr string
}

func newTransport(serverName string) *transport {
	tr := &transport{}

	tlsconfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}

	tlsconfig.VerifyPeerCertificate =
		func(certificates [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(certificates))
			for i, asn1Data := range certificates {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}

			opts := x509.VerifyOptions{
				Roots:         tlsconfig.RootCAs,
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)
			if err != nil {
				fmt.Printf("%v\n", err)
			}

			// succeed
			return nil
		}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	tr.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   !keepalive,
		TLSClientConfig:     tlsconfig,
		// we set TLSClientConfig, so http2 is off by default
		ForceAttemptHTTP2: !http11,

		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr) // force our network preference
		},
	}

	return tr
}

func (t *transport) GotConn(info httptrace.GotConnInfo) {
	t.addr = info.Conn.RemoteAddr().String()
}

type result struct {
	dur  float64
	code int
}

func ping(ctx context.Context, url string, seq int, myTransport *transport, results chan result) {
	start := time.Now()

	requestCounter.WithLabelValues(url).Inc()
	atomic.AddInt32(&ntotal, 1)

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Printf("error=%v\n", err)
		}
		return
	}

	req.Header.Set("User-Agent", "htping/"+version)

	for _, e := range myHeaders {
		req.Header.Set(e.key, e.value)
	}

	trace := &httptrace.ClientTrace{
		GotConn: myTransport.GotConn,
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Transport: myTransport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Printf("error=%v\n", err)
		}
		return
	}

	written, _ := io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()

	stop := time.Now()

	dur := float64(stop.Sub(start)) / float64(time.Second)

	sizeGauge.WithLabelValues(url, string(myTransport.addr), strconv.Itoa(res.StatusCode)).Set(float64(written))
	responseCounter.WithLabelValues(url, string(myTransport.addr), strconv.Itoa(res.StatusCode)).Inc()
	durSummary.WithLabelValues(url, string(myTransport.addr)).Observe(dur)

	if !quiet {
		fmt.Printf("%d bytes from %v: %s %d seq=%d time=%.3f s\n",
			written,
			myTransport.addr,
			res.Proto,
			res.StatusCode,
			seq,
			dur)
	}

	results <- result{dur, res.StatusCode}
}

func stats(ctx context.Context, results chan result) {
	var min, max, sum, sum2 float64
	min = math.Inf(1)
	nrecv := 0
	nsucc := 0

	start := time.Now()

	for {
		select {
		case r := <-results:
			if r.dur < min {
				min = r.dur
			}
			if r.dur > max {
				max = r.dur
			}
			sum += r.dur
			sum2 += r.dur * r.dur
			nrecv++
			if r.code < 400 {
				nsucc++
			}

		case <-ctx.Done():
			stop := time.Now()
			if ntotal > 0 {
				fmt.Printf("\n%d requests sent, %d (%d%%) responses, %d (%d%%) successful, time %d ms\n",
					ntotal,
					nrecv,
					(100*nrecv)/int(ntotal),
					nsucc,
					(100*nsucc)/int(ntotal),
					int64(stop.Sub(start)/time.Millisecond))
			}
			if nrecv > 0 {
				mdev := math.Sqrt(sum2/float64(nrecv) -
					sum/float64(nrecv)*sum/float64(nrecv))
				fmt.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f s\n",
					min, sum/float64(nrecv), max, mdev)
			}
			return
		}
	}
}

type header struct {
	key, value string
}
type headers []header

func (i *headers) String() string {
	return ""
}

func (i *headers) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return errors.New("header does not contain field and value")
	}
	*i = append(*i, header{parts[0], parts[1]})
	return nil
}

func main() {
	flag.BoolVar(&flag4, "4", false, "resolve IPv4 only")
	flag.BoolVar(&flag6, "6", false, "resolve IPv6 only")
	flag.BoolVar(&quiet, "q", false, "quiet")
	flag.Var(&myHeaders, "H", "set custom `header`s")
	flag.StringVar(&method, "X", "HEAD", "HTTP `method`")

	maxCount := flag.Int("c", -1, "quit after `count` requests")
	flood := flag.Bool("f", false, "flood ping")
	sleep := flag.Duration("i", 1*time.Second, "`interval` between requests")
	flag.BoolVar(&insecure, "k", false, "turn TLS errors into warnings")

	flag.BoolVar(&http11, "http1.1", false, "force HTTP/1.1")
	flag.BoolVar(&keepalive, "keepalive", false,
		"enable keepalive/use persistent connections")

	listenAddr := flag.String("l", "", "listen on `addr`")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [FLAGS...] URL\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	switch {
	case flag4:
		network = "tcp4"
	case flag6:
		network = "tcp6"
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	var wg sync.WaitGroup

	if *listenAddr != "" {
		srv := &http.Server{
			Addr: *listenAddr,
		}

		prometheus.MustRegister(requestCounter)
		prometheus.MustRegister(responseCounter)
		prometheus.MustRegister(durSummary)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html>
    <head><title>htpingd</title></head>
    <body>
    <h1>htpingd</h1>
    <p><a href="/metrics">Metrics</a></p>
</body>
    </html>
`))
		})
		http.Handle("/metrics", promhttp.Handler())

		go func() {
			log.Println("Prometheus metrics listening on", *listenAddr)

			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				fmt.Fprintf(os.Stderr, "error shutting down http server: %s\n", err)
			}
		}()
	}

	results := make(chan result)

	go func() {
		wg.Add(1)
		defer wg.Done()
		stats(ctx, results)
	}()

	count := 0

	for _, u := range args {
		wg.Add(1)

		u := u

		parsedURL, err := url.ParseRequestURI(u)
		if err != nil && err.(*url.Error).Op == "parse" {
			u = "http://" + u
		}

		parsedURL, err = url.ParseRequestURI(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
		if !(parsedURL.Scheme == "http" || parsedURL.Scheme == "https") {
			fmt.Fprintf(os.Stderr, "unsupported URL scheme: %s\n", u)
			os.Exit(1)
		}

		fmt.Printf("%s %s\n", method, u)

		go func() {
			myTransport := newTransport(parsedURL.Hostname())
			defer wg.Done()

			if *flood {
				for {
					select {
					case <-ctx.Done():
						return
					default:
						ping(ctx, u, count, myTransport, results)
						count++
					}
				}
			} else {
				pingTicker := time.NewTicker(*sleep)
				defer pingTicker.Stop()

				go ping(ctx, u, count, myTransport, results)
				count++
				for {
					if *maxCount > 0 && count > *maxCount {
						cancel()
					}
					select {
					case <-ctx.Done():
						return
					case <-pingTicker.C:
						go ping(ctx, u, count, myTransport, results)
						count++
					}
				}
			}
		}()
	}

	wg.Wait()
}
