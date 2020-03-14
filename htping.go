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
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"
)

var ntotal int32

var flag4 bool
var flag6 bool
var myHeaders headers
var method string

var insecure bool

var http11 bool
var keepalive bool

type transport struct {
	http.RoundTripper
	msg  string
	addr string
}

func newTransport() *transport {
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
				DNSName:       tlsconfig.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)
			if err != nil {
				tr.msg = err.Error()
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
		// we set TLSClientConfig, so http2 is off by default anyway
		ForceAttemptHTTP2: !http11,

		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if flag4 {
				return dialer.DialContext(ctx, "tcp4", addr)
			} else if flag6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			} else {
				return dialer.DialContext(ctx, "tcp", addr)
			}
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

func ping(url string, seq int, results chan result) {
	start := time.Now()

	atomic.AddInt32(&ntotal, 1)

	t := newTransport()

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Printf("error=%v\n", err)
		return
	}

	for _, e := range myHeaders {
		req.Header.Set(e.key, e.value)
	}

	trace := &httptrace.ClientTrace{
		GotConn: t.GotConn,
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Transport: t,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("error=%v\n", err)
		return
	}

	written, _ := io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()
	client.CloseIdleConnections()

	stop := time.Now()

	dur := float64(stop.Sub(start)) / float64(time.Second)

	if len(t.msg) > 0 {
		fmt.Printf("%v\n", t.msg)
	}

	fmt.Printf("%d bytes from %v: %s %d seq=%d time=%.3f ms\n",
		written,
		t.addr,
		res.Proto,
		res.StatusCode,
		seq,
		dur)

	results <- result{dur, res.StatusCode}
}

func stats(results chan result, done chan bool) {
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
			if r.code <= 400 {
				nsucc++
			}

		case <-done:
			stop := time.Now()
			fmt.Printf("\n%d requests sent, %d (%d%%) responses, %d (%d%%) successful, time %dms\n",
				ntotal,
				nrecv,
				(100*nrecv)/int(ntotal),
				nsucc,
				(100*nsucc)/int(ntotal),
				int64(stop.Sub(start)/time.Millisecond))
			if nrecv > 0 {
				mdev := math.Sqrt(sum2/float64(nrecv) -
					sum/float64(nrecv)*sum/float64(nrecv))
				fmt.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
					min, sum/float64(nrecv), max, mdev)
			}

			done <- true
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
	flag.Var(&myHeaders, "H", "set custom `header`s")
	flag.StringVar(&method, "X", "HEAD", "HTTP `method`")

	maxCount := flag.Int("c", -1, "quit after `count` requests")
	flood := flag.Bool("f", false, "flood ping")
	sleep := flag.Duration("i", 1*time.Second, "`interval` between requests")
	flag.BoolVar(&insecure, "k", false, "turn TLS errors into warnings")

	flag.BoolVar(&http11, "http1.1", false, "force HTTP/1.1")
	flag.BoolVar(&keepalive, "keepalive", false,
		"enable keepalive/use persistent connections")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [FLAGS...] URL\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	u := args[0]

	u2, err := url.ParseRequestURI(u)
	if (err != nil && strings.HasSuffix(err.Error(),
		"invalid URI for request")) ||
		(u2.Scheme != "http" && u2.Scheme != "https") {
		u = "http://" + u
	}

	_, err = url.ParseRequestURI(u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%s %s\n", method, u)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	results := make(chan result)
	done := make(chan bool)
	go stats(results, done)

	count := 0

	if *flood {
	flood_loop:
		for {
			select {
			default:
				ping(u, count, results)
				count++
			case <-interrupt:
				break flood_loop
			}
		}
	} else {
		pingTicker := time.NewTicker(*sleep)
		go ping(u, count, results)
		count++
	ping_loop:
		for {
			if *maxCount > 0 && count > *maxCount {
				break
			}
			select {
			case <-pingTicker.C:
				go ping(u, count, results)
				count++
			case <-interrupt:
				break ping_loop
			}
		}
	}

	done <- true
	<-done
}
