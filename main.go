package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type records struct {
	issue     []*dns.CAA
	issueWild []*dns.CAA
	iodef     []*dns.CAA
	unknown   []*dns.CAA
}

func filter(returned []dns.RR) *records {
	r := &records{}
	for _, rr := range returned {
		if rr.Header().Rrtype != dns.TypeCAA {
			continue
		}
		caa, ok := rr.(*dns.CAA)
		if !ok {
			continue
		}
		switch strings.ToLower(caa.Tag) {
		case "issue":
			r.issue = append(r.issue, caa)
		case "issuewild":
			r.issueWild = append(r.issueWild, caa)
		case "iodef":
			r.iodef = append(r.iodef, caa)
		default:
			r.unknown = append(r.unknown, caa)
		}
	}
	return r
}

func (r *records) containsCriticalUnknown() bool {
	for _, rr := range r.unknown {
		if (rr.Flag & 128) != 0 {
			return true
		}
	}
	return false
}

func (r *records) useful() bool {
	if len(r.issue) > 0 || len(r.issueWild) > 0 {
		return true
	}
	return false
}

func (r *records) print() {
	for _, section := range [][]*dns.CAA{r.issue, r.issueWild, r.iodef, r.unknown} {
		for _, rr := range section {
			fmt.Printf("\t%s\n", rr.String())
		}
	}
}

var maxAliasRedirects = 10

func query(name string, rrType uint16, resolver string, iterations int) ([]dns.RR, error) {
	if iterations >= maxAliasRedirects {
		return nil, fmt.Errorf("Stuck in alias loop (%d redirects)", iterations)
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), rrType)
	m.RecursionDesired = true
	resp, err := dns.Exchange(m, resolver)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Non-zero RCODE in response (%s)", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 1 && (resp.Answer[0].Header().Rrtype == dns.TypeCNAME || resp.Answer[0].Header().Rrtype == dns.TypeDNAME) {
		var alias string
		switch t := resp.Answer[0].(type) {
		case *dns.CNAME:
			alias = t.Target
		case *dns.DNAME:
			alias = t.Target
		default:
			return nil, fmt.Errorf("Answer contains malformed %q record", dns.TypeToString[resp.Answer[0].Header().Rrtype])
		}
		iterations++
		return query(alias, rrType, resolver, iterations)
	}

	return resp.Answer, nil
}

func matchesIssuer(r *dns.CAA, issuer string) bool {
	ri := strings.TrimSpace(r.Value)
	if index := strings.Index(ri, ";"); index > 0 {
		ri = ri[:index]
	}
	return ri == issuer
}

func main() {
	resolver := flag.String("resolver", "", "DNS server and port to send questions to (defaults to resolvers in /etc/resolv.conf if empty)")
	issuer := flag.String("issuer", "", "Name of issuer to test against (if empty exit code will always be 0 and full chain will be displayed)")
	verbose := flag.Bool("verbose", false, "Print extra information about the CAA sets that are returned")
	flag.Usage = func() {
		fmt.Printf("Usage of caatest:\n")
		fmt.Printf("\tcaatest [flags] domain-name\n")
		fmt.Printf("Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	domain := flag.Arg(0)
	if domain == "" {
		fmt.Fprintln(os.Stderr, "No domain name provided")
		flag.Usage()
		os.Exit(1)
	}

	var upstream string
	if *resolver == "" {
		cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read nameservers from /etc/resolv.conf: %s\n", err)
			os.Exit(1)
		}
		if len(cc.Servers) == 0 {
			fmt.Fprintln(os.Stderr, "/etc/resolv.conf contains no nameservers")
			os.Exit(1)
		}
		upstream = fmt.Sprintf("%s:%s", cc.Servers[rand.Intn(len(cc.Servers))], cc.Port)
	} else {
		upstream = *resolver
	}

	labels := strings.Split(strings.TrimRight(domain, "."), ".")
	if labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-2]
	}
	for i := 0; i < len(labels); i++ {
		dn := strings.Join(labels[i:], ".")
		resp, err := query(dn, dns.TypeCAA, upstream, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Failed to send CAA query to %q: %s\n", dn, upstream, err)
			os.Exit(1)
		}
		if len(resp) == 0 {
			if *issuer == "" || *verbose {
				fmt.Printf("[%s] Empty response\n", dn)
			}
			continue
		}
		set := filter(resp)
		if set.containsCriticalUnknown() {
			fmt.Fprintf(os.Stderr, "[%s] CAA set contains a unknown record with critical bit set\n", dn)
			if *verbose {
				set.print()
			}
			os.Exit(1)
		}
		if !set.useful() {
			if *issuer == "" || *verbose {
				fmt.Printf("[%s] CAA set contains no relevant records\n", dn)
				if *verbose {
					set.print()
				}
			}
			continue
		}
		if *issuer == "" {
			fmt.Printf("[%s] CAA set contains following records\n", dn)
			set.print()
			continue
		}
		if strings.HasPrefix(domain, ".*") {
			if len(set.issueWild) == 0 {
				continue // I think this is wrong?
			}
			for _, rr := range set.issueWild {
				fmt.Println(rr)
			}
		} else {
			if len(set.issue) == 0 {
				if *verbose {
					fmt.Printf("[%s] No issue tag records in set\n", dn)
					set.print()
				}
				continue
			}
			for _, rr := range set.issue {
				if matchesIssuer(rr, *issuer) {
					fmt.Printf("[%s] Valid issue tag record for found %q in set\n", dn, *issuer)
					if *verbose {
						set.print()
					}
					os.Exit(0)
				}
			}
			fmt.Fprintf(os.Stderr, "[%s] Issuer %q not present in CAA issue tag set\n", dn, *issuer)
			if *verbose {
				set.print()
			}
			os.Exit(1)
		}
	}
}
