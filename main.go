package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DnsMessage struct {
	TimeStamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ESSender struct {
	Address string
	Client  Doer
}

func NewESSender(address string) *ESSender {
	return &ESSender{
		Address: address,
		Client:  &http.Client{},
	}
}

func (s *ESSender) SendToElastic(dnsMsg DnsMessage, wg *sync.WaitGroup) {
	defer wg.Done()

	jsonMsg, jsonErr := json.Marshal(dnsMsg)
	if jsonErr != nil {
		panic(jsonErr)
	}

	request, reqErr := http.NewRequest("POST", "http://"+s.Address+":9200/dns_index/syslog/", bytes.NewBuffer(jsonMsg))
	if reqErr != nil {
		panic(reqErr)
	}

	_, elErr := s.Client.Do(request)
	if elErr != nil {
		panic(elErr)
	}
}

type DNSProcessor struct {
	handle *pcap.Handle
	sender *ESSender
	wg     *sync.WaitGroup
}

func NewDNSProcessor(handle *pcap.Handle, sender *ESSender) *DNSProcessor {
	return &DNSProcessor{
		handle: handle,
		sender: sender,
		wg:     &sync.WaitGroup{},
	}
}

func (p *DNSProcessor) Process() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {

		data, _, err := p.handle.ReadPacketData()
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}

		err = parser.DecodeLayers(data, &decodedLayers)

		SrcIP, DstIP := "", ""
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
			}
		}

		if SrcIP == "" || DstIP == "" {
			continue
		}

		for _, dnsQuestion := range dns.Questions {
			if dns.ANCount == 0 && dns.ResponseCode == 0 {
				continue
			}

			t := time.Now()
			timestamp := t.Format(time.RFC3339)

			d := DnsMessage{
				TimeStamp:       timestamp,
				SourceIP:        SrcIP,
				DestinationIP:   DstIP,
				DnsQuery:        string(dnsQuestion.Name),
				DnsOpCode:       strconv.Itoa(int(dns.OpCode)),
				DnsResponseCode: strconv.Itoa(int(dns.ResponseCode)),
				NumberOfAnswers: strconv.Itoa(int(dns.ANCount)),
			}

			for _, dnsAnswer := range dns.Answers {
				d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
				if dnsAnswer.IP.String() != "<nil>" {
					d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
				}
			}

			p.wg.Add(1)
			go p.sender.SendToElastic(d, p.wg)
		}
		if err != nil {
			fmt.Println("  Error encountered:", err)
		}
	}
}

const (
	devName    = "\\Device\\NPF_{}"
	es_Address = "localhost"
)

func main() {
	handle, err := pcap.OpenLive(devName, 1400, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	sender := NewESSender(es_Address)

	p := NewDNSProcessor(handle, sender)
	p.Process()
}
