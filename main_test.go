package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockDoType func(req *http.Request) (*http.Response, error)

type MockClient struct {
	MockDo      MockDoType
	LastRequest *http.Request
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	m.LastRequest = req
	return m.MockDo(req)
}

func TestSendToElastic(t *testing.T) {
	mockClient := &MockClient{
		MockDo: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewBufferString("OK")),
			}, nil
		},
	}

	sender := &ESSender{
		Address: "localhost",
		Client:  mockClient,
	}

	dnsMsg := DnsMessage{
		TimeStamp:       "2022-01-01T00:00:00Z",
		SourceIP:        "192.168.1.1",
		DestinationIP:   "192.168.1.2",
		DnsQuery:        "example.com",
		DnsOpCode:       "0",
		DnsResponseCode: "0",
		NumberOfAnswers: "1",
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	sender.SendToElastic(dnsMsg, wg)

	wg.Wait()

	assert.NotNil(t, mockClient.LastRequest)
	assert.Equal(t, "POST", mockClient.LastRequest.Method)
	assert.Equal(t, "http://localhost:9200/dns_index/syslog/", mockClient.LastRequest.URL.String())
}
