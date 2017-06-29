package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"bitbucket.org/bodhisnarkva/cbor/go"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"sync"
	"testing"
)

func TestFido20(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Fido20 Suite")
}

var _ = Describe("FIDO 2.0 Library", func() {

	Context("BLE Framing", func() {

		It("BLE Framing", func() {

			msgA := fillBytes(2, '\x01')

			responseA := &Response{Status: MSG, Data: msgA}
			framesA := responseA.Process(5)
			Ω(framesA).Should(HaveLen(1))

			msgB := fillBytes(6, '\x02')
			responseB := &Response{Status: MSG, Data: msgB}
			framesB := responseB.Process(5)
			Ω(framesB).Should(HaveLen(2))

			msgC := fillBytes(8, '\x03')
			responseC := &Response{Status: MSG, Data: msgC}
			framesC := responseC.Process(5)
			Ω(framesC).Should(HaveLen(3))

			requestA := &Request{}
			for i, f := range framesA {
				more, err := requestA.Receive(f)
				if Ω(err).ShouldNot(HaveOccurred()) {
					if i == len(framesA)-1 {
						Ω(more).Should(BeFalse())
					} else {
						Ω(more).Should(BeTrue())
					}
				}
			}

			_, err := requestA.Receive(framesB[0])
			if Ω(err).Should(HaveOccurred()) {
				Ω(requestA.Data()).Should(Equal(msgA))
			}

			requestB := &Request{}
			for i, f := range framesB {
				more, err := requestB.Receive(f)
				if Ω(err).ShouldNot(HaveOccurred()) {
					if i == len(framesB)-1 {
						Ω(more).Should(BeFalse())
					} else {
						Ω(more).Should(BeTrue())
					}
				}
			}

			Ω(requestB.Data()).Should(Equal(msgB))

			requestC := &Request{}
			for i, f := range framesC {
				more, err := requestC.Receive(f)
				if Ω(err).ShouldNot(HaveOccurred()) {
					if i == len(framesC)-1 {
						Ω(more).Should(BeFalse())
					} else {
						Ω(more).Should(BeTrue())
					}
				}
			}

			Ω(requestC.Data()).Should(Equal(msgC))

		})

		It("BLE Messageing", func() {

			//Central
			c := &fakeCentral{}
			//Connect
			entry := &StoreEntry{
				Central:  c,
				Notifier: c,
				Receiver: make(chan *Request, 1),
			}
			entry.Receiver <- &Request{}
			centralStore.m[c.ID()] = entry
			//Authenticator
			aaguid, _ := uuid.NewRandom()

			storage := &memStore{
				cache:  make([][]byte, 0),
				aaguid: aaguid,
			}

			authenticator, _ := NewAuthenticator(storage, nil, nil)

			//Make Info Request

			cmdAuthenticatorGetInfo := &Response{Status: MSG, Data: []byte{authenticatorGetInfo}}
			for i, f := range cmdAuthenticatorGetInfo.Process(c.MTU()) {
				fmt.Fprintf(GinkgoWriter, "GetInfo Frame[%d]=%s\n", i, hex.EncodeToString(f))
				getInfo := <-entry.Receiver
				hasMore, err := getInfo.Receive(f)
				if Ω(err).ShouldNot(HaveOccurred()) {
					if hasMore {
						entry.Receiver <- getInfo
					} else {
						entry.Receiver <- &Request{}

						executeMessage(&bleRequest{
							central: c,
							message: getInfo,
						}, authenticator, storage)
					}
				}
			}
			if Ω(c.Cache).Should(HaveLen(1)) {
				//fmt.Fprintf(GinkgoWriter, "GetInfo: '%s'\n", hex.EncodeToString(c.Cache[0]))
				c.Cache = nil
			}

			command, _ := cbor.Dumps(map[byte]interface{}{
				0x01: "RPID",
				0x02: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				0x03: map[string]string{
					"id":   "https://forgerocklabs.com",
					"name": "ForgeRock",
				},
				0x04: map[string]string{
					"id":          "lhordos",
					"name":        "lhordos",
					"displayName": "Laszlo Hordos",
				},
				0x05: []map[string]string{
					map[string]string{
						"alg": "P-256",
						"op":  "generateKey",
					},
					map[string]string{
						"alg": "P-384",
						"op":  "generateKey",
					},
					map[string]string{
						"alg": "P-521",
						"op":  "generateKey",
					},
				},
				//0x06 : [][]byte{},
				0x07: map[string]interface{}{
					"tup":  true,
					"test": "test",
				},
				0x08: false,
			})

			cmdMakeCredentialRequest := &Response{Status: MSG, Data: append([]byte{authenticatorMakeCredential}, command...)}
			for i, f := range cmdMakeCredentialRequest.Process(c.MTU()) {
				fmt.Fprintf(GinkgoWriter, "MakeCredential Frame[%d]=%s\n", i, hex.EncodeToString(f))
				makeCredential := <-entry.Receiver
				hasMore, err := makeCredential.Receive(f)
				if Ω(err).ShouldNot(HaveOccurred()) {
					if hasMore {
						entry.Receiver <- makeCredential
					} else {
						entry.Receiver <- &Request{}
						executeMessage(&bleRequest{
							central: c,
							message: makeCredential,
						}, authenticator, storage)
					}
				}
			}
			fmt.Fprintf(GinkgoWriter, "MakeCredential: '%s'\n", hex.EncodeToString(c.Cache[0]))
			if Ω(c.Cache).Should(HaveLen(2)) {
				//fmt.Fprintf(GinkgoWriter, "MakeCredential: '%s'\n", hex.EncodeToString(c.Cache[0]))
				c.Cache = nil
			}

			command, _ = cbor.Dumps(map[byte]interface{}{
				0x01: "https://forgerocklabs.com",
				0x02: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				//0x03 : [][]byte{},
				0x04: map[string]interface{}{
					"tup":  true,
					"test": "test",
				},
			})

			cmdGetAssertionRequest := &Response{Status: MSG, Data: append([]byte{authenticatorGetAssertion}, command...)}
			for i, f := range cmdGetAssertionRequest.Process(c.MTU()) {
				fmt.Fprintf(GinkgoWriter, "GetAssertion Frame[%d]=%s\n", i, hex.EncodeToString(f))
				getAssertion := <-entry.Receiver
				hasMore, err := getAssertion.Receive(f)
				if Ω(err).ShouldNot(HaveOccurred()) {
					if hasMore {
						entry.Receiver <- getAssertion
					} else {
						entry.Receiver <- &Request{}
						executeMessage(&bleRequest{
							central: c,
							message: getAssertion,
						}, authenticator, storage)
					}
				}
			}
			if Ω(c.Cache).Should(HaveLen(1)) {
				//fmt.Fprintf(GinkgoWriter, "GetAssertion: '%s'\n", hex.EncodeToString(c.Cache[0]))
				c.Cache = nil
			}

		})

	})
})

func fillBytes(l int, b byte) []byte {
	buf := make([]byte, l)
	for i := 0; i < l; i++ {
		buf[i] = b
	}
	return buf
}

type fakeCentral struct {
	Cache [][]byte
}

//Central
func (b *fakeCentral) ID() string {
	// ID returns platform specific ID of the remote central device.
	return "0a:cf:e9:1c:fd:4b"
}
func (b *fakeCentral) Close() error { // Close disconnects the connection.
	return nil
}
func (b *fakeCentral) MTU() int {
	// MTU returns the current connection mtu.
	return 255
}

//Notifier
// Write sends data to the central.
func (b *fakeCentral) Write(data []byte) (int, error) {
	if b.Cache == nil {
		b.Cache = make([][]byte, 0)
	}
	b.Cache = append(b.Cache, data)
	return len(data), nil
}

// Done reports whether the central has requested not to
// receive any more notifications with this notifier.
func (b *fakeCentral) Done() bool {
	return false
}

// Cap returns the maximum number of bytes that may be sent
// in a single notification.
func (b *fakeCentral) Cap() int {
	return b.MTU()
}

type memStore struct {
	sync.RWMutex
	cache  [][]byte
	aaguid uuid.UUID
}

func (s *memStore) Store(cred Credential) error {
	data, err := cred.Serialise()
	if err != nil {
		return err
	}
	fmt.Fprintf(GinkgoWriter, "Credential: \n%s\n", string(data))
	s.cache = append(s.cache, data)
	return nil
}
func (s *memStore) LoadAll() [][]byte {
	return s.cache
}
func (s *memStore) AAGUID() uuid.UUID {
	return s.aaguid
}
