package main

import (
	cbor "bitbucket.org/bodhisnarkva/cbor/go"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/inconshreveable/log15"
	"github.com/jroimartin/gocui"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var (
	CancelOperationError = errors.New("Operation Cancelled")

	messages = make(chan Op)
	signals  = make(chan bool, 1)

	aaguid = flag.String("aaguid", "bf30ae6a-6489-4a10-8bff-07ec2e6a93d1", "AAGUID of authenticator")
	logger = log15.New("module", "FIDO 2.0")
)

func init() {
	//journalctl -f -u fido20
	syslog, err := log15.SyslogHandler(syslog.LOG_DEBUG, "FIDO", log15.TerminalFormat())
	if err == nil {
		logger.SetHandler( /*log15.MultiHandler(log15.StreamHandler(os.Stdout, log15.LogfmtFormat()),*/ syslog)
	}
}

func load() (CredentialStorage, error) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return nil, err
	}
	store := storage{}
	if aaguid != nil {
		store.aaguid, err = uuid.Parse(*aaguid)
		store.path = filepath.Join(dir, (*aaguid)+".dat")
	} else {
		return nil, errors.New("Missing AAGUID")
	}

	if _, err = os.Stat(store.path); os.IsNotExist(err) {
		return &store, nil
	} else if err != nil {
		return nil, err
	}
	var content []byte
	content, err = ioutil.ReadFile(store.path)
	if err != nil {
		return nil, err
	}
	err = LoadCBOR(content, &store.content)
	if err != nil {
		return nil, err
	}
	return &store, nil
}

// CredentialStorage Implementation
type storage struct {
	path    string
	content [][]byte
	aaguid  uuid.UUID
}

func (s *storage) Store(cred Credential) (err error) {
	if cred != nil {
		var data []byte
		data, err = cred.Serialise()
		if err != nil {
			return
		}
		if s.content == nil {
			s.content = make([][]byte, 0)
		}
		s.content = append(s.content, data)
		data, err = cbor.Dumps(s.content)
		if err != nil {
			return
		}
		err = ioutil.WriteFile(s.path, data, 0600)
		if err != nil {
			logger.Error("Failed to store", "error", err, "credential", base64.RawURLEncoding.EncodeToString(cred.Identifier()))
		}
	}
	return
}

func (s *storage) LoadAll() [][]byte {
	if s.content != nil {
		return s.content
	} else {
		return make([][]byte, 0)
	}
}
func (s *storage) AAGUID() uuid.UUID {
	return s.aaguid
}

func NewDoneChannel(restart <-chan struct{}, errorChan <-chan error) <-chan struct{} {
	//Global Done Channel
	done := make(chan struct{})
	go func(d chan struct{}) {
		defer close(d)

		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc,
			os.Interrupt,
			os.Kill,
			syscall.SIGTERM,
			syscall.SIGHUP,
			syscall.SIGTERM,
			syscall.SIGQUIT)

		select {
		case <-restart:
			logger.Info("Handle Restart Event")
		case err := <-errorChan:
			logger.Error("Handle Fatal Error Event", "error", err)
			fmt.Printf("err %s\n", err)
		case sig := <-sigc:
			logger.Info("Handle Signal Event", "event", sig.String())
			fmt.Printf("err %s\n", sig.String())
		}

	}(done)
	return done
}

func main() {

	//Open Persistent Storage
	store, err := load()
	if err != nil {
		log.Fatalln(err)
	}

	//Global Stop Channel
	stopChan := make(chan struct{})
	//Global Fatal Error Channel
	errorChan := make(chan error)

	done := NewDoneChannel(stopChan, errorChan)

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Fatalln(err)
	}
	defer g.Close()

	auth, err := NewAuthenticator(store, CredentialSelectorUIFunc(done, g), CredentialApproverUIFunc(done, g))
	if err != nil {
		log.Fatalln(err)
	}

	g.SelBgColor = gocui.ColorRed
	g.SelFgColor = gocui.ColorWhite
	g.BgColor = gocui.ColorBlack
	g.FgColor = gocui.ColorWhite
	g.Highlight = true

	g.Cursor = false
	g.Mouse = false
	g.SetManagerFunc(layout)
	layout(g)

	if err := initKeybindings(g); err != nil {
		log.Fatalln(err)
	}

	if err := g.SetKeybinding("log", 's', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		///TEST

		logger.Info("Call create")

		//Given
		challenge := []byte("Challenge received from OpenAM/IEC")
		rpId := "oJRS5JP9Bob8q4H8PXfe3UQipqaUvHPhB"

		//Client
		var authenticatorExtensions map[string]interface{}

		//			authenticatorExtensions = map[string]interface{}{"id": "value"}
		hs := sha256.New()
		clientDataJSON, _ := json.Marshal(map[string]interface{}{
			"challenge":               base64.RawURLEncoding.EncodeToString(challenge),
			"origin":                  rpId,        //The unicode serialization of rpId
			"hashAlg":                 "SHA-256",   //http://www.w3.org/TR/WebCryptoAPI/#sha-registration
			"tokenBinding":            "something", //IEC Auth ChallengeResponse?
			"clientExtensions":        map[string]interface{}{"id": "value"},
			"authenticatorExtensions": authenticatorExtensions,
		})
		hs.Write(clientDataJSON)

		clientDataHash := hs.Sum(nil)

		params := []map[string]string{
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
		}

		///TEST

		go func() {
			att, err := auth.MakeCredential(rpId, clientDataHash,
				&PublicKeyCredentialEntity{
					Id:   rpId,
					Name: "Car Name",
				}, &PublicKeyCredentialUserEntity{
					Id:          "userId",
					Name:        "laszlo.hordos@forgerock.com",
					DisplayName: "Laszlo Hordos",
				}, params, nil, authenticatorExtensions, false)
			if err != nil {
				logger.Error("MakeCredential Error", "error", err)
			} else {
				logger.Error("MakeCredential OK", "assertionObject", hex.EncodeToString(att))
				logger.Error("MakeCredential OK", "clientDataJSON", hex.EncodeToString(clientDataJSON))
			}
		}()

		return nil
	}); err != nil {
		log.Fatalln(err)
	}

	if err := g.SetKeybinding("log", 'a', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		///TEST

		logger.Info("Call Assert")

		//Given
		challenge := []byte("Challenge received from OpenAM/IEC")
		rpId := "oJRS5JP9Bob8q4H8PXfe3UQipqaUvHPhB"

		//Client
		var authenticatorExtensions map[string]interface{}

		//			authenticatorExtensions = map[string]interface{}{"id": "value"}
		hs := sha256.New()
		clientDataJSON, _ := json.Marshal(map[string]interface{}{
			"challenge":               base64.RawURLEncoding.EncodeToString(challenge),
			"origin":                  rpId,        //The unicode serialization of rpId
			"hashAlg":                 "SHA-256",   //http://www.w3.org/TR/WebCryptoAPI/#sha-registration
			"tokenBinding":            "something", //IEC Auth ChallengeResponse?
			"clientExtensions":        map[string]interface{}{"id": "value"},
			"authenticatorExtensions": authenticatorExtensions,
		})
		hs.Write(clientDataJSON)

		clientDataHash := hs.Sum(nil)

		///TEST

		go func() {

			id, authenticatorData, signature, err := auth.GetAssertion(rpId, clientDataHash, nil, authenticatorExtensions)

			if err != nil {
				logger.Error("GetAssertion Error", "error", err)
			} else {
				logger.Error("GetAssertion OK", "Id", hex.EncodeToString(id))
				logger.Error("GetAssertion OK", "authenticatorData", hex.EncodeToString(authenticatorData))
				logger.Error("GetAssertion OK", "signature", hex.EncodeToString(signature))
				logger.Error("GetAssertion OK", "clientDataJSON", hex.EncodeToString(clientDataJSON))
			}
		}()

		return nil
	}); err != nil {
		log.Fatalln(err)
	}

	if err := <-BLE(done, auth, store); err != nil {
		select {
		case errorChan <- err:
		case <-done:
		}
	}

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		select {
		case errorChan <- err:
		case <-done:
		}

	} else {
		select {
		case stopChan <- struct{}{}:
		case <-done:
		}
	}
}
