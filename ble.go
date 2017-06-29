package main

import (
	"bitbucket.org/bodhisnarkva/cbor/go"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/paypal/gatt"
	"sync"
)

const (
	authenticatorMakeCredential byte = 0x01
	authenticatorGetAssertion   byte = 0x02
	authenticatorCancel         byte = 0x03
	authenticatorGetInfo        byte = 0x04
	successCode                 byte = 0x00
)

var (
	attrGAPUUID = gatt.UUID16(0x1800)

	attrDeviceNameUUID        = gatt.UUID16(0x2A00)
	attrAppearanceUUID        = gatt.UUID16(0x2A01)
	attrPeripheralPrivacyUUID = gatt.UUID16(0x2A02)
	//https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.gap.reconnection_address.xml
	attrReconnectionAddrUUID = gatt.UUID16(0x2A03)
	attrPeferredParamsUUID   = gatt.UUID16(0x2A04)
	attrGATTUUID             = gatt.UUID16(0x1801)
	attrServiceChangedUUID   = gatt.UUID16(0x2A05)
	// https://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicViewer.aspx?u=org.bluetooth.characteristic.gap.appearance.xml
	gapCharAppearanceGenericComputer = []byte{0x00, 0x80}
)

type (
	StoreEntry struct {
		Central  gatt.Central
		Notifier gatt.Notifier
		Receiver chan *Request
	}

	CentralStore struct {
		sync.RWMutex
		m map[string]*StoreEntry
	}

	bleRequest struct {
		central gatt.Central
		message *Request
	}

	broadcast struct {
		c chan *broadcast
		v *bleRequest
	}

	/*
		The caller’s RP ID, as determined by the user agent and the client.
		The hash of the serialized client data, provided by the client.
		The relying party's PublicKeyCredentialEntity.
		The user account’s PublicKeyCredentialEntity.
		The PublicKeyCredentialType and cryptographic parameters requested by the Relying Party, with the cryptographic algorithms normalized as per the procedure in Web Cryptography API §algorithm-normalization-normalize-an-algorithm.
		A list of PublicKeyCredential objects provided by the Relying Party with the intention that, if any of these are known to the authenticator, it should not create a new credential.
		Extension data created by the client based on the extensions requested by the Relying Party.
		The requireResidentKey parameter of the options.authenticatorSelection dictionary.
	*/
	authenticatorMakeCredentialRequest struct {
		rpId                 string
		clientDataHash       []byte
		rp                   *PublicKeyCredentialEntity
		user                 *PublicKeyCredentialUserEntity
		normalizedParameters []map[string]string
		blacklist            [][]byte
		extensions           map[string]interface{}
		requireResidentKey   bool
	}

	/*
		On successful completion of this operation, the authenticator returns the attestation object to the client.
	*/
	authenticatorMakeCredentialResponse struct {
		AuthData []byte `json:"authData,omitempty"`
		Fmt      string `json:"fmt,omitempty"`
		AttStmt  []byte `json:"attStmt,omitempty"`
	}

	/*
		The caller’s RP ID, as determined by the user agent and the client.
		The hash of the serialized client data, provided by the client.
		A list of credentials acceptable to the Relying Party (possibly filtered by the client).
		Extension data created by the client based on the extensions requested by the Relying Party.
	*/
	authenticatorGetAssertionRequest struct {
		rpId           string
		clientDataHash []byte
		whiteList      [][]byte
		extensions     map[string]interface{}
	}

	/*
		The identifier of the credential used to generate the signature.
		The authenticator data used to generate the signature.
		The assertion signature.
	*/
	authenticatorGetAssertionResponse struct {
		credential        []byte
		authenticatorData []byte
		signature         []byte
	}

	Op struct {
		action func()
		cancel func(cancel bool)
	}
)

var centralStore = &CentralStore{
	m: make(map[string]*StoreEntry),
}

func (s *CentralStore) Send(id string, response *Response) error {
	s.RLock()
	defer s.RUnlock()
	if e, ok := s.m[id]; ok {
		if e.Notifier == nil {
			logger.Debug("Notifier is not available", "mac", id)
		} else if e.Notifier.Done() {
			logger.Debug("Notifier is done", "mac", id)
		} else {
			for _, frame := range response.Process(e.Notifier.Cap()) {
				_, err := e.Notifier.Write(frame)
				if err != nil {
					logger.Info("Write BLE->NOK", "mac", id, "err", err, "data", hex.EncodeToString(frame))
					return err
				}
				logger.Info("Write BLE->OK", "mac", id, "data", hex.EncodeToString(frame))
			}
		}
	}
	return nil
}

func executeMessage(r *bleRequest, authenticator Authenticator, storage CredentialStorage) {
	var resp []byte
	//var err error

	switch r.message.cmd {
	case PING:
		centralStore.Send(r.central.ID(), &Response{
			Status: PING,
			Data:   r.message.data,
		})
	case KEEPALIVE:

	case MSG:
		if len(r.message.data) > 0 {
			switch r.message.data[0] {
			case authenticatorMakeCredential:

				req := &authenticatorMakeCredentialRequest{}
				ferr := req.FromCBOR(r.message.data[1:])
				if ferr != nil {
					fmt.Printf("ERROR %s\n", ferr)
					centralStore.Send(r.central.ID(), ferr.ToResponse())
					return
				}

				attestationObject, err := authenticator.MakeCredential(req.rpId, req.clientDataHash, req.rp, req.user, req.normalizedParameters, req.blacklist, req.extensions, req.requireResidentKey)
				if err != nil {
					fmt.Printf("ERROR %s\n", err)
					centralStore.Send(r.central.ID(), (&FidoError{code: ERR_OTHER}).ToResponse())
					return
				}

				resp, _ := cbor.Dumps(map[byte]interface{}{
					0x01: attestationObject,
				})
				centralStore.Send(r.central.ID(), &Response{
					Status: successCode,
					Data:   resp,
				})

			case authenticatorGetAssertion:

				req := &authenticatorGetAssertionRequest{}
				ferr := req.FromCBOR(r.message.data[1:])
				if ferr != nil {
					centralStore.Send(r.central.ID(), ferr.ToResponse())
					return
				}

				identifier, authenticatorData, signature, err := authenticator.GetAssertion(req.rpId, req.clientDataHash, req.whiteList, req.extensions)
				if err != nil {
					centralStore.Send(r.central.ID(), (&FidoError{code: ERR_OTHER}).ToResponse())
					return
				}

				resp, _ = cbor.Dumps(map[byte]interface{}{
					0x01: identifier,
					0x02: authenticatorData,
					0x03: signature,
				})

				centralStore.Send(r.central.ID(), &Response{
					Status: successCode,
					Data:   resp,
				})

			case authenticatorCancel:
			case authenticatorGetInfo:
				/*
					authenticatorGetInfo_Response
					versions	0x01	CBOR definite length array (CBOR major type 4) of UTF-8 encoded strings (CBOR major type 3).
					extensions	0x02	CBOR definite length array (CBOR major type 4) of UTF-8 encoded strings (CBOR major type 3).
					aaguid	0x03	CBOR UTF-8 encoded string (CBOR major type 3).
				*/
				resp, _ = cbor.Dumps(map[byte]interface{}{
					0x01: []string{"FIDO_2_0"},
					0x02: []string{"tup"},
					0x03: storage.AAGUID().String(),
				})

				centralStore.Send(r.central.ID(), &Response{
					Status: successCode,
					Data:   resp,
				})
			default:
				centralStore.Send(r.central.ID(), (&FidoError{code: ERR_OTHER}).ToResponse())
			}

		}
	default:
		centralStore.Send(r.central.ID(), (&FidoError{code: ERR_OTHER}).ToResponse())
	}
}

func NewFIDO11Service(done <-chan struct{}, authenticator Authenticator, storage CredentialStorage) *gatt.Service {

	//FIDO Service
	s := gatt.NewService(gatt.UUID16(0xFFFD))

	//sink := startProcessingInput(done)

	u2fControlPoint := s.AddCharacteristic(gatt.MustParseUUID("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB"))
	u2fControlPoint.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("Control Point"))
	u2fControlPoint.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{4, 0, 39, 00, 1, 0, 0})
	u2fControlPoint.HandleWriteFunc(func(bleR gatt.Request, data []byte) (status byte) {
		logger.Info("Receive BLE", "mac", bleR.Central.ID(), "data", hex.EncodeToString(data))

		centralStore.RLock()
		defer centralStore.RUnlock()
		entry, ok := centralStore.m[bleR.Central.ID()]
		if !ok {
			return gatt.StatusSuccess
		}

		select {
		case <-done:
		//Do nothing
		case r := <-entry.Receiver:
			hasMore, err := r.Receive(data)
			if err != nil {
				entry.Receiver <- &Request{}
				centralStore.Send(bleR.Central.ID(), err.ToResponse())
			}
			if hasMore {
				entry.Receiver <- r
				return
			} else {
				entry.Receiver <- &Request{}

				go executeMessage(&bleRequest{
					central: bleR.Central,
					message: r,
				}, authenticator, storage)
			}
		}

		return gatt.StatusSuccess
	})

	u2fStatus := s.AddCharacteristic(gatt.MustParseUUID("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB"))
	u2fStatus.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("Status"))
	u2fStatus.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{4, 0, 39, 00, 1, 0, 0})
	u2fStatus.HandleNotifyFunc(
		func(r gatt.Request, n gatt.Notifier) {
			centralStore.RLock()
			defer centralStore.RUnlock()
			e, ok := centralStore.m[r.Central.ID()]
			if ok {
				logger.Info("Add new Notifier", "Central", r.Central.ID())
				e.Notifier = n
			} else {
				logger.Info("Faield to add new Notifier", "Central", r.Central.ID())
			}
		})

	u2fControlPointLength := s.AddCharacteristic(gatt.MustParseUUID("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB"))
	u2fControlPointLength.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("ControlPointLength"))
	u2fControlPointLength.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{6, 0, 39, 00, 1, 0, 0})
	u2fControlPointLength.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			bs := make([]byte, 2)
			binary.BigEndian.PutUint16(bs, uint16(req.Cap))
			logger.Info("Read Max Capacity", "cap", req.Cap, "value", hex.EncodeToString(bs))
			rsp.Write(bs)
		})

	fido2ServiceRevision := s.AddCharacteristic(gatt.UUID16(0x2A28))
	fido2ServiceRevision.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("Fido20 ServiceRevision"))
	fido2ServiceRevision.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{6, 0, 39, 00, 1, 0, 0})
	fido2ServiceRevision.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			bs := make([]byte, 2)
			binary.BigEndian.PutUint16(bs, 20)
			logger.Info("Read Revision", "value", hex.EncodeToString(bs))
			rsp.Write(bs)
		})

	return s
}

//https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.service.user_data.xml
func NewUserDataService() *gatt.Service {
	s := gatt.NewService(gatt.UUID16(0x181C))
	firstName, lastName, email, language := []byte{}, []byte{}, []byte{}, []byte{}

	//https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.first_name.xml
	c := s.AddCharacteristic(gatt.UUID16(0x2A8A))
	c.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			rsp.Write(firstName)
		})
	c.HandleWriteFunc(func(r gatt.Request, data []byte) (status byte) {
		logger.Info("First Name", "hex", hex.EncodeToString(data), "value", string(data))
		firstName = data
		return gatt.StatusSuccess
	})
	// Characteristic User Description
	c.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("First name of the user"))
	c.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{25, 0, 39, 00, 1, 0, 0})

	//https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.last_name.xml
	c = s.AddCharacteristic(gatt.UUID16(0x2A90))
	c.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			rsp.Write(lastName)
		})
	c.HandleWriteFunc(func(r gatt.Request, data []byte) (status byte) {
		logger.Info("Last Name", "hex", hex.EncodeToString(data), "value", string(data))
		lastName = data
		return gatt.StatusSuccess
	})

	// Characteristic User Description
	c.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("Last name of the user"))
	c.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{25, 0, 39, 00, 1, 0, 0})

	//https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.email_address.xml
	c = s.AddCharacteristic(gatt.UUID16(0x2A87))
	c.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			rsp.Write(email)
		})
	c.HandleWriteFunc(func(r gatt.Request, data []byte) (status byte) {
		logger.Info("Email", "hex", hex.EncodeToString(data), "value", string(data))
		email = data
		return gatt.StatusSuccess
	})

	// Characteristic User Description
	c.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("Email of the user"))
	c.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{25, 0, 39, 00, 1, 0, 0})

	//https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.language.xml
	c = s.AddCharacteristic(gatt.UUID16(0x2AA2))
	c.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			rsp.Write(language)
		})
	c.HandleWriteFunc(func(r gatt.Request, data []byte) (status byte) {
		logger.Info("Language", "hex", hex.EncodeToString(data), "value", string(data))
		language = data
		return gatt.StatusSuccess
	})

	// Characteristic User Description
	c.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("The Language definition is based on ISO639-1"))

	// Characteristic Presentation Format
	//https://www.bluetooth.com/specifications/assigned-numbers/units
	//0x2700	unitless
	//25 - UTF-8 string (0x19)
	//0 -  0
	//39 - 27
	//00 - 00
	c.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{25, 0, 39, 00, 1, 0, 0})

	return s
}

func NewBatteryService() *gatt.Service {
	s := gatt.NewService(gatt.UUID16(0x180F))
	c := s.AddCharacteristic(gatt.UUID16(0x2A19))
	c.HandleReadFunc(
		func(rsp gatt.ResponseWriter, req *gatt.ReadRequest) {
			rsp.Write([]byte{byte(100)})
		})

	// Characteristic User Description
	c.AddDescriptor(gatt.UUID16(0x2901)).SetValue([]byte("Battery level between 0 and 100 percent"))

	// Characteristic Presentation Format
	c.AddDescriptor(gatt.UUID16(0x2904)).SetValue([]byte{4, 1, 39, 173, 1, 0, 0})

	return s
}

// NOTE: OS X provides GAP and GATT services, and they can't be customized.
// For Linux/Embedded, however, this is something we want to fully control.
func NewGapService(name string) *gatt.Service {
	s := gatt.NewService(attrGAPUUID)
	s.AddCharacteristic(attrDeviceNameUUID).SetValue([]byte(name))
	s.AddCharacteristic(attrAppearanceUUID).SetValue(gapCharAppearanceGenericComputer)
	s.AddCharacteristic(attrPeripheralPrivacyUUID).SetValue([]byte{0x01})
	s.AddCharacteristic(attrReconnectionAddrUUID).SetValue([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	s.AddCharacteristic(attrPeferredParamsUUID).SetValue([]byte{0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xd0, 0x07})
	return s
}

// NOTE: OS X provides GAP and GATT services, and they can't be customized.
// For Linux/Embedded, however, this is something we want to fully control.
func NewGattService() *gatt.Service {
	s := gatt.NewService(attrGATTUUID)
	s.AddCharacteristic(attrServiceChangedUUID).HandleNotifyFunc(
		func(r gatt.Request, n gatt.Notifier) {
			go func() {
				logger.Info("TODO: indicate client when the services are changed")
			}()
		})
	return s
}

func (c *authenticatorGetAssertionRequest) FromCBOR(blob []byte) *FidoError {

	var value map[byte]interface{}
	err := LoadCBOR(blob, &value)
	if err != nil {
		return &FidoError{code: ERR_INVALID_PAR, msg: err.Error()}
	}
	for k, v := range value {
		switch k {
		case 0x01:
			if in, ok := v.(string); ok {
				c.rpId = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: string", k, v)}
			}
		case 0x02:
			if in, ok := v.([]byte); ok {
				c.clientDataHash = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: []byte", k, v)}
			}
		case 0x03:
			if in, ok := v.([][]byte); ok {
				c.whiteList = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: string", k, v)}
			}
		case 0x04:
			if in, ok := v.(map[interface{}]interface{}); ok {
				c.extensions = make(map[string]interface{})
				for mk, mv := range in {
					if smk, ok := mk.(string); ok {
						c.extensions[smk] = mv
					} else {
						return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid key: %s type: %T expect: string", mk, mk)}
					}
				}
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value: %d type: %T expect: map", k, v)}
			}
		default:
			logger.Debug("Unknown Key and value", "key", hex.EncodeToString([]byte{k}), "value", v)

		}
	}
	return nil
}

/*MakeCredential(	1 rpId string,
2 clientDataHash []byte,
3 relyingParty *PublicKeyCredentialEntity,
4 user *PublicKeyCredentialUserEntity,
5 normalizedParameters []map[string]string,
6 excludeList [][]byte,
7 extensions map[string]interface{},
8 requireResidentKey bool) (attestationObject []byte, err error)*/

func (c *authenticatorMakeCredentialRequest) FromCBOR(blob []byte) *FidoError {

	var value map[byte]interface{}
	err := LoadCBOR(blob, &value)
	if err != nil {
		return &FidoError{code: ERR_INVALID_PAR, msg: err.Error()}
	}

	for k, v := range value {
		switch k {
		case 0x01:
			if in, ok := v.(string); ok {
				c.rpId = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value: %d type: %T expect: string", k, v)}
			}
		case 0x02:
			if in, ok := v.([]byte); ok {
				c.clientDataHash = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value: %d type: %T expect: []byte", k, v)}
			}
		case 0x03:
			if in, ok := v.(map[interface{}]interface{}); ok {
				c.rp = &PublicKeyCredentialEntity{}
				for ki, vi := range in {
					if ks, kgood := ki.(string); kgood {
						if vs, vgood := vi.(string); vgood {
							switch ks {
							case "id":
								c.rp.Id = vs
							case "name":
								c.rp.Name = vs
							}
						} else {
							return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value value: %s type: %T expect: string", vi, vi)}
						}
					} else {
						return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %s type: %T expect: string", ki, ki)}
					}
				}
				if c.rp.Id == "" {
					return &FidoError{code: ERR_INVALID_PAR, msg: "Missing 'rp.Id'"}
				}
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: map", k, v)}
			}
		case 0x04:
			if in, ok := v.(map[interface{}]interface{}); ok {
				c.user = &PublicKeyCredentialUserEntity{}
				for ki, vi := range in {
					if ks, kgood := ki.(string); kgood {
						if vs, vgood := vi.(string); vgood {
							switch ks {
							case "id":
								c.user.Id = vs
							case "name":
								c.user.Name = vs
							case "displayName":
								c.user.DisplayName = vs
							}
						} else {
							return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value value: %s type: %T expect: string", vi, vi)}
						}
					} else {
						return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %s type: %T expect: string", ki, ki)}
					}
				}
				if c.user.Id == "" {
					return &FidoError{code: ERR_INVALID_PAR, msg: "Missing 'user.Id'"}
				}
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: map", k, v)}
			}
		case 0x05:
			if in, ok := v.([]interface{}); ok {
				c.normalizedParameters = make([]map[string]string, 0)
				for _, vm := range in {
					if svm, ok := vm.(map[interface{}]interface{}); ok {
						var op, alg string
						for ki, vi := range svm {
							if ks, kgood := ki.(string); kgood {
								if vs, vgood := vi.(string); vgood {
									switch ks {
									case "op":
										op = vs
									case "alg":
										alg = vs
									}
								} else {
									return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value value: %s type: %T expect: string", vi, vi)}
								}
							} else {
								return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %s type: %T expect: string", ki, ki)}
							}
						}

						if op == "" || alg == "" {
							return &FidoError{code: ERR_INVALID_PAR, msg: "Missing 'op' and 'alg'"}
						}
						c.normalizedParameters = append(c.normalizedParameters, map[string]string{
							"alg": alg,
							"op":  op,
						})
					} else {
						return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: map", k, v)}
					}
				}

			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: []map[string]interface{}", k, v)}
			}
		case 0x06:
			if in, ok := v.([][]byte); ok {
				c.blacklist = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: [][]byte", k, v)}
			}
		case 0x07:
			if in, ok := v.(map[interface{}]interface{}); ok {
				c.extensions = make(map[string]interface{})
				for mk, mv := range in {
					if smk, ok := mk.(string); ok {
						c.extensions[smk] = mv
					} else {
						return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid key: %s type: %T expect: string", mk, mk)}
					}
				}
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value: %d type: %T expect: map", k, v)}
			}
		case 0x08:
			if in, ok := v.(bool); ok {
				c.requireResidentKey = in
			} else {
				return &FidoError{code: ERR_INVALID_PAR, msg: fmt.Sprintf("Invalid value key: %d type: %T expect: bool", k, v)}
			}
		default:
			logger.Debug("Unknown Key and value", "key", hex.EncodeToString([]byte{k}), "value", v)

		}
	}
	return nil
}
