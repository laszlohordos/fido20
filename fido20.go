package main

import (
	cbor "bitbucket.org/bodhisnarkva/cbor/go"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/square/go-jose"

	"strings"
	"sync"
)

type (
	Flag byte

	Authenticator interface {
		MakeCredential(rpId string,
			clientDataHash []byte,
			relyingParty *PublicKeyCredentialEntity,
			user *PublicKeyCredentialUserEntity,
			normalizedParameters []map[string]string,
			excludeList [][]byte,
			extensions map[string]interface{},
			requireResidentKey bool) (attestationObject []byte, err error)

		GetAssertion(rpId string,
			clientDataHash []byte,
			whiteList [][]byte,
			extensions map[string]interface{}) (identifier, authenticatorData, signature []byte, err error)
	}

	Credential interface {
		Identifier() []byte
		RelyingParty() *PublicKeyCredentialEntity
		User() *PublicKeyCredentialUserEntity
		Serialise() ([]byte, error)
	}

	CredentialStorage interface {
		Store(Credential) error
		LoadAll() [][]byte
		AAGUID() uuid.UUID
	}

	CredentialSelector func([]Credential) Credential
	CredentialApprover func(Credential) bool

	authenticator struct {
		sync.RWMutex
		sorage      CredentialStorage
		aauid       uuid.UUID
		counter     uint32
		credentials map[string]*publicCredentialHandler
		selector    CredentialSelector
		approver    CredentialApprover
	}

	publicCredentialHandler struct {
		idb        []byte
		Id         string                         `json:"id"`
		Rp         *PublicKeyCredentialEntity     `json:"rp"`
		UserEntity *PublicKeyCredentialUserEntity `json:"user"`
		PrivateKey jose.JsonWebKey                `json:"key"`
	}
)

const (
	TUP Flag = 1 << iota
	UV
	RES2
	RES3
	RES4
	RES5
	AT
	ED
)

func (c *publicCredentialHandler) Identifier() []byte {
	return c.idb
}
func (c *publicCredentialHandler) identity() string {
	if c.Id == "" {
		c.Id = base64.RawURLEncoding.EncodeToString(c.idb)
	}
	return c.Id
}
func (c *publicCredentialHandler) RelyingParty() *PublicKeyCredentialEntity {
	return c.Rp
}
func (c *publicCredentialHandler) User() *PublicKeyCredentialUserEntity {
	return c.UserEntity
}

func (c *publicCredentialHandler) marshalPublicCredential() ([]byte, error) {

	switch key := c.PrivateKey.Key.(type) {
	case *ecdsa.PrivateKey:
		if key.Curve == nil || key.X == nil || key.Y == nil || key.D == nil {
			return nil, errors.New("Invalid EC Key")
		}
		//"ES256" / "ES384" / "ES512"
		return cbor.Dumps(map[string]interface{}{
			"alg": c.PrivateKey.Algorithm,
			"x":   key.PublicKey.X.Bytes(),
			"y":   key.PublicKey.Y.Bytes(),
		})
	case *rsa.PrivateKey:
		if key.N == nil || key.E == 0 || key.D == nil || len(key.Primes) < 2 {
			return nil, errors.New("Invalid RSA Key")
		}
		//"RS256" / "RS384" / "RS512" / "PS256" / "PS384" / "PS512"
		return cbor.Dumps(map[string]interface{}{
			"alg": c.PrivateKey.Algorithm,
			"n":   key.PublicKey.N.Bytes(),
			"e":   uint64(key.PublicKey.E),
		})
	default:
		return nil, fmt.Errorf("Unsupported privateKey %T", c.PrivateKey.Key)
	}
}

func (c *publicCredentialHandler) Serialise() ([]byte, error) {
	return json.MarshalIndent(*c, "", "  ")
}

func (k *publicCredentialHandler) deSerialise(data []byte) (err error) {
	if data != nil && len(data) > 32 {
		err = json.Unmarshal(data, k)
		if err == nil {
			k.idb, err = base64.RawURLEncoding.DecodeString(k.Id)
		}
	} else {
		err = errors.New("Invalid input")
	}
	return
}

func (c *publicCredentialHandler) sign(payload []byte) ([]byte, *string, error) {

	switch key := c.PrivateKey.Key.(type) {
	case *ecdsa.PrivateKey:
		var expectedBitSize int
		var hash crypto.Hash

		switch c.PrivateKey.Algorithm {
		case "ES256":
			expectedBitSize = 256
			hash = crypto.SHA256
		case "ES384":
			expectedBitSize = 384
			hash = crypto.SHA384
		case "ES512":
			expectedBitSize = 521
			hash = crypto.SHA512
		}

		curveBits := key.Curve.Params().BitSize
		if expectedBitSize != curveBits {
			return nil, nil, fmt.Errorf("expected %d bit key, got %d bits instead", expectedBitSize, curveBits)
		}

		hasher := hash.New()

		// According to documentation, Write() on hash never fails
		_, _ = hasher.Write(payload)
		hashed := hasher.Sum(nil)

		r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			return nil, nil, err
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		// We serialize the outpus (r and s) into big-endian byte arrays and pad
		// them with zeros on the left to make sure the sizes work out. Both arrays
		// must be keyBytes long, and the output must be 2*keyBytes long.
		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)

		return out, &c.PrivateKey.Algorithm, nil
	case *rsa.PrivateKey:
		var hash crypto.Hash

		switch c.PrivateKey.Algorithm {
		case "RS256", "PS256":
			hash = crypto.SHA256
		case "RS384", "PS384":
			hash = crypto.SHA384
		case "RS512", "PS512":
			hash = crypto.SHA512
		default:
			return nil, nil, fmt.Errorf("Unsupported alg %s", c.PrivateKey.Algorithm)
		}

		hasher := hash.New()

		// According to documentation, Write() on hash never fails
		_, _ = hasher.Write(payload)
		hashed := hasher.Sum(nil)

		var out []byte
		var err error

		switch c.PrivateKey.Algorithm {
		case "RS256", "RS384", "RS512":
			out, err = rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
		case "PS256", "PS384", "PS512":
			out, err = rsa.SignPSS(rand.Reader, key, hash, hashed, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
			})
		}
		if err != nil {
			return nil, nil, err
		}
		return out, &c.PrivateKey.Algorithm, nil
	default:
		return nil, nil, fmt.Errorf("Unsupported privateKey %T", c.PrivateKey.Key)
	}

}

func NewDefaultAuthenticator() Authenticator {
	auth, _ := NewAuthenticator(nil, nil, nil)
	return auth
}

func NewAuthenticator(storage CredentialStorage, selector CredentialSelector, approver CredentialApprover) (Authenticator, error) {
	a := authenticator{
		counter:     0,
		credentials: make(map[string]*publicCredentialHandler),
	}

	if storage == nil {
		a.aauid = uuid.New()

	} else {
		a.aauid = storage.AAGUID()
		a.sorage = storage
	}

	if selector == nil {
		a.selector = func(creds []Credential) Credential {
			if creds != nil && len(creds) > 0 {
				return creds[0]
			}
			return nil
		}
	} else {
		a.selector = selector
	}

	if approver == nil {
		a.approver = func(creds Credential) bool {
			return true
		}
	} else {
		a.approver = approver
	}

	return a.open()
}

func (b authenticator) open() (Authenticator, error) {
	if b.sorage != nil {
		b.Lock()
		defer b.Unlock()
		for _, data := range b.sorage.LoadAll() {
			cred := &publicCredentialHandler{}

			err := cred.deSerialise(data)
			if err != nil {
				return nil, err
			}
			b.credentials[cred.identity()] = cred
		}
	}
	return &b, nil
}

//https://w3c.github.io/webauthn/#authenticator-ops
func (b *authenticator) MakeCredential(rpId string,
	clientDataHash []byte,
	relyingParty *PublicKeyCredentialEntity,
	user *PublicKeyCredentialUserEntity,
	normalizedParameters []map[string]string,
	excludeList [][]byte,
	extensions map[string]interface{},
	requireResidentKey bool) (attestationObject []byte, err error) {
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

	/*
		On successful completion of this operation, the authenticator returns the attestation object to the client.
	*/
	var c *publicCredentialHandler

	if c, err = b.findExistingCredential(relyingParty.Id, user.Id, excludeList); err != nil {
		return
	} else if c != nil {
		err = fmt.Errorf("Existing Credential %s %s", relyingParty.Id, user.Id)
		return
	}

	extensionsResult := make(map[string]interface{})

	for extId, input := range extensions {
		extensionsResult[extId] = input
	}

	if normalizedParameters == nil || len(normalizedParameters) == 0 {
		normalizedParameters = []map[string]string{map[string]string{
			"alg": "P-521",
			"op":  "generateKey",
		}}
	}

	if c, err = b.createCredential(rpId, relyingParty, user, normalizedParameters); err == nil {

		var flag Flag = 0
		var signBase, signature, attStmt []byte
		var alg *string

		signBase, err = b.generateSignData(rpId, clientDataHash, flag, c, extensionsResult)
		if err != nil {
			return
		}
		signature, alg, err = c.sign(signBase)
		if err != nil {
			return
		}
		attStmt, err = cbor.Dumps(map[string]interface{}{
			"alg": alg,
			"sig": signature,
			/*"x5c" : [][]byte{},
			"daaKey" : "",*/
		})
		if err != nil {
			return
		}
		attestationObject, err = cbor.Dumps(map[string]interface{}{
			"authData": signBase[:len(signBase)-len(clientDataHash)],
			"fmt":      "packed",
			"attStmt":  attStmt,
		})
		if err != nil {
			return
		}
		if b.sorage != nil {
			err = b.sorage.Store(c)
		}
	}
	return
}

func (a *authenticator) findExistingCredential(rp, user string, blackList [][]byte) (*publicCredentialHandler, error) {
	a.RLock()
	defer a.RUnlock()

	if blackList != nil {
		for _, id := range blackList {
			ids := base64.RawURLEncoding.EncodeToString(id)
			if _, ok := a.credentials[ids]; ok {
				return nil, fmt.Errorf("Blacklisted credential %s", ids)
			}
		}
	} else {
		for _, c := range a.credentials {
			if c.RelyingParty().Id == rp && c.User().Id == user {
				return c, nil
			}

		}
	}
	return nil, nil
}

func (a *authenticator) createCredential(rpid string, rp *PublicKeyCredentialEntity, user *PublicKeyCredentialUserEntity, params []map[string]string) (cred *publicCredentialHandler, err error) {
	a.Lock()
	defer a.Unlock()
	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		return
	}
	//id := base64.RawURLEncoding.EncodeToString(idb)

	cred = &publicCredentialHandler{
		idb:        id,
		Rp:         rp,
		UserEntity: user,
		PrivateKey: jose.JsonWebKey{},
	}

	if a.approver(cred) {

		for _, v := range params {
			if alg, ok := v["alg"]; ok {

				var privateKey interface{}

				if strings.EqualFold("P-521", alg) {
					privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					if err != nil {
						return
					}
					cred.PrivateKey.Algorithm = "ES512"
					cred.PrivateKey.Key = privateKey
					a.credentials[cred.identity()] = cred
					return
				} else if strings.EqualFold("P-384", alg) {
					privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						return
					}
					cred.PrivateKey.Algorithm = "ES384"
					cred.PrivateKey.Key = privateKey
					a.credentials[cred.identity()] = cred
					return
				} else if strings.EqualFold("P-256", alg) {
					privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						return
					}
					cred.PrivateKey.Algorithm = "ES256"
					cred.PrivateKey.Key = privateKey
					a.credentials[cred.identity()] = cred
					return
				}
			}
		}
		err = errors.New("Not found any supported alg")
	} else {
		err = errors.New("User not approved")
	}
	return
}

func (b *authenticator) GetAssertion(rpId string,
	clientDataHash []byte,
	whiteList [][]byte,
	extensions map[string]interface{}) (identifier, authenticatorData, signature []byte, err error) {
	/*
	   The caller’s RP ID, as determined by the user agent and the client.
	   The hash of the serialized client data, provided by the client.
	   A list of credentials acceptable to the Relying Party (possibly filtered by the client).
	   Extension data created by the client based on the extensions requested by the Relying Party.
	*/

	if c := b.selectCredential(rpId, whiteList); c != nil {

		var signBase []byte

		extensionsResult := make(map[string]interface{})

		for extId, input := range extensions {
			extensionsResult[extId] = input
		}

		var flag Flag = 0

		/*The identifier of the credential used to generate the signature.
		  The authenticator data used to generate the signature.
		  The assertion signature.
		*/
		signBase, err = b.generateSignData(rpId, clientDataHash, flag, nil, extensions)
		identifier = c.Identifier()
		authenticatorData = signBase[:len(signBase)-len(clientDataHash)]
		signature, _, err = c.sign(signBase)
	} else {
		err = fmt.Errorf("No Credential found rpid=%s", rpId)
	}
	return
}

func (a *authenticator) selectCredential(rp string, whiteList [][]byte) *publicCredentialHandler {
	a.RLock()
	defer a.RUnlock()
	candidates := make([]Credential, 0)

	if whiteList != nil {
		for _, id := range whiteList {
			if c, ok := a.credentials[base64.RawURLEncoding.EncodeToString(id)]; ok {
				if c.RelyingParty().Id == rp {
					candidates = append(candidates, c)
				}
			}
		}
	} else {
		for _, c := range a.credentials {
			if c.RelyingParty().Id == rp {
				candidates = append(candidates, c)
			}

		}
	}

	selected := a.selector(candidates)
	if selected != nil {
		for _, c := range candidates {
			if bytes.Equal(c.Identifier(), selected.Identifier()) {
				return c.(*publicCredentialHandler)
			}
		}
	}
	return nil
}

func (a *authenticator) generateSignData(rpId string, clientDataHAsh []byte, flag Flag, credential *publicCredentialHandler, extensions map[string]interface{}) ([]byte, error) {
	a.Lock()
	defer a.Unlock()
	var b bytes.Buffer

	hs := sha256.New()
	if _, err := hs.Write([]byte(rpId)); err != nil {
		return nil, err
	}

	//rpId
	b.Write(hs.Sum(nil))
	if extensions != nil && len(extensions) > 0 {
		flag = flag | ED
	}

	if credential != nil {
		flag = flag | AT
	}
	//flag
	b.WriteByte((byte)(flag))
	//counter
	a.counter += a.counter
	var num []byte
	num = make([]byte, 4)
	binary.BigEndian.PutUint32(num, a.counter)
	b.Write(num)

	//attestation Data
	if flag&AT == AT {
		credentialPublicKey, err := credential.marshalPublicCredential()
		if err != nil {
			return nil, err
		}
		//aaguid
		for _, idb := range a.aauid {
			b.WriteByte(idb)
		}
		//L
		num = make([]byte, 2)
		binary.BigEndian.PutUint16(num, uint16(len(credential.Identifier())))
		b.Write(num)
		//credentialId
		b.Write(credential.Identifier())
		//credentialPublicKey
		b.Write(credentialPublicKey)
	}

	if flag&ED == ED {
		ex, err := cbor.Dumps(extensions)
		if err != nil {
			return nil, err
		}
		b.Write(ex)
	}
	b.Write(clientDataHAsh)
	return b.Bytes(), nil

}

func LoadCBOR(blob []byte, v interface{}) error {
	e := make(chan error, 1)

	if err := loadCBORSafe(blob, v, e); err != nil {
		return err

	}
	return <-e
}

func loadCBORSafe(blob []byte, v interface{}, e chan<- error) error {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				e <- err
			} else if msg, ok := r.(string); ok {
				e <- errors.New(msg)
			} else {
				e <- fmt.Errorf("CBOR Panic %s", r)
			}

		}
		close(e)
	}()
	return cbor.Loads(blob, v)
}
