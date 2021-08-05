package mac

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var defaultKeyParams = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagDecrypt | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
		tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
	AuthPolicy: []byte(""),
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		KeyBits: 2048,
	},
}

func ImportKey(rwc io.ReadWriter, secret string) (string, error) {
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{}}
	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, "", "", defaultKeyParams)
	if err != nil {
		return "", fmt.Errorf("Error creating Primary %v\n", err)
	}
	defer tpm2.FlushContext(rwc, pkh)
	public := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		AuthPolicy: []byte(""),
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagSign, // | tpm2.FlagSensitiveDataOrigin
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:  tpm2.AlgHMAC,
			Hash: tpm2.AlgSHA256,
		},
	}
	hmacKeyBytes := []byte(secret)
	privInternal, pubArea, _, _, _, err := tpm2.CreateKeyWithSensitive(
		rwc, pkh, pcrSelection, "", "", public, hmacKeyBytes)
	if err != nil {
		return "", fmt.Errorf("Error creating Sensitive %v\n", err)
	}
	newHandle, _, err := tpm2.Load(rwc, pkh, "", pubArea, privInternal)
	if err != nil {
		return "", fmt.Errorf("Error loading hash key %v\n", err)
	}
	defer tpm2.FlushContext(rwc, newHandle)
	ekhBytes, err := tpm2.ContextSave(rwc, newHandle)
	if err != nil {
		return "", fmt.Errorf("ContextSave failed for ekh %v\n", err)
	}
	return hex.EncodeToString(ekhBytes), nil
}

func MakeHmacer(tpm io.ReadWriter, key string) (*Hmacer, error) {
	ekh, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	newHandle, err := tpm2.ContextLoad(tpm, ekh)
	if err != nil {
		return nil, fmt.Errorf("ContextLoad failed for ekh: %v\n", err)
	}
	return &Hmacer{tpm, newHandle}, nil
}

type Hmacer struct {
	tpm    io.ReadWriter
	handle tpmutil.Handle
}

func (h *Hmacer) Hmac(dataIn []byte) ([]byte, error) {
	maxDigestBuffer := 1024
	//seqAuth := ""
	seq, err := HmacStart(h.tpm, "", h.handle, tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("Error  starting hash sequence %v\n", err)
	}
	defer tpm2.FlushContext(h.tpm, seq)

	for len(dataIn) > maxDigestBuffer {
		if err = tpm2.SequenceUpdate(h.tpm, "", seq, dataIn[:maxDigestBuffer]); err != nil {
			return nil, fmt.Errorf("Error  updating hash sequence %v\n", err)
		}
		dataIn = dataIn[maxDigestBuffer:]
	}

	digest, _, err := tpm2.SequenceComplete(h.tpm, "", seq, tpm2.HandleNull, dataIn)
	if err != nil {
		return nil, fmt.Errorf("Error  completing  hash sequence %v\n", err)
	}
	return digest, nil
}

func encodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

const CmdHmacStart tpmutil.Command = 0x0000015B

func HmacStart(rw io.ReadWriter, sequenceAuth string, handle tpmutil.Handle, hashAlg tpm2.Algorithm) (seqHandle tpmutil.Handle, err error) {

	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(sequenceAuth)})
	if err != nil {
		return 0, err
	}
	out, err := tpmutil.Pack(handle)
	if err != nil {
		return 0, err
	}
	Cmd, err := concat(out, auth)
	if err != nil {
		return 0, err
	}

	resp, err := runCommand(rw, tpm2.TagSessions, CmdHmacStart, tpmutil.RawBytes(Cmd), tpmutil.U16Bytes(sequenceAuth), hashAlg)
	if err != nil {
		return 0, err
	}
	var rhandle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &rhandle)
	return rhandle, err
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
}
