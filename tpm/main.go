package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/dchest/blake2b"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
)

func getPcrs(tpm io.ReadWriter, pcrs []int) map[int]string {
	if len(pcrs) > 8 {
		panic("can only print 8 pcrs at a time")
	}
	s := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: pcrs,
	}
	if values, err := tpm2.ReadPCRs(tpm, s); err != nil {
		panic(err)
	} else {
		out := make(map[int]string)
		for _, i := range pcrs {
			out[i] = hex.EncodeToString(values[i])
		}
		return out
	}
}

func printPcrs(tpm io.ReadWriter, pcrs []int) {
	values := getPcrs(tpm, pcrs)
	for _, i := range pcrs {
		fmt.Printf("PCR[%v] = %v\n", i, values[i])
	}
}

func getPcr(tpm io.ReadWriter, pcr int) string {
	pcrs := getPcrs(tpm, []int{pcr})
	return pcrs[pcr]
}

func extendPcr(tpm io.ReadWriter, pcr int, value []byte) {
	if e := tpm2.PCRExtend(tpm, tpmutil.Handle(pcr), tpm2.AlgSHA256, value, ""); e != nil {
		panic(e)
	}
}

func isZero(s string) bool {
	return s == "0000000000000000000000000000000000000000000000000000000000000000"
}

func pcrZero(tpm io.ReadWriter, n int) bool {
	return isZero(getPcr(tpm, n))
}

// /mnt/x/pkteer/k/ts/k.txt
// /mnt/x/pkteer/t/k.txt
// /mnt/x/pkteer/d/...
// /tmp/pkteer/k.txt

func assertInit(t io.ReadWriter) {
	if pcrZero(t, 16) {
		panic("pcr16 is zero, not yet initialized")
	}
}

func initialize(t io.ReadWriter) {
	fmt.Println("Initializing")
	if !pcrZero(t, 16) {
		panic("already initialized")
	}
	rand, e := tpm2.GetRandom(t, 32)
	if e != nil {
		panic(e)
	}
	extendPcr(t, 16, rand)
}

func getTpm() io.ReadWriteCloser {
	t, e := tpm2.OpenTPM("/dev/tpmrm0")
	if e != nil {
		panic(e)
	}
	return t
}

func rootKey(t io.ReadWriter) *tpm2tools.Key {
	if k, e := tpm2tools.StorageRootKeyRSA(t); e != nil {
		panic(e)
	} else {
		return k
	}
}

func tpmId(t io.ReadWriter) string {
	k := rootKey(t)
	pk := k.PublicKey().(*rsa.PublicKey)
	hash := blake2b.New256()
	eBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(eBytes, uint64(pk.E))
	hash.Write(eBytes)
	hash.Write(pk.N.Bytes())
	return hex.EncodeToString(hash.Sum(nil))
}

func encrypt(t io.ReadWriter, b []byte) string {
	k := rootKey(t)
	// do not depend on PCR 1, the bios randomly changes it
	// when it changes the boot order without warning.
	sel := tpm2tools.SealCurrent{
		PCRSelection: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{
				0 /*1,*/, 2, 3, 4, 5, 6, 7,
				8, 9, 10, 11, 12, 13, 14, 15},
		},
	}
	sealed, e := k.Seal(b, sel)
	if e != nil {
		panic(e)
	}
	m, e := proto.Marshal(sealed)
	if e != nil {
		panic(e)
	}
	return base64.RawStdEncoding.EncodeToString(m)
}

func decrypt(t io.ReadWriter, s string) []byte {
	k := rootKey(t)
	m, e := base64.RawStdEncoding.DecodeString(s)
	if e != nil {
		panic(e)
	}
	var sealed tpmpb.SealedBytes
	if e := proto.Unmarshal(m, &sealed); e != nil {
		panic(e)
	}
	us, e := k.Unseal(&sealed, nil)
	if e != nil {
		panic(e)
	}
	return us
}

func pcrMac(t io.ReadWriter, n int, str string) string {
	pcr := getPcr(t, n)
	if isZero(pcr) {
		panic(fmt.Sprintf("PCR[%v] is zero, not yet initialized", n))
	}
	b2 := blake2b.NewMAC(32, []byte(pcr))
	_, e := b2.Write([]byte(str))
	if e != nil {
		panic(e)
	}
	return hex.EncodeToString(b2.Sum(nil))
}

// OS_A
// 1. PCR[16] = random()
// 2. sec = request_permit( sess: PCR[16], id: tpm_id() )
// 3. mount /mnt/boot2/
// 4. PCR[10] = H( sec, tpm_decrypt("/mnt/boot2/tpm_sec.txt", PCR[0..15]) )
// 5. decrypt( "/mnt/boot2/pkteer/", H(sec, pcr[10]) )
// 6. launch OS_B

// 1. tpm init
// 2. tpm sess, tpm id "PERMIT"
// 5. tpm decryptsec "/mnt/boot2/pkteer/secret.txt" sec

// OS_B
// 1. sec = request_permit( sess: PCR[16], id: H("PERMIT", PCR[10]) )
// 2. mount /mnt/dat/
// 3. hdd_key = decrypt( "/mnt/dat/pkteer/k/st/k.txt", H(sec, PCR[10]) )
// 4. decrypt( "/mnt/dat/pkteer/d/", hdd_key )

// 1. tpm sess, tpm sec "PERMIT"
// 3. tpm sec $server_secret
func sess(t io.ReadWriter) string {
	assertInit(t)
	return getPcr(t, 16)
}

func sec(t io.ReadWriter, key string) string {
	assertInit(t)
	return pcrMac(t, 10, key)
}

func id(t io.ReadWriter, str string) string {
	mac := blake2b.NewMAC(32, []byte(tpmId(t)))
	mac.Write([]byte(str))
	return hex.EncodeToString(mac.Sum(nil))
}

func decryptsec(t io.ReadWriter, file string, key string) {
	assertInit(t)
	b, e := ioutil.ReadFile(file)
	if e != nil {
		panic(e)
	}
	sec := decrypt(t, string(b))
	mac := blake2b.NewMAC(32, sec)
	mac.Write([]byte(key))
	extendPcr(t, 10, mac.Sum(nil))
	fmt.Fprintln(os.Stderr, "Secret placed in PCR 10")
}

func mksec(t io.ReadWriter) {
	rand, e := tpm2.GetRandom(t, 32)
	if e != nil {
		panic(e)
	}
	fmt.Print(encrypt(t, rand))
}

func main() {
	t := getTpm()
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "init":
		initialize(t)
	case "sess":
		fmt.Println(sess(t))
	case "sec":
		if len(os.Args) < 3 {
			panic("must specify key")
		}
		fmt.Println(sec(t, os.Args[2]))
	case "id":
		if len(os.Args) < 3 {
			panic("must specify key")
		}
		fmt.Println(id(t, os.Args[2]))
	case "decryptsec":
		if len(os.Args) < 4 {
			panic("must specify file and key")
		}
		decryptsec(t, os.Args[2], os.Args[3])
	case "mksec":
		mksec(t)
	default:
		printPcrs(t, []int{0, 1, 2, 3, 4, 5, 6, 7})
		printPcrs(t, []int{8, 9, 10, 11, 12, 13, 14, 15})
		printPcrs(t, []int{16, 17, 18, 19, 20, 21, 22, 23})
	}

	t.Close()
}
