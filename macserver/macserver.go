package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/pkteer/tpm-util/mac"
)

func getTpm() io.ReadWriteCloser {
	t, e := tpm2.OpenTPM("/dev/tpmrm0")
	if e != nil {
		panic(e)
	}
	return t
}

func readFile(file string) string {
	var f *os.File
	if file == "-" {
		f = os.Stdin
	} else {
		ff, e := os.Open(file)
		if e != nil {
			panic(e)
		}
		f = ff
		defer f.Close()
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(f)
	return buf.String()
}

func hmacServer(t io.ReadWriter, hmacKeyFile string) {
	hmacer, e := mac.MakeHmacer(t, readFile(hmacKeyFile))
	if e != nil {
		panic(e)
	}
	http.HandleFunc("/hmac", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 0, 1024)
		l, e := r.Body.Read(buf)
		if e != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "error reading request: %v", e)
			return
		}
		if l > 128 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "request too long")
			return
		}
		if b, e := hmacer.Hmac(buf[:l]); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error computing hmac: %v", e)
			return
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(b))
		}
	})
}

func hmacImportKey(t io.ReadWriter, hmacKeyFile string) {
	r, e := mac.ImportKey(t, readFile(hmacKeyFile))
	if e != nil {
		panic(e)
	}
	fmt.Println(r)
}

func main() {
	t := getTpm()
	cmd := ""
	if len(os.Args) > 2 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "import":
		hmacImportKey(t, os.Args[2])
	case "serv":
		hmacServer(t, os.Args[2])
	default:
		fmt.Println("usage: macserver [import|serv] filename")
	}

	t.Close()
}
