package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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

func hmacServer(t io.ReadWriter, hmacKeyFile string, bind string) {
	hmacer, e := mac.MakeHmacer(t, strings.TrimSpace(readFile(hmacKeyFile)))
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
		time0 := time.Now()
		if b, e := hmacer.Hmac(buf[:l]); e != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error computing hmac: %v", e)
			return
		} else {
			fmt.Printf("hmac computed in data len(%v) in: %v\n", l, time.Since(time0))
			w.WriteHeader(http.StatusOK)
			w.Write(b)
		}
	})
	fmt.Fprintf(os.Stderr, "Listening on %s\n", bind)
	http.ListenAndServe(bind, nil)
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
	bind := "localhost:9999"
	if len(os.Args) > 2 {
		cmd = os.Args[1]
	}
	if len(os.Args) > 3 {
		bind = os.Args[3]
	}
	switch cmd {
	case "import":
		hmacImportKey(t, os.Args[2])
	case "serv":
		hmacServer(t, os.Args[2], bind)
	default:
		fmt.Println("usage: macserver [import|serv] filename")
	}

	t.Close()
}
