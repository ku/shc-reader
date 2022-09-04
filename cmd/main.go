package main

import (
	"bytes"
	"compress/flate"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// based on https://idmlab.eidentity.jp/2021/12/verifiable-credentials.html
func main() {
	if len(os.Args) != 2 {
		fmt.Println("shc: string needed")
		os.Exit(1)
	}

	if err := _main(os.Args[1]); err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

}

func _main(shcRawString string) error {
	if !strings.HasPrefix(shcRawString, "shc:/") {
		return errors.New("should have shc:/ prefix")
	}

	var jwtString string

	for offset := 5; offset < len(shcRawString); offset += 2 {
		hex := shcRawString[offset : offset+2]
		i, err := strconv.Atoi(hex)
		if err != nil {
			return err
		}
		i += 45

		jwtString += fmt.Sprintf("%c", i)

	}
	jwtComps := strings.SplitN(jwtString, ".", 3)

	b64header := jwtComps[0]
	header, err := b64.RawURLEncoding.DecodeString(b64header)
	fmt.Printf("header: %s\n", string(header))

	zippedPayload := make([]byte, 4096)

	b64payload := []byte(jwtComps[1])

	_, err = b64.RawURLEncoding.Decode(zippedPayload, (b64payload))
	if err != nil {
		return err
	}

	payload := make([]byte, 4096)
	br := flate.NewReader(bytes.NewReader(zippedPayload))
	if err != nil {
		return err
	}

	n, err := br.Read(payload)
	if err != nil {
		if err != io.EOF {
			return err
		}
	}
	ps := string(payload[0:n])

	fmt.Printf("payload: %s\n", ps)

	fmt.Printf("signature: %s\n", jwtComps[2])

	return nil
}
