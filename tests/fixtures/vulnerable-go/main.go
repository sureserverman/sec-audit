// Intentionally insecure Go service — fixture for go-runner / gosec +
// staticcheck. Carries multiple Gxxx + SAxxxx findings:
//
// gosec:
//   G101 (hardcoded credentials)
//   G201 (SQL string formatting)
//   G304 (file path traversal via os.Open)
//   G402 (TLS InsecureSkipVerify=true)
//   G404 (math/rand for security-sensitive randomness)
//   G501 (weak hash MD5)
//
// staticcheck:
//   SA1019 (deprecated symbol — io/ioutil.ReadFile in Go 1.16+)

package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
)

const apiKey = "sk_live_4242424242424242"

func openUserFile(name string) ([]byte, error) {
	f, err := os.Open("/srv/uploads/" + name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadFile(f.Name())
}

func userByID(db *sql.DB, id string) error {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	_, err := db.Query(q)
	return err
}

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func hashPassword(pw string) string {
	h := md5.Sum([]byte(pw))
	return fmt.Sprintf("%x", h)
}

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func main() {
	_ = apiKey
	_ = newToken()
	_ = hashPassword("hunter2")
	_ = httpClient()
	_, _ = openUserFile("test.txt")
}
