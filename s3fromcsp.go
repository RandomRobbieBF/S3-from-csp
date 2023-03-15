package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var domainRegex = regexp.MustCompile(`([a-zA-Z0-9-]+)\.([a-z0-9-]+)?\.?s3[\.-]([a-z0-9-]+)?\.?amazonaws\.com|[a-zA-Z0-9-]+\.(s3\.amazonaws\.com)`)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide a URL or file as an argument")
		return
	}

	input := os.Args[1]

	// Check if the argument is a file
	if _, err := os.Stat(input); err == nil {
		// Open the file
		f, err := os.Open(input)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()

		// Read the file line by line
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// Set the URL variable as the scanned line
			url := scanner.Text()

			// Send the URL to the grabber function
			grabber(url)
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(err)
		}
	} else {
		// Set the URL variable as the input argument
		url := input

		// Send the URL to the grabber function
		grabber(url)
	}
}

func check_bucket(domain string) {

	key := "test.txt"
	bucket := domain
	fmt.Printf("Testing " + domain + "")
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Create the S3 endpoint URL
	endpoint := fmt.Sprintf("http://%s/%s", bucket, key)

	// Create the PUT request
	req, err := http.NewRequest("PUT", endpoint, bytes.NewBuffer([]byte("fc5e038d38a57032085441e7fe7010b0")))
	if err != nil {
		fmt.Printf("Error creating PUT request: %v", err)
		return
	}
	// Set other headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0")
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return
	}

	// Check if the PUT request was successful
	if strings.Contains(string(body), "fc5e038d38a57032085441e7fe7010b0") {
		// Append the S3 endpoint URL to the "vuln-buckets.txt" file
		f, err := os.OpenFile("vuln-buckets.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error opening vuln-buckets.txt: %v", err)
			os.Exit(1)
		}
		defer f.Close()

		_, err = f.WriteString("" + endpoint + "")
		if err != nil {
			fmt.Printf("Error writing to vuln-buckets.txt: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Writeable Bucket Found - " + endpoint + "")
	}

}

func grabber(url2 string) {

	u, err := url.Parse(url2)
	if err != nil {
		fmt.Println(err)

	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	// Get the Content-Security-Policy-Report-Only header, if present
	headerValue := resp.Header.Get("Content-Security-Policy")

	domains := domainRegex.FindAllString(headerValue, -1)

	// Create a map to store unique domains
	uniqueDomains := make(map[string]bool)

	// Iterate over the list of domains and add them to the map
	for _, domain := range domains {
		uniqueDomains[domain] = true
	}

	// Open file for saving
	file, _ := os.OpenFile("csp-doms.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()

	// Iterate over the unique domains and print them to the command line and file
	for domain := range uniqueDomains {
		fmt.Println(domain)
		check_bucket(domain)
		file.WriteString(domain + "\n")
	}

}
