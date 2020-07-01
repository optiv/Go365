# Go365

**This tool is still in development. Please read all of this README before using Go365!**

Go365 is a tool designed to perform user enumeration and password guessing attacks on organizations that use Office365 (now/soon Microsoft365). Go365 uses a unique SOAP API endpoint on login.microsoftonline.com that most other tools do not use. When queried with an email address and password, the endpoint responds with an Azure AD Authentication and Authorization code. This code is then processed by Go365 and the result is printed to screen or an output file.


##### Read these three bullets!
- This tool might not work on **all** domains that utilize o365. Tests show that it works with most federated domains. Some domains will only report valid users even if a valid password is also provided. Your results may vary!
- The domains this tool was tested on showed that it did not actually lock out accounts after multiple password failures. Your results may vary!
- This tool is intended to be used by security professionals that are authorized to "attack" the target organization's o365 instance.


## Obtaining

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

	```go build Go365.go```
5. Run the resulting binary and enjoy :)


## Usage
``` 
$ ./Go365 -h

  ██████         ██████   ██████  ██████
 ██                   ██ ██       ██
 ██  ███   ████   █████  ███████  ██████
 ██    ██ ██  ██      ██ ██    ██      ██
  ██████   ████  ██████   ██████  ██████

 Version: 0.1
 Authors: h0useh3ad, paveway3, S4R1N

 This tool is currently in development.

 Usage:
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

   Opions:
     -w <int>              Time to wait between attepmts in seconds.
                              - Default: 1 second. 5 seconds recommended.
                              (-w 10)
     -o <string>           Output file to write to
                              - Will overwrite!
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

 Examples:
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxy 127.0.0.1:1080
   ./Go365 -ul ./user_list.txt -p 'coolpasswordbro!123' -d pwnthisfakedomain.com -w 5 -o Go365output.txt -proxyfile ./proxyfile.txt

```



### Examples
_no u_




## Account Locked Out! (Domain Defenses)

**protip:** _You probably aren't **actually** locking out acocunts._

After a number of queries against a target domain, results might start reporting that accounts are locked out.

Once this defense is triggered, **user enumeration becomes unreliable since both valid and invalid will randomly report that their accounts have been locked out**.
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
The defensive mechanism is **time** and **IP address** based. Go365 provides options to include a wait time between requests and proxy options to distribute the source of the requests. To circumvent the defensive mechanisms on your target domain, use a long wait time and multiple proxy servers.

A wait time of AT LEAST 15 seconds is recommended. ``` -w 15```

If you still get "account locked out" responses, start proxying your requests.

Note: Proxy options have only been tested on SSH dynamic proxies. 

Create a bunch of SOCKS5 proxies and make a file that looks like this:
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

 ```-w 15 -proxyfile ./proxies.txt```


### Example
Watch this tool in action! https://www.youtube.com/watch?v=b9CK37sqoz0
