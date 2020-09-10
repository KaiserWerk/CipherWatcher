package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"
)

var (
	nmapPath    string
	host		string
	port		string
	hostport    string
	repoUrl     string
	gitlabToken string
	filename    string
	interval    int
)

func main() {
	flag.StringVar(&nmapPath, "nmap", "nmap", "The path to the nmap executable (can be left blank on default, if gloablly available)")
	flag.StringVar(&hostport, "host", "codeforge.me:443", "The host with port you want to scan")
	flag.StringVar(&repoUrl, "repo-url", "https://gitlab.com", "The URL of the Git repository you want to use")
	flag.StringVar(&gitlabToken, "gitlab-token", "123abc", "The token to authenticate with Gitlab")
	flag.StringVar(&filename, "filename", "report.txt", "The name of the file the report is read from and written back to")
	flag.IntVar(&interval, "interval", 24, "The interval in hours the check should be run")
	flag.Parse()

	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		log.Fatal("could not separate host and port; invalid host value supplied")
	}
	host, port = h, p

	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	done := make(chan bool)

	log.Println("started running")
	log.Println("starting initial execution")
	checkHost()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		log.Println("quitting")
		// cleanup stuff here
		close(done)
	}()

	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			fmt.Println("Execution started at", t)
			checkHost()
		}
	}

}

func checkHost() {
	c := exec.Command(nmapPath, "-sV", "--script", "ssl-enum-ciphers", "-p", port, host)
	log.Println("Running command", c.String())
	o, _ := c.Output()

	log.Println("Result: ", string(o))
	// do the important stuff here
}
