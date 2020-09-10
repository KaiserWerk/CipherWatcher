package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/xanzy/go-gitlab"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

var (
	nmapPath    string
	host		string
	port		string
	hostport    string
	repoName    string
	gitlabToken string
	interval    int
)

func main() {
	flag.StringVar(&nmapPath, "nmap", "nmap", "The path to the nmap executable (can be left blank on default, if gloablly available)")
	flag.StringVar(&hostport, "host", "localhost:80", "The host with port you want to scan")
	flag.StringVar(&repoName, "reponame", "vendor/repo", "The full name of the Git repository you want to use")
	flag.StringVar(&gitlabToken, "gitlabtoken", "123abc", "The token to authenticate with Gitlab")
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
		log.Println("exit")
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
	// 1. execute nmap to get the list of currently supported ciphers
	c := exec.Command(nmapPath, "-sV", "--script", "ssl-enum-ciphers", "-p", port, host)
	log.Println("Running command", c.String())
	o, err := c.Output()
	if err != nil {
		log.Println("coud not get nmap output:", err.Error())
		return
	}
	localReportContent := []byte(getCipherList(strings.ReplaceAll(string(o), "\r", "")))


	// 2. hash the result
	hasher1 := sha256.New()
	hasher1.Write(localReportContent)
	hash1 := hasher1.Sum(nil) // we need that later on

	// 2.5 create client to interact with gitlab repository
	gitClient, err := gitlab.NewClient(gitlabToken)
	if err != nil {
		log.Println("could not establish connection to gitlab with given token", err.Error())
		return
	}

	hasher2 := sha256.New()
	var hash2 []byte
	var remoteReportContent []byte

	// 3. get remote report file
	gf := &gitlab.GetFileOptions{
		Ref: gitlab.String("master"),
	}
	remoteFileContent, _, err := gitClient.RepositoryFiles.GetFile(repoName, host + "-report.txt", gf)
	if err != nil {
		log.Println("could not get remote file:", err)
	} else {
		remoteFileContentDecoded, err := base64.StdEncoding.DecodeString(remoteFileContent.Content)
		if err != nil {
			log.Println("could not decode base64 content:", err.Error())
		}
		ioutil.WriteFile("C:\\Local\\remoteFileContentDecoded.txt", remoteFileContentDecoded, 0777)

		remoteReportContent = []byte(getCipherList(strings.ReplaceAll(string(remoteFileContentDecoded), "\r", "")))

		hasher2.Write(remoteReportContent)
		hash2 = hasher2.Sum(nil)
	}


	if string(localReportContent) != "" && string(hash1) == string(hash2) {
		log.Println("report contents matching!")
	} else {
		log.Println("report contents NOT matching, uploading...")
		cf := &gitlab.CreateFileOptions{
			Branch:        gitlab.String("master"),
			Content:       gitlab.String(string(o)),
			CommitMessage: gitlab.String("Adding report file " + host + "-report.txt"),
		}
		_, _, err := gitClient.RepositoryFiles.CreateFile(repoName, host + "-report.txt", cf)
		if err != nil {
			log.Fatal(err)
		}

		//ioutil.WriteFile("C:\\Local\\content1.txt", localReportContent, 0777)
		//ioutil.WriteFile("C:\\Local\\content2.txt", remoteReportContent, 0777)
	}
	log.Println("done\n")
}

func getCipherList(reportContent string) string {
	l := strings.Split(reportContent, "\n\r\n")
	//log.Println(l)
	if len(l) > 1 {
		log.Println("There is more than 1 block")
		return l[1]
	}

	l2 := strings.Split(reportContent, "\n\n")
	if len(l2) > 1 {
		log.Println("There is more than 1 block (2)")
		return l2[1]
	}

	log.Println("There is not more than 1 block")
	log.Println(reportContent)
	return ""
}