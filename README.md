# CipherWatcher
A service tool written in Go to monitor changes in the cipher suites of a selected host.
This is a working prototype.

#### What is does
1. Use nmap to get a report on the cipher suite for the given host:port combination.
2. Check if a report for this host exists in the Gitlab repository.
    1. If it does not, create it.
    2. If it does: check if contents match (no changes in the cipher suite occurred).
        1. If contents match, do nothing (since nothing changed)
        2. If contents do not match, update the report file in the repository with 
        the content of the new report.

## What you need

1. A Gitlab account and a new (empty) repository.
2. A Gitlab Personal Access Token with the scope **api**.
3. Have nmap installed on the system you want to run the tool on.

## Setup

Clone the repository and use main.go as entry point to run or build the 
app into an executable.

Use
``go run . -host myhost.com:443 -reponame MyName/MyRepo -gitlabtoken abc123``
to start.

## Usage

Run ``go run . -help`` to display possible command line parameters.

Currently, you can use the following parameters to start the tool:
```
  -gitlabtoken string (*)
        The token to authenticate with Gitlab (default "123abc")
  -host string (*)
        The host with port you want to scan (default "localhost:80")
  -interval int
        The interval in hours the check should be run (default 24)
  -nmap string
        The path to the nmap executable (can be left on default, if globally available) (default "nmap")
  -reponame string (*)
        The full name of the Git repository you want to use (default "vendor/repo")
```
Parameters marked with (*) are required.

Once started, the app will run continuously until you stop execution.

## Further thoughts
Maybe sending out notifications when changes occur might be a nifty idea.