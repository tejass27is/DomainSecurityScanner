# Local Setup – Domain Security  Scanner (Go).

This README explains **only what is required to run the scanner locally for testing**.  
No build, no Docker, no configuration files — just install dependencies, clone the repo, and run the scanner.

**Supported platforms:**
.
- macOS
- Windows

---


## Step 1: System Requirements

Ensure the following are installed:

- Go **1.21 or later**
- Git
- Internet connection

---


## Step 2: Install Go

### macOS

```bash
brew install go
```

Verify:

```bash
go version
```

Official installer (optional):
<https://go.dev/dl/>

## Windows

1. Download Go from:
<https://go.dev/dl/>
2. Install and restart terminal

## Verify Go Installation

```bash
go version
```

## Step 3: Install Scanner Dependencies

The scanner relies on the following **ProjectDiscovery** tools:

- **subfinder** – Subdomain enumeration  
- **dnsx** – DNS resolution and validation  
- **naabu** – Fast port scanning  
- **httpx** – HTTP service probing  
- **tlsx** – TLS / SSL configuration analysis  

Install all required dependencies using Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
```

## Step 4: Add Go Binaries to PATH

## macOS

Temporarily add Go binaries to your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Make this change permanent by adding it to your shell configuration:

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
source ~/.zshrc
```

## Windows

1. **Get your GOPATH**:

```powershell
go env GOPATH
```

 1. Add the Go bin directory to your system PATH:

C:\Users\<your-username>\go\bin

 • Open Environment Variables → Path → Edit → Add New
 • Paste the above path and save

## Step 5: Verify Dependencies

Run each command to ensure that the tools are installed and available:

```bash
subfinder -h
dnsx -h
naabu -h
httpx -h
tlsx -h
```

## Step 6: Clone the Scanner Repository

Clone the scanner repository and navigate into the project directory:

```bash
git clone <scanner-repository-url>
cd scanner
```

## Step 7: Run the Scanner (Test Mode)

No build or additional setup is required.

Run the scanner directly using:

```bash
go run cmd/scanner/main.go
```

## Example Test Run

Run the scanner against a sample domain:

```bash
go run cmd/scanner/main.go example.com
```

## Important Notes

- The scanner runs **entirely locally**  
- Missing results (e.g., TLS data) indicate the service is not available on the target  
- No database or external services are used

---

## Legal Notice

Run this scanner **only on domains you own or have explicit permission to test**.  
Unauthorized scanning may be illegal.

## Liscense
