IMQS Authentication System
==========================

Other references
1. [Overview](./docs/Overview.md)
2. [API](./docs/API.md)
3. [Config schema](docs/config-schema/imqsauth.json)
4. [Static conf](docs/static-conf/imqsauth.json)

More information can be found in Confluence: [Imqs Auth](https://imqssoftware.atlassian.net/wiki/spaces/ASC/pages/94568575/ImqsAuth).

## Building

### Quick build

	go build imqsauth.go

### License Management Considerations

The build requires two binary files to be present in the root of the repository
before `go build` is run, because they are compiled directly into the binary via
`//go:embed`:

| File | Purpose |
|---|---|
| `server.bin` | XOR-masked server public key used by the LicenseClient library |
| `key.bin` | XOR mask used at runtime to recover the real public key from `server.bin` |

Both files are excluded from source control (`.gitignore`). See
[Generating the embedded key files](#generating-the-embedded-key-files) below.

### Build pipeline

We use an older version of Jenkins at the moment, which supports specifying
a secrets _file_.

- Upload both `server.bin` and `key.bin` to Jenkins as secret files:
    - _LICENSE_CLIENT_KEY_BIN_  
        Obfuscation key used by auth build - see `server.bin` for public key.
    - _LICENSE_CLIENT_SERVER_BIN_  
        Public key used by auth build - see `key.bin` for obfuscation key.
- Add them to the build pipeline as secret files, and assign them to named 
    environment variables:
    - _LICENSE_CLIENT_KEY_BIN_ → `KEY_BIN`
    - _LICENSE_CLIENT_SERVER_BIN_ → `SERVER_BIN`
- Copy the files into the correct location in the workspace before building 
    using Windows Batch commands:
-   ```
    copy %KEY_BIN% .\key.bin
    copy %SERVER_BIN% .\server.bin
    ```
- Clean up afterwards by deleting the files from the workspace:
    - `del key.bin`
    - `del server.bin`


### Go module dependencies

All Go dependencies are declared in `go.mod` and fetched automatically by the
Go toolchain. The key external library for license management is:

- `github.com/IMQS/licenseserver v0.0.4` — provides the `LicenseClient` used
  to validate the `enterprise` license at runtime. Consumed via two sub-packages:
  - `github.com/IMQS/licenseserver/client` — `LicenseClient` struct
  - `github.com/IMQS/licenseserver/lib` — `UnmaskPublicKey()` and shared logger

Run `go mod download` to fetch all dependencies before building offline.

### Generating the embedded key files

`server.bin` and `key.bin` are produced from the plaintext public key file
`server.pub` using `xortool`. The source for `xortool` lives in the
`github.com/IMQS/licenseserver` repository. Once you have `xortool.go`:

	go build xortool.go
	xortool ./server.pub

This writes `server.bin` (the XOR-encoded key) and `key.bin` (the XOR mask)
into the current directory. After that, `go build imqsauth.go` will succeed.

### Building the license tooling (`build.bat`)

`build.bat` automates building the supporting license tools. It requires source
files from the `licenseserver` repository (`xortool.go`, `licenseclient.go`, 
`licensetool.go`).

	rem Build and run xortool to produce server.bin and key.bin from server.pub:
	go build xortool.go
	xortool ./server.pub

	rem Build the license client helper:
	go build licenseclient.go

> **Note:** `build.bat` does **not** build `imqsauth.exe` itself. Run
> `go build imqsauth.go` separately after the key files have been generated.

_Garble_

We CAN support `garble` (a Go code obfuscator), but there are
problems with anti-virus scanning, especially in production environments and is 
currently not used.

	rem Install garble (code obfuscation tool):
	go install mvdan.cc/garble@v0.15.0

	rem Build the license tool with literal obfuscation:
	garble --literals build licensetool.go

## Testing

Note that github.com/IMQS/authaus has it's own set of tests, which we run
in it's own CI job.

`imqsauth` has two set of tests: Go and ruby. The ruby tests hit the REST API.

The following block demonstrates running all of the tests:

	go test github.com/IMQS/imqsauth/auth
	go build imqsauth.go
	gem install rest-client
	ruby resttest.rb

## Running

To run imqsauth and create a local postgres database, do

	./imqsauth -c=example-local.conf createdb

You will need to have the appropriate postgres login setup on your database. See the 
`example-local.conf` file for those details.

Next, reset the authorization groups 'admin' and 'enabled'

	./imqsauth -c=example-local.conf resetauthgroups

Create a user called 'root'

	./imqsauth -c=example-local.conf createuser root PASSWORD

Grant the 'root' user 'admin' and 'enabled' rights

	./imqsauth -c=example-local.conf permgroupadd root admin
	./imqsauth -c=example-local.conf permgroupadd root enabled

To create a regular user, you would do the same thing,
except leave out the `permgroupadd root admin` step.

To run the server:

	./imqsauth -c=example-local.conf run

### Running outside docker

The auth service is capable of detecting whether it is running inside or outside of Docker 
upon startup. It leverages the service discovery mechanism in the config service to transparently
rewrite database connection configurations, as well as other serviceconfig utils to detect whether or not
it is inside the auth service.
