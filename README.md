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

A build tag must **always** be specified — omitting it is a compile error:

	go build -tags prod .   # production (requires server.bin and key.bin)
	go build -tags dev  .   # development (no license required, no key files needed)

### Dev build (no license required)

For local development, build with the `dev` tag. This skips the `//go:embed`
key file requirement entirely and disables all license checks at runtime —
no `server.bin`, `key.bin`, or `licenses_client` folder needed:

	go build -tags dev -o imqsauth.exe .

A warning is printed on startup to make it clear the service is running in
dev mode:

	DEV MODE: license checks are disabled (built with -tags dev or no key files embedded)

**Do not use a dev build in production.**

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

### Build pipeline (WINDOWS)

We use an older version of Jenkins at the moment, which supports specifying
a secrets _file_.

- Upload both `server.bin` and `key.bin` to Jenkins as **Secret file** credentials
    (**not** Secret text — Secret text stores the file *contents* as a string, so
    the bound variable will contain binary data instead of a file path, causing
    `copy` to fail with *"The system cannot find the file specified"*):
    - Go to **Jenkins → Manage Jenkins → Credentials → (store) → Add Credentials**
    - Set **Kind** = `Secret file`, upload the file, set the ID:
    - _LICENSE_CLIENT_KEY_BIN_ — upload `key.bin`
    - _LICENSE_CLIENT_SERVER_BIN_ — upload `server.bin`
- Add them to the build pipeline as secret files, and assign them to named 
    environment variables:
    - _LICENSE_CLIENT_KEY_BIN_ → `KEY_BIN`
    - _LICENSE_CLIENT_SERVER_BIN_ → `SERVER_BIN`
- Copy the files into the correct location before building using **Windows Batch**
    commands. Jenkins injects the secret file path using forward slashes, which the
    Windows `copy` command does not handle correctly as a source path — convert them
    to backslashes first:
    ```bat
    set KEY_BIN_WIN=%KEY_BIN:/=\%
    set SERVER_BIN_WIN=%SERVER_BIN:/=\%
    copy "%KEY_BIN_WIN%" "%WORKSPACE%\imqsauth\key.bin"
    copy "%SERVER_BIN_WIN%" "%WORKSPACE%\imqsauth\server.bin"
    cd %WORKSPACE%\imqsauth && go build -tags prod -o imqsauth.exe .
    ```
    > **Note:** if `imqsauth` is checked out as a submodule inside a larger
    > workspace (e.g. `C:\Jenkins\workspace\Build-RC\imqsauth\`), the destination
    > path should include the submodule folder as shown above. If this repository
    > *is* the workspace root, use `%WORKSPACE%\key.bin` / `%WORKSPACE%\server.bin`
    > directly. Either way the files must end up alongside `imqsauth.go`, because
    > the `go:embed` directives resolve paths relative to the `.go` source file.
- Clean up afterwards by deleting the files from the workspace:
    ```bat
    del "%WORKSPACE%\imqsauth\key.bin"
    del "%WORKSPACE%\imqsauth\server.bin"
    ```

### Build pipeline (DOCKER/GitHub Actions)

- Convert the key.bin and server.bin files to base64.
- Add KEY_BIN and SERVER_BIN as secrets to the _repository_ actions secrets and add
  their base64 values as the secret values.
- See actions.yml for details on how the files are used in the build pipeline.

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
into the current directory. After that, `go build -tags prod .` will succeed.

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
> `go build -tags prod .` separately after the key files have been generated.

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
	go build -tags dev .
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
