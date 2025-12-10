# go-volvo

A command-line utility to interact with the Volvo Connected Vehicle API.

## Prerequisites

You need credentials from the [Volvo Developer Portal](https://developer.volvocars.com):

1. **VCC API Key** - Your application's API key
2. **OAuth Client ID & Secret** - For OAuth login flow (recommended)
3. **Access Token** - Or a test token for quick testing

## Installation

```bash
go install github.com/trickyearlobe/go-volvo@latest
```

Or build from source:

```bash
git clone https://github.com/trickyearlobe/go-volvo.git
cd go-volvo
go build .
```

## Configuration of VOLVO application API

1. Sign up for a [Volvo Developer Account](https://developer.volvocars.com) using your normal Volvo credentials
2. Navigate to the [Volvo API Applications page](https://developer.volvocars.com/account/#your-api-applications) and create a new API application
3. Make a note of the VCC API Keys as we will need to add one of them to the `go-volvo` CLI to make API calls
4. If you don't want to publish your app to use OAuth, you can obtain 30min test tokens from the [Test Access Tokens](https://developer.volvocars.com/apis/docs/test-access-tokens) page.
5. If you wish to go ahead with OAuth you will need to publish your app. Please ensure that:-
   1.  Your callback URI points to a valid HTTPS URL (HTTP will not be accepted). The `go-volvo` default is `https://localhost:8089/callback` but if you can issue valid TLS certs then you may wish to use a proper DNS entry
   2.  You selected all the scopes in the `Connected Vehicle` API as `go-volvo` will request access to all of them.
   3.  The terms an conditions URL points to some reachable web page (ideally with some actual T&C's on it for legal reasons).
6. Once your app is published, make a note of the ClientID and ClientSecret as we will need to add them to the `go-volvo` CLI  

## Configuration of go-volvo CLI

### Option 1: OAuth Login (Recommended)

Store your OAuth credentials:

```bash
go-volvo credentials --vcc-api-key YOUR_API_KEY --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
```

Then authenticate via browser:

```bash
go-volvo login
```

This opens your browser to sign in with your Volvo ID. After authentication, tokens are automatically saved.

To refresh an expired token:

```bash
go-volvo refresh
```

### Option 2: Test Token (Quick Testing without getting your app API published by Volvo)

For quick testing with a developer portal test token:

```bash
go-volvo credentials --vcc-api-key YOUR_API_KEY --token YOUR_TEST_TOKEN
```

### Custom Config File

You can specify a custom config file location:

```bash
go-volvo --config /path/to/config.yaml credentials --vcc-api-key YOUR_API_KEY
```

## Commands

### List Vehicles

List all vehicles VIN's associated with your account:

```bash
go-volvo vehicles
```

### Dump Vehicle Data

Dump comprehensive data for a specific vehicle using it's VIN number:

```bash
go-volvo dump --vin YOUR_VIN
```

This fetches data from multiple endpoints as per the scopes which were authorised including:
- commands, command-accessibility
- engine, engine-status
- diagnostics, brakes, tyres
- windows, doors
- fuel, odometer
- statistics, warnings

### Raw API Requests

Make raw HTTP requests to any Volvo API endpoint:

```bash
# GET request
go-volvo raw get /connected-vehicle/v2/vehicles

# POST request with data
go-volvo raw post /some/endpoint --data '{"key": "value"}'

# Other HTTP methods
go-volvo raw put /endpoint --data '{"update": true}'
go-volvo raw patch /endpoint --data '{"field": "value"}'
go-volvo raw delete /endpoint
go-volvo raw head /endpoint
go-volvo raw options /endpoint
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--config` | Config file (default: `~/.go-volvo.yaml`) |
| `-h, --help` | Help for any command |

## Disclaimer

This software is provided as-is with no warranty. See [CONDITIONS.md](CONDITIONS.md) for full terms.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

