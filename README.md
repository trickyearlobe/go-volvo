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

## Configuration

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

