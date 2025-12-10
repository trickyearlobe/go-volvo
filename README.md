# go-volvo

A command-line utility to interact with the Volvo Connected Vehicle API.

## Prerequisites

You need credentials from the [Volvo Developer Portal](https://developer.volvocars.com):

1. **VCC API Key** - Your application's API key
2. **Access Token** - A test token for authentication

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

Store your credentials (saved to `~/.go-volvo.yaml`):

```bash
go-volvo credentials --vcc-api-key YOUR_API_KEY --token YOUR_TOKEN
```

You can also specify a custom config file:

```bash
go-volvo --config /path/to/config.yaml credentials --vcc-api-key YOUR_API_KEY --token YOUR_TOKEN
```

## Commands

### List Vehicles

List all vehicles associated with your account:

```bash
go-volvo vehicles
```

### Dump Vehicle Data

Dump comprehensive data for a specific vehicle:

```bash
go-volvo dump --vin YOUR_VIN
```

This fetches data from multiple endpoints including:
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

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

