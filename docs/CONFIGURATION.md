# Configuration reference

The local proxy can be configured four ways. Where the same option is set in
more than one place, the higher entry in this list wins:

1. [Command line arguments](#options-set-via-command-line-arguments)
2. [`--config` file](#options-set-via---config) (and
   [`--config-dir`](#options-set-via---config-dir) for service ID mappings)
3. [Environment variables](#options-set-via-environment-variables)
4. [Fine-grained settings via `--settings-json`](#fine-grained-settings-via---settings-json)
   — hard-coded defaults these override

---

## Options set via command line arguments

Most command line arguments have both a long form preceded by a double dash `--`
and a short form preceded by a single dash `-` character. Some commands only
have a long form. Any options specified via command line arguments override
values specified in both the config file specification, and environment
variables.

**-h/--help** Will show a help message and a short guide to all of the available
CLI arguments to the console and cause it to exit immediately

**-V/--version** Will show the local proxy version and cause it to exit
immediately. Note the capital **V**: the lowercase **-v** is **-v/--verbose**.
No other arguments are required or validated when this option is given

**-t/--access-token [argvalue]** Specifies the client access token to use when
connecting to the service. We do not recommend using this option as the client
access token will appear in shell history or in process listings that show full
commands and arguments and may unintentionally expose access to the tunnel. Use
the environment variable or set the option via config input file instead. An
access token value must be found supplied via one of those three methods.

**-e/--proxy-endpoint [argvalue]** Specifies an explicit endpoint to use to
connect to the tunneling service. For some customers this may point to unique
domain. You cannot specify this option and **-r/--region** together. Either this
or **--region** is required

**-r/--region [argvalue]** Endpoint region where tunnel exists. You cannot
specify this option and **-e/--process-endpoint** together. Either this or
**--proxy-endpoint** is required

**-s/--source-listen-port [argvalue]** Start local proxy in source mode and sets
the mappings between service identifier and listening port. For example:
SSH1=5555 or 5555.

- It follows format serviceId1=port1, serviceId2=port2, ...
- If only one port is needed to start local proxy, service identifier is not
  needed. You can simply pass the port to be used, for example, 5555.
- SSH1=5555 means that local proxy will start listening requests on port 5555
  for service ID SSH1.
- The value of service ID and how many service IDs are used needs to match with
  **services** in open tunnel call. For example:
  ```shell script
  aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2
  ```
  Then to start local proxy in source mode, need to use:
  `-s SSH1=$port1,SSH2=$port2`

**-d/--destination-app [argvalue]** Start local proxy in destination mode and
sets the mappings between port and service identifier. For example: SSH1=5555
or 5555.

- It follows format serviceId1=endpoint1, serviceId2=endpoint2, ...
- Endpoint can be IP address:port, port, hostname:port, or a Unix domain socket
  path.
- Unix domain socket paths are detected when the endpoint contains a '/'
  character (e.g., /run/ssh-unix-local/socket, /tmp/app.sock, ./local.sock).
  Note: Unix domain sockets are only supported on Unix/Linux/macOS platforms.
- If only one port is needed to start local proxy, service ID is not needed. You
  can simply pass the port used, for example, 5555.
- An item of the mapping SSH1=5555 means that local proxy will forward data
  received from the tunnel to TCP port 5555 for service ID SSH1.
- An item of the mapping SSH1=/run/app.sock means that local proxy will forward
  data received from the tunnel to the Unix domain socket at /run/app.sock for
  service ID SSH1.
- The value of service ID and how many service IDs are used needs to match with
  **services** in open tunnel call. For example:
  ```shell script
  aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2
  ```
  Then to start local proxy in destination mode, need to use:
  `-d SSH1=$port1,SSH2=$port2` or
  `-d SSH1=/path/to/socket1,SSH2=/path/to/socket2`

**-b/--local-bind-address [argvalue]** Specifies the local bind address (network
interface) to use for listening for new connections when running the local proxy
in source mode, or the local bind address to use when reaching out to the
destination service when running in destination mode

**-c/--capath [argvalue]** Specifies an additional directory path that contains
root CAs used for SSL certificate verification when connecting to the service

**-k/--no-ssl-host-verify** Directs the local proxy to disable host verification
when connecting to the service. This option should not be used in production
configurations.

**--export-default-settings [argvalue]** Specifies a file to write out all of
the default fine-grained settings used by the local proxy and exits immediately.
This file can be modified, and supplied as input to **--settings-json** to run
the local proxy with non-default fine-grained settings.

**--settings-json [argvalue]** Specifies a file to read fine-grained settings
for the local proxy to use to override hard coded defaults. All of the settings
need not be present. Settings that do not exist are ignored passively.

**--config [argvalue]** Specifies a file to read command line arguments from.
Actual command line arguments will overwrite contents of file if present in
both.

**-v/--verbose [argvalue]** Specifies the verbosity of the output. Value must be
between 0-255, however meaningful values are between 0-6 where 0 = output off, 1
= fatal, 2 = error, 3 = warning, 4 = info [default], 5 = debug, 6 = trace. Any
values greater than 6 will be treated the same trace level output.

**-m/--mode [argvalue]** Specifies the mode local proxy will run. Accepted
values are: src, source, dst, destination.

**-y/--destination-client-type [argvalue]** Specifies the backward compatibility
mode the local proxy will run when opening a source connection to an older
destination client. Currently supported values are: V1, V2. The localproxy will
assume the destination to be V3 if no/invalid value is passed. See
[COMPATIBILITY.md](COMPATIBILITY.md).

**--config-dir [argvalue]** Specifies the configuration directory where service
identifier mappings are configured. If this parameter is not specified, local
proxy will read configuration files from default directory _./config_, under the
file path where `localproxy` binary are located.

---

## Options set via --config

A configuration file can be used to specify any or all of the CLI arguments. If
an option is set via a config file and CLI argument, the CLI argument value
overrides. Here is an example file named `config.ini`:

    region = us-east-1
    access-token = foobar
    source-listen-port = 5000

Local proxy run command using this configuration:
`./localproxy --config config.ini` is equivalent to running the local proxy
command `./localproxy -r us-east-1 -t foobar -s 5000`

To illustrate composition between using a configuration file and actual CLI
arguments you could have a `config.ini` file with the following contents:

    capath = /opt/rootca
    region = us-west-2
    local-bind-address = ::1
    source-listen-port = 6000

and a local proxy launch command `./localproxy --config config.ini -t foobar` is
equivalent to running the local proxy command
`./localproxy -c /opt/rootca -r us-west-2 -b ::1 -s 6000 -t foobar`

**NOTE**: Service ID mappings should be configured by using parameter
--config-dir, not --config.

---

## Options set via --config-dir

If you want to start local proxy on fixed ports, you can configure these
mappings using configuration files. By default, local proxy will read from
directory _./config_, under the file path where `localproxy` binary are located.
If you need to direct local proxy reads from specific file path, use parameter
`--config-dir` to specify the full path of the configuration directory. You can
put multiple files in this directory or organize them into the sub folders.
Local proxy will read all the files in this directory and search for the port
mapping needed for a tunnel connection.

**NOTE**: The configuration files will be read once when local proxy starts and
will not be read again unless it is restarted.

### Sample configuration files on source device

File name: _SSHSource.ini_

Content example:

    SSH1=3333
    SSH2=5555

This example means:

- Service ID SSH1 is mapped to port 3333.
- Service ID SSH2 is mapped to port 5555.

### Sample configuration files on destination device

Example configuration file on destination device: File name:
_SSHDestination.ini_

Content example:

    SSH1=22
    SSH2=10.0.0.1:80

This example means:

- Service ID SSH1 is mapped to port 22.
- Service ID SSH2 is mapped to host with IP address 10.0.0.1, port 80.

---

## Options set via environment variables

There are a few environment variables that can set configuration options used by
the local proxy. Environment variables have lowest priority in specifying
options. Config and CLI arguments will always override them

- **AWSIOT_TUNNEL_ACCESS_TOKEN** - if present, specifies the access token for
  the local proxy to use
- **AWSIOT_TUNNEL_ENDPOINT** - if present, specifies the AWS IoT Secured
  Tunneling proxy endpoint. Leave out -e or --proxy-endpoint from CLI arg. Still
  mutually exclusive with specifying -r/--region and below environment variable
- **AWSIOT_TUNNEL_REGION** - if present, specifies the region the tunnel exists
  in. Allowing leaving out the -r CLI arg
- **AWSIOT_TUNNEL_CLIENT_TOKEN** - if present, specifies the client token; see
  [Client tokens](SECURITY.md#client-tokens)

---

## Fine-grained settings via --settings-json

There are additional fine-grained settings to control the behavior of the local
proxy. These settings are unlikely to need to be changed, and unless necessary
should be kept at their default values.

Running `./localproxy --export-default-settings lpsettings.json` will produce a
file named `lpsettings.json` containing the default values for all settings.
Example contents:

```
{
    "tunneling": {
        "proxy": {
            "default_bind_address": "localhost",
            "message": {
                "data_length_size": "2",
                "max_payload_size": "64512",
                "max_size": "65536"
            },
            "tcp": {
                "connection_retry_count": "5",
                "connection_retry_delay_ms": "1000",
                "read_buffer_size": "131076"
            },
            "websocket": {
                "ping_period_ms": "5000",
                "retry_delay_ms": "2500",
                "connect_retry_count": "-1",
                "reconnect_on_data_error": "true",
                "subprotocol": "aws.iot.securetunneling-1.0",
                "max_frame_size": "131076",
                "write_buffer_size": "131076",
                "read_buffer_size": "131076"
            }
        }
    }
}
```

After making edits to `lpsettings.json` and saving the changes, the following
command will run the local proxy with the modified settings:
`./localproxy -r us-east-1 -t foobar -d localhost:22 --settings-json lpsettings.json`.

**default_bind_address** Defines the default bind address used when the **-b**
bind address command line argument or option is not present. Address may be a
hostname or IP address

**tunneling.proxy.tcp.connection_retry_count** When a failure occurs while
trying to establish a TCP connection in destination mode this is the number of
consecutive connection attempts to make before sending a notification over the
tunnel that the connection is closed. When running in source mode, this will be
the number of consecutive attempts made to bind and listen on on the TCP socket.
A value of -1 results in infinite retry

**tunneling.proxy.tcp.connection_retry_delay_ms** Defines how long to wait
before executing a retry for TCP connection failures (source or destination
mode) in milliseconds.

**tunneling.proxy.websocket.ping_period_ms** Defines the period (in
milliseconds) between websocket pings to the AWS IoT Tunneling Service. These
pings may be necessary to keep the connection alive.

**tunneling.proxy.websocket.connect_retry_count** When a failure occurs while
trying to connect to the service outside of an HTTP 4xx response on the
handshake it may be retried based on the value of this property. This is the
number of consecutive attempts to make before failing and closing the local
proxy. Any HTTP 4xx response code on handshake does not retry. A value of -1
results in infinite retry

**tunneling.proxy.websocket.retry_delay_ms** Defines how long to wait before
executing another retry to connect to the service in milliseconds.

**tunneling.proxy.websocket.reconnect_on_data_error** Flag indicating whether or
not to try to re-establish connection to the service if an I/O, protocol
handling, or message parsing errors occur.

**tunneling.proxy.message.may_payload_size** Defines the maximum data size
allowed to be carried via a single tunnel message. The current protocol has a
maximum value of 63kb (64512 bytes). Any two active peers communicating over the
same tunnel must set this to the same value.
