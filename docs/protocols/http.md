# HTTP Protocol

rvOS includes an HTTP/1.0 client and server implemented as user-space
programs using `std::net::TcpStream` and `std::net::TcpListener`.

## HTTP Client (`http-get`)

Binary: `user/http-client`

A command-line utility that performs HTTP GET requests.

### Usage

```
http-get <url>
```

Example: `http-get http://example.com/index.html`

### Request Flow

1. Parse URL into host, port (default 80), and path.
2. Resolve hostname to IP: try dotted-decimal parse first, then DNS
   resolution via `rvos::dns::resolve()` using the DHCP-provided DNS server.
3. Connect via `TcpStream::connect(ip, port)`.
4. Send HTTP/1.0 GET request with `Host` and `Connection: close` headers.
5. Read and print the response (headers + body) until EOF.

### Limitations

- HTTP only (no HTTPS/TLS)
- GET method only
- No redirect following
- No chunked transfer encoding handling (relies on `Connection: close`)

## HTTP Server (`http-server`)

Binary: `user/http-server`

A static file server that serves files from the ext2 filesystem.

### Usage

```
http-server [port]
```

Default port: 80. Document root: `/persist/www`.

### Request Handling

1. Accept TCP connection via `TcpListener::accept()`.
2. Read request headers (up to 2 KiB buffer, until `\r\n\r\n`).
3. Parse request line (`METHOD /path HTTP/1.x`).
4. Only GET is supported; other methods return 400.
5. Sanitize path (resolve `.` and `..`, strip query/fragment).
6. If path is a directory, serve `index.html` within it.
7. Read file from `/persist/www/<path>` via `std::fs::read()`.
8. Send HTTP/1.0 response with `Content-Length`, `Content-Type`, and
   `Connection: close` headers.
9. If file not found, return 404.

### Content Types

File extension mapping:

| Extension       | Content-Type             |
|-----------------|--------------------------|
| `.html`, `.htm` | `text/html`              |
| `.css`          | `text/css`               |
| `.js`           | `application/javascript` |
| `.json`         | `application/json`       |
| `.txt`          | `text/plain`             |
| `.png`          | `image/png`              |
| `.jpg`, `.jpeg` | `image/jpeg`             |
| `.gif`          | `image/gif`              |
| `.svg`          | `image/svg+xml`          |
| other           | `application/octet-stream` |

### Security

- Path traversal prevention: `..` segments are resolved to prevent
  escaping the document root.
- Query strings and fragments are stripped before path lookup.

### Limitations

- Single-threaded: handles one connection at a time.
- GET only.
- No keep-alive (HTTP/1.0 with `Connection: close`).
- Maximum request header size: 2 KiB.
