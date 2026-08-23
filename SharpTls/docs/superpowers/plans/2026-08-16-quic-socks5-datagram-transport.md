# QUIC Datagram Transport and SOCKS5 UDP Relay Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a public datagram seam for QUIC plus a conforming SOCKS5 UDP ASSOCIATE client with RFC 1929 username/password authentication.

**Architecture:** A pure, socket-free codec (`TlsQuicSocks5Protocol`) encodes and parses every SOCKS5 message, so the wire format is unit-testable and fuzzable without a network. Two transports implement one public interface: a direct UDP socket, and a SOCKS5 relay that owns a TCP control connection plus a UDP socket. Everything above the interface sees decapsulated origin addresses and never learns a proxy exists.

**Tech Stack:** C# 13, .NET 9, xunit 2.9.3, `System.Net.Sockets`, `System.Buffers.Binary.BinaryPrimitives`.

**Spec:** `docs/superpowers/specs/2026-08-16-quic-socks5-datagram-transport-design.md`

---

## Before you start

Read the spec. Every constant in this plan comes from RFC 1928, RFC 1929 or RFC 9000 §14
and is cited at the point of use. Do not substitute a value you remember; if a value looks
wrong, re-read the RFC rather than changing the code.

Three repository rules that will bite you if you miss them:

1. **`tests/SharpTls.Tests/Api/PublicApi.Shipped.txt` is enforced by a test.** Adding any
   public type, member or constructor fails the build until that file is updated. Task 13
   handles it; if you hit the failure earlier, that is why.
2. **`tools/SharpTls.Fuzz/ProtocolFuzzTargets.cs` is compiled into the test project** via a
   `<Compile Include>` link. Editing it rebuilds both.
3. **Interop tests are gated by `[Trait("Category", "Interop")]`** and must never run in the
   offline suite.

Commands used throughout:

```bash
# offline suite, the one that must always pass
dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "Category!=Interop"

# one test class while iterating
dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"

# build only
dotnet build src/SharpTls/SharpTls.csproj
```

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs` | pure codec, all constants, `TlsQuicProxyError`, `TlsQuicProxyException` | 1–5 |
| `src/SharpTls/Quic/ITlsQuicDatagramTransport.cs` | interface, `TlsQuicDatagramReceiveResult` | 6 |
| `src/SharpTls/Quic/TlsQuicUdpDatagramTransport.cs` | direct UDP socket | 7 |
| `src/SharpTls/Quic/TlsQuicSocks5Options.cs` | proxy endpoint, credentials | 8 |
| `src/SharpTls/Quic/TlsQuicSocks5Transport.cs` | association handshake, datagram path, lifetime | 8–9 |
| `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs` | codec vectors and negative cases | 1–5 |
| `tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs` | transports against a fake relay | 7, 9–11 |
| `tests/SharpTls.Tests/Quic/FakeSocks5Relay.cs` | test-only in-process relay | 10 |
| `tests/SharpTls.Tests/Interop/Socks5RelayInteropTests.cs` | opt-in, real relay | 13 |
| `tools/SharpTls.Fuzz/ProtocolFuzzTargets.cs` | new `socks5` target | 12 |
| `docs/SOCKS5-DATAGRAM-TRANSPORT.md`, `docs/QUIC-TLS.md`, `docs/ROADMAP.md`, `tests/SharpTls.Tests/Api/PublicApi.Shipped.txt` | documentation and API contract | 13 |

**Deviation from the spec, applied in Task 13:** the spec says the codec reuses
`SharpTls.IO` big-endian primitives. It does not. `TlsBinaryWriter` is built around TLS
length-prefixed vectors; SOCKS5 messages are fixed-layout, so stdlib
`System.Buffers.Binary.BinaryPrimitives` is used instead and no `SharpTls.IO` dependency is
taken. Task 13 corrects that sentence in the spec.

---

## Chunk 1: The codec

Everything in this chunk is pure. No sockets, no async, no I/O. If a test in this chunk
needs a network, the design has gone wrong.

### Task 1: Error type and protocol constants

**Files:**
- Create: `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs`
- Test: `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs`

- [ ] **Step 1: Write the failing test**

Create `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs`:

```csharp
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicSocks5ProtocolTests
{
    [Fact]
    public void ProxyExceptionCarriesItsError()
    {
        var exception = new TlsQuicProxyException(
            TlsQuicProxyError.CredentialsRejected,
            "rejected");

        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);
        Assert.Equal("rejected", exception.Message);
        Assert.IsAssignableFrom<IOException>(exception);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: FAIL, `CS0246: The type or namespace name 'TlsQuicProxyException' could not be found`

- [ ] **Step 3: Write minimal implementation**

Create `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs`:

```csharp
using System;
using System.IO;

namespace SharpTls.Quic;

/// <summary>Reasons a SOCKS5 proxy association failed.</summary>
public enum TlsQuicProxyError
{
    /// <summary>The proxy offered no authentication method this client supports.</summary>
    NoAcceptableAuthenticationMethod,
    /// <summary>The proxy selected username/password but no credentials were configured.</summary>
    CredentialsRequired,
    /// <summary>The proxy rejected the supplied credentials.</summary>
    CredentialsRejected,
    /// <summary>The proxy refused the UDP ASSOCIATE request.</summary>
    AssociateRejected,
    /// <summary>A proxy reply was truncated, malformed, or carried an unexpected version.</summary>
    MalformedProxyResponse,
    /// <summary>The control connection closed, which ends the UDP association.</summary>
    AssociationTerminated,
}

/// <summary>A SOCKS5 proxy failure. Distinct from <see cref="TlsQuicTransportException"/>,
/// which carries an RFC 9000 transport error code.</summary>
public sealed class TlsQuicProxyException : IOException
{
    /// <summary>Creates a proxy failure.</summary>
    public TlsQuicProxyException(TlsQuicProxyError error, string message)
        : base(message)
    {
        Error = error;
    }

    /// <summary>Gets the reason the association failed.</summary>
    public TlsQuicProxyError Error { get; }
}

internal static class TlsQuicSocks5Protocol
{
    // RFC 1928 section 3.
    internal const byte Version = 0x05;
    internal const byte MethodNoAuthentication = 0x00;
    internal const byte MethodUsernamePassword = 0x02;
    internal const byte MethodNone = 0xFF;

    // RFC 1929 section 2. The subnegotiation version is 0x01, not 0x05.
    internal const byte AuthenticationVersion = 0x01;
    internal const byte AuthenticationSuccess = 0x00;

    // RFC 1928 section 4.
    internal const byte CommandUdpAssociate = 0x03;

    // RFC 1928 section 5.
    internal const byte AddressIPv4 = 0x01;
    internal const byte AddressDomainName = 0x03;
    internal const byte AddressIPv6 = 0x04;

    // RFC 1928 section 7: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2).
    internal const int UdpHeaderSizeIPv4 = 10;
    internal const int UdpHeaderSizeIPv6 = 22;

    internal static TlsQuicProxyException Malformed(string message) =>
        new(TlsQuicProxyError.MalformedProxyResponse, message);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: PASS, 1 test

- [ ] **Step 5: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Protocol.cs tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs
git commit -m "feat(quic): add SOCKS5 proxy error type and protocol constants"
```

### Task 2: Greeting and method selection

**Files:**
- Modify: `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs`
- Test: `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs`

- [ ] **Step 1: Write the failing tests**

Append to `TlsQuicSocks5ProtocolTests`:

```csharp
    [Fact]
    public void GreetingOffersNoAuthenticationOnlyWithoutCredentials()
    {
        // RFC 1928 s3: VER | NMETHODS | METHODS
        Assert.Equal(
            new byte[] { 0x05, 0x01, 0x00 },
            TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false));
    }

    [Fact]
    public void GreetingOffersBothMethodsWithCredentials()
    {
        Assert.Equal(
            new byte[] { 0x05, 0x02, 0x00, 0x02 },
            TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: true));
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x02)]
    public void MethodSelectionReturnsTheChosenMethod(byte method)
    {
        Assert.Equal(
            method,
            TlsQuicSocks5Protocol.ParseMethodSelection([0x05, method]));
    }

    [Fact]
    public void MethodSelectionRejectsWrongVersion()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ParseMethodSelection([0x04, 0x00]));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }
```

Note on the test for `MethodNone` (`0xFF`): the codec returns it rather than throwing.
Mapping it to `NoAcceptableAuthenticationMethod` is the transport's job, and is covered in
Task 8. Keeping the codec free of policy is what lets it be fuzzed without a state machine.

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: FAIL, `CS0117: 'TlsQuicSocks5Protocol' does not contain a definition for 'EncodeGreeting'`

- [ ] **Step 3: Write minimal implementation**

Add to `TlsQuicSocks5Protocol`:

```csharp
    internal static byte[] EncodeGreeting(bool offerUsernamePassword) =>
        offerUsernamePassword
            ? [Version, 0x02, MethodNoAuthentication, MethodUsernamePassword]
            : [Version, 0x01, MethodNoAuthentication];

    internal static byte ParseMethodSelection(ReadOnlySpan<byte> response)
    {
        if (response.Length != 2)
        {
            throw Malformed(
                $"SOCKS5 method selection must be 2 bytes, received {response.Length}.");
        }

        if (response[0] != Version)
        {
            throw Malformed(
                $"SOCKS5 method selection VER was 0x{response[0]:X2}, expected 0x05.");
        }

        return response[1];
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Protocol.cs tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs
git commit -m "feat(quic): encode SOCKS5 greeting and parse method selection"
```

### Task 3: RFC 1929 username/password subnegotiation

**Files:**
- Modify: `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs`
- Test: `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
    [Fact]
    public void AuthenticationRequestMatchesRfc1929Layout()
    {
        // RFC 1929 s2: VER | ULEN | UNAME | PLEN | PASSWD, VER is 0x01.
        Assert.Equal(
            new byte[] { 0x01, 0x02, (byte)'a', (byte)'b', 0x03, (byte)'x', (byte)'y', (byte)'z' },
            TlsQuicSocks5Protocol.EncodeAuthenticationRequest("ab", "xyz"));
    }

    [Theory]
    [InlineData("", "password")]
    [InlineData("username", "")]
    public void AuthenticationRequestRejectsEmptyFields(string username, string password)
    {
        // RFC 1929 gives ULEN and PLEN a range of 1 to 255, so zero is unrepresentable.
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest(username, password));
    }

    [Fact]
    public void AuthenticationRequestRejectsOversizedFields()
    {
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest(new string('u', 256), "p"));
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest("u", new string('p', 256)));
    }

    [Fact]
    public void AuthenticationRequestMeasuresUtf8BytesNotCharacters()
    {
        // A 128-character string of 2-byte code points is 256 bytes and must be rejected.
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest(new string('é', 128), "p"));
    }

    [Fact]
    public void AuthenticationSuccessIsAccepted()
    {
        TlsQuicSocks5Protocol.ValidateAuthenticationReply([0x01, 0x00]);
    }

    [Fact]
    public void AuthenticationFailureIsRejected()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAuthenticationReply([0x01, 0x01]));

        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);
    }

    [Theory]
    [InlineData(new byte[] { 0x05, 0x00 })]     // wrong subnegotiation version
    [InlineData(new byte[] { 0x01 })]           // truncated
    public void AuthenticationReplyRejectsMalformedInput(byte[] reply)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAuthenticationReply(reply));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: FAIL, `CS0117: ... 'EncodeAuthenticationRequest'`

- [ ] **Step 3: Write minimal implementation**

Add `using System.Text;` to the file, then:

```csharp
    internal static byte[] EncodeAuthenticationRequest(string username, string password)
    {
        var user = Encoding.UTF8.GetBytes(username);
        var pass = Encoding.UTF8.GetBytes(password);

        // RFC 1929 s2: ULEN and PLEN are "1 to 255".
        if (user.Length is 0 or > 255)
        {
            throw new ArgumentException(
                "SOCKS5 username must encode to 1 to 255 UTF-8 bytes.", nameof(username));
        }

        if (pass.Length is 0 or > 255)
        {
            throw new ArgumentException(
                "SOCKS5 password must encode to 1 to 255 UTF-8 bytes.", nameof(password));
        }

        var buffer = new byte[3 + user.Length + pass.Length];
        buffer[0] = AuthenticationVersion;
        buffer[1] = (byte)user.Length;
        user.CopyTo(buffer, 2);
        buffer[2 + user.Length] = (byte)pass.Length;
        pass.CopyTo(buffer, 3 + user.Length);

        CryptographicOperations.ZeroMemory(user);
        CryptographicOperations.ZeroMemory(pass);
        return buffer;
    }

    internal static void ValidateAuthenticationReply(ReadOnlySpan<byte> reply)
    {
        if (reply.Length != 2)
        {
            throw Malformed(
                $"SOCKS5 authentication reply must be 2 bytes, received {reply.Length}.");
        }

        if (reply[0] != AuthenticationVersion)
        {
            throw Malformed(
                $"SOCKS5 authentication reply VER was 0x{reply[0]:X2}, expected 0x01.");
        }

        if (reply[1] != AuthenticationSuccess)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.CredentialsRejected,
                $"SOCKS5 proxy rejected the supplied credentials with status 0x{reply[1]:X2}.");
        }
    }
```

Add `using System.Security.Cryptography;` for `CryptographicOperations`. The caller is
responsible for zeroing the returned buffer after it is written to the socket; Task 8 does
that.

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: PASS, 15 tests

- [ ] **Step 5: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Protocol.cs tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs
git commit -m "feat(quic): implement RFC 1929 username/password subnegotiation"
```

### Task 4: UDP ASSOCIATE request and reply

**Files:**
- Modify: `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs`
- Test: `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
    [Fact]
    public void AssociateRequestSendsAllZeroAddressForIPv4()
    {
        // RFC 1928 s4: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT.
        // Zeros are sent because a bound local port is rewritten by NAT.
        Assert.Equal(
            new byte[] { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 },
            TlsQuicSocks5Protocol.EncodeAssociateRequest(AddressFamily.InterNetwork));
    }

    [Fact]
    public void AssociateRequestSendsAllZeroAddressForIPv6()
    {
        var expected = new byte[4 + 16 + 2];
        expected[0] = 0x05;
        expected[1] = 0x03;
        expected[3] = 0x04;

        Assert.Equal(
            expected,
            TlsQuicSocks5Protocol.EncodeAssociateRequest(AddressFamily.InterNetworkV6));
    }

    [Theory]
    [InlineData(0x01, TlsQuicProxyError.AssociateRejected)]
    [InlineData(0x07, TlsQuicProxyError.AssociateRejected)]
    [InlineData(0x08, TlsQuicProxyError.AssociateRejected)]
    public void AssociateReplyHeaderRejectsFailureCodes(byte reply, TlsQuicProxyError expected)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x05, reply, 0x00, 0x01]));

        Assert.Equal(expected, exception.Error);
        Assert.Contains($"0x{reply:X2}", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AssociateReplyHeaderRejectsWrongVersion()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x04, 0x00, 0x00, 0x01]));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Fact]
    public void AssociateReplyHeaderAcceptsSuccess()
    {
        Assert.Equal(
            0x01,
            TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x05, 0x00, 0x00, 0x01]));
    }

    [Fact]
    public void RelayEndPointUsesTheAddressTheProxyReturned()
    {
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv4,
            [203, 0, 113, 9],
            port: 1080,
            proxyAddress: IPAddress.Parse("198.51.100.1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointSubstitutesTheProxyForAWildcardAddress()
    {
        // Many relays answer 0.0.0.0, meaning "the host you are already talking to".
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv4,
            [0, 0, 0, 0],
            port: 1080,
            proxyAddress: IPAddress.Parse("198.51.100.1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("198.51.100.1"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointSubstitutesTheProxyForAWildcardIPv6Address()
    {
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv6,
            new byte[16],
            port: 1080,
            proxyAddress: IPAddress.Parse("2001:db8::1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointRejectsADomainNameReply()
    {
        // The client never sends ATYP 0x03, so a name in the reply is anomalous.
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ResolveRelayEndPoint(
                TlsQuicSocks5Protocol.AddressDomainName,
                "relay.example"u8,
                port: 1080,
                proxyAddress: IPAddress.Loopback));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }
```

Add `using System.Net;` and `using System.Net.Sockets;` to the test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: FAIL, `CS0117: ... 'EncodeAssociateRequest'`

- [ ] **Step 3: Write minimal implementation**

Add `using System.Net;` and `using System.Net.Sockets;`, then:

```csharp
    internal static byte[] EncodeAssociateRequest(AddressFamily family)
    {
        var addressLength = family == AddressFamily.InterNetworkV6 ? 16 : 4;
        var request = new byte[4 + addressLength + 2];
        request[0] = Version;
        request[1] = CommandUdpAssociate;
        request[2] = 0x00;
        request[3] = family == AddressFamily.InterNetworkV6 ? AddressIPv6 : AddressIPv4;
        // DST.ADDR and DST.PORT stay zero: RFC 1928 permits this when the client
        // cannot know the address it will send datagrams from.
        return request;
    }

    /// <summary>Validates VER, REP and RSV, and returns the reply's ATYP.</summary>
    internal static byte ValidateAssociateReplyHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != 4)
        {
            throw Malformed(
                $"SOCKS5 reply header must be 4 bytes, received {header.Length}.");
        }

        if (header[0] != Version)
        {
            throw Malformed(
                $"SOCKS5 reply VER was 0x{header[0]:X2}, expected 0x05.");
        }

        if (header[1] != 0x00)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.AssociateRejected,
                $"SOCKS5 proxy refused UDP ASSOCIATE with REP 0x{header[1]:X2}: " +
                DescribeReplyCode(header[1]));
        }

        return header[3];
    }

    // RFC 1928 s6.
    private static string DescribeReplyCode(byte code) => code switch
    {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unassigned reply code",
    };

    internal static IPEndPoint ResolveRelayEndPoint(
        byte addressType,
        ReadOnlySpan<byte> address,
        ushort port,
        IPAddress proxyAddress)
    {
        if (addressType is not (AddressIPv4 or AddressIPv6))
        {
            throw Malformed(
                $"SOCKS5 reply ATYP was 0x{addressType:X2}; only 0x01 and 0x04 are accepted.");
        }

        var expected = addressType == AddressIPv4 ? 4 : 16;
        if (address.Length != expected)
        {
            throw Malformed(
                $"SOCKS5 reply address was {address.Length} bytes, expected {expected}.");
        }

        var bound = new IPAddress(address);

        // A wildcard BND.ADDR means "the host you are already talking to".
        // Without this substitution the client sends datagrams to a null route.
        if (bound.Equals(IPAddress.Any) || bound.Equals(IPAddress.IPv6Any))
        {
            bound = proxyAddress;
        }

        return new IPEndPoint(bound, port);
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: PASS, 25 tests

- [ ] **Step 5: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Protocol.cs tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs
git commit -m "feat(quic): encode UDP ASSOCIATE and resolve the relay endpoint"
```

### Task 5: UDP datagram header

**Files:**
- Modify: `src/SharpTls/Quic/TlsQuicSocks5Protocol.cs`
- Test: `tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs`

This is the hot path: it runs on every datagram in both directions. Read is
`TryRead`-shaped and never throws, because the spec requires malformed datagrams to be
discarded rather than to fail the connection (RFC 9000 §14).

- [ ] **Step 1: Write the failing tests**

```csharp
    [Fact]
    public void UdpHeaderMatchesRfc1928Layout()
    {
        var buffer = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            buffer,
            new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443));

        // RSV(2)=0 | FRAG(1)=0 | ATYP(1)=1 | DST.ADDR(4) | DST.PORT(2, network order)
        Assert.Equal(TlsQuicSocks5Protocol.UdpHeaderSizeIPv4, written);
        Assert.Equal(
            new byte[] { 0x00, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB },
            buffer);
    }

    [Fact]
    public void UdpHeaderForIPv6IsTwentyTwoBytes()
    {
        var buffer = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv6];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            buffer,
            new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443));

        Assert.Equal(22, written);
        Assert.Equal(TlsQuicSocks5Protocol.AddressIPv6, buffer[3]);
        Assert.Equal(new byte[] { 0x01, 0xBB }, buffer[20..22]);
    }

    [Fact]
    public void UdpHeaderRoundTrips()
    {
        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4 + 3];
        TlsQuicSocks5Protocol.WriteUdpHeader(datagram, origin);

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(
            datagram, out var parsed, out var headerLength));
        Assert.Equal(origin, parsed);
        Assert.Equal(TlsQuicSocks5Protocol.UdpHeaderSizeIPv4, headerLength);
    }

    [Theory]
    // RSV must be 0x0000.
    [InlineData(new byte[] { 0x01, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    [InlineData(new byte[] { 0x00, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    // FRAG other than 0x00 must be dropped by an implementation without fragmentation.
    [InlineData(new byte[] { 0x00, 0x00, 0x01, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    [InlineData(new byte[] { 0x00, 0x00, 0x80, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    // ATYP 0x03 is never sent, so it is never expected back.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x03, 0x04, (byte)'h', (byte)'o', (byte)'s', (byte)'t', 0x01, 0xBB })]
    // Unknown ATYP.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x09, 203, 0, 113, 9, 0x01, 0xBB })]
    // Truncated: header declares IPv4 but the datagram ends inside DST.PORT.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01 })]
    // Truncated: shorter than the fixed 4-byte prefix.
    [InlineData(new byte[] { 0x00, 0x00, 0x00 })]
    [InlineData(new byte[0])]
    public void MalformedUdpHeadersAreRejectedWithoutThrowing(byte[] datagram)
    {
        Assert.False(TlsQuicSocks5Protocol.TryReadUdpHeader(datagram, out _, out _));
    }

    [Fact]
    public void ZeroLengthPayloadIsStillAValidDatagram()
    {
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4];
        TlsQuicSocks5Protocol.WriteUdpHeader(
            datagram, new IPEndPoint(IPAddress.Loopback, 443));

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(datagram, out _, out var length));
        Assert.Equal(datagram.Length, length);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: FAIL, `CS0117: ... 'WriteUdpHeader'`

- [ ] **Step 3: Write minimal implementation**

Add `using System.Buffers.Binary;`, then:

```csharp
    internal static int HeaderSizeFor(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? UdpHeaderSizeIPv6 : UdpHeaderSizeIPv4;

    internal static int WriteUdpHeader(Span<byte> destination, IPEndPoint target)
    {
        var isIPv6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        var headerLength = isIPv6 ? UdpHeaderSizeIPv6 : UdpHeaderSizeIPv4;

        destination[0] = 0x00;                                      // RSV
        destination[1] = 0x00;                                      // RSV
        destination[2] = 0x00;                                      // FRAG, never fragmented
        destination[3] = isIPv6 ? AddressIPv6 : AddressIPv4;        // ATYP

        if (!target.Address.TryWriteBytes(destination[4..], out var addressLength))
        {
            throw new ArgumentException(
                "Destination address did not fit the datagram header.", nameof(target));
        }

        BinaryPrimitives.WriteUInt16BigEndian(
            destination[(4 + addressLength)..], (ushort)target.Port);
        return headerLength;
    }

    internal static bool TryReadUdpHeader(
        ReadOnlySpan<byte> datagram,
        out IPEndPoint origin,
        out int headerLength)
    {
        origin = null!;
        headerLength = 0;

        if (datagram.Length < 4)
        {
            return false;
        }

        // RSV must be X'0000' and FRAG must be X'00': RFC 1928 s7 permits an
        // implementation without fragmentation support to drop anything else.
        if (datagram[0] != 0x00 || datagram[1] != 0x00 || datagram[2] != 0x00)
        {
            return false;
        }

        var addressLength = datagram[3] switch
        {
            AddressIPv4 => 4,
            AddressIPv6 => 16,
            _ => 0,
        };

        if (addressLength == 0)
        {
            return false;
        }

        headerLength = 4 + addressLength + 2;
        if (datagram.Length < headerLength)
        {
            headerLength = 0;
            return false;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(
            datagram[(4 + addressLength)..headerLength]);
        origin = new IPEndPoint(
            new IPAddress(datagram[4..(4 + addressLength)]), port);
        return true;
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicSocks5ProtocolTests"`
Expected: PASS, 38 tests

- [ ] **Step 5: Run the whole offline suite to confirm nothing regressed**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "Category!=Interop"`
Expected: PASS, no new failures

- [ ] **Step 6: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Protocol.cs tests/SharpTls.Tests/Quic/TlsQuicSocks5ProtocolTests.cs
git commit -m "feat(quic): encode and validate the SOCKS5 UDP datagram header"
```

---

## Chunk 2: The transports

### Task 6: The datagram interface

**Files:**
- Create: `src/SharpTls/Quic/ITlsQuicDatagramTransport.cs`

No test of its own. An interface with no implementation has no behaviour to assert; Task 7
is where it gets its first test.

- [ ] **Step 1: Write the interface**

```csharp
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SharpTls.Quic;

/// <summary>The result of receiving one datagram.</summary>
public readonly struct TlsQuicDatagramReceiveResult
{
    /// <summary>Creates a receive result.</summary>
    public TlsQuicDatagramReceiveResult(int length, IPEndPoint remoteEndPoint)
    {
        Length = length;
        RemoteEndPoint = remoteEndPoint;
    }

    /// <summary>Gets the number of payload bytes written to the caller's buffer.</summary>
    public int Length { get; }

    /// <summary>Gets the address of the peer that originated the datagram. For a relayed
    /// transport this is the decapsulated origin address, never the relay.</summary>
    public IPEndPoint RemoteEndPoint { get; }
}

/// <summary>Sends and receives UDP datagrams on behalf of a QUIC connection.</summary>
/// <remarks>One concurrent send and one concurrent receive are permitted. The shipped
/// implementations perform no internal locking.</remarks>
public interface ITlsQuicDatagramTransport : IAsyncDisposable
{
    /// <summary>Gets the largest payload this transport can carry after its own
    /// encapsulation. This is an endpoint ceiling, not a path MTU: QUIC path MTU
    /// discovery operates below this value.</summary>
    int MaxDatagramPayloadSize { get; }

    /// <summary>Sends one datagram.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The payload exceeds
    /// <see cref="MaxDatagramPayloadSize"/>.</exception>
    ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);

    /// <summary>Receives one datagram. Malformed or unauthorised datagrams are discarded
    /// and the call keeps waiting; it does not fail the connection.</summary>
    ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken);
}
```

- [ ] **Step 2: Verify it compiles**

Run: `dotnet build src/SharpTls/SharpTls.csproj`
Expected: Build succeeded

- [ ] **Step 3: Commit**

```bash
git add src/SharpTls/Quic/ITlsQuicDatagramTransport.cs
git commit -m "feat(quic): add the datagram transport interface"
```

### Task 7: Direct UDP transport

**Files:**
- Create: `src/SharpTls/Quic/TlsQuicUdpDatagramTransport.cs`
- Test: `tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs`:

```csharp
using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicDatagramTransportTests
{
    [Fact]
    public async Task DirectTransportRoundTripsADatagram()
    {
        using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var peerEndPoint = (IPEndPoint)peer.LocalEndPoint!;

        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        await transport.SendAsync(peerEndPoint, new byte[] { 1, 2, 3 }, CancellationToken.None);

        var received = new byte[16];
        var result = await peer
            .ReceiveFromAsync(received, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, result.ReceivedBytes);
        Assert.Equal(new byte[] { 1, 2, 3 }, received[..3]);
    }

    [Fact]
    public async Task DirectTransportRejectsAnOversizedPayload()
    {
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 9),
                new byte[transport.MaxDatagramPayloadSize + 1],
                CancellationToken.None));
    }

    [Fact]
    public async Task DirectTransportCeilingIsTheMaximumUdpPayload()
    {
        // RFC 9000 s18.2 names 65527 as the maximum permitted UDP payload.
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        Assert.Equal(65527, transport.MaxDatagramPayloadSize);
    }
}
```

This project is on xunit **2.9.3**, which has no `TestContext.Current` — that is xunit v3.
Use `CancellationToken.None` and bound the waits with `.WaitAsync(TimeSpan)` as above.
There is no existing socket code anywhere in this repository, so there is no in-house style
to copy; these tests set it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicDatagramTransportTests"`
Expected: FAIL, `CS0103: The name 'TlsQuicUdpDatagramTransport' does not exist`

- [ ] **Step 3: Write minimal implementation**

```csharp
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpTls.Quic;

/// <summary>Sends and receives QUIC datagrams directly over a UDP socket.</summary>
public sealed class TlsQuicUdpDatagramTransport : ITlsQuicDatagramTransport
{
    // RFC 9000 s18.2: 65527 is the maximum permitted UDP payload.
    private const int MaximumUdpPayload = 65527;

    private readonly Socket _socket;

    private TlsQuicUdpDatagramTransport(Socket socket) => _socket = socket;

    /// <summary>Creates a transport bound to an ephemeral port of the given family.</summary>
    public static ITlsQuicDatagramTransport Create(AddressFamily family)
    {
        var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(
            family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
        SetDontFragment(socket, family);
        return new TlsQuicUdpDatagramTransport(socket);
    }

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => MaximumUdpPayload;

    /// <summary>Sets the IPv4 Don't Fragment bit, which RFC 9000 s14 requires where the
    /// platform supports it. IPv6 routers do not fragment, so the flag does not apply.</summary>
    internal static void SetDontFragment(Socket socket, AddressFamily family)
    {
        if (family != AddressFamily.InterNetwork)
        {
            return;
        }

        try
        {
            socket.DontFragment = true;
        }
        catch (SocketException)
        {
            // The platform refused; QUIC still bounds datagrams to 1200 bytes until
            // path MTU discovery raises the limit.
        }
        catch (NotSupportedException)
        {
        }
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));

        _ = await _socket
            .SendToAsync(payload, SocketFlags.None, destination, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var any = new IPEndPoint(
            _socket.AddressFamily == AddressFamily.InterNetworkV6
                ? IPAddress.IPv6Any
                : IPAddress.Any,
            0);

        var result = await _socket
            .ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken)
            .ConfigureAwait(false);

        return new TlsQuicDatagramReceiveResult(
            result.ReceivedBytes, (IPEndPoint)result.RemoteEndPoint);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        _socket.Dispose();
        return ValueTask.CompletedTask;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicDatagramTransportTests"`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicUdpDatagramTransport.cs tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs
git commit -m "feat(quic): add the direct UDP datagram transport"
```

### Task 8: SOCKS5 options and association handshake

**Files:**
- Create: `src/SharpTls/Quic/TlsQuicSocks5Options.cs`
- Create: `src/SharpTls/Quic/TlsQuicSocks5Transport.cs`

The handshake cannot be tested without a server, so its tests arrive with the fake relay in
Task 10. Write the options validation test now, because that part is pure.

- [ ] **Step 1: Write the failing test**

Append to `TlsQuicDatagramTransportTests`:

```csharp
    [Theory]
    [InlineData("user", null)]
    [InlineData(null, "pass")]
    public async Task Socks5OptionsRejectHalfSuppliedCredentials(string? user, string? pass)
    {
        var options = new TlsQuicSocks5Options
        {
            ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 1080),
            Username = user,
            Password = pass,
        };

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await TlsQuicSocks5Transport.ConnectAsync(options, CancellationToken.None));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~Socks5OptionsRejectHalfSuppliedCredentials"`
Expected: FAIL, `CS0103: The name 'TlsQuicSocks5Options' does not exist`

- [ ] **Step 3: Write the options type**

Create `src/SharpTls/Quic/TlsQuicSocks5Options.cs`:

```csharp
using System.Net;

namespace SharpTls.Quic;

/// <summary>Configuration for a SOCKS5 UDP relay.</summary>
public sealed class TlsQuicSocks5Options
{
    /// <summary>Gets the SOCKS5 server. A <see cref="DnsEndPoint"/> is resolved for the
    /// TCP control connection.</summary>
    public required EndPoint ProxyEndPoint { get; init; }

    /// <summary>Gets the RFC 1929 username, 1 to 255 bytes when encoded as UTF-8.</summary>
    public string? Username { get; init; }

    /// <summary>Gets the RFC 1929 password, 1 to 255 bytes when encoded as UTF-8.</summary>
    public string? Password { get; init; }
}
```

- [ ] **Step 4: Write the transport's construction and handshake**

Create `src/SharpTls/Quic/TlsQuicSocks5Transport.cs`:

```csharp
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SharpTls.Quic;

/// <summary>Sends and receives QUIC datagrams through a SOCKS5 UDP relay.</summary>
public sealed class TlsQuicSocks5Transport : ITlsQuicDatagramTransport
{
    private const int MaximumUdpPayload = 65527;

    private readonly Socket _control;
    private readonly Socket _udp;
    private readonly IPEndPoint _relay;
    private readonly int _headerSize;
    private readonly CancellationTokenSource _terminated = new();

    private TlsQuicSocks5Transport(Socket control, Socket udp, IPEndPoint relay)
    {
        _control = control;
        _udp = udp;
        _relay = relay;
        _headerSize = TlsQuicSocks5Protocol.HeaderSizeFor(relay.AddressFamily);
        _ = WatchControlConnectionAsync();
    }

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => MaximumUdpPayload - _headerSize;

    /// <summary>Establishes a UDP association with the configured proxy.</summary>
    public static async ValueTask<ITlsQuicDatagramTransport> ConnectAsync(
        TlsQuicSocks5Options options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var hasUser = options.Username is not null;
        var hasPassword = options.Password is not null;
        if (hasUser != hasPassword)
        {
            throw new ArgumentException(
                "SOCKS5 username and password must both be supplied or both be omitted.",
                nameof(options));
        }

        Socket? control = null;
        Socket? udp = null;
        try
        {
            control = new Socket(SocketType.Stream, ProtocolType.Tcp);
            await control.ConnectAsync(options.ProxyEndPoint, cancellationToken)
                .ConfigureAwait(false);

            var proxy = (IPEndPoint)control.RemoteEndPoint!;
            var family = proxy.AddressFamily;

            udp = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(
                family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            TlsQuicUdpDatagramTransport.SetDontFragment(udp, family);

            var relay = await NegotiateAsync(control, options, proxy, family, cancellationToken)
                .ConfigureAwait(false);

            var transport = new TlsQuicSocks5Transport(control, udp, relay);
            control = null;
            udp = null;
            return transport;
        }
        finally
        {
            control?.Dispose();
            udp?.Dispose();
        }
    }

    private static async ValueTask<IPEndPoint> NegotiateAsync(
        Socket control,
        TlsQuicSocks5Options options,
        IPEndPoint proxy,
        AddressFamily family,
        CancellationToken cancellationToken)
    {
        var offerCredentials = options.Username is not null;

        await SendAllAsync(
            control,
            TlsQuicSocks5Protocol.EncodeGreeting(offerCredentials),
            cancellationToken).ConfigureAwait(false);

        var selection = new byte[2];
        await ReceiveExactlyAsync(control, selection, cancellationToken).ConfigureAwait(false);
        var method = TlsQuicSocks5Protocol.ParseMethodSelection(selection);

        switch (method)
        {
            case TlsQuicSocks5Protocol.MethodNoAuthentication:
                break;

            case TlsQuicSocks5Protocol.MethodUsernamePassword when offerCredentials:
                await AuthenticateAsync(control, options, cancellationToken).ConfigureAwait(false);
                break;

            case TlsQuicSocks5Protocol.MethodUsernamePassword:
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.CredentialsRequired,
                    "The SOCKS5 proxy requires username/password authentication but no credentials were configured.");

            case TlsQuicSocks5Protocol.MethodNone:
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.NoAcceptableAuthenticationMethod,
                    "The SOCKS5 proxy accepted none of the offered authentication methods.");

            default:
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.NoAcceptableAuthenticationMethod,
                    $"The SOCKS5 proxy selected unsupported method 0x{method:X2}.");
        }

        await SendAllAsync(
            control,
            TlsQuicSocks5Protocol.EncodeAssociateRequest(family),
            cancellationToken).ConfigureAwait(false);

        var header = new byte[4];
        await ReceiveExactlyAsync(control, header, cancellationToken).ConfigureAwait(false);
        var addressType = TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(header);

        var addressLength = addressType == TlsQuicSocks5Protocol.AddressIPv4 ? 4 : 16;
        var tail = new byte[addressLength + 2];
        await ReceiveExactlyAsync(control, tail, cancellationToken).ConfigureAwait(false);

        var port = (ushort)((tail[addressLength] << 8) | tail[addressLength + 1]);
        return TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            addressType, tail.AsSpan(0, addressLength), port, proxy.Address);
    }

    private static async ValueTask AuthenticateAsync(
        Socket control,
        TlsQuicSocks5Options options,
        CancellationToken cancellationToken)
    {
        var request = TlsQuicSocks5Protocol.EncodeAuthenticationRequest(
            options.Username!, options.Password!);
        try
        {
            await SendAllAsync(control, request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request);
        }

        var reply = new byte[2];
        await ReceiveExactlyAsync(control, reply, cancellationToken).ConfigureAwait(false);
        TlsQuicSocks5Protocol.ValidateAuthenticationReply(reply);
    }

    private static async ValueTask SendAllAsync(
        Socket socket, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        while (!buffer.IsEmpty)
        {
            var sent = await socket
                .SendAsync(buffer, SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            buffer = buffer[sent..];
        }
    }

    private static async ValueTask ReceiveExactlyAsync(
        Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var total = buffer.Length;
        while (!buffer.IsEmpty)
        {
            var read = await socket
                .ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw TlsQuicSocks5Protocol.Malformed(
                    $"The SOCKS5 control connection closed after {total - buffer.Length} of {total} expected bytes.");
            }

            buffer = buffer[read..];
        }
    }
}
```

The datagram path, the control-connection watcher and disposal land in Task 9; this file
does not compile until then.

- [ ] **Step 5: Commit the work in progress**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Options.cs src/SharpTls/Quic/TlsQuicSocks5Transport.cs
git commit -m "feat(quic): negotiate a SOCKS5 UDP association"
```

### Task 9: SOCKS5 datagram path, lifetime and disposal

**Files:**
- Modify: `src/SharpTls/Quic/TlsQuicSocks5Transport.cs`

- [ ] **Step 1: Add the remaining members**

Add to `TlsQuicSocks5Transport`:

```csharp
    /// <inheritdoc />
    public async ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));
        ThrowIfTerminated();

        var datagram = new byte[_headerSize + payload.Length];
        TlsQuicSocks5Protocol.WriteUdpHeader(datagram, destination);
        payload.Span.CopyTo(datagram.AsSpan(_headerSize));

        _ = await _udp
            .SendToAsync(datagram, SocketFlags.None, _relay, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, _terminated.Token);

        var scratch = new byte[_headerSize + buffer.Length];
        var any = new IPEndPoint(
            _relay.AddressFamily == AddressFamily.InterNetworkV6
                ? IPAddress.IPv6Any
                : IPAddress.Any,
            0);

        while (true)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _udp
                    .ReceiveFromAsync(scratch, SocketFlags.None, any, linked.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_terminated.IsCancellationRequested)
            {
                ThrowIfTerminated();
                throw;
            }

            // RFC 1928: the relay records one client address for the association.
            // Anything from another source is not part of it.
            if (!_relay.Equals(result.RemoteEndPoint))
            {
                continue;
            }

            var datagram = scratch.AsSpan(0, result.ReceivedBytes);
            if (!TlsQuicSocks5Protocol.TryReadUdpHeader(datagram, out var origin, out var headerLength))
            {
                // RFC 9000 s14: discard rather than fail the connection.
                continue;
            }

            var payload = datagram[headerLength..];
            if (payload.Length > buffer.Length)
            {
                continue;
            }

            payload.CopyTo(buffer.Span);
            return new TlsQuicDatagramReceiveResult(payload.Length, origin);
        }
    }

    /// <summary>RFC 1928: the association ends when the control connection ends. The read
    /// exists only to observe that; any payload is a protocol violation.</summary>
    private async Task WatchControlConnectionAsync()
    {
        var scratch = new byte[1];
        try
        {
            var read = await _control
                .ReceiveAsync(scratch, SocketFlags.None, _terminated.Token)
                .ConfigureAwait(false);
            _ = read;
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        await _terminated.CancelAsync().ConfigureAwait(false);
    }

    private void ThrowIfTerminated()
    {
        if (_terminated.IsCancellationRequested)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.AssociationTerminated,
                "The SOCKS5 control connection closed, which ends the UDP association.");
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _terminated.CancelAsync().ConfigureAwait(false);
        _udp.Dispose();
        _control.Dispose();
        _terminated.Dispose();
    }
```

Note the ordering in `DisposeAsync`: the UDP socket closes first so an in-flight receive
unblocks before the control connection goes away, which keeps the shutdown path from
reporting `AssociationTerminated` for an ordinary dispose.

**Allocation note, carried forward from Task 5's review.** `TryReadUdpHeader` constructs an
`IPAddress` (plus a `ushort[8]` for IPv6) and an `IPEndPoint` for every datagram it parses.
That was accepted as the right shape for a header codec rather than optimised away, but it
means this receive loop pays 2-3 heap allocations per packet at QUIC rates. The allocation
is genuinely needed here, because `origin` is returned to the caller as
`TlsQuicDatagramReceiveResult.RemoteEndPoint`. It becomes wasteful only one layer up, where
subsystem A compares that endpoint against an already-known peer address and discards it.
If profiling shows it matters, the fast path belongs in subsystem A's packet loop — a
byte-level comparison against the expected peer before materialising an `IPEndPoint` — not
in this codec. Do not restructure the codec's return type to chase it.

- [ ] **Step 2: Verify it compiles**

Run: `dotnet build src/SharpTls/SharpTls.csproj`
Expected: Build succeeded

- [ ] **Step 3: Run the offline suite**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "Category!=Interop"`
Expected: PASS. `Socks5OptionsRejectHalfSuppliedCredentials` now passes; the rest are unchanged.

- [ ] **Step 4: Commit**

```bash
git add src/SharpTls/Quic/TlsQuicSocks5Transport.cs
git commit -m "feat(quic): relay QUIC datagrams through a SOCKS5 UDP association"
```

---

## Chunk 3: Evidence

### Task 10: In-process fake relay and end-to-end tests

**Files:**
- Create: `tests/SharpTls.Tests/Quic/FakeSocks5Relay.cs`
- Modify: `tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs`

- [ ] **Step 1: Write the fake relay**

```csharp
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpTls.Tests.Quic;

/// <summary>A deterministic in-process SOCKS5 UDP relay for offline tests.</summary>
internal sealed class FakeSocks5Relay : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly Socket _udp;
    private readonly CancellationTokenSource _stopping = new();
    private readonly string? _username;
    private readonly string? _password;
    private readonly bool _wildcardBoundAddress;
    private Socket? _control;
    private IPEndPoint? _client;

    private FakeSocks5Relay(string? username, string? password, bool wildcardBoundAddress)
    {
        _username = username;
        _password = password;
        _wildcardBoundAddress = wildcardBoundAddress;

        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(1);

        _udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    }

    internal static FakeSocks5Relay Start(
        string? username = null,
        string? password = null,
        bool wildcardBoundAddress = false)
    {
        var relay = new FakeSocks5Relay(username, password, wildcardBoundAddress);
        _ = relay.AcceptAsync();
        return relay;
    }

    internal IPEndPoint ProxyEndPoint => (IPEndPoint)_listener.LocalEndPoint!;

    internal IPEndPoint UdpEndPoint => (IPEndPoint)_udp.LocalEndPoint!;

    /// <summary>Closes the control connection, which RFC 1928 says ends the association.</summary>
    internal void DropControlConnection() => _control?.Dispose();

    /// <summary>Sends a raw datagram to the associated client, bypassing encapsulation.</summary>
    internal void SendRaw(byte[] datagram) => _udp.SendTo(datagram, _client!);

    private async Task AcceptAsync()
    {
        try
        {
            _control = await _listener.AcceptAsync(_stopping.Token);

            var greeting = new byte[2];
            await ReceiveExactlyAsync(_control, greeting);
            var methods = new byte[greeting[1]];
            await ReceiveExactlyAsync(_control, methods);

            var wantsAuthentication = _username is not null;
            await _control.SendAsync(
                new byte[] { 0x05, wantsAuthentication ? (byte)0x02 : (byte)0x00 },
                SocketFlags.None);

            if (wantsAuthentication)
            {
                var header = new byte[2];
                await ReceiveExactlyAsync(_control, header);
                var user = new byte[header[1]];
                await ReceiveExactlyAsync(_control, user);
                var passwordLength = new byte[1];
                await ReceiveExactlyAsync(_control, passwordLength);
                var pass = new byte[passwordLength[0]];
                await ReceiveExactlyAsync(_control, pass);

                var ok = Encoding.UTF8.GetString(user) == _username
                    && Encoding.UTF8.GetString(pass) == _password;
                await _control.SendAsync(
                    new byte[] { 0x01, ok ? (byte)0x00 : (byte)0x01 }, SocketFlags.None);
                if (!ok)
                {
                    _control.Dispose();
                    return;
                }
            }

            var request = new byte[10];
            await ReceiveExactlyAsync(_control, request);

            var bound = _wildcardBoundAddress
                ? IPAddress.Any.GetAddressBytes()
                : UdpEndPoint.Address.GetAddressBytes();
            var port = (ushort)UdpEndPoint.Port;
            byte[] reply =
            [
                0x05, 0x00, 0x00, 0x01,
                bound[0], bound[1], bound[2], bound[3],
                (byte)(port >> 8), (byte)(port & 0xFF),
            ];
            await _control.SendAsync(reply, SocketFlags.None);

            _ = RelayAsync();
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>Echoes each datagram back with its header rewritten as the origin would appear.</summary>
    private async Task RelayAsync()
    {
        var buffer = new byte[70000];
        var any = new IPEndPoint(IPAddress.Any, 0);
        try
        {
            while (!_stopping.IsCancellationRequested)
            {
                var result = await _udp.ReceiveFromAsync(
                    buffer, SocketFlags.None, any, _stopping.Token);
                _client = (IPEndPoint)result.RemoteEndPoint;
                await _udp.SendToAsync(
                    buffer.AsMemory(0, result.ReceivedBytes),
                    SocketFlags.None,
                    _client,
                    _stopping.Token);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task ReceiveExactlyAsync(Socket socket, Memory<byte> buffer)
    {
        while (!buffer.IsEmpty)
        {
            var read = await socket.ReceiveAsync(buffer, SocketFlags.None);
            if (read == 0)
            {
                throw new IOException("The fake relay's peer closed early.");
            }

            buffer = buffer[read..];
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync();
        _control?.Dispose();
        _udp.Dispose();
        _listener.Dispose();
        _stopping.Dispose();
    }
}
```

The echo behaviour means a sent datagram comes back with the same header, so the origin the
client parses is whatever destination it sent to. That is enough to prove encapsulation,
decapsulation and address reporting in one round trip.

- [ ] **Step 2: Write the end-to-end tests**

Append to `TlsQuicDatagramTransportTests`:

```csharp
    [Fact]
    public async Task RelayedTransportRoundTripsADatagram()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        await transport.SendAsync(origin, new byte[] { 9, 8, 7 }, CancellationToken.None);

        var buffer = new byte[64];
        var result = await transport.ReceiveAsync(buffer, CancellationToken.None);

        Assert.Equal(3, result.Length);
        Assert.Equal(new byte[] { 9, 8, 7 }, buffer[..3]);
        Assert.Equal(origin, result.RemoteEndPoint);
    }

    [Fact]
    public async Task RelayedTransportAuthenticatesWithCredentials()
    {
        await using var relay = FakeSocks5Relay.Start("alice", "s3cret");
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options
            {
                ProxyEndPoint = relay.ProxyEndPoint,
                Username = "alice",
                Password = "s3cret",
            },
            CancellationToken.None);

        Assert.NotNull(transport);
    }

    [Fact]
    public async Task RelayedTransportReportsRejectedCredentials()
    {
        await using var relay = FakeSocks5Relay.Start("alice", "s3cret");

        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await TlsQuicSocks5Transport.ConnectAsync(
                new TlsQuicSocks5Options
                {
                    ProxyEndPoint = relay.ProxyEndPoint,
                    Username = "alice",
                    Password = "wrong",
                },
                CancellationToken.None));

        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);
    }

    [Fact]
    public async Task RelayedTransportReportsMissingCredentials()
    {
        await using var relay = FakeSocks5Relay.Start("alice", "s3cret");

        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await TlsQuicSocks5Transport.ConnectAsync(
                new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
                CancellationToken.None));

        Assert.Equal(TlsQuicProxyError.CredentialsRequired, exception.Error);
    }

    [Fact]
    public async Task RelayedTransportSubstitutesAWildcardBoundAddress()
    {
        await using var relay = FakeSocks5Relay.Start(wildcardBoundAddress: true);
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        // If substitution failed the datagram goes to 0.0.0.0 and the round trip never returns.
        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        await transport.SendAsync(origin, new byte[] { 1 }, CancellationToken.None);

        var buffer = new byte[16];
        var result = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, result.Length);
    }

    [Fact]
    public async Task DroppingTheControlConnectionEndsTheAssociation()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        relay.DropControlConnection();

        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await transport.ReceiveAsync(new byte[64], CancellationToken.None)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(TlsQuicProxyError.AssociationTerminated, exception.Error);
    }

    [Theory]
    // FRAG != 0 must be dropped.
    [InlineData(new byte[] { 0x00, 0x00, 0x01, 0x01, 203, 0, 113, 9, 0x01, 0xBB, 0xAA })]
    // RSV != 0 must be dropped.
    [InlineData(new byte[] { 0x00, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB, 0xAA })]
    // Header overruns the datagram.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x01, 203, 0, 113 })]
    public async Task MalformedRelayedDatagramsAreDroppedNotFatal(byte[] hostile)
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        // Prime the relay so it knows the client's address, then inject, then send a good one.
        await transport.SendAsync(origin, new byte[] { 5 }, CancellationToken.None);
        var buffer = new byte[64];
        _ = await transport.ReceiveAsync(buffer, CancellationToken.None);

        relay.SendRaw(hostile);
        await transport.SendAsync(origin, new byte[] { 6 }, CancellationToken.None);

        var result = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(5));

        // The hostile datagram was skipped and the good one arrived.
        Assert.Equal(1, result.Length);
        Assert.Equal(6, buffer[0]);
    }
```

- [ ] **Step 3: Run the tests**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicDatagramTransportTests"`
Expected: PASS. If `MalformedRelayedDatagramsAreDroppedNotFatal` hangs, the receive loop is
returning instead of continuing on a bad header; re-read `ReceiveAsync` in Task 9.

- [ ] **Step 4: Commit**

```bash
git add tests/SharpTls.Tests/Quic/FakeSocks5Relay.cs tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs
git commit -m "test(quic): cover the SOCKS5 association against an in-process relay"
```

### Task 11: Size budget

**Files:**
- Modify: `tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs`

This is the test that catches a silent regression in the one place SOCKS5 can break QUIC.

- [ ] **Step 1: Write the tests**

```csharp
    [Fact]
    public async Task RelayedCeilingSubtractsTheIPv4HeaderOverhead()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        // RFC 9000 s18.2 maximum UDP payload, minus the 10-byte RFC 1928 s7 header.
        Assert.Equal(65527 - 10, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task RelayedTransportRejectsAnOversizedPayload()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 443),
                new byte[transport.MaxDatagramPayloadSize + 1],
                CancellationToken.None));
    }

    [Fact]
    public void MinimumInitialDatagramCostsTenBytesOverIPv4()
    {
        // RFC 9000 s14.1: the client MUST expand Initial datagrams to at least 1200 bytes.
        // Through a SOCKS5 relay that becomes 1210 bytes on the client-to-relay path.
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4 + 1200];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            datagram, new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443));

        Assert.Equal(10, written);
        Assert.Equal(1210, datagram.Length);
    }

    [Fact]
    public void MinimumInitialDatagramCostsTwentyTwoBytesOverIPv6()
    {
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv6 + 1200];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            datagram, new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443));

        Assert.Equal(22, written);
        Assert.Equal(1222, datagram.Length);
    }
```

`TlsQuicSocks5Protocol` is `internal`. `src/SharpTls/Properties/AssemblyInfo.cs` already
carries `[assembly: InternalsVisibleTo("SharpTls.Tests")]` and
`[assembly: InternalsVisibleTo("SharpTls.Fuzz")]`, so both the tests and the Task 12 fuzz
target reach it without changes. Do not make the codec public to work around a visibility
error; fix the assembly name instead.

- [ ] **Step 2: Run the tests**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~TlsQuicDatagramTransportTests"`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/SharpTls.Tests/Quic/TlsQuicDatagramTransportTests.cs
git commit -m "test(quic): pin the SOCKS5 encapsulation size budget"
```

### Task 12: Fuzz target

**Files:**
- Modify: `tools/SharpTls.Fuzz/ProtocolFuzzTargets.cs`

- [ ] **Step 1: Register the target**

Add `"socks5"` to the `Names` array at line 20:

```csharp
    private static readonly string[] Names =
    [
        "clienthello",
        "serverflight",
        "certificates",
        "records",
        "sessions",
        "ech-quic-dns",
        "state-machines",
        "socks5",
    ];
```

- [ ] **Step 2: Add the boundary helper**

Next to the existing `QuicBoundary` and `DnsBoundary` helpers:

```csharp
    private static void ProxyBoundary(Action action)
    {
        try { action(); }
        catch (TlsQuicProxyException) { }
    }
```

- [ ] **Step 3: Add the target body and its switch case**

Add a case `"socks5": FuzzSocks5(owned); break;` to the `switch (target)` in `Run`,
alongside the existing cases, and add:

```csharp
    private static void FuzzSocks5(byte[] input)
    {
        ProxyBoundary(() => TlsQuicSocks5Protocol.ParseMethodSelection(input));
        ProxyBoundary(() => TlsQuicSocks5Protocol.ValidateAuthenticationReply(input));
        ProxyBoundary(() => TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(input));
        ProxyBoundary(() =>
        {
            if (input.Length >= 3)
            {
                _ = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
                    input[0],
                    input.AsSpan(1, input.Length - 3),
                    (ushort)((input[^2] << 8) | input[^1]),
                    IPAddress.Loopback);
            }
        });

        // TryReadUdpHeader must never throw for any input at all.
        _ = TlsQuicSocks5Protocol.TryReadUdpHeader(input, out _, out _);
    }
```

Also add a `case "socks5": AddSocks5Seeds(seeds); break;` to the seed switch around line
189, with a seed method contributing a valid method selection, a valid auth reply, a valid
ASSOCIATE reply and a valid UDP header — the same byte arrays already asserted in Tasks 2
through 5.

- [ ] **Step 4: Verify the target is registered**

Run: `dotnet run --project tools/SharpTls.Fuzz -- --list-targets`
Expected: output includes `socks5`

- [ ] **Step 5: Run the target**

Run: `dotnet run --project tools/SharpTls.Fuzz -- --target socks5 --iterations 200000 --seed 1`
Expected: completes with no unhandled exception and no allocation-limit violation

- [ ] **Step 6: Commit**

```bash
git add tools/SharpTls.Fuzz/ProtocolFuzzTargets.cs
git commit -m "test(quic): add a SOCKS5 decoder fuzz target"
```

### Task 13: Documentation, public API contract and opt-in interop

**Files:**
- Create: `docs/SOCKS5-DATAGRAM-TRANSPORT.md`
- Create: `tests/SharpTls.Tests/Interop/Socks5RelayInteropTests.cs`
- Modify: `docs/QUIC-TLS.md`, `docs/ROADMAP.md`, `SECURITY.md`, `tests/SharpTls.Tests/Api/PublicApi.Shipped.txt`
- Modify: `docs/superpowers/specs/2026-08-16-quic-socks5-datagram-transport-design.md`

- [ ] **Step 1: Update the public API contract**

Run the API compat test to get the exact expected lines:

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~PublicApi"`
Expected: FAIL, listing the new public members

Add those lines to `tests/SharpTls.Tests/Api/PublicApi.Shipped.txt` verbatim, in the file's
existing sort order. The new surface is: `TlsQuicProxyError`, `TlsQuicProxyException`,
`TlsQuicDatagramReceiveResult`, `ITlsQuicDatagramTransport`, `TlsQuicUdpDatagramTransport`,
`TlsQuicSocks5Options`, `TlsQuicSocks5Transport`.

- [ ] **Step 2: Re-run the API test**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "FullyQualifiedName~PublicApi"`
Expected: PASS

- [ ] **Step 3: Correct the spec's codec sentence**

In `docs/superpowers/specs/2026-08-16-quic-socks5-datagram-transport-design.md`, replace:

> SOCKS5 uses fixed-width big-endian fields only, so it reuses the existing `SharpTls.IO` big-endian primitives; the existing `QuicVariableLengthInteger` is not involved.

with:

> SOCKS5 uses fixed-width big-endian fields only, so the codec uses `System.Buffers.Binary.BinaryPrimitives` directly. `TlsBinaryWriter` is built around TLS length-prefixed vectors and is not a fit; `QuicVariableLengthInteger` is not involved either.

- [ ] **Step 4: Write `docs/SOCKS5-DATAGRAM-TRANSPORT.md`**

Cover, with the same citations used in the spec: the interface contract and its threading
rule; `TlsQuicSocks5Options` and the both-or-neither credential rule; the association
sequence; the three deployed-relay behaviours (wildcard `BND.ADDR`, all-zero ASSOCIATE
address, DF bit); the size budget table; the inbound drop rules; the error model; and the
explicit non-goals (CONNECT, BIND, SOCKS4, GSS-API, fragmentation).

State plainly that a SOCKS5 relay sees every datagram's destination address and that the
client resolves origin names locally, so the client's resolver observes them.

- [ ] **Step 5: Update `docs/QUIC-TLS.md` and `docs/ROADMAP.md`**

`docs/QUIC-TLS.md` currently says the surrounding transport owns UDP and that "HTTP/3 and
QPACK are not part of this library". Amend the UDP claim: the datagram transport now ships
here, while packets, recovery, congestion control, streams, QPACK and HTTP/3 remain
outside. Do not weaken the HTTP/3 statement; it is still true.

`docs/ROADMAP.md` "Deliberate core boundaries" lists "QUIC transport, recovery, streams,
QPACK and HTTP/3" as non-goals. Narrow that bullet to the parts still out of scope and add
a new numbered phase for the datagram transport, following the format of the existing
phases, with its status and its test gate.

Add a line to `SECURITY.md` noting that a configured SOCKS5 relay observes every datagram's
destination address and the timing and size of all traffic.

- [ ] **Step 6: Write the opt-in interop test**

Create `tests/SharpTls.Tests/Interop/Socks5RelayInteropTests.cs`. Every test carries
`[Trait("Category", "Interop")]` and reads its proxy endpoint and credentials from
environment variables, skipping when they are absent — match the gating style already used
in `tests/SharpTls.Tests/Interop/PublicServerInteropTests.cs`. Two tests: association plus
datagram round trip without credentials, and the same with credentials.

Document in the file header that the harness is verified against 3proxy, Dante and gost.

- [ ] **Step 7: Confirm interop is excluded from the offline suite**

Run: `dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "Category!=Interop"`
Expected: PASS, and the interop tests do not appear in the run

- [ ] **Step 8: Full verification**

```bash
dotnet build src/SharpTls/SharpTls.csproj
dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj --filter "Category!=Interop"
dotnet run --project tools/SharpTls.Fuzz -- --target socks5 --iterations 200000 --seed 1
```

Expected: build succeeds, all offline tests pass, fuzz target completes clean.

- [ ] **Step 9: Commit**

```bash
git add docs/ tests/SharpTls.Tests/Api/PublicApi.Shipped.txt tests/SharpTls.Tests/Interop/Socks5RelayInteropTests.cs SECURITY.md
git commit -m "docs(quic): document the SOCKS5 datagram transport and update boundaries"
```

---

## Done when

- `dotnet test --filter "Category!=Interop"` passes on Linux, macOS and Windows.
- `dotnet run --project tools/SharpTls.Fuzz -- --target socks5 --iterations 200000` is clean.
- `PublicApi.Shipped.txt` matches the shipped surface.
- `docs/QUIC-TLS.md` and `docs/ROADMAP.md` no longer claim UDP is out of scope.
- The interop tests pass against at least one real relay, run manually.

## Not in this plan

QUIC packets, frames, streams, loss recovery, congestion control and HTTP/3. Those are
subsystems A, B, C and E in the spec's roadmap table, each with its own spec and plan.
