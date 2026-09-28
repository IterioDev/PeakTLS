using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TlsClient;

/// <summary>Describes an HTTP CONNECT, SOCKS5, or MASQUE (RFC 9298 CONNECT-UDP) proxy.</summary>
public sealed class TlsProxy
{
    private readonly NetworkCredential? _credentials;

    private TlsProxy(
        TlsProxyType type,
        Uri address,
        NetworkCredential? credentials)
    {
        Type = type;
        Address = address;
        _credentials = credentials is null
            ? null
            : new NetworkCredential(credentials.UserName, credentials.Password, credentials.Domain);
        PoolKey = CreatePoolKey(type, address, EffectivePort, _credentials);
    }

    /// <summary>Gets the proxy protocol.</summary>
    public TlsProxyType Type { get; }

    /// <summary>Gets the proxy endpoint without user-info.</summary>
    public Uri Address { get; }

    /// <summary>Gets credentials without exposing them through <see cref="ToString"/>.</summary>
    public NetworkCredential? Credentials => _credentials is null
        ? null
        : new NetworkCredential(_credentials.UserName, _credentials.Password, _credentials.Domain);

    /// <summary>Creates an HTTP CONNECT proxy from a URL, including optional user-info.</summary>
    public static TlsProxy Http(string address) => CreateFromUri(
        TlsProxyType.Http,
        address,
        Uri.UriSchemeHttp);

    /// <summary>Creates an HTTP CONNECT proxy from a URL, including optional user-info.</summary>
    public static TlsProxy Http(Uri address) => CreateFromUri(
        TlsProxyType.Http,
        address,
        Uri.UriSchemeHttp);

    /// <summary>Creates an HTTP CONNECT proxy with Basic credentials.</summary>
    public static TlsProxy Http(string address, string username, string password) => Create(
        TlsProxyType.Http,
        new Uri(address, UriKind.Absolute),
        Uri.UriSchemeHttp,
        new NetworkCredential(username, password));

    /// <summary>Creates a SOCKS5 proxy from a URL, including optional user-info.</summary>
    public static TlsProxy Socks5(string address) => CreateFromUri(
        TlsProxyType.Socks5,
        address,
        "socks5");

    /// <summary>Creates a SOCKS5 proxy with username/password authentication.</summary>
    public static TlsProxy Socks5(string address, string username, string password)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);
        return Create(
            TlsProxyType.Socks5,
            new Uri(address, UriKind.Absolute),
            "socks5",
            new NetworkCredential(username, password));
    }

    /// <summary>An RFC 9298 CONNECT-UDP proxy reached over HTTP/3 on an explicit UDP port.</summary>
    /// <remarks>Used through <see cref="TlsSessionOptions"/>'s Quic.Proxy. TCP requests never use
    /// it. The port is required; <c>:443</c> counts as default and is rejected.</remarks>
    /// <summary>The inner UDP payload ceiling a MASQUE dial applies by default: the 1352
    /// bytes the Oxylabs MASQUE guide states for inner packets under its 1392-byte outer
    /// packets. The outer connection's own arithmetic allows a few bytes more; a proxy that
    /// ends a tunnel on a datagram it finds too large does not say so, so the guide's number
    /// is the default and <see cref="Masque"/> takes another.</summary>
    public const int DefaultMaxInnerDatagramPayload = 1352;

    /// <summary>An RFC 9298 CONNECT-UDP proxy reached over HTTP/3 on an explicit UDP port.</summary>
    /// <remarks>Used through <see cref="TlsSessionOptions"/>'s Quic.Proxy. TCP requests never use
    /// it. The port is required; <c>:443</c> counts as default and is rejected.
    /// <paramref name="maxInnerDatagramPayload"/> caps every inner datagram; it can only lower
    /// what the outer connection's frame budget allows, and cannot go below RFC 9000 s14.1's
    /// 1200, which an inner Initial needs.</remarks>
    public static TlsProxy Masque(
        string address,
        string username,
        string password,
        Action<TlsQuicOptions>? configureOuter = null,
        int maxInnerDatagramPayload = DefaultMaxInnerDatagramPayload)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxInnerDatagramPayload, 1200);
        var uri = new Uri(address, UriKind.Absolute);
        var proxy = Create(
            TlsProxyType.Masque,
            uri,
            Uri.UriSchemeHttps,
            new NetworkCredential(username, password));
        if (proxy.Address.IsDefaultPort)
        {
            throw new ArgumentException(
                "A MASQUE proxy address must name a UDP port other than 443 explicitly, "
                    + "for example https://proxy.example:50000.",
                nameof(address));
        }
        proxy.ConfigureOuterQuic = configureOuter;
        proxy.MaxInnerDatagramPayload = maxInnerDatagramPayload;
        return proxy;
    }

    /// <summary>The inner datagram ceiling this MASQUE proxy applies; see
    /// <see cref="DefaultMaxInnerDatagramPayload"/>. Not part of <see cref="PoolKey"/> for the
    /// same reason <see cref="ConfigureOuterQuic"/> is not.</summary>
    internal int MaxInnerDatagramPayload { get; private set; } = DefaultMaxInnerDatagramPayload;

    /// <summary>Shapes the OUTER QUIC connection to a MASQUE proxy; null means TlsClient's
    /// defaults. Only the proxy sees that connection; the target sees the inner one. Not part of
    /// <see cref="PoolKey"/>: one proxy endpoint and credential has one outer shape in the
    /// connection pool, so callers wanting different outer shapes use different proxy instances
    /// with different credentials or addresses.</summary>
    internal Action<TlsQuicOptions>? ConfigureOuterQuic { get; private set; }

    /// <inheritdoc />
    public override string ToString() => $"{Type} proxy {Address.Host}:{EffectivePort}";

    // Masque() rejects a default-port address before returning, so a Masque proxy's own port is
    // always the one it was built with; only Http/Socks5 fall back to a conventional port.
    internal int EffectivePort => Type == TlsProxyType.Masque
        ? Address.Port
        : Address.IsDefaultPort || Address.Port < 0
            ? Type == TlsProxyType.Http ? 80 : 1080
            : Address.Port;

    internal string PoolKey { get; }

    internal NetworkCredential? GetCredentials() => Credentials;

    internal string? GetBasicAuthorizationValue()
    {
        if (Type != TlsProxyType.Http || _credentials is null)
        {
            return null;
        }
        var bytes = Encoding.UTF8.GetBytes($"{_credentials.UserName}:{_credentials.Password}");
        return $"Basic {Convert.ToBase64String(bytes)}";
    }

    private static TlsProxy CreateFromUri(
        TlsProxyType type,
        string address,
        string expectedScheme)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return CreateFromUri(type, new Uri(address, UriKind.Absolute), expectedScheme);
    }

    private static TlsProxy CreateFromUri(
        TlsProxyType type,
        Uri address,
        string expectedScheme)
    {
        ArgumentNullException.ThrowIfNull(address);
        NetworkCredential? credentials = null;
        if (!string.IsNullOrEmpty(address.UserInfo))
        {
            var separator = address.UserInfo.IndexOf(':');
            var username = separator < 0 ? address.UserInfo : address.UserInfo[..separator];
            var password = separator < 0 ? string.Empty : address.UserInfo[(separator + 1)..];
            credentials = new NetworkCredential(
                Uri.UnescapeDataString(username),
                Uri.UnescapeDataString(password));
        }
        return Create(type, address, expectedScheme, credentials);
    }

    private static TlsProxy Create(
        TlsProxyType type,
        Uri address,
        string expectedScheme,
        NetworkCredential? credentials)
    {
        if (!address.IsAbsoluteUri ||
            !address.Scheme.Equals(expectedScheme, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"The proxy URL must be an absolute {expectedScheme}:// URL.",
                nameof(address));
        }
        if (string.IsNullOrWhiteSpace(address.Host))
        {
            throw new ArgumentException("The proxy URL must contain a host.", nameof(address));
        }
        ValidateNoNull(credentials?.UserName, "proxy username");
        ValidateNoNull(credentials?.Password, "proxy password");
        var builder = new UriBuilder(address)
        {
            UserName = string.Empty,
            Password = string.Empty,
        };
        return new TlsProxy(type, builder.Uri, credentials);
    }

    private static string CreatePoolKey(
        TlsProxyType type,
        Uri address,
        int port,
        NetworkCredential? credentials)
    {
        var credentialBytes = Encoding.UTF8.GetBytes(
            $"{credentials?.UserName}\0{credentials?.Password}");
        var credentialHash = Convert.ToHexString(SHA256.HashData(credentialBytes));
        return $"{type}|{address.IdnHost.ToLowerInvariant()}|{port}|{credentialHash}";
    }

    private static void ValidateNoNull(string? value, string description)
    {
        if (value?.Contains('\0', StringComparison.Ordinal) == true)
        {
            throw new ArgumentException($"The {description} cannot contain NUL.");
        }
    }
}

/// <summary>Identifies a supported proxy protocol.</summary>
/// <remarks>THE VALUES ARE PINNED AND 1 IS DELIBERATELY VACANT. It was SOCKS4, which this
/// client no longer speaks. Letting Socks5 slide down into the hole would silently change the
/// meaning of every persisted or interoperated integer, so the gap stays.</remarks>
public enum TlsProxyType
{
    /// <summary>HTTP CONNECT.</summary>
    Http = 0,

    /// <summary>SOCKS5 with optional username/password authentication.</summary>
    Socks5 = 2,

    /// <summary>MASQUE: an RFC 9298 CONNECT-UDP proxy reached over HTTP/3.</summary>
    Masque = 3,
}
