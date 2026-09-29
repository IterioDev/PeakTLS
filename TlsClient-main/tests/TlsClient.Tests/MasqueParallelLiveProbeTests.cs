using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>A probe, not a test: many proxy sessions at once, every one taking the same steps in
/// the same order, which is the consumer's load shape and the one the sequential live tests
/// never produce. It asserts nothing; it writes what happened to a report.</summary>
/// <remarks>Runs only when TLSCLIENT_LIVE_MASQUE, TLSCLIENT_LIVE_SOCKS5 and
/// TLSCLIENT_LIVE_PARALLEL (the session count) are all set. The report goes to
/// TLSCLIENT_LIVE_REPORT, or to peaktls-masque-parallel.txt in the temp directory. Every session
/// takes a fresh session id; the credential is read from the environment and never written.</remarks>
public sealed class MasqueParallelLiveProbeTests
{
    private static readonly string[] Http3Hosts =
    [
        "spclient.wg.spotify.com",
        "gue1-spclient.spotify.com",
        "login5.spotify.com",
    ];

    [Fact]
    public async Task ManySessionsInLockstep()
    {
        if (Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_MASQUE") is not { } masqueUrl
            || Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_SOCKS5") is not { } socksUrl
            || !int.TryParse(Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_PARALLEL"), out var sessions))
        {
            return;
        }
        var deadline = int.TryParse(
            Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_DEADLINE"), out var seconds)
            ? TimeSpan.FromSeconds(seconds)
            : TimeSpan.FromSeconds(5);
        var masque = new Uri(masqueUrl);
        var socks = new Uri(socksUrl);
        var credentials = masque.UserInfo.Split(':', 2);
        var template = Uri.UnescapeDataString(credentials[0]);
        var password = Uri.UnescapeDataString(credentials[1]);

        var outcomes = new ConcurrentBag<(string Step, string Outcome, string Detail, double Seconds)>();
        var events = new ConcurrentBag<(string Kind, double Seconds, string Detail)>();
        var clock = Stopwatch.StartNew();

        // The client's own health while the sessions run: how late a 50 ms timer fires on the
        // thread pool, and how deep the pool's queue gets. Seconds of lateness are a starved
        // pool, and every deadline in the dial is then measured on a stalled clock.
        using var probing = new CancellationTokenSource();
        var worstLateness = TimeSpan.Zero;
        long deepestQueue = 0;
        var mostThreads = 0;
        var heartbeat = Task.Run(async () =>
        {
            while (!probing.IsCancellationRequested)
            {
                var beat = Stopwatch.GetTimestamp();
                await Task.Delay(TimeSpan.FromMilliseconds(50));
                var late = Stopwatch.GetElapsedTime(beat) - TimeSpan.FromMilliseconds(50);
                worstLateness = late > worstLateness ? late : worstLateness;
                deepestQueue = Math.Max(deepestQueue, ThreadPool.PendingWorkItemCount);
                mostThreads = Math.Max(mostThreads, ThreadPool.ThreadCount);
            }
        });

        await Task.WhenAll(Enumerable.Range(0, sessions).Select(async _ =>
        {
            var user = Regex.Replace(
                template, @"sessid-\d+", $"sessid-{Random.Shared.NextInt64(1_000_000_000, 9_999_999_999)}");
            var tcp = TlsProxy.Socks5($"socks5://{socks.Host}:{socks.Port}", user, password);
            var udp = TlsProxy.Masque($"https://{masque.Host}:{masque.Port}", user, password);
            void Observe(TlsConnectEvent e)
            {
                if (e.Kind.ToString().StartsWith("Masque", StringComparison.Ordinal))
                {
                    events.Add((
                        e.Exception is null ? e.Kind.ToString() : $"{e.Kind} failed: {Classify(e.Exception)}",
                        e.Elapsed.TotalSeconds,
                        e.Exception is null ? string.Empty : $"{e.Host}: {Describe(e.Exception)}"));
                }
            }

            // The consumer's order: h2 over SOCKS5 first, then h3 over MASQUE, same session id.
            var h2 = TlsPresets.SpotifyH2.CreateOptions();
            h2.Proxy = tcp;
            h2.Quic.Proxy = udp;
            h2.Quic.HandshakeDeadline = deadline;
            h2.ConnectObserver = Observe;
            h2.Timeout = TimeSpan.FromSeconds(30);
            await using (var warmUp = new TlsSession(h2))
            {
                await StepAsync(warmUp, "h2 spclient.wg.spotify.com", "https://spclient.wg.spotify.com/", outcomes);
            }

            var h3 = TlsPresets.Spotify.CreateOptions();
            h3.Proxy = tcp;
            h3.Quic.Proxy = udp;
            h3.Quic.HandshakeDeadline = deadline;
            h3.ConnectObserver = Observe;
            h3.Timeout = TimeSpan.FromSeconds(30);
            await using var session = new TlsSession(h3);
            foreach (var host in Http3Hosts)
            {
                await StepAsync(session, $"h3 {host}", $"https://{host}/", outcomes);
            }
        }));

        probing.Cancel();
        await heartbeat;

        var report = new StringBuilder();
        report.AppendLine(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{sessions} session(s) in lockstep, handshake deadline {deadline}, {clock.Elapsed.TotalSeconds:F1} s in all.");
        report.AppendLine(
            System.Globalization.CultureInfo.InvariantCulture,
            $"Thread pool: a 50 ms timer fired up to {worstLateness.TotalSeconds:F2} s late; queue up to "
                + $"{deepestQueue} item(s); up to {mostThreads} thread(s); {Environment.ProcessorCount} processor(s).");
        report.AppendLine();
        foreach (var step in outcomes.GroupBy(o => o.Step).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            report.AppendLine(step.Key);
            foreach (var kind in step.GroupBy(o => o.Outcome).OrderByDescending(g => g.Count()))
            {
                var times = kind.Select(o => o.Seconds).Order().ToArray();
                report.AppendLine(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"  {kind.Count(),4}  {kind.Key}  (median {times[times.Length / 2]:F1} s, max {times[^1]:F1} s)");
                foreach (var sample in kind.Where(o => o.Detail.Length > 0).Take(3))
                {
                    report.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"        {sample.Detail}");
                }
            }
        }
        report.AppendLine();
        report.AppendLine("MASQUE connect events, with what each took");
        foreach (var kind in events.GroupBy(e => e.Kind).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var times = kind.Select(e => e.Seconds).Order().ToArray();
            report.AppendLine(
                System.Globalization.CultureInfo.InvariantCulture,
                $"  {times.Length,4}  {kind.Key}  (median {times[times.Length / 2]:F2} s, "
                    + $"p90 {times[times.Length * 9 / 10]:F2} s, p99 {times[times.Length * 99 / 100]:F2} s, "
                    + $"max {times[^1]:F2} s)");
            foreach (var sample in kind.Where(e => e.Detail.Length > 0).DistinctBy(e => e.Detail).Take(4))
            {
                report.AppendLine(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"        {sample.Detail[..Math.Min(sample.Detail.Length, 2400)]}");
            }
        }

        var path = Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_REPORT")
            ?? Path.Combine(Path.GetTempPath(), "peaktls-masque-parallel.txt");
        await File.WriteAllTextAsync(path, report.ToString());
    }

    /// <summary>Every address the proxy name resolves to, under a burst of its own: the outer
    /// dial alone (QUIC handshake and SETTINGS), TLSCLIENT_LIVE_PARALLEL at once per address.
    /// A dial takes the first address in resolver order, so every session of a run lands on
    /// one address; this says whether the addresses differ.</summary>
    [Fact]
    public async Task EachProxyAddressUnderABurst()
    {
        if (Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_MASQUE") is not { } masqueUrl
            || !int.TryParse(Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_PARALLEL"), out var dials))
        {
            return;
        }
        var masque = new Uri(masqueUrl);
        var credentials = masque.UserInfo.Split(':', 2);
        var proxy = TlsProxy.Masque(
            $"https://{masque.Host}:{masque.Port}",
            Uri.UnescapeDataString(credentials[0]),
            Uri.UnescapeDataString(credentials[1]));
        var session = TlsPresets.Spotify.CreateOptions();
        session.Quic.Proxy = proxy;
        session.Quic.HandshakeDeadline = TimeSpan.FromSeconds(10);
        var template = Http3Connection.MasqueOptionsFor(proxy, session.Snapshot());
        // The lookup a dial makes for itself, as many at once as there are dials: every
        // session resolves the proxy name before its outer handshake.
        var lookups = await Task.WhenAll(Enumerable.Range(0, dials).Select(async _ =>
        {
            var startedAt = Stopwatch.GetTimestamp();
            await System.Net.Dns.GetHostAddressesAsync(masque.Host, CancellationToken.None);
            return Stopwatch.GetElapsedTime(startedAt).TotalSeconds;
        }));
        Array.Sort(lookups);
        var addresses = await System.Net.Dns.GetHostAddressesAsync(masque.Host);

        var report = new StringBuilder();
        report.AppendLine(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{dials} lookup(s) of {masque.Host} at once: median {lookups[lookups.Length / 2]:F2} s, "
                + $"p90 {lookups[lookups.Length * 9 / 10]:F2} s, max {lookups[^1]:F2} s.");
        report.AppendLine(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{dials} outer dial(s) at once per address, in resolver order, deadline 10 s.");
        foreach (var address in addresses)
        {
            var endPoint = new System.Net.IPEndPoint(address, masque.Port);
            var results = await Task.WhenAll(Enumerable.Range(0, dials).Select(async _ =>
            {
                await using var socket = TlsQuicUdpDatagramTransport.Create(address.AddressFamily);
                var options = new TlsQuicMasqueOptions
                {
                    ProxyEndPoint = template.ProxyEndPoint,
                    Username = template.Username,
                    Password = template.Password,
                    OuterSpec = template.OuterSpec,
                    OuterHttp3Spec = template.OuterHttp3Spec,
                    ConfigureOuterClientHello = template.ConfigureOuterClientHello,
                    HandshakeDeadline = template.HandshakeDeadline,
                    OuterTransport = socket,
                    OuterRemoteEndPoints = [endPoint],
                };
                var startedAt = Stopwatch.GetTimestamp();
                try
                {
                    await using var outer = await TlsQuicMasqueConnection.ConnectAsync(
                        options, CancellationToken.None);
                    return (Seconds: Stopwatch.GetElapsedTime(startedAt).TotalSeconds, Failure: string.Empty);
                }
                catch (Exception exception)
                {
                    return (
                        Seconds: Stopwatch.GetElapsedTime(startedAt).TotalSeconds,
                        Failure: exception.Message[..Math.Min(exception.Message.Length, 160)]);
                }
            }));
            var good = results.Where(r => r.Failure.Length == 0).Select(r => r.Seconds).Order().ToArray();
            var timing = good.Length == 0
                ? string.Empty
                : string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $" (median {good[good.Length / 2]:F2} s, p90 {good[good.Length * 9 / 10]:F2} s, max {good[^1]:F2} s)");
            report.AppendLine(
                System.Globalization.CultureInfo.InvariantCulture,
                $"  {address,-16} {good.Length,4} up{timing}, {results.Length - good.Length} failed");
            foreach (var failure in results.Where(r => r.Failure.Length > 0).DistinctBy(r => r.Failure).Take(2))
            {
                report.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"        {failure.Failure}");
            }
        }

        var path = (Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_REPORT")
            ?? Path.Combine(Path.GetTempPath(), "peaktls-masque-parallel.txt")) + ".addresses.txt";
        await File.WriteAllTextAsync(path, report.ToString());
    }

    private static async Task StepAsync(
        TlsSession session,
        string step,
        string url,
        ConcurrentBag<(string Step, string Outcome, string Detail, double Seconds)> outcomes)
    {
        var startedAt = Stopwatch.GetTimestamp();
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
            var response = await session.SendAsync(request);
            outcomes.Add((
                step,
                $"HTTP/{response.HttpVersion} {(int)response.StatusCode}",
                string.Empty,
                Stopwatch.GetElapsedTime(startedAt).TotalSeconds));
        }
        catch (Exception exception)
        {
            outcomes.Add((
                step,
                Classify(exception),
                Describe(exception),
                Stopwatch.GetElapsedTime(startedAt).TotalSeconds));
        }
    }

    // The most specific name in the chain: a proxy error by its member, a handshake that ran
    // out of time, or the outermost type.
    private static string Classify(Exception exception)
    {
        for (var cursor = exception; cursor is not null; cursor = cursor.InnerException)
        {
            if (cursor is TlsQuicProxyException proxy)
            {
                return proxy.Error.ToString();
            }
            if (cursor is TimeoutException)
            {
                return "inner handshake deadline";
            }
        }
        return exception.GetType().Name;
    }

    private static string Describe(Exception exception)
    {
        var text = new StringBuilder();
        for (var cursor = exception; cursor is not null; cursor = cursor.InnerException)
        {
            text.Append(cursor.GetType().Name).Append(": ").Append(cursor.Message).Append(" | ");
        }

        // The numbers, not the essay: the connection's own commentary is the same every time.
        var all = text.ToString();
        var parts = new List<string>();
        foreach (Match match in Regex.Matches(
            all,
            @"(PROGRESS: [^.]*\.[^.]*\.|Through the MASQUE tunnel: [^.]*\.|DISCARD REASONS: [^.]*\.|did not [^.]*\.|answered \d+[^.]*\.|during [^(]*\([^)]*\))"))
        {
            parts.Add(match.Value);
        }
        // A handshake that failed short of its deadline is the rare one: keep all it said.
        if (all.Contains("handshake with", StringComparison.Ordinal))
        {
            return Regex.Replace(all, @"READ THE WANT-OF-KEYS.*?drained\. |READ PROGRESS BY DIRECTION.*?deadline\. | AuthenticationFailed on the.*?handshake\.", string.Empty);
        }
        return parts.Count > 0 ? string.Join(" ", parts) : all[..Math.Min(all.Length, 600)];
    }
}
