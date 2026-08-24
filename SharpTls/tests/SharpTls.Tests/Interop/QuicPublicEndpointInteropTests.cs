using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Quic;

namespace SharpTls.Tests.Interop;

// A4-minimal task 13: THE LIVE RUN. The first time this QUIC client meets a server it did not
// write, and the only place three numbers can be measured rather than guessed:
//
//   1. HOW OFTEN LOSS KILLS AN ATTEMPT. A3 is deferred, so nothing retransmits: one lost
//      packet ends the attempt. The retry is at the ATTEMPT level - a whole new connection,
//      new connection IDs, new ClientHello - because that is the only retry A4-minimal has.
//      AttemptsPerHost is fixed rather than "loop until one works" on purpose: stopping at the
//      first success measures nothing, and the failure rate is A3's first piece of evidence.
//
//   2. HOW MUCH UNRELATED TRAFFIC A LIVE SOCKET MEETS. DiscardedPackets and
//      DiscardedForMissingKeys are reported SEPARATELY and must never be summed. The first is
//      RFC 9000 s12.2 doing its job on off-path noise; the second is the coalescing stall -
//      a Handshake packet coalesced behind ServerHello that met no keys - and a non-zero
//      value there is a bug report about us, not about the internet.
//
//   3. WHAT THE KNOWINGLY VIOLATED MUST COSTS. A4-minimal never acknowledges a 1-RTT packet,
//      including the one carrying HANDSHAKE_DONE (RFC 9000 s13.2.1). A conforming server
//      therefore retransmits it until it gives up. The observation phase below keeps pumping
//      AFTER confirmation, to the handshake deadline, so HandshakeDoneFramesReceived counts
//      the retransmissions instead of predicting them. That number is task 14's urgency.
//
// THIS TEST MUST NEVER BE ADJUSTED TO GO GREEN. It asserts one thing - that a handshake
// completed somewhere - and everything else it produces is a recording. A failure here is a
// finding about A4, and eighteen downstream tasks inherit whatever it does not catch.
[Collection(nameof(PublicInteropCollection))]
public sealed class QuicPublicEndpointInteropTests
{
    // Both hosts answer h3 on 443. fp.impersonate.pro is the fingerprint target; tls3.peet.ws
    // is the independent second deployment, so a failure can be told apart from a host quirk.
    private static readonly string[] Hosts = ["fp.impersonate.pro", "tls3.peet.ws"];

    // Five is enough for a rate to mean something and small enough that a total loss of
    // reachability costs one minute per host rather than ten.
    private const int AttemptsPerHost = 5;

    // The deadline bounds a FAILED attempt (nothing retransmits, so a lost packet just waits)
    // and it also bounds the post-confirmation observation, because ConnectAsync and
    // PumpOnceAsync share one deadline. A handshake over the public internet costs a few
    // hundred milliseconds, so ~14 of these 15 seconds are observation - long enough for a
    // server's PTO backoff to emit several HANDSHAKE_DONE retransmissions.
    private static readonly TimeSpan HandshakeDeadline = TimeSpan.FromSeconds(15);

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task AQuicHandshakeCompletesAgainstALivePublicEndpoint()
    {
        var report = new StringBuilder();
        report.AppendLine("# A4 task 13 - live QUIC run");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        var anyCompleted = false;

        foreach (var host in Hosts)
        {
            report.AppendLine();
            report.AppendLine($"## {host}");
            IPEndPoint endPoint;
            try
            {
                endPoint = await ResolveAsync(host);
            }
            catch (Exception exception)
            {
                report.AppendLine($"  DNS failed: {exception.GetType().Name}: {exception.Message}");
                continue;
            }

            report.AppendLine($"  endpoint: {endPoint}");
            var succeeded = 0;
            string? firstReadout = null;

            for (var attempt = 1; attempt <= AttemptsPerHost; attempt++)
            {
                // Only the first success observes past confirmation. Every attempt after it
                // stops at confirmation, so the remaining attempts cost a round trip each and
                // the failure rate is measured over all five rather than over however many fit
                // in the time the observation phase left.
                var observe = succeeded == 0;
                var outcome = await AttemptAsync(host, endPoint, observe);
                report.AppendLine($"  attempt {attempt}: {outcome.Summary}");
                if (outcome.Completed)
                {
                    succeeded++;
                    anyCompleted = true;
                    firstReadout ??= outcome.Readout;
                }
            }

            report.AppendLine(
                $"  RESULT: {succeeded}/{AttemptsPerHost} attempts completed the handshake.");
            if (firstReadout is not null)
            {
                report.AppendLine();
                report.AppendLine($"### readout from live traffic - {host}");
                report.AppendLine(firstReadout);
            }
        }

        // The recording is written out whether or not the assertion below passes: a failed run
        // is the more valuable one, and its diagnosis is in these numbers.
        var path = Path.Combine(Path.GetTempPath(), "quic-live-run.txt");
        await File.WriteAllTextAsync(path, report.ToString());

        Assert.True(
            anyCompleted,
            "No live QUIC handshake completed. This is a finding about A4, not a flaky test: "
                + "read DiscardedForMissingKeys (the coalescing stall) and DiscardedPackets "
                + "(off-path noise) per attempt before changing anything.\n"
                + $"Full recording also written to {path}.\n\n{report}");
    }

    // =======================================================================================
    // C13: THE LIVE HTTP/3 RUN. A4 task 13 above stops at the handshake; this one carries a
    // whole GET and reads back what the server says our fingerprint was. Four things it
    // measures that nothing offline can:
    //
    //   1. THE FAILURE RATE, WHICH IS A3'S STRONGEST EVIDENCE. A3 is deferred, so nothing
    //      retransmits and a single lost packet ends the attempt. C's traffic spans far more
    //      packets than a handshake - three unidirectional stream headers, a SETTINGS frame, a
    //      HEADERS frame, and every DATA frame of the response - so the exposure here is
    //      materially larger than A4 task 13's. The retry is at the ATTEMPT level, a whole new
    //      connection, and Http3AttemptsPerHost is FIXED rather than "loop until one works"
    //      for the same reason A4's is: stopping at the first success measures nothing.
    //
    //   2. THE `perk` STRING, VERBATIM. fp.impersonate.pro/api/http3 answers only when h3 was
    //      GENUINELY negotiated - it reports the protocol it was reached over, so a fallback
    //      to HTTP/2 or HTTP/1.1 cannot satisfy it. That is why "a body rather than the
    //      protocol-segregation refusal" is this task's gate: no fallback can fake it.
    //
    //   3. WHETHER TWO INDEPENDENT DEPLOYMENTS READ THE SAME CLIENT THE SAME WAY. Both hosts
    //      are queried ON THE SAME RUN. **DISAGREEMENT BETWEEN THEM IS A FINDING TO
    //      INVESTIGATE, NOT A RESULT TO AVERAGE** - the likely causes, in rough order, are our
    //      client behaving non-deterministically between the two connections, a fallback
    //      silently serving one request over a different protocol, or one endpoint's own
    //      derivation differing. None of those is fixed by taking a mean, and the report below
    //      prints both readings side by side rather than a verdict computed from them. The one
    //      disagreement the first run found - tls3.peet.ws reporting HTTP/3 `settings: null`
    //      for a connection whose SETTINGS fp.impersonate.pro read back in full - is written
    //      up in docs/superpowers/specs/reference-captures/2026-08-20-sharptls-c13-live-http3.md
    //      rather than restated here, because that file is where a dated observation belongs.
    //
    //   4. WHICH QPACK ARM WAS IN FORCE. Recorded explicitly because confusing the two
    //      produced a wrong reading once already. A TEST'S CHOSEN SPEC IS NOT THE LIBRARY'S
    //      CAPABILITY: TlsQuicHttp3Spec's DEFAULT settings are CaptureSettings, all five of
    //      the capture's pairs including 1:65536, 7:100, 51:1 and the GREASE identifier, and
    //      that default emits an exact segment 1.
    //
    //      C16 REMOVED THE NARROWING, AND THE TRAP THIS PARAGRAPH DESCRIBED IS GONE RATHER
    //      THAN DOCUMENTED. This run used to narrow to QPACK 0/0 because RFC 9204 s3.2.3
    //      leaves the peer's encoder unable to use the dynamic table at capacity 0, which is
    //      what made the static-only decoder C5-C8 shipped a CORRECT decoder here rather than
    //      a lucky one. C14 built the dynamic table, C15 the decoder-stream instructions and
    //      C16 s2.2.1's blocking, so the arm in force IS the default and segment 1's live
    //      value is now a statement about what this library emits. There is no second arm: an
    //      A/B against the narrowed settings would measure a configuration nothing ships.
    //
    // WHAT THIS TEST DOES NOT FILE AGAINST C. `perk` segment 3 (transport parameter wire
    // order) and segment 4 (the connection ID length pair) live in the ClientHello under RFC
    // 9001 s5.2's Initial keys. They are SUBSYSTEM B'S, not C's failures. Task 11 already
    // recorded the wire order as a MISMATCH and C must not re-file it; it is reported here so
    // that a perk readout is not silently missing a perk segment, and for no other reason.
    //
    // LIKE ITS NEIGHBOUR, THIS TEST MUST NEVER BE ADJUSTED TO GO GREEN. It asserts one thing -
    // that /api/http3 returned a body rather than its refusal - and everything else it
    // produces is a recording.
    // =======================================================================================

    /// <summary>C13's two targets, queried on the same run. <c>fp.impersonate.pro</c> is the
    /// gate; <c>tls3.peet.ws</c> is the independent second reading.</summary>
    private static readonly (string Host, string RequestPath)[] Http3Targets =
    [
        (GateHost, "/api/http3"),
        ("tls3.peet.ws", "/api/all"),
    ];

    /// <summary>The one host whose answer cannot be produced by a fallback.</summary>
    private const string GateHost = "fp.impersonate.pro";

    /// <summary>The fingerprint fields to record, looked up by name wherever the endpoint nests
    /// them.</summary>
    /// <remarks>
    /// <para>THE PLAN AND THE CAPTURE BOTH CALL THE STRING <c>perk</c>. THE WIRE CALLS IT
    /// <c>perk_text</c>, and the normalized string <c>perk_text_normalized</c>. Only the two
    /// hashes carry the names the documents use. Both spellings are looked up so a recording is
    /// never empty because a document used the other one.</para>
    /// <para>tls3.peet.ws publishes no perk of any spelling; <c>akamai_fingerprint</c> is the
    /// nearest thing it does publish, and including it is what leaves the two-endpoint
    /// comparison with something to compare.</para>
    /// </remarks>
    private static readonly string[] PerkFields =
    [
        "perk",
        "perk_text",
        "perk_hash",
        "perk_text_normalized",
        "perk_hash_normalized",
        "akamai_fingerprint",
        "akamai_fingerprint_hash",
    ];

    /// <summary>Same count as <see cref="AttemptsPerHost"/> and for the same reason - a rate
    /// needs more than one sample, and a total loss of reachability must not cost ten minutes.
    /// A whole request costs more wall clock than a handshake, hence the separate name.</summary>
    private const int Http3AttemptsPerHost = 5;

    /// <summary>Bounds the wait for the response, separately from the handshake's deadline,
    /// because the two measure different things.</summary>
    private static readonly TimeSpan ResponseDeadline = TimeSpan.FromSeconds(20);

    /// <summary>THE QPACK ARM IN FORCE FOR THIS RUN, AND C16 MADE IT THE DEFAULT ONE.</summary>
    /// <remarks>
    /// <para>This used to be a hand-narrowed <c>1:0;6:262144;7:0</c>, and its stated reason -
    /// that RFC 9204 s3.2.3 leaves the peer's encoder unable to use the dynamic table at
    /// capacity 0, which is what made a static-only decoder a CORRECT one rather than a lucky
    /// one - is exactly what C16 closed. The decoder now drives a dynamic table from the peer's
    /// encoder stream and blocks on s2.2.1 rather than failing, so the narrowing buys nothing
    /// and costs the thing this file exists to measure: perk segment 1.</para>
    /// <para>IT IS THE TEST ASSEMBLY'S LIST NOW, NOT THE LIBRARY'S. This used to read
    /// <c>SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable</c> - a captured browser's five pairs, shipped as
    /// the library default - and the point of naming it rather than copying it was that this
    /// report and the arm <see cref="Http3AttemptAsync"/> runs could not drift apart. They
    /// still cannot: both read <see cref="SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable"/>.</para>
    /// </remarks>
    private static ImmutableArray<TlsQuicHttp3Setting> ShippedQpackSettings =>
        SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable;

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task AnHttp3RequestReturnsTheLiveFingerprintFromBothEndpoints()
    {
        var report = new StringBuilder();
        report.AppendLine("# C13 - live HTTP/3 run");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        report.AppendLine($"attempts per host: {Http3AttemptsPerHost}");
        report.AppendLine(
            "QPACK arm in force: DEFAULT "
                + $"({TlsQuicHttp3Settings.Render(ShippedQpackSettings)})");
        // TWO SENTENCES THAT CONTRADICTED EACH OTHER, AND THE SECOND WAS THE STALE ONE. It
        // read "the DEFAULT arm is TlsQuicHttp3Spec's own CaptureSettings (...) and it is NOT
        // what ran here" - true while ShippedQpackSettings was a hand-narrowed 1:0;6:x;7:0, and
        // false the moment C16 pointed that property at CaptureSettings itself. It survived
        // because it RE-RENDERED CaptureSettings rather than comparing against it, so the
        // printed line went on looking specific while its claim had inverted. Printed as a
        // comparison now: the report states which of the two it is rather than asserting it,
        // so the same edit that made it wrong before would now change what it prints.
        report.AppendLine(
            "  the DEFAULT arm "
                + (ShippedQpackSettings.SequenceEqual(SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable)
                    ? "IS TlsQuicHttp3Spec's own CaptureSettings, unnarrowed"
                    : "differs from TlsQuicHttp3Spec's own CaptureSettings "
                        + $"({TlsQuicHttp3Settings.Render(SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable)})")
                + " - so perk segment 1 is what this client ships, not a narrowing of it.");

        // host -> the first body a completed attempt returned. Only the first: a second one
        // would be a second measurement of a different connection and this file records what
        // one connection was told about itself.
        var bodies = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var (host, requestPath) in Http3Targets)
        {
            report.AppendLine();
            report.AppendLine($"## {host}{requestPath}");
            IPEndPoint endPoint;
            try
            {
                endPoint = await ResolveAsync(host);
            }
            catch (Exception exception)
            {
                report.AppendLine($"  DNS failed: {exception.GetType().Name}: {exception.Message}");
                continue;
            }

            report.AppendLine($"  endpoint: {endPoint}");
            var succeeded = 0;
            for (var attempt = 1; attempt <= Http3AttemptsPerHost; attempt++)
            {
                var outcome = await Http3AttemptAsync(host, requestPath, endPoint);
                report.AppendLine($"  attempt {attempt}: {outcome.Summary}");
                if (outcome.Body is not { } body)
                {
                    continue;
                }

                succeeded++;
                if (!bodies.ContainsKey(host))
                {
                    bodies.Add(host, body);
                }
            }

            var failed = Http3AttemptsPerHost - succeeded;
            report.AppendLine(
                $"  RESULT: {succeeded}/{Http3AttemptsPerHost} attempts returned a complete "
                    + $"response; failure rate {failed}/{Http3AttemptsPerHost}.");
            if (bodies.TryGetValue(host, out var recorded))
            {
                foreach (var field in PerkFields)
                {
                    report.AppendLine(
                        $"  {field} = {FindJsonString(recorded, field) ?? "<not-published-by-this-endpoint>"}");
                }

                report.AppendLine($"  body_bytes = {Encoding.UTF8.GetByteCount(recorded)}");
                report.AppendLine("  --- body verbatim ---");
                report.AppendLine(recorded);
                report.AppendLine("  --- end body ---");
            }
        }

        // THE CROSS-ENDPOINT COMPARISON. It prints both readings; it does not reconcile them.
        report.AppendLine();
        report.AppendLine("## the two endpoints, field by field");
        foreach (var field in PerkFields)
        {
            var readings = Http3Targets
                .Select(target => (
                    target.Host,
                    Value: bodies.TryGetValue(target.Host, out var body)
                        ? FindJsonString(body, field)
                        : null))
                .ToArray();
            var published = readings.Where(r => r.Value is not null).ToArray();
            var verdict = published.Length switch
            {
                0 => "neither endpoint published this field",
                1 => $"only {published[0].Host} published it",
                _ when published.Select(r => r.Value).Distinct(StringComparer.Ordinal).Count() == 1
                    => "AGREE",
                // Not averaged, not resolved, and not tolerated silently - see point 3 above.
                _ => "DISAGREE - INVESTIGATE BEFORE ANYTHING ELSE",
            };
            report.AppendLine($"  {field}: {verdict}");
            foreach (var (host, value) in readings)
            {
                report.AppendLine($"    {host} = {value ?? "<not-published-by-this-endpoint>"}");
            }
        }

        // Written whether or not the assertion passes: a failed run is the more valuable one.
        var reportPath = Path.Combine(Path.GetTempPath(), "quic-http3-live-run.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        // THE GATE. /api/http3 reports the protocol it was reached over, so this single
        // assertion cannot be satisfied by a fallback to HTTP/2 or HTTP/1.1.
        var gateBody = bodies.GetValueOrDefault(GateHost);
        Assert.True(
            gateBody is not null && gateBody.Contains("\"protocol\": \"http3\"", StringComparison.Ordinal),
            $"{GateHost}/api/http3 did not return a body over genuinely negotiated h3. That is a "
                + "finding about C, not a flaky test: read the per-attempt failure rate above "
                + "before changing anything, because a zero success rate is A3's evidence and "
                + "not a reason to retry harder.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");
    }

    /// <summary>One whole HTTP/3 request attempt: a fresh socket, fresh connection IDs, a fresh
    /// ClientHello and a fresh HTTP/3 connection, because A4-minimal's attempt is one-shot and
    /// there is nothing to resume.</summary>
    /// <remarks>A non-null <c>parameterSpec</c> selects the B11 path: the ClientHello comes
    /// from <see cref="TlsQuicClientHelloProfileFactory"/> driving that spec, and the
    /// hand-composed <c>compose</c> list is not consulted at all.</remarks>
    private static async Task<Http3Outcome> Http3AttemptAsync(
        string host,
        string requestPath,
        IPEndPoint endPoint,
        ParameterComposer? compose = null,
        TlsQuicTransportParameterSpec? parameterSpec = null,
        Action<ImpairingDatagramTransport>? impair = null,
        TlsQuicRecoverySpec? recovery = null)
    {
        // ONE SPEC OBJECT PER ATTEMPT, AND ON THE B11 PATH IT REACHES BOTH PLACES: the
        // connection options below, and the profile factory through the client callback. See
        // FactoryClient's remarks for what silently diverges when those two are not the same
        // object.
        var spec = parameterSpec is null
            ? new TlsQuicConnectionSpec
            {
                PaddingTarget = 1200,
                Recovery = recovery ?? new TlsQuicRecoverySpec(),
            }
            : new TlsQuicConnectionSpec
            {
                PaddingTarget = 1200,
                TransportParameters = parameterSpec,
                Recovery = recovery ?? new TlsQuicRecoverySpec(),
            };
        var clock = Stopwatch.StartNew();
        // A3-13's IMPAIRING DECORATOR GOES UNDER THE RECORDER, NOT OVER IT, and the order is
        // load-bearing in one direction only. RecordingTransport counts what the CONNECTION
        // offered; ImpairingDatagramTransport's ordinals count the same offers, so the two
        // agree on what "the 4th datagram" means and a script written against one reads
        // correctly against the other. Reversed, the recorder would count deliveries and a
        // duplicated ordinal would inflate datagrams_sent into a number the connection never
        // produced.
        var socket = TlsQuicUdpDatagramTransport.Create(endPoint.AddressFamily);
        ImpairingDatagramTransport? impairing = null;
        if (impair is not null)
        {
            impairing = new ImpairingDatagramTransport(socket);
            impair(impairing);
        }

        // Wrapped rather than used raw so that the Initial flight's DATAGRAM COUNT is a
        // measurement and not a prediction: B9 splits the Initial across more than one
        // datagram, and the loss rate below is only readable next to how many datagrams had
        // to survive to produce it.
        await using var transport = new RecordingTransport(
            (ITlsQuicDatagramTransport?)impairing ?? socket);
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(transport, endPoint, spec)
            {
                HandshakeDeadline = HandshakeDeadline,
                IdleTimeout = HandshakeDeadline + ResponseDeadline,
            },
            source => parameterSpec is null
                ? TlsClient(host, source, spec.LocalFlowControl, compose)
                : FactoryClient(host, source, spec));

        try
        {
            await connection.ConnectAsync();
            var handshakeAt = clock.Elapsed;
            // THE DEFAULT SPEC, WITH NOTHING NARROWED. TlsQuicHttp3Spec's own default is
            // CaptureSettings, so this is the capture's five pairs - 1:65536, 6:262144, 7:100,
            // 51:1 and the GREASE identifier - and the segment 1 it emits is the exact one.
            var http3 = new TlsQuicHttp3Connection(connection, new TlsQuicHttp3Spec());
            http3.OpenLocalStreams();

            var stream = http3.TryOpenRequest(
                new TlsQuicHttp3Request
                {
                    Method = "GET",
                    Scheme = "https",
                    Authority = host,
                    Path = requestPath,
                },
                out var refusal,
                out var malformed);
            if (stream is null)
            {
                return new(
                    $"FAILED refused={refusal} malformed={malformed} "
                        + $"handshake_ms={handshakeAt.TotalMilliseconds:F0}",
                    null);
            }

            if (!await connection.SendPendingAsync())
            {
                return new(
                    $"FAILED nothing_to_send handshake_ms={handshakeAt.TotalMilliseconds:F0}",
                    null);
            }

            var refusedAt = 0UL;
            while (!stream.ReceiveComplete && clock.Elapsed - handshakeAt < ResponseDeadline)
            {
                if (!await http3.PumpOnceAsync())
                {
                    refusedAt = http3.ConnectionErrorCode;
                    break;
                }
            }

            var response = http3.ResponseFor(stream.Id);
            var summary = new StringBuilder();
            summary.Append(response is { IsComplete: true } ? "COMPLETED" : "FAILED");
            summary.Append($" handshake_ms={handshakeAt.TotalMilliseconds:F0}");
            summary.Append($" response_ms={(clock.Elapsed - handshakeAt).TotalMilliseconds:F0}");
            summary.Append($" status={response?.Status ?? -1}");
            summary.Append($" body_bytes={response?.Body.Length ?? 0}");
            summary.Append($" fin={stream.FinReceived}");
            summary.Append($" h3_error=0x{refusedAt:x}");
            // Two counters, never one number - the neighbouring test's header explains why.
            summary.Append($" discarded={connection.DiscardedPackets}");
            summary.Append($" discarded_missing_keys={connection.DiscardedForMissingKeys}");
            summary.Append($" unprocessed={connection.UnprocessedPackets}");
            summary.Append($" idle_timed_out={connection.IdleTimedOut}");
            // How many datagrams had to survive before anything came back, and how many were
            // sent in total. Two numbers, because the first is the Initial flight and the
            // second is the whole attempt.
            summary.Append($" initial_datagrams={transport.InitialFlightDatagrams}");
            summary.Append($" datagrams_sent={transport.Sent.Count}");
            summary.Append(
                $" peer_settings={TlsQuicHttp3Settings.Render(http3.Streams.PeerSettings)}");
            if (connection.PeerCloseErrorCode is { } code)
            {
                summary.Append($" peer_close=0x{code:x}");
            }

            var recoveryReading = Recovery(response is { IsComplete: true });
            summary.Append(' ').Append(recoveryReading.Render());
            return new(
                summary.ToString(),
                response is { IsComplete: true } ? Encoding.UTF8.GetString(response.Body) : null,
                recoveryReading);
        }
        catch (Exception exception)
        {
            // A lost packet lands here when nothing repaired it. That is the measurement, and
            // the recovery counters beside it are what tell a repair that was never attempted
            // apart from one that was attempted and did not arrive in time.
            var recoveryReading = Recovery(false);
            return new(
                $"FAILED elapsed_ms={clock.Elapsed.TotalMilliseconds:F0} "
                    + $"discarded={connection.DiscardedPackets} "
                    + $"discarded_missing_keys={connection.DiscardedForMissingKeys} "
                    + $"idle_timed_out={connection.IdleTimedOut} "
                    + $"initial_datagrams={transport.InitialFlightDatagrams} "
                    + $"datagrams_sent={transport.Sent.Count} "
                    + $"{recoveryReading.Render()} "
                    + $"ended_with=\"{exception.GetType().Name}: {Flatten(exception.Message)}\"",
                null,
                recoveryReading);
        }

        // Read from the live connection while it is still open, because `await using` above
        // disposes it on the way out of this method and a counter read afterwards would be a
        // read of a torn-down connection.
        Http3Recovery Recovery(bool completed) =>
            new(
                completed,
                connection.PacketsDeclaredLost,
                connection.FramesRetransmitted,
                connection.ProbeDatagramsSent,
                connection.PersistentCongestionEvents,
                connection.CongestionControl.CongestionWindowBytes,
                connection.CongestionControl.Name,
                transport.Sent.Count,
                impairing?.Dropped.Count ?? 0,
                impairing?.Held.Count ?? 0,
                impairing?.Delivered.Count ?? 0,
                OutOfOrder(impairing));

        // A REORDER LEAVES NO OTHER TRACE, AND THE FIRST RUN OF THIS TEST PROVED IT THE HARD
        // WAY. HoldUntilAfter drops nothing, holds nothing once its release ordinal arrives,
        // and delivers exactly as many datagrams as were offered - so every other counter
        // here reads identically to a run that impaired nothing at all, and the REORDER arm
        // was reported as vacuous while it was in fact working. The delivery ORDER is the only
        // witness, and it is the one the instrument was built to control.
        static bool OutOfOrder(ImpairingDatagramTransport? impairing)
        {
            if (impairing is null)
            {
                return false;
            }

            var delivered = impairing.Delivered;
            for (var index = 1; index < delivered.Count; index++)
            {
                if (delivered[index] < delivered[index - 1])
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>What A3's recovery machinery did during one live attempt.</summary>
    /// <remarks>THE POINT OF THIS RECORD IS THAT "a 200 came back" IS NOT EVIDENCE OF ANYTHING.
    /// A3-8's first loss test completed in 220 ms having lost nothing and passed; only
    /// <see cref="PacketsDeclaredLost"/> and <see cref="FramesRetransmitted"/> caught it. An
    /// impaired arm whose <see cref="DatagramsDropped"/> is zero impaired nothing, and an
    /// impaired arm that dropped something while these counters stayed at zero recovered
    /// nothing - the two are different findings and both are invisible from the status
    /// code.</remarks>
    private sealed record Http3Recovery(
        bool Completed,
        int PacketsDeclaredLost,
        int FramesRetransmitted,
        int ProbeDatagramsSent,
        int PersistentCongestionEvents,
        long CongestionWindowBytes,
        string ControllerName,
        int DatagramsOffered,
        int DatagramsDropped,
        int DatagramsStillHeld,
        int DatagramsDelivered,
        bool DeliveredOutOfOrder)
    {
        /// <summary>Whether the script did anything at all to this attempt's traffic.</summary>
        /// <remarks>FOUR WITNESSES BECAUSE THERE ARE FOUR IMPAIRMENTS, and each leaves a
        /// different trace: a drop shows in <see cref="DatagramsDropped"/>, a duplicate makes
        /// <see cref="DatagramsDelivered"/> exceed <see cref="DatagramsOffered"/>, a hold that
        /// was never released shows in <see cref="DatagramsStillHeld"/>, and a hold that WAS
        /// released shows only in <see cref="DeliveredOutOfOrder"/>.</remarks>
        public bool Impaired =>
            DatagramsDropped > 0
                || DatagramsDelivered > DatagramsOffered
                || DatagramsStillHeld > 0
                || DeliveredOutOfOrder;

        public string Render() =>
            $"lost={PacketsDeclaredLost} retransmitted={FramesRetransmitted} "
                + $"probes={ProbeDatagramsSent} persistent_congestion={PersistentCongestionEvents} "
                + $"cwnd={CongestionWindowBytes} controller={ControllerName} "
                + $"offered={DatagramsOffered} dropped={DatagramsDropped} "
                + $"delivered={DatagramsDelivered} still_held={DatagramsStillHeld} "
                + $"reordered={DeliveredOutOfOrder}";
    }

    private sealed record Http3Outcome(string Summary, string? Body, Http3Recovery? Recovery = null);

    /// <summary>Finds a named string field wherever the endpoint nests it, because the two
    /// endpoints do not agree on where in their JSON the fingerprint lives.</summary>
    private static string? FindJsonString(string body, string name)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            return FindJsonString(document.RootElement, name);
        }
        catch (JsonException)
        {
            // A body that is not JSON is itself the recording; the caller prints it verbatim.
            return null;
        }
    }

    private static string? FindJsonString(JsonElement element, string name)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (property.NameEquals(name) && property.Value.ValueKind == JsonValueKind.String)
                    {
                        return property.Value.GetString();
                    }

                    if (FindJsonString(property.Value, name) is { } nested)
                    {
                        return nested;
                    }
                }

                return null;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (FindJsonString(item, name) is { } nested)
                    {
                        return nested;
                    }
                }

                return null;
            default:
                return null;
        }
    }

    /// <summary>One whole connection attempt: a fresh socket, fresh connection IDs and a fresh
    /// ClientHello, because A4-minimal's attempt is one-shot.</summary>
    private static async Task<Outcome> AttemptAsync(string host, IPEndPoint endPoint, bool observe)
    {
        // PaddingTarget is RFC 9000 s14.1's 1200-byte floor. Every other knob is
        // TlsQuicConnectionSpec's default, which means SourceConnectionIdLength 0 and
        // DestinationConnectionIdLength 8 - a client capture's two observed QUIC fields.
        // The loopback snapshot uses a five-byte source connection ID so that
        // initial_source_connection_id has a header field to agree with; this run uses the
        // target's own zero-length shape, so that comparison is the one thing the live readout
        // deliberately does not reproduce.
        var spec = new TlsQuicConnectionSpec { PaddingTarget = 1200 };
        var recorder = new RecordingTransport(
            TlsQuicUdpDatagramTransport.Create(endPoint.AddressFamily));
        await using (recorder.ConfigureAwait(false))
        {
            await using var connection = new TlsQuicConnection(
                new TlsQuicConnectionOptions(recorder, endPoint, spec)
                {
                    HandshakeDeadline = HandshakeDeadline,
                    IdleTimeout = HandshakeDeadline,
                },
                source => TlsClient(host, source, spec.LocalFlowControl));

            var clock = Stopwatch.StartNew();
            var completed = false;
            TimeSpan? completedAt = null;
            // AT-CONFIRMATION SNAPSHOTS, because measurement 3 is a DELTA and a total cannot be
            // read as one. Without these, a HANDSHAKE_DONE that arrived during the handshake
            // and one retransmitted at it afterwards are the same number, and so are a
            // NewSessionTicket's CRYPTO and the handshake's.
            var sentAtConfirmation = 0;
            var receivedAtConfirmation = 0;
            var handshakeDoneAtConfirmation = 0;
            var cryptoChunksAtConfirmation = 0;
            string failure = "";
            try
            {
                await connection.ConnectAsync();
                completed = true;
                completedAt = clock.Elapsed;
                sentAtConfirmation = recorder.Sent.Count;
                receivedAtConfirmation = recorder.Received;
                handshakeDoneAtConfirmation = connection.HandshakeDoneFramesReceived;
                cryptoChunksAtConfirmation = connection.DeliveredCryptoChunks;

                if (observe)
                {
                    // PAST CONFIRMATION ON PURPOSE. Nothing here is required for the handshake;
                    // it exists to make the server retransmit its unacknowledged HANDSHAKE_DONE
                    // at us until either the deadline or the server gives up first. Whichever
                    // ends it is itself the measurement, so both endings are recorded rather
                    // than one being treated as the failure.
                    while (true)
                    {
                        await connection.PumpOnceAsync();
                    }
                }
            }
            catch (Exception exception)
            {
                failure = $"{exception.GetType().Name}: {Flatten(exception.Message)}";
            }

            var summary = new StringBuilder();
            summary.Append(completed ? "COMPLETED" : "FAILED");
            summary.Append($" tls_complete={connection.IsHandshakeComplete}");
            summary.Append($" confirmed={connection.IsHandshakeConfirmed}");
            summary.Append(completedAt is { } at
                ? $" handshake_ms={at.TotalMilliseconds:F0}"
                : $" elapsed_ms={clock.Elapsed.TotalMilliseconds:F0}");
            summary.Append($" sent_datagrams={recorder.Sent.Count}");
            summary.Append($" received_datagrams={recorder.Received}");
            // TWO COUNTERS, NEVER ONE NUMBER - see the header comment. missing_keys is a subset
            // of discarded and the two mean different things.
            summary.Append($" discarded={connection.DiscardedPackets}");
            summary.Append($" discarded_missing_keys={connection.DiscardedForMissingKeys}");
            summary.Append($" unprocessed={connection.UnprocessedPackets}");
            summary.Append($" cid_mismatch={connection.IgnoredForConnectionIdMismatch}");
            summary.Append($" scid_change={connection.DiscardedForSourceConnectionIdChange}");
            summary.Append($" ignored_retry={connection.IgnoredRetryPackets}");
            summary.Append($" ignored_vn={connection.IgnoredVersionNegotiationPackets}");
            summary.Append($" retry_token_bytes={connection.RetryToken.Length}");
            summary.Append($" handshake_done_frames={connection.HandshakeDoneFramesReceived}");
            summary.Append($" crypto_chunks={connection.DeliveredCryptoChunks}");
            summary.Append($" idle_timed_out={connection.IdleTimedOut}");
            // draining WITHOUT peer_close is OUR deadline path, not the server hanging up:
            // TlsQuicConnection sets it on the way out of ReceiveWithinDeadlineAsync. Only
            // peer_close below says the server closed.
            summary.Append($" draining={connection.IsDraining}");
            if (completed)
            {
                summary.Append(
                    $" | at_confirmation: sent={sentAtConfirmation}"
                        + $" received={receivedAtConfirmation}"
                        + $" handshake_done_frames={handshakeDoneAtConfirmation}"
                        + $" crypto_chunks={cryptoChunksAtConfirmation}");
                summary.Append(
                    $" | after_confirmation: sent={recorder.Sent.Count - sentAtConfirmation}"
                        + $" received={recorder.Received - receivedAtConfirmation}"
                        + " handshake_done_retransmissions="
                        + $"{connection.HandshakeDoneFramesReceived - handshakeDoneAtConfirmation}"
                        + $" crypto_chunks={connection.DeliveredCryptoChunks - cryptoChunksAtConfirmation}");
            }
            if (connection.OfferedVersions is { } versions)
            {
                summary.Append(
                    $" version_negotiation_offered=[{string.Join(",", versions.Select(v => $"0x{v:x8}"))}]");
            }
            if (connection.PeerCloseErrorCode is { } code)
            {
                summary.Append($" peer_close=0x{code:x}");
            }
            if (failure.Length > 0)
            {
                // ON A COMPLETED ATTEMPT THIS IS THE OBSERVATION PHASE ENDING, NOT THE
                // HANDSHAKE FAILING. The observation loop deliberately runs to the handshake
                // deadline, so its message is the deadline's - read completed= above first.
                summary.Append(
                    completed ? $" observation_ended_with=\"{failure}\"" : $" ended_with=\"{failure}\"");
            }

            // THE READOUT IS GONE, AND SO IS WHAT IT DIFFED AGAINST. It rendered this
            // connection's fingerprint beside a captured browser's, scoring each field MATCH
            // or DIFFER - which only meant anything while that browser's numbers were the
            // library default. They are not: the default transport-parameter list is now RFC
            // 9000 s7.3's single mandatory entry, so there is no target for a verdict column.
            // What is left is the datagram count, which is still evidence about the wire.
            var readout = recorder.Sent.Count == 0
                ? null
                : $"{recorder.Sent.Count} datagram(s) sent; no fingerprint readout is shipped.";
            return new Outcome(completed, summary.ToString(), readout);
        }
    }

    private sealed record Outcome(bool Completed, string Summary, string? Readout);

    private static string Flatten(string message) =>
        message.ReplaceLineEndings(" ").Trim();

    private static async Task<IPEndPoint> ResolveAsync(string host)
    {
        var addresses = await System.Net.Dns.GetHostAddressesAsync(host);
        // IPv4 first: the runner's IPv6 path to these hosts is not part of what this run
        // measures, and an unreachable IPv6 route would be recorded as QUIC loss.
        var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault()
            ?? throw new InvalidOperationException($"{host} resolved to no addresses.");
        return new IPEndPoint(address, 443);
    }

    // A fresh client per attempt carrying THIS attempt's source connection ID as
    // initial_source_connection_id (0x0F), which RFC 9000 s7.3 makes mandatory. The spec's
    // default source connection ID length is zero, so that value is an empty byte string -
    // legal, and the target's own shape.
    //
    // ack_delay_exponent (0x0A) IS DELIBERATELY ABSENT. TlsQuicConnection throws at start if
    // the advertised and scaled exponents disagree, and s18.2's default of 3 is also
    // TlsQuicConnectionOptions.AckDelayExponent's default, so omitting it is the one
    // configuration that agrees by construction.
    //
    // THE SIX FLOW-CONTROL PARAMETERS COME FROM THE SPEC AND ARE NOT TYPED HERE. This test
    // used to advertise exactly the two below, which s18.2 lines 62-64 turn into six zeros:
    // "Transport parameters have a default value of 0 if the transport parameter is absent" -
    // a server that may open no stream and send no byte. The handshake completes anyway, which
    // is why a handshake-only test never noticed and the first GET did. The SAME object the
    // connection enforces against emits them, so the advertised number and the enforced one
    // cannot drift.
    //
    // THE LIST ITSELF IS `BaselineParameters`, at the foot of this file, because the
    // B11 probe below sends deliberately altered versions of it and both must come from one
    // definition or the probe's control is not a control.
    private static CustomTlsQuicClient TlsClient(
        string host,
        ReadOnlyMemory<byte> sourceConnectionId,
        TlsQuicLocalFlowControlSpec localFlowControl,
        ParameterComposer? compose = null) =>
        new(new CustomTlsQuicClientOptions
        {
            ServerName = host,
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                // Two suites and two groups rather than the loopback profile's one of each:
                // this run's job is to reach a real server, and a HelloRetryRequest over a
                // group guess would end the attempt (A4-minimal sends one ClientHello). X25519
                // leads because it is what every deployed QUIC server prefers.
                .WithCipherSuites(
                    TlsCipherSuite.TlsAes128GcmSha256,
                    TlsCipherSuite.TlsAes256GcmSha384)
                .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.X25519)
                .WithAlpn("h3")
                .WithQuicTransportParameters(new TlsQuicTransportParameters(
                    (compose ?? BaselineParameters)(sourceConnectionId, localFlowControl)))),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                // Chain and hostname validation stay on - these are real public certificates
                // and there is no reason to weaken that. Revocation is switched off because an
                // OCSP fetch happens INSIDE the pump loop, between two datagrams, and a
                // several-second fetch would spend the handshake deadline and be recorded as
                // QUIC loss. That would corrupt measurement 1, which is this test's point.
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

    /// <summary>The B11 client: the SAME TLS half <see cref="TlsClient"/> sends, but with ALPN
    /// and extension 57's body coming from <see cref="TlsQuicClientHelloProfileFactory"/>
    /// instead of from a list typed in this file.</summary>
    /// <remarks>
    /// <para>THE SAME SPEC OBJECT GOES TO BOTH PLACES, and this method is where that is
    /// enforced by construction: <paramref name="connectionSpec"/> is the object
    /// <c>Http3AttemptAsync</c> already handed to <c>TlsQuicConnectionOptions</c>, so there is
    /// no second spec here to disagree with it.</para>
    /// <para>WHAT HAPPENS IF IT IS NOT THE SAME OBJECT, measured against the source rather
    /// than assumed - three different failures, and only the first is loud.
    /// <list type="number">
    /// <item>A different <c>SourceConnectionIdLength</c> THROWS. <c>Compose</c> compares the
    /// span it is handed against its own spec's declared length and raises
    /// <see cref="ArgumentException"/>; the connection generates the ID from ITS spec, so two
    /// specs with different lengths cannot both be satisfied and the attempt ends at
    /// <c>ConnectAsync</c>.</item>
    /// <item>A different <c>LocalFlowControl</c> IS SILENT AND IS THE DANGEROUS ONE.
    /// <c>Compose</c> places the six advertised flow-control values from the factory's spec
    /// while <c>TlsQuicStreamSet</c> enforces the six from the connection's - so the client
    /// advertises one budget and polices another, with nothing throwing. That is precisely the
    /// gap <c>Compose</c> placing them rather than letting them be typed twice exists to
    /// close, and handing this factory a second spec re-opens it from outside.</item>
    /// <item>A different <c>InitialRttRange</c> IS ALSO SILENT: the drawn entry reads the
    /// spec it is composed against, so the connection's range is simply ignored.</item>
    /// </list>
    /// </para>
    /// </remarks>
    private static CustomTlsQuicClient FactoryClient(
        string host,
        ReadOnlyMemory<byte> sourceConnectionId,
        TlsQuicConnectionSpec connectionSpec)
    {
        var factory = new TlsQuicClientHelloProfileFactory
        {
            ConnectionSpec = connectionSpec,
            AlpnProtocols = [TlsQuicClientHelloProfileFactory.Http3AlpnToken],
            // Subsystem E's half, unchanged from TlsClient's - two suites and two groups, so
            // that a HelloRetryRequest over a group guess does not end the attempt. Held
            // IDENTICAL to TlsClient's on purpose: the only thing this arm changes relative to
            // C13's recorded run is who composes extension 57's body.
            Tls = builder => builder
                .WithTls13()
                .WithCipherSuites(
                    TlsCipherSuite.TlsAes128GcmSha256,
                    TlsCipherSuite.TlsAes256GcmSha384)
                .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.X25519),
        };

        return new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = host,
            ClientHello = factory.Create(sourceConnectionId.Span),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                // Same reason as TlsClient's: an OCSP fetch inside the pump loop would spend
                // the handshake deadline and be recorded as QUIC loss.
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
    }

    /// <summary>Wraps the real UDP transport and keeps every datagram sent, because the
    /// fingerprint readout is a function of the emitted bytes and there is no other way to
    /// recover them from a socket.</summary>
    private sealed class RecordingTransport(ITlsQuicDatagramTransport inner)
        : ITlsQuicDatagramTransport
    {
        /// <summary>Every datagram sent, in send order, copied out because the caller's buffer
        /// is reused.</summary>
        public List<ReadOnlyMemory<byte>> Sent { get; } = [];

        /// <summary>How many datagrams the socket handed up - INCLUDING ones the connection
        /// then discarded, which is the difference between this and the connection's own
        /// counters.</summary>
        public int Received { get; private set; }

        /// <summary>How many datagrams had been sent when the FIRST one came back - the
        /// Initial flight's datagram count, because nothing else has been sent by then.
        /// <c>-1</c> until a datagram arrives: an attempt that got nothing back has not
        /// measured this, and reporting 0 for it would read as "the flight was empty".</summary>
        public int InitialFlightDatagrams { get; private set; } = -1;

        public int MaxDatagramPayloadSize => inner.MaxDatagramPayloadSize;

        public ValueTask SendAsync(
            IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            Sent.Add(payload.ToArray());
            return inner.SendAsync(destination, payload, cancellationToken);
        }

        public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer, CancellationToken cancellationToken)
        {
            var result = await inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (Received == 0)
            {
                InitialFlightDatagrams = Sent.Count;
            }

            Received++;
            return result;
        }

        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }

    // =======================================================================================
    // B11, PULLED FORWARD: WHAT DOES THE FINGERPRINT SERVICE ACTUALLY HASH?
    //
    // The B plan names one riskiest ordering assumption - that B7 (wire order) can be reached
    // with B5's `initial_rtt` range still a placeholder - and rests it entirely on prose. The
    // client capture says wire order is fingerprinted "because both perk_hash and
    // perk_hash_normalized are published, and sorting the parameters would change perk_hash
    // while leaving perk_hash_normalized intact"; Finding 3 says the hash sees a parameter's
    // POSITION and not its VALUE "because the perk renders 12583:AUTO". NEITHER SENTENCE IS A
    // MEASUREMENT. This test makes both of them one, by round-tripping deliberately altered
    // parameter lists past the live service and reading back what moved.
    //
    // FOUR ARMS, ONE ENDPOINT. Only fp.impersonate.pro publishes a perk of any spelling, so
    // tls3.peet.ws has nothing to contribute here and is not queried.
    //
    //   BASELINE      the exact list C13 sent: 15,14,4,5,6,7,8,9. RE-MEASURED rather than
    //                 inherited, because a hash quoted from a file is not a control.
    //   REVERSED      the SAME eight parameters with the SAME eight values, emitted back to
    //                 front: 9,8,7,6,5,4,14,15. Nothing but position differs, and that order is
    //                 neither the baseline's nor the ascending order the normalized form sorts
    //                 to - so a service that sorts internally and one that preserves wire order
    //                 cannot both produce the same answer here.
    //   RTT_100000 /  the baseline list with `initial_rtt` (12583) APPENDED, once at 100000 and
    //   RTT_900000    once at 900000. Same set, same order, one value apart - and both encode to
    //                 a FOUR-byte varint (RFC 9000 s16: 16384..2^30-1), so not even the encoded
    //                 length differs. That removes "the blob got longer" as an explanation and
    //                 leaves the value itself as the only variable.
    //
    // WHY 12583 AND NOT 15. `initial_source_connection_id` also renders AUTO, but its value IS
    // the source connection ID, so changing it also moves perk segment 4, the CID length pair.
    // That is a confound. 12583 is inert here - RFC 9000 s18.1 makes a receiver ignore a
    // transport parameter it does not understand - so an arm that changes only its value
    // changes only its value.
    //
    // THIS TEST HAS NO PREDICTION TO PROTECT, and the assertion at the end is deliberately on
    // NEITHER outcome: it checks only that all four arms reached the service and were given a
    // perk back, because an arm that never connected measures nothing. If the hashes move the
    // way the capture's prose says, B7 proceeds with B5's range unsettled; if they do not,
    // B7's done-when is wrong, and that is the more valuable result. The recording lives in
    // docs/superpowers/specs/reference-captures/2026-08-20-sharptls-b11-perk-order-probe.md.
    // =======================================================================================

    /// <summary>Composes one arm's transport-parameter list from the same two inputs the
    /// baseline gets, so that two arms differ in nothing except what the arm changes.</summary>
    private delegate TlsQuicTransportParameter[] ParameterComposer(
        ReadOnlyMemory<byte> sourceConnectionId, TlsQuicLocalFlowControlSpec localFlowControl);

    /// <summary>The list every test on this class sends by default, and the probe's control.
    /// Declared once so the altered arms are provably the same list plus one edit.</summary>
    /// <remarks>
    /// <para>THE NINTH ENTRY IS <c>max_datagram_frame_size</c> AND IT IS HERE BECAUSE THE
    /// SERVER SAID SO. C16 stopped hand-narrowing the HTTP/3 SETTINGS, so every test on this
    /// class now sends <c>SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable</c> - which includes
    /// <c>51:1</c>, SETTINGS_H3_DATAGRAM - while this list carried no RFC 9221 s3 parameter to
    /// back it. fp.impersonate.pro answered that pair with H3_SETTINGS_ERROR every time.</para>
    /// <para>MEASURED, ONE VARIABLE PER ARM, THREE WHOLE CONNECTIONS EACH. Without 0x20:
    /// 0/3 and 0x109. With 0x20 and nothing else changed: 3/3 and HTTP 200. With 0x20 still
    /// absent but <c>51</c> dropped, or sent as 0: 3/3 either way. Still 0/3 with <c>51:1</c>
    /// and the GREASE pair, <c>1:65536</c> or <c>7:100</c> removed - so the identifier, the
    /// QPACK capacity and the blocked-streams count are all exonerated and 0x20 is the whole
    /// cause.</para>
    /// <para>65536 IS THE CAPTURE'S NUMBER, not a value invented to satisfy a check:
    /// <c>TlsQuicTransportParameterSpec.RfcMinimumParameters</c> row 3 cites capture line 81,
    /// "32 max_datagram_frame_size = 65536", and this list now agrees with the preset it sits
    /// beside instead of contradicting it. The position - after 14, before the flow-control
    /// run - is the capture's relative order too, 32 preceding 9,8,7,5.</para>
    /// <para>THE PROBE BELOW STAYS A CONTROL. Its arms are this list reversed or this list plus
    /// one appended parameter, so all four moved together and each still differs from the
    /// baseline in exactly one thing. The B11 recording is a record of what was sent THEN and
    /// is not restated here.</para>
    /// </remarks>
    private static readonly ParameterComposer BaselineParameters =
        (sourceConnectionId, localFlowControl) =>
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                sourceConnectionId.ToArray()),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxDatagramFrameSize, 65536),
            .. localFlowControl.ToTransportParameters(),
        ];

    // A PLAIN Fact IN A FILE OF InteropFacts, AND THAT IS THE POINT. The five [InteropFact]s
    // here are skipped unless SHARPTLS_RUN_INTEROP=1, which is exactly how the pair this
    // asserts stayed broken through a green 2081/0/5 gate: C16 pointed ShippedQpackSettings at
    // CaptureSettings, whose 51:1 claims willingness to receive HTTP/3 datagrams, and nothing
    // added the RFC 9221 s3 parameter that backs the claim. fp.impersonate.pro answered
    // H3_SETTINGS_ERROR 5/5 and the gate saw none of it.
    //
    // SO THE INVARIANT IS PINNED OFFLINE. TlsQuicHttp3Connection's constructor already refuses
    // the inconsistent pair at run time, but every caller of it in THIS file is skipped by
    // default - a mutation that deletes 0x20 from the list below therefore survives the whole
    // Quic gate. This test costs no socket and closes that: it composes the same list the
    // attempts compose and asks the same question the constructor asks.
    [Fact]
    [Trait("Category", "Quic")]
    public void TheBaselineParametersBackTheDatagramSettingThisFileSends()
    {
        var datagramSetting = TlsQuicHttp3Settings.Value(
            ShippedQpackSettings, TlsQuicHttp3Spec.H3DatagramIdentifier);
        if (datagramSetting is not 1)
        {
            // NOT AN ASSERTION ON WHICH ARM SHIPS. A caller may legitimately narrow the
            // settings again, and then there is no claim to back and nothing to check.
            return;
        }

        var composed = BaselineParameters(
            ReadOnlyMemory<byte>.Empty, new TlsQuicConnectionSpec().LocalFlowControl);
        var advertised = Array.Find(
            composed, p => p.Id == (ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize);

        Assert.True(
            advertised is not null,
            "This file sends SETTINGS_H3_DATAGRAM = 1 but BaselineParameters carries no "
                + "max_datagram_frame_size (0x20), which fp.impersonate.pro closes with "
                + "H3_SETTINGS_ERROR (0x0109).");

        // RFC 9221 s3 makes a zero and an absence one state, so a present-but-zero parameter
        // would satisfy the search above and none of the claim.
        Assert.NotEqual(0UL, advertised!.GetVariableInteger());
    }

    /// <summary>Google's private <c>initial_rtt</c> identifier - the one parameter Finding 3's
    /// "position, not value" claim is actually about.</summary>
    private const ulong InitialRttIdentifier = 12583;

    /// <summary>Whole connections per arm. One cannot tell a real difference from a flake, and
    /// four arms times this is the run's whole cost.</summary>
    private const int ProbeAttemptsPerArm = 3;

    /// <summary>Declared after <see cref="BaselineParameters"/> because it reads it during
    /// static initialisation, and C# initialises static fields in textual order.</summary>
    private static readonly (string Name, ParameterComposer Compose)[] ParameterArms =
    [
        ("BASELINE", BaselineParameters),
        ("REVERSED", (scid, fc) => [.. BaselineParameters(scid, fc).Reverse()]),
        ("RTT_100000", (scid, fc) => [.. BaselineParameters(scid, fc), InitialRtt(100000)]),
        ("RTT_900000", (scid, fc) => [.. BaselineParameters(scid, fc), InitialRtt(900000)]),
    ];

    private static TlsQuicTransportParameter InitialRtt(ulong microseconds) =>
        TlsQuicTransportParameter.VariableInteger(
            (TlsQuicTransportParameterId)InitialRttIdentifier, microseconds);

    /// <summary>One arm's four published strings. A record so that two attempts producing the
    /// same reading compare equal without a hand-written comparison.</summary>
    private sealed record Reading(
        string? Text, string? Hash, string? NormalizedText, string? NormalizedHash);

    /// <summary>Pulls one pipe-separated perk segment out of a perk_text: 0 the h3 SETTINGS,
    /// 1 the pseudo-header order, 2 the transport parameters, 3 the CID length pair.</summary>
    private static string Segment(string? perkText, int index) =>
        perkText?.Split('|') is { } parts && index < parts.Length
            ? parts[index]
            : "<no-segment>";

    /// <summary>Pulls perk segment 3 - the transport parameters - out of a perk_text.</summary>
    private static string Segment3(string? perkText) => Segment(perkText, 2);

    /// <summary>Prints one arm against another: segment 3, then both hashes, then whether each
    /// moved. Shared by the order-and-value probe and by the B11 run below, so the two
    /// experiments cannot report the same comparison in two different shapes.</summary>
    private static void CompareReadings(
        StringBuilder report,
        string question,
        string leftName,
        Reading? left,
        string rightName,
        Reading? right)
    {
        report.AppendLine();
        report.AppendLine($"### {question}");
        if (left is null || right is null)
        {
            report.AppendLine($"  NOT MEASURED - {leftName} or {rightName} returned no perk.");
            return;
        }

        report.AppendLine($"  segment 3            {leftName,-10} = {Segment3(left.Text)}");
        report.AppendLine($"  segment 3            {rightName,-10} = {Segment3(right.Text)}");
        report.AppendLine($"  perk_hash            {leftName,-10} = {left.Hash}");
        report.AppendLine($"  perk_hash            {rightName,-10} = {right.Hash}");
        report.AppendLine(
            $"  -> perk_hash {(left.Hash == right.Hash ? "DID NOT MOVE" : "MOVED")}");
        report.AppendLine($"  perk_hash_normalized {leftName,-10} = {left.NormalizedHash}");
        report.AppendLine($"  perk_hash_normalized {rightName,-10} = {right.NormalizedHash}");
        report.AppendLine(
            "  -> perk_hash_normalized "
                + $"{(left.NormalizedHash == right.NormalizedHash ? "DID NOT MOVE" : "MOVED")}");
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task TheLiveServiceIsAskedWhetherItHashesParameterOrderAndParameterValue()
    {
        var report = new StringBuilder();
        report.AppendLine("# B11 (pulled forward) - what does fp.impersonate.pro hash?");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        report.AppendLine($"attempts per arm: {ProbeAttemptsPerArm}");
        report.AppendLine(
            "QPACK arm in force: DEFAULT "
                + $"({TlsQuicHttp3Settings.Render(ShippedQpackSettings)}) - the same arm C13 "
                + "ran, so perk segment 1 is held constant across every arm below.");

        var endPoint = await ResolveAsync(GateHost);
        report.AppendLine($"endpoint: {endPoint}");

        // arm -> every DISTINCT reading it produced. A list, not a single value: one arm
        // answering two different ways is an instability to investigate before anything below
        // it is read, never something to average.
        var readings = new Dictionary<string, List<Reading>>(StringComparer.Ordinal);
        var flowControl = new TlsQuicConnectionSpec().LocalFlowControl;

        foreach (var (name, compose) in ParameterArms)
        {
            // Printed FROM the composed list rather than retyped beside it, so the record of
            // what was sent cannot drift from what the socket sent.
            var ids = string.Join(
                ",", compose(ReadOnlyMemory<byte>.Empty, flowControl).Select(p => p.Id));
            report.AppendLine();
            report.AppendLine($"## {name}");
            report.AppendLine($"  sent parameter ids, in wire order: {ids}");

            var seen = new List<Reading>();
            readings[name] = seen;
            for (var attempt = 1; attempt <= ProbeAttemptsPerArm; attempt++)
            {
                var outcome = await Http3AttemptAsync(GateHost, "/api/http3", endPoint, compose);
                report.AppendLine($"  attempt {attempt}: {outcome.Summary}");
                if (outcome.Body is not { } body)
                {
                    continue;
                }

                var reading = new Reading(
                    FindJsonString(body, "perk_text"),
                    FindJsonString(body, "perk_hash"),
                    FindJsonString(body, "perk_text_normalized"),
                    FindJsonString(body, "perk_hash_normalized"));
                report.AppendLine($"    perk_text            = {reading.Text}");
                report.AppendLine($"    perk_hash            = {reading.Hash}");
                report.AppendLine($"    perk_text_normalized = {reading.NormalizedText}");
                report.AppendLine($"    perk_hash_normalized = {reading.NormalizedHash}");
                if (!seen.Contains(reading))
                {
                    seen.Add(reading);
                }
            }

            report.AppendLine(
                $"  RESULT: {seen.Count} distinct reading(s) over {ProbeAttemptsPerArm} attempts.");
            if (seen.Count > 1)
            {
                report.AppendLine(
                    "  UNSTABLE - this arm answered two different ways. That is a finding to "
                        + "investigate, and every comparison below it is unsafe until it is.");
            }
        }

        report.AppendLine();
        report.AppendLine("## the two questions, as measured");
        Compare(
            "Q1 - does WIRE ORDER move the hashes? (same set, same values, reversed order)",
            "BASELINE",
            "REVERSED");
        Compare(
            "Q2 - does an AUTO-rendered VALUE move the hashes? (same set, same order, 12583 differs)",
            "RTT_100000",
            "RTT_900000");

        var reportPath = Path.Combine(Path.GetTempPath(), "quic-b11-order-probe.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        // NOT AN ASSERTION ON EITHER PREDICTION - both answers are the finding, and a test that
        // asserted one of them would be a test that could be made to lie by editing it. This
        // checks only that the experiment RAN: every arm must have reached the service and been
        // handed a perk back, because an arm that never connected measures nothing at all.
        var silent = ParameterArms
            .Where(arm => readings.GetValueOrDefault(arm.Name) is not [{ Hash: not null }, ..])
            .Select(arm => arm.Name)
            .ToArray();
        Assert.True(
            silent.Length == 0,
            $"These arms returned no perk_hash from {GateHost}/api/http3 and therefore measured "
                + $"nothing: {string.Join(", ", silent)}. Read the per-attempt lines before "
                + "changing anything - a zero success rate is A3's evidence, not a reason to "
                + "retry harder.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        void Compare(string question, string left, string right) =>
            CompareReadings(
                report,
                question,
                left,
                readings.GetValueOrDefault(left) is [var first, ..] ? first : null,
                right,
                readings.GetValueOrDefault(right) is [var second, ..] ? second : null);
    }

    // =======================================================================================
    // TASK B11: THE LIVE RUN, AND THE POINT OF THE WHOLE PHASE.
    //
    // Everything B0-B10 built is a claim about bytes nobody outside this repo has read back.
    // This test drives TlsQuicClientHelloProfileFactory - not a list typed into this file -
    // against fp.impersonate.pro and reads the verdict. After it, "change a fingerprint knob
    // and watch the endpoint's answer move" is an operation, not an aspiration.
    //
    // THE THREE ARMS, AND THE PREDICTION EACH ONE IS THERE TO TEST. The predictions are
    // written here, BEFORE the run, and the recording states each measured result against the
    // prediction beside it. A prediction that fails is the valuable outcome; nothing in this
    // file may be edited afterwards to make one come true.
    //
    //   PRESET         TlsQuicTransportParameterSpec's own default Parameters - the a captured client
    //                  preset as shipped, fourteen entries in the capture's order.
    //                  PREDICTION: /api/http3 answers with a body over genuinely negotiated
    //                  h3, and segment 3 reproduces the capture's fourteen identifiers in the
    //                  capture's order, with GREASE for the reserved parameter, 12583:AUTO for
    //                  initial_rtt and 15:AUTO for the source connection ID.
    //
    //   SORTED         the SAME fourteen entries, ascending by the identifier each is emitted
    //                  under. Position is the only thing that differs, and the 4ed90bf probe
    //                  measured position as hashed and an AUTO-rendered VALUE as not.
    //                  PREDICTION: perk_hash MOVES; perk_hash_normalized DOES NOT.
    //                  AND A SHARPER ONE, which is the reason this arm sorts rather than
    //                  merely reverses: the normalized form IS the ascending sort, so this
    //                  arm's perk_text should equal PRESET's perk_text_normalized and this
    //                  arm's perk_hash should equal PRESET's perk_hash_normalized. That
    //                  prediction has one known soft spot - the reserved parameter renders as
    //                  the bare token GREASE, so where the service sorts it in the normalized
    //                  form is not something any capture states - and it is stated anyway,
    //                  because a prediction with a named weak point is still a prediction.
    //
    //   PRESET_REPEAT  PRESET again, on fresh connections.
    //                  PREDICTION: both hashes are byte-identical to PRESET's. The three
    //                  values the factory redraws per connection - initial_rtt, the reserved
    //                  identifier, and the GREASE version inside version_information - are
    //                  exactly the three the perk renders as AUTO or GREASE rather than as a
    //                  number, so none of them can reach a hash. If this arm moves, the
    //                  factory's whole reason for being a factory is visible to the endpoint
    //                  and that is a finding, not a flake.
    //
    // ONE ENDPOINT ONLY. tls3.peet.ws publishes no perk of any spelling; C13 already recorded
    // that, and a second endpoint that cannot answer the question is not a second reading.
    // =======================================================================================

    /// <summary>Whole connections per arm - the same reasoning as the probe's: one attempt
    /// cannot tell a real difference from a flake, and three arms times this is the run's
    /// whole cost.</summary>
    private const int FactoryAttemptsPerArm = 4;

    /// <summary>A client capture's perk, line 47 of
    /// <c>the preset that measured it</c>.
    // THE CAPTURED-PERSONA TARGETS ARE GONE, and so is the comparison that used them. This
    // file used to hold one browser's perk string and its two hashes and diff the LIBRARY
    // DEFAULT against them, which only made sense while that browser's numbers WERE the
    // library default. SharpTls ships no captured persona now - the default parameter list is
    // RFC 9000 s7.3's single mandatory entry - so there is nothing for a captured hash to be
    // the target of. A persona's fingerprint is asserted where the persona lives, against the
    // capture that measured it.

    /// <summary>C13's recorded segment 3, from
    /// <c>docs/superpowers/specs/reference-captures/2026-08-20-sharptls-c13-live-http3.md</c>.
    /// Quoted so the delta from wiring the factory in is visible in the run's own output
    /// rather than only in a document written afterwards.</summary>
    private const string C13Segment3 =
        "15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103";

    /// <summary>C13's recorded <c>perk_hash</c> and <c>perk_hash_normalized</c>, for the same
    /// reason.</summary>
    private const string C13PerkHash = "6d94f63e5db7fe12fa493e5b23c2443f";

    /// <inheritdoc cref="C13PerkHash"/>
    private const string C13PerkHashNormalized = "ff76216a19258be0123a5ee76da4fa7a";

    /// <summary>The preset as shipped: a default <see cref="TlsQuicTransportParameterSpec"/>,
    /// whose <c>Parameters</c> default is <c>RfcMinimumParameters</c>. Deliberately NOT a copy of
    /// that list - an arm that retyped it would stop measuring what ships.</summary>
    private static TlsQuicTransportParameterSpec PresetParameters() => new();

    /// <summary>The preset's fourteen entries, ascending by the identifier each is emitted
    /// under.</summary>
    /// <remarks>THE SORT KEY IS READ BACK FROM A COMPOSITION, NOT RETYPED. Three of the
    /// fourteen entries are drawn, and a drawn entry's <c>Id</c> is zero until its function has
    /// run - so sorting the slots by their own <c>Id</c> would put version_information and
    /// initial_rtt at the front rather than at 17 and 12583. Composing once and sorting the
    /// slots by the identifiers that composition emitted keeps this arm's order a fact about
    /// what goes on the wire. The reserved parameter's identifier is redrawn per connection
    /// over the whole of RFC 9000 s18.1's set, so this arm's position for it is fixed by ONE
    /// draw; every draw above 12584 sorts to the same place, which is all but all of
    /// them.</remarks>
    private static TlsQuicTransportParameterSpec SortedParameters()
    {
        var reference = new TlsQuicConnectionSpec();
        var composed = reference.TransportParameters
            .Compose(reference, new byte[reference.SourceConnectionIdLength])
            .Parameters;
        var slots = TlsQuicTransportParameterSpec.RfcMinimumParameters;
        if (composed.Count != slots.Length)
        {
            // A drawn entry returning null shortens the composed list, and a shortened list
            // would silently pair each slot with the WRONG identifier. Refused rather than
            // sorted into nonsense.
            throw new InvalidOperationException(
                $"The preset composed {composed.Count} parameters from {slots.Length} entries, "
                    + "so the composed identifiers no longer line up one-to-one with the "
                    + "entries they came from and this sort would reorder the wrong things.");
        }

        return new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                .. slots
                    .Select((slot, index) => (Slot: slot, composed[index].Id))
                    .OrderBy(entry => entry.Id)
                    .Select(entry => entry.Slot),
            ],
        };
    }

    /// <summary>The three arms, in run order. <c>PRESET</c> and <c>PRESET_REPEAT</c> name the
    /// same builder deliberately: the repeat is the same configuration and not a copy of
    /// it.</summary>
    private static readonly (string Name, Func<TlsQuicTransportParameterSpec> Build)[]
        FactoryArms =
        [
            ("PRESET", PresetParameters),
            ("SORTED", SortedParameters),
            ("PRESET_REPEAT", PresetParameters),
        ];

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task AFingerprintChangeIsVisibleEndToEndThroughTheProfileFactory()
    {
        var report = new StringBuilder();
        report.AppendLine("# B11 - the live run, through TlsQuicClientHelloProfileFactory");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        report.AppendLine($"attempts per arm: {FactoryAttemptsPerArm}");
        report.AppendLine(
            "QPACK arm in force: DEFAULT "
                + $"({TlsQuicHttp3Settings.Render(ShippedQpackSettings)}) - the same arm C13 "
                + "and the order probe ran, so perk segment 1 is held constant and the delta "
                + "against C13 is segment 3 alone.");
        report.AppendLine(
            "ClientHello source: TlsQuicClientHelloProfileFactory. ALPN and extension 57's "
                + "body come from the factory; the TLS half is the same two suites and two "
                + "groups this file's other live tests send.");

        var endPoint = await ResolveAsync(GateHost);
        report.AppendLine($"endpoint: {endPoint}");

        // arm -> every DISTINCT reading it produced, exactly as the probe records them. A list
        // and not a value: one arm answering two ways is an instability to investigate before
        // anything below it is read, never something to average away.
        var readings = new Dictionary<string, List<Reading>>(StringComparer.Ordinal);
        var attempted = 0;
        var completed = 0;
        string? presetBody = null;

        foreach (var (name, build) in FactoryArms)
        {
            var parameterSpec = build();
            report.AppendLine();
            report.AppendLine($"## {name}");

            // Printed FROM a composition rather than retyped beside it, so the record of what
            // this arm sends cannot drift from what it sends. The reserved identifier below is
            // ONE draw; the wire carries a fresh one per connection, which is the point.
            var describeSpec = new TlsQuicConnectionSpec { TransportParameters = parameterSpec };
            var ids = string.Join(
                ",",
                parameterSpec
                    .Compose(describeSpec, new byte[describeSpec.SourceConnectionIdLength])
                    .Parameters
                    .Select(parameter => parameter.Id));
            report.AppendLine($"  parameter ids, in wire order: {ids}");

            var seen = new List<Reading>();
            readings[name] = seen;
            for (var attempt = 1; attempt <= FactoryAttemptsPerArm; attempt++)
            {
                attempted++;
                var outcome = await Http3AttemptAsync(
                    GateHost, "/api/http3", endPoint, compose: null, parameterSpec: parameterSpec);
                report.AppendLine($"  attempt {attempt}: {outcome.Summary}");
                if (outcome.Body is not { } body)
                {
                    continue;
                }

                completed++;
                if (name == "PRESET")
                {
                    presetBody ??= body;
                }

                var reading = new Reading(
                    FindJsonString(body, "perk_text"),
                    FindJsonString(body, "perk_hash"),
                    FindJsonString(body, "perk_text_normalized"),
                    FindJsonString(body, "perk_hash_normalized"));
                report.AppendLine($"    perk_text            = {reading.Text}");
                report.AppendLine($"    perk_hash            = {reading.Hash}");
                report.AppendLine($"    perk_text_normalized = {reading.NormalizedText}");
                report.AppendLine($"    perk_hash_normalized = {reading.NormalizedHash}");
                if (!seen.Contains(reading))
                {
                    seen.Add(reading);
                }
            }

            report.AppendLine(
                $"  RESULT: {seen.Count} distinct reading(s) over {FactoryAttemptsPerArm} "
                    + "attempts.");
            if (seen.Count > 1)
            {
                report.AppendLine(
                    "  UNSTABLE - this arm answered more than one way. That is a finding to "
                        + "investigate, and every comparison below it is unsafe until it is.");
            }
        }

        report.AppendLine();
        report.AppendLine(
            $"## attempts: {completed}/{attempted} returned a complete response; failure rate "
                + $"{attempted - completed}/{attempted}.");
        report.AppendLine(
            "  Prior totals, for the running A3 evidence: A4 task 13 0/10, C13 0/20, the "
                + "order probe 0/12, and the 12 this run just added above - 54 unimpaired "
                + "attempts. A3-13 extends the list with 8 more unimpaired attempts from its "
                + "own CONTROL arm, for 62; its per-arm rates are in "
                + "docs/superpowers/specs/reference-captures/"
                + "2026-08-22-sharptls-a3-13-live-run-under-induced-loss.md rather than "
                + "repeated here, because an arm with loss SCRIPTED INTO IT does not belong in "
                + "a total about how often the path loses something by itself. Read the "
                + "per-attempt initial_datagrams above beside this rate - a loss rate is only "
                + "meaningful next to how many datagrams had to survive.");

        var preset = First("PRESET");
        var sorted = First("SORTED");
        var repeat = First("PRESET_REPEAT");

        report.AppendLine();
        report.AppendLine("## the three predictions, as measured");
        CompareReadings(
            report,
            "P2 - does WIRE ORDER move the hashes? PREDICTED: perk_hash MOVES, "
                + "perk_hash_normalized DOES NOT.",
            "PRESET",
            preset,
            "SORTED",
            sorted);
        CompareReadings(
            report,
            "P3 - do the three PER-CONNECTION DRAWS move the hashes? PREDICTED: neither "
                + "moves, because all three render as AUTO or GREASE.",
            "PRESET",
            preset,
            "PRESET_REPEAT",
            repeat);

        report.AppendLine();
        report.AppendLine(
            "### P2b - the sharper one: is SORTED's raw form PRESET's normalized form?");
        if (preset is null || sorted is null)
        {
            report.AppendLine("  NOT MEASURED - PRESET or SORTED returned no perk.");
        }
        else
        {
            report.AppendLine($"  PRESET perk_text_normalized = {preset.NormalizedText}");
            report.AppendLine($"  SORTED perk_text            = {sorted.Text}");
            report.AppendLine(
                "  -> texts "
                    + $"{(string.Equals(preset.NormalizedText, sorted.Text, StringComparison.Ordinal) ? "MATCH" : "DIFFER")}");
            report.AppendLine($"  PRESET perk_hash_normalized = {preset.NormalizedHash}");
            report.AppendLine($"  SORTED perk_hash            = {sorted.Hash}");
            report.AppendLine(
                "  -> hashes "
                    + $"{(string.Equals(preset.NormalizedHash, sorted.Hash, StringComparison.Ordinal) ? "MATCH" : "DIFFER")}");
        }

        // THE SEGMENTS ARE STILL PRINTED, WITH NOTHING TO DIFF THEM AGAINST. What the live
        // service returns for this connection is the interesting half either way; the other
        // half used to be one browser's published perk string, and that comparison went with
        // the persona it belonged to.
        report.AppendLine();
        report.AppendLine("## P1 - PRESET segments as the live service rendered them");
        var owners = new[]
        {
            "C - h3 SETTINGS",
            "C - pseudo-header order",
            "B - transport parameters, wire order",
            "B - connection ID length pair",
        };
        for (var index = 0; index < owners.Length; index++)
        {
            report.AppendLine();
            report.AppendLine($"  segment {index + 1} [{owners[index]}]");
            report.AppendLine($"    ours  = {Segment(preset?.Text, index)}");
        }

        report.AppendLine();
        report.AppendLine("## segment 3 against C13's recorded run - the delta the factory made");
        report.AppendLine($"  C13   = {C13Segment3}");
        report.AppendLine($"  B11   = {Segment3(preset?.Text)}");
        report.AppendLine();
        report.AppendLine($"  perk_hash            C13 = {C13PerkHash}");
        report.AppendLine($"  perk_hash            B11 = {preset?.Hash}");
        report.AppendLine($"  perk_hash_normalized C13 = {C13PerkHashNormalized}");
        report.AppendLine($"  perk_hash_normalized B11 = {preset?.NormalizedHash}");

        if (presetBody is { } recorded)
        {
            report.AppendLine();
            report.AppendLine($"  body_bytes = {Encoding.UTF8.GetByteCount(recorded)}");
            report.AppendLine("  --- PRESET body verbatim ---");
            report.AppendLine(recorded);
            report.AppendLine("  --- end body ---");
        }

        // Written whether or not the assertions pass: a failed run is the more valuable one.
        var reportPath = Path.Combine(Path.GetTempPath(), "quic-b11-live-run.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        // TWO ASSERTIONS, AND NEITHER IS ON A PREDICTION. The predictions are recorded above
        // and answered by the recording; a test that asserted one of them would be a test that
        // could be made to lie by editing it. These check only that the experiment RAN.
        var silent = FactoryArms
            .Where(arm => readings.GetValueOrDefault(arm.Name) is not [{ Hash: not null }, ..])
            .Select(arm => arm.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        Assert.True(
            silent.Length == 0,
            $"These arms returned no perk_hash from {GateHost}/api/http3 and therefore measured "
                + $"nothing: {string.Join(", ", silent)}. Read the per-attempt lines before "
                + "changing anything - a zero success rate is A3's evidence, not a reason to "
                + $"retry harder.\nFull recording also written to {reportPath}.\n\n{report}");

        // /api/http3 reports the protocol it was reached over, so this cannot be satisfied by
        // a fallback to HTTP/2 or HTTP/1.1, and it is the task's own done-when: a body rather
        // than the endpoint's protocol-segregation refusal, driven through the B8 factory.
        Assert.True(
            presetBody is not null
                && presetBody.Contains("\"protocol\": \"http3\"", StringComparison.Ordinal),
            $"{GateHost}/api/http3 did not return a body over genuinely negotiated h3 when the "
                + "ClientHello came from TlsQuicClientHelloProfileFactory. That is a finding "
                + "about B, not a flaky test.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        Reading? First(string arm) =>
            readings.GetValueOrDefault(arm) is [var reading, ..] ? reading : null;
    }

    // =======================================================================================
    // A3-13: THE LIVE RUN, UNDER INDUCED LOSS.
    // =======================================================================================
    //
    // EVERY OTHER A3 TEST IS OFFLINE OR FACES A PEER THIS REPOSITORY WROTE. The recovery
    // machinery - RTT, loss detection, PTO, retransmission, NewReno, persistent congestion,
    // pacing - has never met a server it did not write, on a path it does not control, with
    // something actually missing. This is that run, and its output is a RECORDING with two
    // assertions on it.
    //
    // THE ASSERTIONS ARE ON THE INSTRUMENT AND THE MECHANISM, NEVER ON THE NETWORK.
    //
    //   1. PER ATTEMPT: the script impaired something. An arm whose `dropped` is zero measured
    //      NOTHING, and it is indistinguishable from a passing arm by every other number the
    //      run prints. A3-8's first loss test completed in 220 ms having lost nothing and went
    //      green; A3-11 found a vacuous test of its own the same way. This is the assertion
    //      that catches the third one.
    //
    //   2. PER ARM, ACROSS ITS ATTEMPTS: the recovery machinery engaged at least once, for the
    //      arms configured to repair. Per-attempt would be the wrong altitude - a dropped
    //      datagram carrying only an ACK is not ack-eliciting, so no packet is declared lost
    //      and nothing is owed a retransmission, and that is CORRECT rather than a failure.
    //      An arm that never once repaired across every attempt is a different claim, and it
    //      is a finding.
    //
    // THE COMPLETION RATE IS RECORDED AND NEVER ASSERTED. A failure here is the most valuable
    // output this test can produce: it is the first real-network evidence A3 has, and an
    // assertion on it would be an invitation to edit the number until it passed.
    //
    // WHAT THIS IS NOT. A completion rate against two cooperative endpoints, on one path, from
    // one machine, on one day, is not a claim about the internet. It is a claim about these
    // two endpoints on this path, and the arms differ only in the script - which is what makes
    // the comparison BETWEEN arms worth more than any arm's own number.

    /// <summary>Four per host, eight per arm.</summary>
    /// <remarks>The same reasoning <see cref="Http3AttemptsPerHost"/> gives, one attempt
    /// larger: an arm's rate is compared against another arm's rate here rather than read on
    /// its own, so the arms need to be the same size and large enough that a single flake does
    /// not invert the ordering. Seven arms times two hosts times four is 56 attempts, and the
    /// two arms that are EXPECTED to spend a deadline dominate the wall clock.</remarks>
    private const int A3AttemptsPerArm = 4;

    /// <summary>The recovery spec whose probe carries data rather than a PING.</summary>
    /// <remarks>
    /// <para>THE SHIPPED DEFAULT IS <see cref="TlsQuicProbeContents.Ping"/> - see
    /// <c>TlsQuicRecoverySpec._probeContents</c> - AND THAT IS THE WHOLE REASON THIS ARM
    /// EXISTS BESIDE THE DEFAULT ONE. Loss detection is ACK-driven: RFC 9002 s6.1 declares a
    /// packet lost only once a LATER packet has been acknowledged. When the opening flight is
    /// one datagram, as it measurably is against both of these endpoints, dropping it means no
    /// ACK ever returns, so nothing is ever declared lost and the only thing that can repair
    /// the connection is the PTO probe's contents. A PING is not the ClientHello.</para>
    /// <para>So this is not a knob turned to make a test pass. It is the A/B the plan asks
    /// for - "the same scripted loss pattern run with retransmission disabled and enabled" -
    /// with the DISABLED side being the shipped default rather than a configuration invented
    /// to lose. Both numbers are recorded.</para>
    /// </remarks>
    private static TlsQuicRecoverySpec RepairingProbe() =>
        new() { ProbeContents = TlsQuicProbeContents.RetransmittedData };

    /// <summary>One row of the experiment.</summary>
    /// <param name="Name">The label the recording groups by.</param>
    /// <param name="Why">What this arm is for, copied into the recording so the file explains
    /// itself without this source beside it.</param>
    /// <param name="Script">What to impair, or <see langword="null"/> for the control.</param>
    /// <param name="Recovery">The recovery spec, or <see langword="null"/> for the shipped
    /// default.</param>
    /// <param name="RepairExpected">Whether an arm that never engaged the recovery machinery
    /// is a failure. False for the control (nothing was lost) and for the shipped-default
    /// probe arm (whose point is that it CANNOT repair this loss).</param>
    private sealed record ImpairmentArm(
        string Name,
        string Why,
        Action<ImpairingDatagramTransport>? Script,
        TlsQuicRecoverySpec? Recovery,
        bool RepairExpected);

    /// <summary>The seven arms, and every ordinal in them is justified by a measurement rather
    /// than a guess.</summary>
    /// <remarks>
    /// <para>ORDINAL 1 IS THE ENTIRE OPENING FLIGHT. The C13 recording of these same two
    /// endpoints prints <c>initial_datagrams=1</c> on all ten of its attempts, so
    /// <c>Drop(1)</c> is not "a datagram of the opening flight", it is the ClientHello.</para>
    /// <para>ORDINAL 5 IS INSIDE THE REQUEST/RESPONSE EXCHANGE. The same recording prints
    /// <c>datagrams_sent=12</c> for a whole successful attempt against both hosts, so ordinal 5
    /// is past the handshake and well short of the end. If an attempt ends before offering
    /// five datagrams the script impairs nothing, and assertion 1 above says so out loud
    /// rather than reporting the arm as clean.</para>
    /// <para>THE BLACKOUT IS EIGHT CONSECUTIVE ORDINALS FROM 6, NOT A LOSS RATE. RFC 9002
    /// s7.6 needs a span of at least <c>kPersistentCongestionThreshold</c> probe timeouts in
    /// which everything is lost; the PTO doubles on each expiry, so eight consecutive drops
    /// starting after the handshake covers roughly 0.2 + 0.4 + 0.8 + 1.6 seconds of backoff
    /// before ordinal 14 is allowed through to draw the ACK that lets the span be declared
    /// lost at all. Whether that is enough on a real path is exactly what has never been
    /// measured, and the recording states the answer either way.</para>
    /// </remarks>
    private static readonly ImpairmentArm[] ImpairmentArms =
    [
        new(
            "CONTROL",
            "no impairment - the baseline failure rate of this path, on this day, with the "
                + "recovery machinery present.",
            null,
            null,
            RepairExpected: false),
        new(
            "DUPLICATE_OPENING",
            "the opening flight delivered twice. Not loss: a duplicate is what a retransmitting "
                + "middlebox produces, and the question is whether the server's reply to a "
                + "doubled Initial confuses this client.",
            static impair => impair.Duplicate(1),
            null,
            RepairExpected: false),
        new(
            "DROP_OPENING_SHIPPED_PROBE",
            "the opening flight dropped, with the SHIPPED recovery spec whose probe is a PING. "
                + "Predicted to fail: no ACK returns, so nothing is declared lost, and a PING "
                + "is not a ClientHello.",
            static impair => impair.Drop(1),
            null,
            RepairExpected: false),
        new(
            "DROP_OPENING_REPAIRING_PROBE",
            "the same drop, with the probe carrying retransmitted data. This is the A/B: the "
                + "only difference from the arm above is one knob.",
            static impair => impair.Drop(1),
            RepairingProbe(),
            RepairExpected: true),
        new(
            "DROP_MID_EXCHANGE",
            "a datagram dropped after the handshake, inside the request/response exchange, "
                + "where an ACK can still come back and ack-driven loss detection can run.",
            static impair => impair.Drop(5),
            RepairingProbe(),
            RepairExpected: true),
        new(
            "REORDER",
            "the 4th datagram held until the 5th has gone, so the peer sees them out of order. "
                + "RFC 9002 s6.1.1's packet threshold is a REORDERING TOLERANCE, so the "
                + "interesting answer is that nothing is declared lost.",
            static impair => impair.HoldUntilAfter(4, 5),
            RepairingProbe(),
            RepairExpected: false),
        new(
            "BURST_BLACKOUT",
            "eight consecutive datagrams dropped after the handshake, long enough for the PTO "
                + "to back off several times - the only arm that can reach RFC 9002 s7.6's "
                + "persistent congestion.",
            static impair =>
            {
                for (var ordinal = 6; ordinal <= 13; ordinal++)
                {
                    impair.Drop(ordinal);
                }
            },
            RepairingProbe(),
            RepairExpected: true),
    ];

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task AnImpairedHttp3RequestMeetsTheRecoveryMachineryOnALivePath()
    {
        var report = new StringBuilder();
        report.AppendLine("# A3-13 - the live run, under induced loss");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        report.AppendLine($"attempts per arm per host: {A3AttemptsPerArm}");
        report.AppendLine(
            "impairment is SEND-SIDE ONLY and SCRIPTED BY ORDINAL, never by rate - see "
                + "ImpairingDatagramTransport's remarks for why a rate would not reproduce.");
        report.AppendLine();

        var resolved = new Dictionary<string, IPEndPoint>(StringComparer.OrdinalIgnoreCase);
        foreach (var (host, _) in Http3Targets)
        {
            resolved[host] = await ResolveAsync(host);
            report.AppendLine($"resolved {host} -> {resolved[host]}");
        }

        // arm -> host -> readings, so the per-arm rate AND the two endpoints' agreement both
        // come out of one pass over the same dictionary.
        var readings =
            new Dictionary<string, Dictionary<string, List<Http3Recovery>>>(StringComparer.Ordinal);

        foreach (var arm in ImpairmentArms)
        {
            report.AppendLine();
            report.AppendLine($"## arm {arm.Name}");
            report.AppendLine($"  {arm.Why}");
            var perHost = new Dictionary<string, List<Http3Recovery>>(StringComparer.OrdinalIgnoreCase);
            readings[arm.Name] = perHost;

            foreach (var (host, requestPath) in Http3Targets)
            {
                report.AppendLine($"  {host}{requestPath}");
                var samples = new List<Http3Recovery>();
                perHost[host] = samples;
                for (var attempt = 1; attempt <= A3AttemptsPerArm; attempt++)
                {
                    var outcome = await Http3AttemptAsync(
                        host,
                        requestPath,
                        resolved[host],
                        impair: arm.Script,
                        recovery: arm.Recovery);
                    report.AppendLine($"    attempt {attempt}: {outcome.Summary}");
                    if (outcome.Recovery is { } reading)
                    {
                        samples.Add(reading);
                    }
                }
            }
        }

        // ---------------------------------------------------------------------------------
        // THE TABLE THE TASK EXISTS TO PRODUCE.
        // ---------------------------------------------------------------------------------
        report.AppendLine();
        report.AppendLine("## per-arm completion, per host - RECORDED, NEVER ASSERTED");
        report.AppendLine(
            "  arm | host | completed/attempts | failure rate | lost | retransmitted | probes "
                + "| persistent_congestion | dropped | reordered | min_cwnd");
        foreach (var arm in ImpairmentArms)
        {
            foreach (var (host, _) in Http3Targets)
            {
                var samples = readings[arm.Name][host];
                var completed = samples.Count(static s => s.Completed);
                report.AppendLine(
                    $"  {arm.Name} | {host} | {completed}/{samples.Count} | "
                        + $"{samples.Count - completed}/{samples.Count} | "
                        + $"{samples.Sum(static s => s.PacketsDeclaredLost)} | "
                        + $"{samples.Sum(static s => s.FramesRetransmitted)} | "
                        + $"{samples.Sum(static s => s.ProbeDatagramsSent)} | "
                        + $"{samples.Sum(static s => s.PersistentCongestionEvents)} | "
                        + $"{samples.Sum(static s => s.DatagramsDropped)} | "
                        + $"{samples.Count(static s => s.DeliveredOutOfOrder)} | "
                        + $"{(samples.Count == 0 ? 0 : samples.Min(static s => s.CongestionWindowBytes))}");
            }
        }

        // THE TWO ENDPOINTS ARE COMPARED RATHER THAN AVERAGED, because the plan says a
        // disagreement is a finding to investigate and an average would hide it.
        report.AppendLine();
        report.AppendLine("## do the two endpoints agree, arm by arm?");
        foreach (var arm in ImpairmentArms)
        {
            var rates = Http3Targets
                .Select(target => (
                    target.Host,
                    Completed: readings[arm.Name][target.Host].Count(static s => s.Completed),
                    Total: readings[arm.Name][target.Host].Count))
                .ToArray();
            var agree = rates.Select(static r => r.Completed == r.Total).Distinct().Count() == 1;
            report.AppendLine(
                $"  {arm.Name}: "
                    + string.Join(
                        ", ",
                        rates.Select(static r => $"{r.Host} {r.Completed}/{r.Total}"))
                    + $" -> {(agree ? "AGREE" : "DISAGREE - a finding to investigate")}");
        }

        // Written whether or not the assertions pass: a failed run is the more valuable one.
        var reportPath = Path.Combine(Path.GetTempPath(), "quic-a3-13-induced-loss.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        // ---------------------------------------------------------------------------------
        // ASSERTION 1 - THE INSTRUMENT FIRED. A vacuous arm is invisible without this.
        // ---------------------------------------------------------------------------------
        var vacuous = ImpairmentArms
            .Where(arm => arm.Script is not null)
            .SelectMany(arm => readings[arm.Name].SelectMany(
                host => host.Value.Select(sample => (arm.Name, host.Key, sample))))
            .Where(static row => !row.sample.Impaired)
            .Select(static row => $"{row.Name}/{row.Key} offered={row.sample.DatagramsOffered}")
            .ToArray();
        Assert.True(
            vacuous.Length == 0,
            "These impaired attempts IMPAIRED NOTHING - the script named an ordinal the "
                + "attempt never reached, so they measured nothing and are indistinguishable "
                + $"from clean runs by every other number here: {string.Join("; ", vacuous)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // ---------------------------------------------------------------------------------
        // ASSERTION 2 - THE MECHANISM ENGAGED, per arm rather than per attempt.
        // ---------------------------------------------------------------------------------
        var inert = ImpairmentArms
            .Where(arm => arm.RepairExpected)
            .Where(arm => !readings[arm.Name].SelectMany(static host => host.Value).Any(
                static sample => sample.PacketsDeclaredLost > 0 || sample.FramesRetransmitted > 0))
            .Select(static arm => arm.Name)
            .ToArray();
        Assert.True(
            inert.Length == 0,
            "These arms dropped datagrams and the recovery machinery NEVER ONCE ENGAGED across "
                + "every attempt against both endpoints - nothing was declared lost and "
                + $"nothing was retransmitted: {string.Join(", ", inert)}. That is a finding "
                + "about A3, not a flaky network, and the per-attempt lines say which counter "
                + "stayed at zero.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");
    }
}
