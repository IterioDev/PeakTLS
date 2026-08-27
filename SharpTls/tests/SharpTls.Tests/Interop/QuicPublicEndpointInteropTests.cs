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
            summary.Append($" fin={stream.FinalSizeKnown}");
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

    // =====================================================================================
    // THE SPOTIFY EDGE - the servers this repository's QUIC persona was decoded from.
    //
    // Everything above this line meets fp.impersonate.pro and tls3.peet.ws: fingerprint
    // services that answer h3 and publish what they saw. Useful, and not the target. The
    // shipped QUIC ClientHello was recovered from the Initial CRYPTO frames of real
    // connections to *.spotify.com, so Spotify's own edge - BoringSSL behind Envoy - is the
    // only peer that can say whether the persona works where it was captured.
    //
    // WHAT A PASS IS HERE. These are API hosts and nothing below carries a credential, so
    // 401, 404 and 405 are the expected answers and every one of them is a PASS: RFC 9114
    // s4.1 is satisfied by "an HTTP message ... consisting of ... a HEADERS frame", whatever
    // the status says. The transport is what is on trial. A handshake failure, a transport
    // error, a stall, a body that disagrees with its own content-length, or a connection that
    // ends by idle timeout rather than by CONNECTION_CLOSE is the failure this section exists
    // to catch, and none of these assertions may be relaxed to make a run go green.
    // =====================================================================================

    /// <summary>The three production hosts under test, each confirmed to advertise
    /// <c>alt-svc: h3=":443"; ma=2592000</c> over its TCP leg before this file was
    /// written.</summary>
    /// <remarks>THREE RATHER THAN ONE, AND THEY ARE NOT INTERCHANGEABLE. clienttoken and
    /// spclient are different Envoy fleets and gew4 is a geographically pinned access point;
    /// a failure on one of the three is a deployment quirk, and the same failure on all three
    /// is ours.</remarks>
    private static readonly string[] SpotifyHosts =
    [
        "clienttoken.spotify.com",
        "spclient.wg.spotify.com",
        "gew4-spclient.spotify.com",
    ];

    /// <summary>The one Spotify host that answers a body without a credential.</summary>
    /// <remarks>THE THREE HOSTS ABOVE ANSWER WITH ZERO BODY BYTES, measured rather than
    /// assumed: every unauthenticated path tried on them returns 401, 404 or 405 with
    /// <c>content-length: 0</c>. That is a complete HTTP/3 exchange and it exercises the
    /// HEADERS path, but it puts not one byte through DATA reassembly. apresolve is the same
    /// Envoy edge, advertises the same <c>h3=":443"</c>, and answers 200 with a JSON body - so
    /// it is what makes a reassembly assertion possible against Spotify at all.</remarks>
    private const string SpotifyBodyHost = "apresolve.spotify.com";

    /// <summary>The path apresolve answers 200 on.</summary>
    private const string SpotifyBodyPath = "/?type=accesspoint";

    /// <summary>The Spotify host that serves a body big enough to span many STREAM
    /// frames.</summary>
    /// <remarks>
    /// <para>ITS h3 IS NOT ADVERTISED, WHICH IS WHY THE ARM BELOW RECORDS BEFORE IT ASSERTS.
    /// The four API hosts above all answer <c>alt-svc: h3=":443"</c>; this one, on the same
    /// <c>server: envoy</c>, sends no <c>alt-svc</c> at all over its TCP leg. RFC 9114 s3.1
    /// makes that header the discovery mechanism - "the origin ... indicates ... using the
    /// Alt-Svc HTTP response header field" - so a client has no standing to expect UDP/443 to
    /// be open here, and a refusal would be the endpoint's answer rather than a defect.</para>
    /// <para>IT ANSWERS ANYWAY, MEASURED RATHER THAN ASSUMED: UDP/443 completes, selects h3,
    /// and its SETTINGS differ from the API fleet's - which is how the recording says this is a
    /// different deployment and not the same Envoy under another name. It is here because
    /// nothing Spotify serves unauthenticated on the API fleet is large enough to make
    /// reassembly, MAX_DATA and MAX_STREAM_DATA all run at once, and a body of about 300 kB
    /// under a narrowed window makes all three run on one stream.</para>
    /// </remarks>
    private const string SpotifyLargeBodyHost = "open.spotify.com";

    /// <inheritdoc cref="SpotifyLargeBodyHost"/>
    private const string SpotifyLargeBodyPath = "/";

    /// <summary>The user agent the captured client sends. Recorded here because a request that
    /// omits it is not the request the persona was captured making.</summary>
    private const string SpotifyUserAgent = "Spotify/9.1.76.2050 iOS/27.0 (iPhone17,2)";

    /// <summary>How many requests this file puts on ONE Spotify connection, one after the
    /// other.</summary>
    private const int SpotifySequentialRequests = 4;

    /// <summary>How many requests are opened before any of them is pumped, so that four
    /// request streams are in flight at once on one connection.</summary>
    /// <remarks>MULTIPLEXED, NOT MULTI-THREADED, and the distinction is itself the finding.
    /// This layer has no synchronisation and assumes single-thread affinity, so the concurrency
    /// RFC 9114 s2.1 describes - "Multiple requests ... proceed concurrently and
    /// independently" - is the one worth testing: four streams open at once, one thread
    /// pumping all of them. Driving the same connection from four threads would be testing an
    /// assumption the library never made and reporting the crash as a live-interop
    /// finding.</remarks>
    private const int SpotifyMultiplexedRequests = 4;

    /// <summary>The captured connection's own flow-control numbers, decoded from the iOS 27
    /// transport-parameter blocks: <c>0x04</c> as the four-byte varint <c>0x81000000</c>, and
    /// <c>0x05</c>, <c>0x06</c> and <c>0x07</c> each as <c>0x80200000</c>.</summary>
    private const ulong SpotifyInitialMaxData = 16_777_216;

    /// <inheritdoc cref="SpotifyInitialMaxData"/>
    private const ulong SpotifyInitialMaxStreamData = 2_097_152;

    /// <summary>The connection spec the Spotify persona dials with.</summary>
    /// <remarks>
    /// <para>THE SEVEN PARAMETERS ARE THE CAPTURE'S SEVEN, IN THE CAPTURE'S ORDER, ROTATING.
    /// The persona in <c>CapturedClientHelloProfiles</c> carries the same seven as a baked
    /// list; a live dial cannot use that list, because RFC 9000 s7.3 requires
    /// <c>initial_source_connection_id</c> to carry "the value ... that it selected for the
    /// connection" and a baked list carries the captured one. So the seven are re-declared as
    /// SLOTS here - five placed from <see cref="TlsQuicConnectionSpec.LocalFlowControl"/>, one
    /// literal, one placed from the live connection ID - and <c>CyclicRotationLength</c> is 7
    /// because every captured connection showed a cyclic rotation of one order and never a
    /// shuffle.</para>
    /// <para><c>initial_max_streams_bidi</c> (0x08) IS ABSENT ON PURPOSE. The capture carries
    /// exactly seven parameters and 0x08 is not among them, so RFC 9000 s18.2 applies:
    /// "Transport parameters have a default value of 0 if the transport parameter is absent" -
    /// the server may open no bidirectional stream. That is correct for an HTTP/3 client, which
    /// initiates every request stream itself.</para>
    /// <para>ONE SPEC OBJECT REACHES BOTH THE CONNECTION AND THE PROFILE FACTORY. See
    /// <see cref="FactoryClient"/>'s remarks for the three ways a second spec diverges in
    /// silence; the two window arguments below exist precisely so that a caller can narrow the
    /// advertised window without ever producing a second spec to do it with.</para>
    /// </remarks>
    /// <param name="maximumData">What <c>initial_max_data</c> advertises AND what this endpoint
    /// enforces - one number, because <c>Compose</c> places it rather than copying it.</param>
    /// <param name="maximumRequestStreamData">The same, for <c>initial_max_stream_data_bidi_
    /// local</c>, which is the limit every response body arrives under. The unidirectional
    /// limit is deliberately NOT narrowed with it: the peer's control and QPACK encoder streams
    /// arrive under that one, and starving them would stall the connection before any request
    /// body could demonstrate anything.</param>
    private static TlsQuicConnectionSpec SpotifyConnectionSpec(
        ulong maximumData = SpotifyInitialMaxData,
        ulong maximumRequestStreamData = SpotifyInitialMaxStreamData) =>
        new()
        {
            PaddingTarget = 1200,

            // THE CAPTURED CLIENT'S OWN SPLIT, AND WITHOUT IT NOTHING BELOW EVEN LEAVES THE
            // SOCKET. This persona offers X25519MLKEM768, whose key share alone is 1216 bytes,
            // so its ClientHello weighs about 1490 and a single Initial datagram carrying it
            // would be about 1540 - refused outright by a DF-set socket on any ordinary path,
            // which is what RFC 9000 s14 requires: "UDP datagrams MUST NOT be fragmented at
            // the IP layer". The capture splits the CRYPTO stream into a 999-byte frame and
            // the remainder, one frame per datagram, each padded to 1200 - so these two lists
            // are the capture's shape and not a workaround chosen to make a socket accept
            // something.
            //
            // 999 TWICE RATHER THAN 999 AND A MEASURED REMAINDER: the second element is a
            // CEILING, and RFC 9000 s19.6 leaves the sender free to end the frame where the
            // stream ends, so the last frame is simply short. Writing the remainder as a
            // constant would make this list a function of the server name's length, since the
            // hello grows and shrinks with the SNI it carries.
            InitialCryptoFrameByteCounts = [999, 999],
            InitialCryptoFramesPerDatagram = [1, 1],
            LocalFlowControl = new TlsQuicLocalFlowControlSpec
            {
                InitialMaxData = maximumData,
                InitialMaxStreamDataBidiLocal = maximumRequestStreamData,
                InitialMaxStreamDataBidiRemote = SpotifyInitialMaxStreamData,
                InitialMaxStreamDataUni = SpotifyInitialMaxStreamData,
                // 0x09 in the capture is the single byte 0x08.
                InitialMaxStreamsUni = 8,
            },
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters =
                [
                    TlsQuicTransportParameterSlot.Placed(
                        (ulong)TlsQuicTransportParameterId.InitialMaxData),
                    TlsQuicTransportParameterSlot.Placed(
                        (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal),
                    TlsQuicTransportParameterSlot.Placed(
                        (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote),
                    TlsQuicTransportParameterSlot.Placed(
                        (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataUni),
                    TlsQuicTransportParameterSlot.Placed(
                        (ulong)TlsQuicTransportParameterId.InitialMaxStreamsUni),
                    // The capture's two-byte 0x4040 - 64 written in the two-byte varint form
                    // where one byte would do. Kept as the literal bytes rather than as the
                    // number, because the encoding is part of the fingerprint.
                    TlsQuicTransportParameterSlot.Literal(
                        (ulong)TlsQuicTransportParameterId.ActiveConnectionIdLimit,
                        [0x40, 0x40]),
                    TlsQuicTransportParameterSlot.Placed(
                        (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
                    // The Google-private entry iOS 27 sends, last in every proxy capture
                    // regardless of where the rotation of the other seven started - which is
                    // why the rotation length above is 7 and not 8.
                    TlsQuicTransportParameterSlot.Literal(0xFF08_0808, [0x09]),
                ],
                CyclicRotationLength = 7,
            },
        };

    /// <summary>The Spotify client: the captured TLS half, with ALPN and extension 57's body
    /// composed per connection by <see cref="TlsQuicClientHelloProfileFactory"/>.</summary>
    /// <remarks>THE FACTORY IS NOT OPTIONAL FOR THIS PEER. RFC 9001 s8.4: "the TLS ClientHello
    /// ... legacy_session_id ... MUST be set to a zero-length vector" - and the factory forces
    /// that alongside ALPN and the transport parameters. Every Spotify host answers
    /// CRYPTO_ERROR with alert 47 (illegal_parameter) to a hello that carries the 32 random
    /// bytes a TCP encoder supplies for compatibility mode, and no offline test can see
    /// it.</remarks>
    private static CustomTlsQuicClient SpotifyClient(
        string host,
        ReadOnlyMemory<byte> sourceConnectionId,
        TlsQuicConnectionSpec connectionSpec)
    {
        var factory = new TlsQuicClientHelloProfileFactory
        {
            ConnectionSpec = connectionSpec,
            AlpnProtocols = [TlsQuicClientHelloProfileFactory.Http3AlpnToken],
            // The persona itself and not a re-typing of it: the same method the shipped
            // profile is built from, so this dial and that profile cannot drift apart. The
            // ALPN and transport parameters it sets are overwritten by the factory
            // afterwards, which is the whole reason the factory exists.
            Tls = ClientHelloProfiles.ApplySpotify917602050IOS270QuicClientHello,
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

    /// <summary>One request/response exchange on a Spotify connection.</summary>
    private sealed record SpotifyExchange(
        string Path,
        int Status,
        int BodyBytes,
        long DeclaredContentLength,
        bool FinReceived,
        bool Complete,
        string? Refusal)
    {
        /// <summary>Whether the peer's own <c>content-length</c> agrees with the number of
        /// bytes reassembly delivered.</summary>
        /// <remarks>RFC 9110 s8.6: "the Content-Length header field ... indicates ... the
        /// number of octets in the ... content". A body reassembled in the WRONG order still
        /// weighs the right number of octets, so this is the COMPLETENESS witness and nothing
        /// more; ordering is witnessed separately, by the head and the tail of the body being
        /// where the content type requires them. A header the peer omits reads -1 and is not a
        /// disagreement.</remarks>
        public bool ContentLengthAgrees =>
            DeclaredContentLength < 0 || DeclaredContentLength == BodyBytes;

        public string Render() =>
            $"{Path} status={Status} body_bytes={BodyBytes} "
                + $"content_length={DeclaredContentLength} fin={FinReceived} "
                + $"complete={Complete} refusal={Refusal ?? "-"}";
    }

    /// <summary>What one whole Spotify connection did, from ClientHello to
    /// CONNECTION_CLOSE.</summary>
    private sealed record SpotifySession(
        string Host,
        bool HandshakeCompleted,
        string? NegotiatedAlpn,
        bool PeerSettingsReceived,
        string PeerSettings,
        ulong? PeerControlStreamId,
        ulong QpackInsertCount,
        ulong PeerBidirectionalStreamLimit,
        ImmutableArray<SpotifyExchange> Exchanges,
        bool CloseSent,
        int DatagramsAfterClose,
        bool IdleTimedOut,
        int DiscardedForMissingKeys,
        ulong Http3ErrorCode,
        ulong? PeerCloseErrorCode,
        string? Failure,
        string? BodyHead,
        string? BodyTail)
    {
        public string Render()
        {
            var text = new StringBuilder();
            text.AppendLine(
                $"  handshake_completed={HandshakeCompleted} alpn={NegotiatedAlpn ?? "<none>"}");
            text.AppendLine(
                $"  peer_settings_received={PeerSettingsReceived} peer_settings={PeerSettings}");
            text.AppendLine(
                $"  peer_control_stream={PeerControlStreamId?.ToString() ?? "<none>"} "
                    + $"qpack_insert_count={QpackInsertCount} "
                    + $"peer_initial_max_streams_bidi={PeerBidirectionalStreamLimit}");
            foreach (var exchange in Exchanges)
            {
                text.AppendLine($"  exchange: {exchange.Render()}");
            }

            text.AppendLine(
                $"  close_sent={CloseSent} datagrams_after_close={DatagramsAfterClose} "
                    + $"idle_timed_out={IdleTimedOut} "
                    + $"discarded_missing_keys={DiscardedForMissingKeys} "
                    + $"h3_error=0x{Http3ErrorCode:x} "
                    + $"peer_close={(PeerCloseErrorCode is { } code ? $"0x{code:x}" : "<none>")}");
            if (Failure is not null)
            {
                text.AppendLine($"  FAILURE: {Failure}");
            }

            return text.ToString();
        }
    }

    /// <summary>Runs ONE Spotify connection end to end: handshake, some sequential requests,
    /// some multiplexed ones, then a graceful CONNECTION_CLOSE.</summary>
    /// <remarks>ONE CONNECTION AND NOT ONE PER REQUEST, WHICH IS THE POINT. RFC 9114 s3.3:
    /// "clients SHOULD NOT open more than one HTTP/3 connection to a given host". Everything
    /// that can only go wrong on the second request lives here - the peer's MAX_STREAMS
    /// accounting, the QPACK dynamic table its encoder stream fills, and whether a completed
    /// stream's flow-control credit ever comes back - and every one of them is invisible to a
    /// test that dials once per request.</remarks>
    private static async Task<SpotifySession> SpotifySessionAsync(
        string host,
        IPEndPoint endPoint,
        IReadOnlyList<string> sequentialPaths,
        IReadOnlyList<string> multiplexedPaths,
        TlsQuicConnectionSpec? connectionSpec = null,
        bool captureBody = false)
    {
        var spec = connectionSpec ?? SpotifyConnectionSpec();
        var clock = Stopwatch.StartNew();
        var exchanges = new List<SpotifyExchange>();
        CustomTlsQuicClient? client = null;
        string? failure = null;
        string? bodyHead = null;
        string? bodyTail = null;
        var closeSent = false;
        var datagramsAfterClose = 0;

        await using var transport = new RecordingTransport(
            TlsQuicUdpDatagramTransport.Create(endPoint.AddressFamily));
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(transport, endPoint, spec)
            {
                HandshakeDeadline = HandshakeDeadline,
                IdleTimeout = HandshakeDeadline + ResponseDeadline,
            },
            // Kept so NegotiatedApplicationProtocol can be read afterwards: RFC 9001 s8.1
            // makes ALPN mandatory over QUIC, and "the handshake completed" is not the same
            // claim as "the peer chose h3".
            source => client = SpotifyClient(host, source, spec));

        TlsQuicHttp3Connection? http3 = null;
        try
        {
            await connection.ConnectAsync();
            http3 = new TlsQuicHttp3Connection(connection, new TlsQuicHttp3Spec());
            http3.OpenLocalStreams();

            foreach (var path in sequentialPaths)
            {
                exchanges.Add(await OneAsync(path));
            }

            // ALL OPENED BEFORE ANY IS PUMPED. Opening one and reading it before opening the
            // next would be four more sequential requests wearing a different name.
            var inFlight = new List<(string Path, TlsQuicStream Stream)>();
            foreach (var path in multiplexedPaths)
            {
                var opened = http3.TryOpenRequest(
                    SpotifyRequest(host, path), out var refusal, out var malformed);
                if (opened is null)
                {
                    exchanges.Add(new(path, -1, 0, -1, false, false, $"{refusal}/{malformed}"));
                    continue;
                }

                inFlight.Add((path, opened));
            }

            if (inFlight.Count > 0)
            {
                await connection.SendPendingAsync();
                var deadline = clock.Elapsed + ResponseDeadline;
                while (clock.Elapsed < deadline
                    && inFlight.Exists(static entry => !entry.Stream.ReceiveComplete))
                {
                    if (!await http3.PumpOnceAsync())
                    {
                        break;
                    }
                }

                foreach (var (path, stream) in inFlight)
                {
                    exchanges.Add(Reading(path, stream));
                }
            }

            if (captureBody && http3.RequestStreamIds.Count > 0)
            {
                var last = http3.ResponseFor(http3.RequestStreamIds[^1]);
                if (last is { IsComplete: true } && last.Body.Length > 0)
                {
                    // HEAD AND TAIL RATHER THAN THE WHOLE BODY, because the body may be a few
                    // hundred kilobytes and the only question left once the byte COUNT already
                    // matches content-length is whether the first bytes are first and the last
                    // bytes are last. That is what reassembly order can be caught out on.
                    var text = Encoding.UTF8.GetString(last.Body);
                    bodyHead = text[..Math.Min(120, text.Length)];
                    bodyTail = text[^Math.Min(120, text.Length)..];
                }
            }

            // THE GRACEFUL CLOSE. RFC 9114 s5.2: "An endpoint that completes a graceful
            // shutdown SHOULD use the H3_NO_ERROR error code when closing the connection."
            // Counted in datagrams, because a close that put nothing on the wire is an idle
            // timeout with a nicer name and every other counter here would read the same.
            var before = transport.Sent.Count;
            await http3.CloseAsync(TlsQuicHttp3ErrorCode.H3NoError);
            datagramsAfterClose = transport.Sent.Count - before;
            closeSent = true;
        }
        catch (Exception exception)
        {
            failure = $"{exception.GetType().Name}: {Flatten(exception.Message)}";
        }

        return new(
            host,
            connection.IsHandshakeConfirmed,
            client?.NegotiatedApplicationProtocol,
            http3?.Streams.PeerSettingsReceived ?? false,
            http3 is null
                ? "<no-http3-connection>"
                : TlsQuicHttp3Settings.Render(http3.Streams.PeerSettings),
            http3?.Streams.PeerControlStreamId,
            http3?.Streams.Table?.InsertCount ?? 0,
            PeerBidirectionalLimit(),
            [.. exchanges],
            closeSent,
            datagramsAfterClose,
            connection.IdleTimedOut,
            connection.DiscardedForMissingKeys,
            http3?.ConnectionErrorCode ?? 0,
            connection.PeerCloseErrorCode,
            failure,
            bodyHead,
            bodyTail);

        // Read while the connection is still open, because `await using` disposes it on the
        // way out of this method and a counter read afterwards would be a read of a torn-down
        // connection.
        ulong PeerBidirectionalLimit()
        {
            try
            {
                return connection.PeerFlowControl.InitialMaxStreamsBidi;
            }
            catch (InvalidOperationException)
            {
                // The peer's parameters never arrived, which the handshake flag already says.
                return 0;
            }
        }

        async Task<SpotifyExchange> OneAsync(string path)
        {
            var stream = http3!.TryOpenRequest(
                SpotifyRequest(host, path), out var refusal, out var malformed);
            if (stream is null)
            {
                return new(path, -1, 0, -1, false, false, $"{refusal}/{malformed}");
            }

            await connection.SendPendingAsync();
            var deadline = clock.Elapsed + ResponseDeadline;
            while (!stream.ReceiveComplete && clock.Elapsed < deadline)
            {
                if (!await http3.PumpOnceAsync())
                {
                    break;
                }
            }

            return Reading(path, stream);
        }

        SpotifyExchange Reading(string path, TlsQuicStream stream)
        {
            var response = http3!.ResponseFor(stream.Id);
            return new(
                path,
                response?.Status ?? -1,
                response?.Body.Length ?? 0,
                response is null ? -1 : DeclaredContentLength(response.HeaderFields),
                stream.FinalSizeKnown,
                response is { IsComplete: true },
                null);
        }
    }

    /// <summary>The request the captured client makes: the four pseudo-header fields RFC 9114
    /// s4.3.1 requires of a GET, plus the user agent the capture carries.</summary>
    private static TlsQuicHttp3Request SpotifyRequest(string host, string path) =>
        new()
        {
            Method = "GET",
            Scheme = "https",
            Authority = host,
            Path = path,
            Fields = [new TlsQuicHttp3Field("user-agent", SpotifyUserAgent)],
        };

    /// <summary>The peer's own <c>content-length</c>, or -1 where it sent none.</summary>
    private static long DeclaredContentLength(ImmutableArray<TlsQuicHttp3Field> fields)
    {
        foreach (var field in fields)
        {
            // RFC 9114 s4.1.2: "field names MUST be converted to lowercase prior to their
            // encoding", so an ordinal compare against the lowercase name is exact rather than
            // merely convenient.
            if (string.Equals(field.Name, "content-length", StringComparison.Ordinal)
                && long.TryParse(field.Value, out var declared))
            {
                return declared;
            }
        }

        return -1;
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task EverySpotifyEdgeHostCompletesQuicAndAnswersOverHttp3()
    {
        var report = new StringBuilder();
        report.AppendLine("# Spotify edge - QUIC and HTTP/3, one connection per host");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        report.AppendLine("persona: the shipped iOS 27 Spotify QUIC ClientHello");

        var sessions = new List<SpotifySession>();
        foreach (var host in SpotifyHosts)
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
            var session = await SpotifySessionAsync(host, endPoint, ["/"], []);
            sessions.Add(session);
            report.Append(session.Render());
        }

        var reportPath = Path.Combine(Path.GetTempPath(), "quic-spotify-edge.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        var missing = SpotifyHosts
            .Except(sessions.Select(static session => session.Host), StringComparer.Ordinal)
            .ToArray();
        Assert.True(
            missing.Length == 0,
            $"These hosts never got as far as a UDP socket: {string.Join(", ", missing)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // A HANDSHAKE FAILURE IS THE FINDING, so it is asserted first, before anything
        // downstream can restate it as "no response".
        var unhandshaken = sessions
            .Where(static session => !session.HandshakeCompleted)
            .Select(static session => $"{session.Host}: {session.Failure ?? "no exception"}")
            .ToArray();
        Assert.True(
            unhandshaken.Length == 0,
            "The QUIC handshake did not complete against these Spotify hosts: "
                + $"{string.Join("; ", unhandshaken)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // RFC 9001 s8.1: "Unless another mechanism is used ... endpoints MUST use ALPN".
        // A handshake that completed under some other protocol is not this test passing.
        var wrongAlpn = sessions
            .Where(static session => session.NegotiatedAlpn != "h3")
            .Select(static session => $"{session.Host}={session.NegotiatedAlpn ?? "<none>"}")
            .ToArray();
        Assert.True(
            wrongAlpn.Length == 0,
            $"These hosts did not select h3: {string.Join(", ", wrongAlpn)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // RFC 9114 s6.2.1: "Each side MUST initiate a single control stream at the beginning of
        // the connection and send its SETTINGS frame as the first frame on this stream."
        var noSettings = sessions
            .Where(static session => !session.PeerSettingsReceived)
            .Select(static session => session.Host)
            .ToArray();
        Assert.True(
            noSettings.Length == 0,
            "These hosts' SETTINGS never arrived on a peer control stream: "
                + $"{string.Join(", ", noSettings)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        var incomplete = sessions
            .SelectMany(session => session.Exchanges.Select(exchange => (session.Host, exchange)))
            .Where(static row => !row.exchange.Complete)
            .Select(static row => $"{row.Host}{row.exchange.Render()}")
            .ToArray();
        Assert.True(
            incomplete.Length == 0,
            "These exchanges never produced a complete HTTP/3 response. A 4xx here would have "
                + "been a PASS - an unauthenticated API request is expected to be refused at "
                + "the application layer - so what these rows record is a TRANSPORT failure: "
                + $"{string.Join("; ", incomplete)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // The coalescing stall, reported separately from DiscardedPackets for the reason this
        // file's header gives: a non-zero value here is a bug report about us.
        var stalled = sessions
            .Where(static session => session.DiscardedForMissingKeys > 0)
            .Select(static session => $"{session.Host}={session.DiscardedForMissingKeys}")
            .ToArray();
        Assert.True(
            stalled.Length == 0,
            "Packets were discarded for want of keys against these hosts, which is a finding "
                + $"about this client and not about the network: {string.Join(", ", stalled)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // RFC 9000 s10.2: "An immediate close ... sends a CONNECTION_CLOSE frame". A close
        // that emitted no datagram left the peer to time the connection out instead.
        var unclosed = sessions
            .Where(static session =>
                !session.CloseSent || session.DatagramsAfterClose == 0 || session.IdleTimedOut)
            .Select(static session =>
                $"{session.Host} close_sent={session.CloseSent} "
                    + $"datagrams={session.DatagramsAfterClose} "
                    + $"idle_timed_out={session.IdleTimedOut}")
            .ToArray();
        Assert.True(
            unclosed.Length == 0,
            "These connections did not end in a CONNECTION_CLOSE the peer could act on: "
                + $"{string.Join("; ", unclosed)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task OneSpotifyConnectionCarriesSequentialAndMultiplexedHttp3Requests()
    {
        const string Host = "spclient.wg.spotify.com";
        var report = new StringBuilder();
        report.AppendLine("# Spotify edge - many requests on ONE connection");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");
        report.AppendLine(
            $"{SpotifySequentialRequests} sequential, then {SpotifyMultiplexedRequests} opened "
                + "before any of them is pumped");

        var endPoint = await ResolveAsync(Host);
        report.AppendLine();
        report.AppendLine($"## {Host} at {endPoint}");

        // DISTINCT PATHS SO A RESPONSE CANNOT LAND ON THE WRONG STREAM UNNOTICED. Every one of
        // these answers 401, so the status cannot tell them apart; the query string can, and
        // the peer echoes nothing - which is why the count of exchanges and their per-stream
        // completion is what this test reads rather than the bodies.
        var sequential = Enumerable
            .Range(1, SpotifySequentialRequests)
            .Select(static index => $"/melody/v1/product_state?seq={index}")
            .ToArray();
        var multiplexed = Enumerable
            .Range(1, SpotifyMultiplexedRequests)
            .Select(static index => $"/melody/v1/product_state?mux={index}")
            .ToArray();

        var session = await SpotifySessionAsync(Host, endPoint, sequential, multiplexed);
        report.Append(session.Render());

        var reportPath = Path.Combine(Path.GetTempPath(), "quic-spotify-multiplex.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        Assert.True(
            session.HandshakeCompleted,
            $"The handshake did not complete: {session.Failure ?? "no exception"}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        var expected = SpotifySequentialRequests + SpotifyMultiplexedRequests;
        Assert.True(
            session.Exchanges.Length == expected,
            $"{session.Exchanges.Length} of {expected} requests reached the wire; the rest were "
                + "refused before being sent, which is a stream-limit or malformed-request "
                + $"finding rather than a network one.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        var failed = session.Exchanges
            .Where(static exchange => !exchange.Complete)
            .Select(static exchange => exchange.Render())
            .ToArray();
        Assert.True(
            failed.Length == 0,
            "These requests on the shared connection never completed. A 401 would have been a "
                + $"PASS; an incomplete response is not: {string.Join("; ", failed)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // EVERY REQUEST GOT AN ANSWER OF ITS OWN. RFC 9114 s4.1: "A client sends an HTTP
        // request on a request stream", one per exchange, so eight exchanges is eight streams
        // and a status below 100 anywhere means one stream's HEADERS never decoded.
        var statusless = session.Exchanges
            .Where(static exchange => exchange.Status < 100)
            .Select(static exchange => exchange.Render())
            .ToArray();
        Assert.True(
            statusless.Length == 0,
            $"These exchanges completed with no status: {string.Join("; ", statusless)}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        Assert.True(
            session.CloseSent && session.DatagramsAfterClose > 0 && !session.IdleTimedOut,
            "The shared connection did not end in a CONNECTION_CLOSE: "
                + $"close_sent={session.CloseSent} datagrams={session.DatagramsAfterClose} "
                + $"idle_timed_out={session.IdleTimedOut}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task ASpotifyResponseBodyIsReassembledWholeAndInOrderUnderANarrowWindow()
    {
        var report = new StringBuilder();
        report.AppendLine("# Spotify edge - DATA reassembly and flow-control crediting");
        report.AppendLine($"started {DateTimeOffset.UtcNow:O}");

        // A DELIBERATELY NARROW WINDOW, AND THAT IS THE EXPERIMENT. The capture's own
        // initial_max_stream_data is 2 MiB and no unauthenticated Spotify body comes near it,
        // so dialling with the captured numbers would leave MAX_STREAM_DATA untouched and the
        // crediting path untested by a run that still looked green. RFC 9000 s4.1: "A sender
        // MUST NOT send data in excess of ... the largest maximum stream data" - so a client
        // that advertises 128 bytes and never credits more STALLS at 128, and a body larger
        // than that arriving whole is the proof that crediting ran.
        var narrow = SpotifyConnectionSpec(maximumData: 8_192, maximumRequestStreamData: 128);
        report.AppendLine(
            "advertised window: initial_max_data=8192 initial_max_stream_data_bidi_local=128 "
                + "(narrowed from the capture's 16777216/2097152 so that MAX_STREAM_DATA is "
                + "REQUIRED rather than merely permitted; the unidirectional limit is left at "
                + "the capture's value so the peer's control and QPACK streams are not starved)");

        var endPoint = await ResolveAsync(SpotifyBodyHost);
        report.AppendLine();
        report.AppendLine($"## {SpotifyBodyHost}{SpotifyBodyPath} at {endPoint}");
        var session = await SpotifySessionAsync(
            SpotifyBodyHost, endPoint, [SpotifyBodyPath], [], narrow, captureBody: true);
        report.Append(session.Render());
        report.AppendLine($"  body_head = {session.BodyHead ?? "<none>"}");
        report.AppendLine($"  body_tail = {session.BodyTail ?? "<none>"}");

        // THE LARGE-BODY ARM, RECORDED WHETHER OR NOT IT REACHES ANYTHING. See
        // SpotifyLargeBodyHost's remarks: this host publishes no alt-svc, so a QUIC handshake
        // failure here is the endpoint declining to offer h3 and not a defect. What is asserted
        // is conditional on the handshake, and nothing else about it is.
        report.AppendLine();
        report.AppendLine($"## {SpotifyLargeBodyHost}{SpotifyLargeBodyPath} - the large body");
        SpotifySession? large = null;
        try
        {
            var largeEndPoint = await ResolveAsync(SpotifyLargeBodyHost);
            report.AppendLine($"  endpoint: {largeEndPoint}");
            large = await SpotifySessionAsync(
                SpotifyLargeBodyHost,
                largeEndPoint,
                [SpotifyLargeBodyPath],
                [],
                SpotifyConnectionSpec(maximumData: 65_536, maximumRequestStreamData: 16_384),
                captureBody: true);
            report.Append(large.Render());
            report.AppendLine($"  body_head = {large.BodyHead ?? "<none>"}");
            report.AppendLine($"  body_tail = {large.BodyTail ?? "<none>"}");
        }
        catch (Exception exception)
        {
            report.AppendLine($"  DNS failed: {exception.GetType().Name}: {exception.Message}");
        }

        var reportPath = Path.Combine(Path.GetTempPath(), "quic-spotify-body.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        Assert.True(
            session.HandshakeCompleted,
            $"The handshake did not complete: {session.Failure ?? "no exception"}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        var exchange = Assert.Single(session.Exchanges);
        Assert.True(
            exchange.Complete && exchange.Status == 200,
            $"{SpotifyBodyHost}{SpotifyBodyPath} did not answer 200 over a completed HTTP/3 "
                + $"exchange: {exchange.Render()}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        Assert.True(
            exchange.BodyBytes > 128,
            "The body fitted inside the advertised 128-byte window, so no MAX_STREAM_DATA was "
                + "ever required and this test measured nothing about crediting: "
                + $"{exchange.Render()}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        Assert.True(
            exchange.ContentLengthAgrees,
            "The peer's content-length and the number of bytes reassembly delivered disagree, "
                + $"so what arrived is not what was sent: {exchange.Render()}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // ORDER, WHICH THE BYTE COUNT CANNOT SEE. A body reassembled from its frames in the
        // wrong order weighs exactly as much as one reassembled correctly; only its shape gives
        // it away, and a JSON document begins and ends with the braces of its root object.
        Assert.True(
            session.BodyHead is not null && session.BodyTail is not null,
            "The 200 carried no body, so nothing was reassembled.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");
        Assert.True(
            session.BodyHead!.TrimStart().StartsWith('{')
                && session.BodyTail!.TrimEnd().EndsWith('}'),
            "The reassembled body does not begin and end where a JSON document must, which is "
                + $"an ORDERING failure and not a completeness one: head={session.BodyHead} "
                + $"tail={session.BodyTail}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        if (large is not { HandshakeCompleted: true })
        {
            // Recorded above, asserted nowhere: this host advertises no h3 and is entitled not
            // to answer on UDP/443.
            return;
        }

        var largeExchange = Assert.Single(large.Exchanges);
        Assert.True(
            largeExchange.Complete && largeExchange.ContentLengthAgrees
                && largeExchange.BodyBytes > 65_536,
            "The large body did not arrive whole under a 16384-byte stream window inside a "
                + "65536-byte connection window, so reassembly, MAX_STREAM_DATA or MAX_DATA "
                + "failed on the one exchange large enough to need all three: "
                + $"{largeExchange.Render()}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");

        // THE ORDER WITNESS FOR THE LARGE BODY, AND HERE IT IS THE ONLY ONE. This response is
        // chunked, so RFC 9114 s4.1.2's "content-length" is absent and the byte count has
        // nothing to be compared against: ContentLengthAgrees is vacuously true above. What is
        // left is the shape - a document that begins with its doctype and ends with its root
        // close tag is a document whose ~250 STREAM frames were reassembled in the order they
        // were sent.
        Assert.True(
            large.BodyHead is not null
                && large.BodyHead.StartsWith("<!DOCTYPE html", StringComparison.OrdinalIgnoreCase)
                && large.BodyTail is not null
                && large.BodyTail.TrimEnd().EndsWith("</html>", StringComparison.Ordinal),
            "The large body does not begin and end where an HTML document must, which is an "
                + $"ORDERING failure and the only one this chunked response can show: "
                + $"head={large.BodyHead} tail={large.BodyTail}.\n"
                + $"Full recording also written to {reportPath}.\n\n{report}");
    }
}
