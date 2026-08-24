using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <summary>Sample values the tests in this assembly need, held here rather than in the
/// library.</summary>
/// <remarks>
/// <para>THESE ARE FIXTURES, NOT MEASUREMENTS. They used to be a captured browser's numbers,
/// shipped from <c>TlsQuicTransportParameterSpec</c> as part of the persona that WAS the
/// library default. SharpTls ships no persona now, so a test that needs "some initial_rtt
/// range" or "some reserved identifier" says so itself with round numbers that assert nothing
/// about anybody's client.</para>
/// <para>NOTHING HERE MAY BE CITED AS EVIDENCE. A value in this file is chosen for legibility;
/// a value that is evidence lives in the preset that measured it, beside its capture.</para>
/// </remarks>
internal static class TestQuicSpecValues
{
    /// <summary>Flow-control limits generous enough not to be the subject of a test.</summary>
    /// <remarks>A bare <see cref="TlsQuicLocalFlowControlSpec"/> advertises RFC 9000 s18.2's
    /// zero for all six now that SharpTls ships no captured persona - correct for a library
    /// that advertises none of them, and useless as a fixture for a harness that has to move
    /// bytes. Both halves of the loopback read this one object, so they agree by
    /// construction.</remarks>
    internal static TlsQuicLocalFlowControlSpec HarnessFlowControl { get; } = new()
    {
        InitialMaxData = 1_000_000,
        InitialMaxStreamDataBidiLocal = 100_000,
        InitialMaxStreamDataBidiRemote = 100_000,
        InitialMaxStreamDataUni = 100_000,
        InitialMaxStreamsBidi = 100,
        InitialMaxStreamsUni = 100,
    };

    /// <summary>A parameter list that actually advertises <see cref="HarnessFlowControl"/>.
    /// </summary>
    /// <remarks>ENFORCEMENT READS THE ADVERTISEMENT. TlsQuicLocalFlowControlSpec.AsAdvertisedBy
    /// zeroes any limit the transport-parameter list does not emit, so a populated spec paired
    /// with the default one-entry list would still enforce zero. These two go together.</remarks>
    internal static TlsQuicTransportParameterSpec HarnessParameters { get; } = new()
    {
        Parameters =
        [
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxData),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataUni),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamsBidi),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamsUni),
        ],
    };

    /// <summary>A sample <c>initial_rtt</c> range, wide enough that a draw over it can move.
    /// </summary>
    internal static readonly (TimeSpan Minimum, TimeSpan Maximum) SampleInitialRttRange =
        (TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(300));

    /// <summary>A sample N for RFC 9000 section 18.1's reserved identifier form,
    /// <c>31 * N + 27</c>.</summary>
    /// <remarks>Large enough to exercise the 62-bit varint path and well under
    /// <see cref="TlsQuicTransportParameterSpec.MaximumReservedIdentifierN"/>.</remarks>
    internal const ulong SampleReservedIdentifierN = 120829032258064516;

    /// <summary>The identifier <see cref="SampleReservedIdentifierN"/> produces.</summary>
    internal const ulong SampleReservedIdentifier =
        (TlsQuicTransportParameterSpec.ReservedIdentifierStep * SampleReservedIdentifierN)
            + TlsQuicTransportParameterSpec.ReservedIdentifierBase;
}
