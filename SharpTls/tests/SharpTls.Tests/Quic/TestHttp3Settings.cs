using System.Collections.Immutable;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <summary>SETTINGS lists the harnesses in this assembly need, held here rather than in the
/// library.</summary>
/// <remarks>
/// <para>THESE USED TO BE <c>TlsQuicHttp3Spec.CaptureSettings</c> - a captured browser's five
/// pairs, shipped as the library DEFAULT. SharpTls ships no captured persona now, and
/// <c>TlsQuicHttp3Spec.DefaultSettings</c> is empty, which is the right default for a library
/// that has not been told who to imitate.</para>
/// <para>WHAT THE TESTS ACTUALLY NEEDED FROM IT was never the persona. It was "a SETTINGS list
/// that claims HTTP/3 datagrams", because <c>TlsQuicHttp3Connection</c> refuses the pair when
/// only one half is present and the harness advertises both. That is what
/// <see cref="DatagramCapable"/> is, written out here so a test reads as the test it is
/// rather than borrowing somebody's fingerprint for its side effects.</para>
/// </remarks>
internal static class TestHttp3Settings
{
    /// <summary>A SETTINGS list with a usable QPACK dynamic table and NO datagram claim.</summary>
    /// <remarks>THE DEFAULT FOR A HARNESS THAT IS NOT ABOUT DATAGRAMS. RFC 9297 s2.1.1's
    /// SETTINGS_H3_DATAGRAM is half a claim - <c>TlsQuicHttp3Connection</c>'s constructor
    /// refuses it unless the connection also advertises RFC 9221 s3's max_datagram_frame_size -
    /// so a list carrying it forces every harness that uses it to advertise the other half
    /// too. This one carries neither, and still gives the QPACK tests a non-zero
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY, which is what they were really getting from the
    /// captured browser's list.</remarks>
    internal static readonly ImmutableArray<TlsQuicHttp3Setting> QpackCapable =
    [
        new(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 65536),
        new(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
        new(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 100),
    ];

    /// <summary>A SETTINGS list that claims willingness to receive HTTP/3 datagrams.</summary>
    /// <remarks>The four identifiers are RFC 9114 s11.2.2 Table 3's and RFC 9297 s2.1.1's; the
    /// values are round numbers chosen for legibility and assert nothing about any client.
    /// </remarks>
    internal static readonly ImmutableArray<TlsQuicHttp3Setting> DatagramCapable =
    [
        new(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 65536),
        new(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
        new(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 100),
        new(TlsQuicHttp3Spec.H3DatagramIdentifier, 1),
    ];
}
