namespace TlsClient;

/// <summary>Configures how a request body is cut into DATA frames.</summary>
public sealed class TlsHttp2DataOptions
{
    /// <summary>
    /// Gets or sets the largest DATA frame payload the client emits for its own request
    /// bodies. <see langword="null"/>, the default, frames as large as the peer and the
    /// flow-control windows permit, which is today's behaviour.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The effective size is
    /// <c>min(MaxDataFrameSize, peerMaxFrameSize, connectionWindow, streamWindow)</c>. The
    /// clamp against the peer is not a separate rule that has to be written down: RFC 9113
    /// section 4.2 lets a peer advertise SETTINGS_MAX_FRAME_SIZE anywhere in
    /// [16384, 16777215], so without a declared cap a large body is framed at up to 16 MiB,
    /// while real clients self-cap well below that — 16384 is the common value.
    /// </para>
    /// <para>
    /// The pre-SETTINGS determinism rule is the same one
    /// <see cref="TlsHttp2Options.HeaderBlockFragmentSize"/> documents, and for the same
    /// reason it needs no separate implementation: the peer's maximum is seeded at the RFC
    /// 9113 section 6.5.2 default of 16384 and only rises once the peer's SETTINGS has been
    /// processed, so taking the minimum against it already clamps a pre-SETTINGS frame at
    /// that fixed default rather than at whatever arrives while the first request is being
    /// written.
    /// </para>
    /// <para>
    /// A declared pad comes out of this cap rather than being added on top of it. RFC 9113
    /// section 6.1 puts the Pad Length octet and the padding inside the DATA frame payload,
    /// and section 4.2 measures the whole payload, so a frame capped at 16384 with a
    /// 255-octet pad carries 16128 octets of body.
    /// </para>
    /// </remarks>
    public int? MaxDataFrameSize { get; set; }

    /// <summary>
    /// Gets or sets where END_STREAM lands when the request carries a body. The default,
    /// <see cref="TlsHttp2EndStreamPlacement.OnLastDataFrame"/>, is what a request whose body
    /// was supplied as a buffer does today.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both placements are legal. RFC 9113 section 6.1 attaches END_STREAM to a DATA frame
    /// and says nothing about that frame carrying octets; section 6.9.1 names the empty
    /// END_STREAM DATA frame explicitly — "Frames with zero length with the END_STREAM flag
    /// set (that is, an empty DATA frame) MAY be sent if there is no available space in
    /// either flow-control window" — so a client that always closes with one is conformant.
    /// </para>
    /// <para>
    /// A request carrying trailers ignores this: RFC 9113 section 8.1 has the trailing field
    /// block end the stream, so END_STREAM rides the trailer HEADERS and no DATA frame
    /// carries it.
    /// </para>
    /// <para>
    /// <see cref="TlsHttp2EndStreamPlacement.OnLastDataFrame"/> needs to know which frame is
    /// last before writing it. A body supplied as a stream only knows that from a declared
    /// <c>Content-Length</c>; reading ahead to find out would hold written octets across a
    /// blocking read of the caller's producer, which is the deadlock fixed in 892f951 and is
    /// not reintroduced here. A streaming body of unknown length therefore closes with a
    /// separate empty DATA frame whatever this says.
    /// </para>
    /// </remarks>
    public TlsHttp2EndStreamPlacement NonEmptyBody { get; set; }
        = TlsHttp2EndStreamPlacement.OnLastDataFrame;

    /// <summary>
    /// Gets or sets whether a request with no body ends its stream on the HEADERS frame. The
    /// default, <see langword="true"/>, is today's behaviour. When <see langword="false"/>
    /// the header block leaves without END_STREAM and a zero-length DATA frame carries it.
    /// </summary>
    /// <remarks>
    /// That trailing frame is deliberately never padded. RFC 9113 section 6.9.1 exempts a
    /// zero-length END_STREAM DATA frame from flow control, and padding it would turn it into
    /// a frame that needs credit which this path never reserves.
    /// </remarks>
    public bool EmptyBodyEndsOnHeaders { get; set; } = true;

    internal TlsHttp2DataConfiguration Snapshot()
    {
        // The ceiling is SETTINGS_MAX_FRAME_SIZE's own upper bound (RFC 9113 section 4.2);
        // anything above the peer's advertised value is clamped down rather than rejected.
        // The floor is 1 rather than 16384: this value only ever makes the client's own
        // frames smaller, and section 4.2's 2^14 lower bound binds what an endpoint must be
        // able to *receive*, not how small a sender may frame.
        if (MaxDataFrameSize is < 1 or > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxDataFrameSize),
                "MaxDataFrameSize must be within [1, 16777215].");
        }
        if (!Enum.IsDefined(NonEmptyBody))
        {
            throw new ArgumentOutOfRangeException(
                nameof(NonEmptyBody),
                "NonEmptyBody must be a defined value.");
        }
        return new TlsHttp2DataConfiguration(
            MaxDataFrameSize,
            NonEmptyBody,
            EmptyBodyEndsOnHeaders);
    }
}

/// <summary>Where the END_STREAM flag of a request with a body is carried.</summary>
public enum TlsHttp2EndStreamPlacement
{
    /// <summary>The last DATA frame of the body carries END_STREAM.</summary>
    OnLastDataFrame = 0,

    /// <summary>
    /// The body's DATA frames all leave without END_STREAM and a zero-length DATA frame
    /// carries it.
    /// </summary>
    SeparateEmptyDataFrame = 1,
}

/// <summary>The frozen DATA framing policy a connection writes from.</summary>
internal sealed record TlsHttp2DataConfiguration(
    int? MaxDataFrameSize,
    TlsHttp2EndStreamPlacement NonEmptyBody,
    bool EmptyBodyEndsOnHeaders);
