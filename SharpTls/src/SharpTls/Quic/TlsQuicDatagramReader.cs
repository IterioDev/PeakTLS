using System.Buffers.Binary;

namespace SharpTls.Quic;

// Which RFC 9000 wire format a packet split out of a coalesced datagram uses. Downstream code
// needs this to know which parser to hand the returned slice to (TlsQuicPacketHeader.
// TryReadLongHeader / TryReadShortHeader, or TlsQuicVersionNegotiation.TryRead) without
// re-deriving the same Header Form / Version dispatch that TlsQuicDatagramReader already
// performed once just to find the boundary.
internal enum TlsQuicCoalescedPacketKind
{
    Long,
    Short,
    VersionNegotiation,
}

// One packet split out of a coalesced UDP datagram (RFC 9000 s12.2). Packet is the raw,
// still-encoded bytes of exactly that one packet - RFC 9000 s12.2: "Every QUIC packet that is
// coalesced into a single UDP datagram is separate and complete. The receiver of coalesced QUIC
// packets MUST individually process each QUIC packet ... as if they were received as the payload
// of different UDP datagrams." Handing back the raw slice rather than a pre-parsed header lets a
// caller treat it exactly that way: feed it to TlsQuicPacketHeader / TlsQuicVersionNegotiation the
// same way it would feed a freshly received, uncoalesced datagram.
//
// LIFETIME: Packet is a zero-copy slice of the datagram passed to TlsQuicDatagramReader.Read, not
// an independent copy - same contract as TlsQuicLongHeader and TlsQuicShortHeader. It is only
// valid while that buffer is unmodified.
internal readonly struct TlsQuicCoalescedPacket
{
    internal TlsQuicCoalescedPacketKind Kind { get; init; }
    internal ReadOnlyMemory<byte> Packet { get; init; }
}

// RFC 9000 s12.2 Coalescing Packets: splits one UDP datagram into the QUIC packets coalesced
// into it.
internal static class TlsQuicDatagramReader
{
    // RFC 9000 s17.2 / s17.3.1, Header Form: bit 0x80 of byte 0, 1 for a long header, 0 for a
    // short header. Redefined locally rather than shared from TlsQuicPacketHeader's private
    // constant of the same name and value - every file in this namespace that needs this bit
    // (see also TlsQuicVersionNegotiation) defines its own, since the RFC fixes the bit position
    // permanently and there is nothing that could drift out of sync.
    private const byte HeaderFormBit = 0x80;

    // Header Form byte + the 4-byte Version field that RFC 9000 s17.2 and s17.2.1 both start
    // with - the minimum needed to read Version and tell a real long header packet from a
    // Version Negotiation packet before attempting either parse.
    private const int MinimumLongFormPrefixLength = 1 + 4;

    // Try-shaped and never throws for any input: this walks attacker-controlled network bytes,
    // and once a receive loop exists (a later phase) a throw here would let one malformed
    // datagram tear down the connection.
    //
    // Returns an enumerator, not a List<TlsQuicCoalescedPacket>: every Packet field yielded
    // aliases the datagram passed in, exactly like TlsQuicLongHeader and TlsQuicShortHeader
    // already do for a single packet (see their LIFETIME comments). This is the first place
    // several of those aliasing results exist at once, which makes it more, not less, important
    // that the API not hand back something a caller can mistake for safe to keep: a materialized
    // list looks like an ordinary owned collection, so a caller who stores one and then returns
    // the datagram buffer to a pool (or reuses it for the next receive) would silently corrupt
    // every packet already "found," with no compiler error to catch it. An iterator instead
    // forces the natural single-pass foreach shape - nothing stops a caller from still calling
    // ToList(), but nothing about the return type invites it either, and the source buffer
    // remains the one thing guarding every yielded packet's lifetime, same as it already is for
    // a single parsed header.
    //
    // LIFETIME (enumeration timing, not just the result): a yield-return method runs none of its
    // body until the first MoveNext(), so the walk itself - reading the first byte, calling
    // TryReadLongHeader, computing consumed - happens when the caller enumerates, not when Read
    // is called. A caller that stores the returned IEnumerable (or its enumerator) and resumes it
    // after an await is not reading stale results; it is parsing whatever the buffer holds at
    // that later point and yielding boundaries that were never true of any single datagram, with
    // no exception, because never-throwing is this method's whole contract. The returned sequence
    // MUST therefore be enumerated synchronously and completely, in place, before the datagram
    // buffer is reused, returned to a pool, or overwritten by the next receive - never stored
    // across an await or carried past the current receive iteration.
    //
    // THE WORDING IS DELIBERATELY STRICTER THAN THE MECHANISM, and it stays that way. What the
    // walk actually needs is narrower: the bytes AHEAD of its cursor unchanged between one
    // MoveNext and the next. A caller that awaits inside the loop body but only ever writes
    // BEHIND the cursor, and whose buffer has exactly one writer, is safe - and there is one
    // such caller, LoopbackQuicPeer.PumpOnceAsync, which writes that arithmetic out at its loop
    // and is the only violator of the sentence above in the tree. The sentence is not narrowed
    // to match, because the narrow rule is one a caller breaks BY ACCIDENT - a second writer, or
    // a body that touches bytes past its own packet, and neither shows up as an exception - while
    // the broad rule can only be broken on purpose, by someone who then has to justify it. A
    // contract that is safe to obey mechanically beats one that is exactly true.
    internal static IEnumerable<TlsQuicCoalescedPacket> Read(ReadOnlyMemory<byte> datagram)
    {
        var offset = 0;

        // The bound stopping this walk from indexing past the end of the datagram once every
        // coalesced packet has been consumed. Deliberately the only such check: every packet
        // parsed inside the loop already knows its own bounds on its own (TryReadLongHeader
        // validates its declared Length against what remains; a short header or Version
        // Negotiation packet takes everything left by definition), so nothing inside the loop
        // body needs to re-check offset against datagram.Length before indexing - this line is
        // the single place that does.
        while (offset < datagram.Length)
        {
            var remaining = datagram.Slice(offset);
            var firstByte = remaining.Span[0];

            if ((firstByte & HeaderFormBit) == 0)
            {
                // RFC 9000 s12.2: "A packet with a short header does not include a length, so it
                // can only be the last packet included in a UDP datagram." Nothing follows a
                // short header packet regardless of what bytes remain - there is no Length field
                // to say where its payload ends short of the datagram itself, so whatever is
                // left is this packet, not a separate one.
                yield return new TlsQuicCoalescedPacket { Kind = TlsQuicCoalescedPacketKind.Short, Packet = remaining };
                yield break;
            }

            // Version Negotiation shares the long header's Header Form bit but is never
            // coalesced with anything: RFC 9000 s12.2 - "there is no situation where a Retry or
            // Version Negotiation packet is coalesced with another packet" - and s17.2.1 - "a
            // Version Negotiation packet consumes an entire UDP datagram." Both are read
            // literally here: only recognised as the very first packet (offset 0), and once
            // recognised it always takes everything, leaving no remainder to keep walking. A
            // Version-Negotiation-shaped Version field (0) turning up later in the walk would
            // mean an earlier packet was coalesced in front of it, which RFC 9000 s12.2 says
            // never happens for this packet type - that configuration is left to the ordinary
            // long header parse below, which will reject it like any other malformed trailing
            // packet rather than being special-cased here.
            if (offset == 0
                && remaining.Length >= MinimumLongFormPrefixLength
                && BinaryPrimitives.ReadUInt32BigEndian(remaining.Span[1..]) == 0)
            {
                yield return new TlsQuicCoalescedPacket { Kind = TlsQuicCoalescedPacketKind.VersionNegotiation, Packet = remaining };
                yield break;
            }

            if (!TlsQuicPacketHeader.TryReadLongHeader(remaining, out _, out var consumed))
            {
                // RFC 9000 s12.2: "Every QUIC packet that is coalesced into a single UDP
                // datagram is separate and complete." A packet whose header cannot even be
                // parsed carries no declared Length this reader can trust, so there is no way to
                // know where a next packet would begin. That is different from the RFC's
                // decryption-failure case ("the receiver MAY either discard or buffer the packet
                // ... and MUST attempt to process the remaining packets") - decryption failure
                // still leaves the Length field, and therefore the next packet's boundary,
                // intact; a header parse failure does not. Stop here; every packet already
                // yielded above is still valid and still returned.
                yield break;
            }

            yield return new TlsQuicCoalescedPacket
            {
                Kind = TlsQuicCoalescedPacketKind.Long,
                Packet = remaining.Slice(0, consumed),
            };
            offset += consumed;
        }
    }
}
