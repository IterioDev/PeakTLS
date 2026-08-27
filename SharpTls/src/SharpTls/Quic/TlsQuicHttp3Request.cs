using System.Collections.Immutable;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER - TASK C9 (this file)
// ============================================================================
//
//   ROWS BELOW                   45  = numbered 1-45 with no gaps
//   KILLED WHEN FIRST RUN        41  = 45 rows, less 2 [WAS-SURVIVOR] and 2 [SURVIVED]
//   SURVIVED, THEN WITNESSED      2  = rows 26 and 36
//   SURVIVING STILL               2  = rows 2 and 33
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicHttp3Request.cs`                  must return 45
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicHttp3Request.cs` must return 2
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicHttp3Request.cs`     must return 2
//
// Every row was applied to a private `git worktree` of this branch, one edit at a time, each
// restored before the next, against `dotnet test --filter
// FullyQualifiedName~TlsQuicHttp3Request` - a 42-case suite, and no test outside it
// references this type. Counts are per xUnit CASE, so a Theory failing in three rows counts
// three. All 45 counts below come from ONE run against the FINAL suite; the sweep was re-run
// whole after rows 26 and 36 gained witnesses, rather than leaving forty counts measured
// against a suite that no longer exists.
//
// THE HARNESS WAS DISTRUSTED FIRST, because a prior task's reported "all 32 survived" turned
// out to be a bad failure-match pattern. Before any real row ran, a deliberate known-bad
// mutation - `":method"` spelled `":methodX"` - was applied and the harness reported KILLED
// with 5 failures. A harness that cannot fail is not a harness. The verdict is read from the
// run's own `Failed: <n>, Passed: <m>` summary line and nothing else.
//
// ROW 14 IS THE CS0162 SHAPE THIS BUILD FORCES. Deleting the `:path` clause outright left
// `if (a || b ))` and the sweep recorded BUILD-ERROR, which is a non-result, not a survivor.
// Rewritten as `|| (COND && false)` it kills. That is the handoff's rule applied: a sweep
// that records a build error as "no result" leaves the guard unmeasured.
//
//   1. ReservedRequestStreamFrameType: ReservedIdentifier(0) -> ReservedIdentifier(1).
//      Killed by 1, .TheReservedRequestStreamFrameTypeIsAReservedIdentifier - and NOT by
//      .TheReservedFrameIsPresentOnlyWhenTheSpecAsks, because 0x40 is still a reserved
//      identifier and IsReservedIdentifier still says so. That is exactly why the recompute
//      test exists next to the is-reserved one.
//   2. [SURVIVED] InitialFieldSectionLength 256 -> 2. VACUOUS, and no test is written.
//      The constant is only where the doubling loop STARTS; every value that admits the
//      two-octet field section prefix produces byte-identical output, because the buffer is
//      sliced to the written length. A test asserting the literal 256 would fail against the
//      mutant and would be a false witness - it would pin a performance number as though it
//      were wire format. That the loop grows at all is witnessed separately, by
//      .AFieldSectionLargerThanTheInitialBufferStillRoundTrips.
//   3. The HEADERS payload handed over as buffer.AsSpan() instead of buffer.AsSpan(0,
//      length), so the frame carries the unused tail. Killed by 12 - the trailing zero octets
//      decode as RFC 9204 s4.5.5's post-base form, which task C8's decoder rejects.
//   4. The pseudo-header loop walked in reverse. Killed by 6.
//   5. THE MOST IMPORTANT ROW HERE. `spec.PseudoHeaderOrder` replaced by
//      `TlsQuicHttp3Spec.CapturePseudoHeaderOrder` - the literal "fix" this file's header
//      warns about, which reproduces the capture perfectly and silently ignores the knob.
//      Killed by 9, .EveryPermutationOfTheFourPseudoHeadersIsEmittedAsGiven among them.
//      Note what does NOT kill it: .AGetForTheCaptureEndpointDecodesInTheCapturesPseudoHeader
//      Order passes against this mutant, because the mutant's hard-coded order IS the
//      capture's. A done-when checked only against the capture would have shipped it.
//   6. spec.QpackHuffmanStringLiterals -> literal true. Killed by 2.
//   7. spec.QpackHuffmanStringLiterals -> literal false. Killed by 2.
//   8. The QpackNameMatchPolicy comparison -> literal true. Killed by 1.
//   9. The QpackNameMatchPolicy comparison -> literal false. Killed by 1.
//  10. The SendReservedFramesOnRequestStreams gate never taken. Killed by 1.
//  11. The same gate always taken. Killed by 16 - every test that counts frames.
//  12. The mandatory-pseudo-header check drops :method. Killed by 1.
//  13. The same check drops :scheme. Killed by 1.
//  14. The same check drops :path, written `|| (COND && false)`. Killed by 1. See the note
//      above on why the plain deletion was a non-result.
//  15. The same check GAINS :authority - the over-strict misreading of s4.3.1, which lists
//      three names and not four. Killed by 4 including
//      .AnOrderMissingOnlyTheAuthorityIsAccepted.
//  16. The empty-value check drops the method half. Killed by 2.
//  17. The empty-value check drops the scheme half. Killed by 2.
//  18. The empty-:path rule applied to EVERY scheme rather than the http family. Killed by 1,
//      the `ftp` row of .AnEmptyPathIsRefusedForHttpSchemesOnly.
//  19. The empty-:path rule never applied. Killed by 5.
//  20. The scheme comparison OrdinalIgnoreCase -> Ordinal, so "HTTPS" escapes the http-family
//      rules. Killed by 1, the "HTTPS" row.
//  21. The scheme comparison drops its "http" arm. Killed by 1.
//  22. The authority-non-empty check drops its :authority half. Killed by 2.
//  23. The same check drops its host half. Killed by 1.
//  24. The AuthorityMissing check never taken. Killed by 1.
//  25. The AuthorityMissing check stops accepting a `host` field in :authority's place -
//      s4.3.1's requirement read as an AND where the RFC writes "either ... or". Killed by 2.
//  26. [WAS-SURVIVOR] The AuthorityMissing check ignores the scheme, demanding an authority
//      for every scheme. SURVIVED the first sweep: every existing non-http row carried
//      :authority in the default order, so the check was never reached with it absent.
//      Witnessed by .ASchemeOutsideTheHttpFamilyNeedsNeitherAuthorityNorHost, written for
//      this row and quoting s4.3.1's own converse sentence. Now killed by 1.
//  27. The leading-colon check compares against ';'. Killed by 1.
//  28. The leading-colon check never taken. Killed by 1.
//  29. The s4.2 uppercase scan never fires. Killed by 2.
//  30. The uppercase scan narrowed from A-Z to A-S, which still catches "User-Agent" on its
//      'A'. Killed by 1 - the "accepT" row, which exists for exactly this class of mutant.
//  31. string.IsNullOrEmpty(name) weakened to `name is null`, so an empty name reaches
//      name[0]. Killed by 1: .AnEmptyRegularFieldNameIsRefused, which fails on the throw
//      rather than on a wrong error code. The distinction matters - this file's contract is
//      that it does not throw.
//  32. HostFieldName "host" -> "x-host". Killed by 3.
//  33. [SURVIVED] The host lookup's StringComparison.Ordinal -> OrdinalIgnoreCase.
//      UNREACHABLE BY CONSTRUCTION, and no test is written. The s4.2 uppercase scan runs
//      EARLIER IN THE SAME LOOP ITERATION and refuses any name with an uppercase character,
//      so by the time this comparison runs `name` cannot differ from its own lowercase form
//      and the two comparers cannot disagree. A test would have to pass "Host", which is
//      refused before reaching this line - it would pass against the mutant too, which is the
//      definition of a false witness. The guard stays Ordinal because it is one reordering
//      away from being reachable.
//  34. The default-valued Fields array no longer read as empty. Killed by 1, on the
//      NullReferenceException that fact predicts.
//  35. `Method ?? string.Empty` -> `Method!`. Killed by 1.
//  36. [WAS-SURVIVOR] `Path ?? string.Empty` -> `Path!`. SURVIVED the first sweep: the
//      only null test nulled all four pseudo-headers at once, so the :method check returned
//      before anything dereferenced the path. That is the general defect in an all-at-once
//      totality test, and it was invisible until this row. The test was split into
//      .ANullPseudoHeaderValueIsRefusedRatherThanThrowing, one row per pseudo-header, which
//      also produced rows 44 and 45. Now killed by 1.
//  37. The regular field VALUE's `?? string.Empty` dropped. Killed by 1.
//  38. The HEADERS frame written with type DATA. Killed by 3.
//  39. The RFC 9204 s4.5.1 field section prefix not written. Killed by 13.
//  40. The field-line cursor `offset += count` -> `offset = count`. Killed by 14.
//  41. The regular fields emitted BEFORE the pseudo-headers - s4.3's one ordering MUST,
//      inverted. Killed by 5 including .EveryRegularFieldFollowsEveryPseudoHeader.
//  42. The reserved frame written AFTER the HEADERS frame instead of before. Killed by 1.
//      The position is a declared placeholder, so this row measures that the placeholder is
//      pinned rather than that it is right - see ReservedRequestStreamFrameType.
//  43. AuthorityEmpty and AuthorityMissing swapped, so the two halves of s4.3.1's authority
//      rule report each other's code. Killed by 2.
//  44. `Authority ?? string.Empty` -> `Authority!`. Killed by 1. Row 36's consequence.
//  45. `Scheme ?? string.Empty` -> `Scheme!`. Killed by 1. Row 36's consequence.
//
// ============================================================================

/// <summary>One HTTP field line - a name and a value - RFC 9114 s4.2.</summary>
/// <remarks>
/// <para>NAMED <c>TlsQuicHttp3RequestField</c> BY TASK C9 AND RENAMED BY C10 RATHER THAN
/// COPIED. A response's header and trailer sections are the same name/value pairs a request's
/// are - s4.2 defines fields once, for both directions - so a second identical record struct
/// called <c>...ResponseField</c> would have been two names for one thing. The only asymmetry
/// is which pseudo-headers are legal, and that is s4.3.1 against s4.3.2 rather than this
/// type. C9's <see cref="TlsQuicHttp3Request.Fields"/> still holds only ORDINARY fields, and
/// says so itself; <see cref="TlsQuicHttp3Response.HeaderFields"/> holds <c>:status</c> among
/// the rest, which is why the summary line above no longer says "non-pseudo".</para>
/// <para>A LIST OF PAIRS AND NOT A DICTIONARY, for the reason
/// <see cref="TlsQuicHttp3Setting"/> gives about SETTINGS: the order these go on the wire is
/// the sender's choice and is therefore fingerprint surface, and a dictionary would destroy
/// it. RFC 9114 s4.2.1 also makes a repeated name legal - "the Cookie header field ... MAY be
/// split into separate field lines" - which a name-keyed container cannot express at
/// all.</para></remarks>
/// <param name="Name">The field name. RFC 9114 s4.2: "Characters in field names MUST be
/// converted to lowercase prior to their encoding."</param>
/// <param name="Value">The field value.</param>
internal readonly record struct TlsQuicHttp3Field(string Name, string Value);

/// <summary>Why <see cref="TlsQuicHttp3Request.TryEncode"/> refused to build a request.</summary>
/// <remarks>
/// <para>EVERY MEMBER IS A "malformed" RULE FROM RFC 9114 s4.2 OR s4.3.1, checked BEFORE any
/// byte is written. The refusal is a return value and never an exception, which is the shape
/// <see cref="TlsQuicHttp3Frames.TryRead"/> and <see cref="TlsQuicQpackDecoder"/> already use;
/// see the remarks on <see cref="TlsQuicHttp3Request.TryEncode"/> for why this path holds to
/// that convention even though its input is ours rather than the peer's.</para>
/// <para>There is no member for "a pseudo-header appeared after a regular field", s4.3's other
/// malformed rule, because this encoder cannot produce one: it emits
/// <see cref="TlsQuicHttp3Spec.PseudoHeaderOrder"/> first and
/// <see cref="TlsQuicHttp3Request.Fields"/> second, always. The only way a caller could smuggle
/// a pseudo-header in among the regular fields is a name beginning with ':', which is
/// <see cref="PseudoHeaderAmongRegularFields"/>.</para>
/// </remarks>
internal enum TlsQuicHttp3RequestError
{
    /// <summary>No error.</summary>
    None = 0,

    /// <summary><see cref="TlsQuicHttp3Spec.PseudoHeaderOrder"/> omits <c>:method</c>,
    /// <c>:scheme</c> or <c>:path</c>.</summary>
    /// <remarks>RFC 9114 s4.3.1: "All HTTP/3 requests MUST include exactly one value for the
    /// :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT
    /// request; see Section 4.4."</remarks>
    MandatoryPseudoHeaderOmitted,

    /// <summary>A mandatory pseudo-header carries a value RFC 9114 s4.3.1 forbids.</summary>
    /// <remarks>s4.3.1: "An HTTP request that omits mandatory pseudo-header fields or contains
    /// invalid values for those pseudo-header fields is malformed." The specific invalid value
    /// s4.3.1 names for <c>:path</c> is the empty one: "This pseudo-header field MUST NOT be
    /// empty for \"http\" or \"https\" URIs".</remarks>
    MandatoryPseudoHeaderValueInvalid,

    /// <summary>The scheme has a mandatory authority component and neither <c>:authority</c>
    /// nor a <c>host</c> field supplies one.</summary>
    /// <remarks>RFC 9114 s4.3.1: "If the :scheme pseudo-header field identifies a scheme that
    /// has a mandatory authority component (including \"http\" and \"https\"), the request MUST
    /// contain either an :authority pseudo-header field or a Host header field."</remarks>
    AuthorityMissing,

    /// <summary>An <c>:authority</c> or <c>host</c> field is present but empty.</summary>
    /// <remarks>RFC 9114 s4.3.1, the sentence immediately after
    /// <see cref="AuthorityMissing"/>'s: "If these fields are present, they MUST NOT be
    /// empty."</remarks>
    AuthorityEmpty,

    /// <summary>A member of <see cref="TlsQuicHttp3Request.Fields"/> has a name beginning with
    /// ':'.</summary>
    /// <remarks>RFC 9114 s4.3: "All pseudo-header fields MUST appear in the header section
    /// before regular header fields. Any request or response that contains a pseudo-header
    /// field that appears in a header section after a regular header field MUST be treated as
    /// malformed."</remarks>
    PseudoHeaderAmongRegularFields,

    /// <summary>A member of <see cref="TlsQuicHttp3Request.Fields"/> has an uppercase character
    /// in its name.</summary>
    /// <remarks>RFC 9114 s4.2: "Characters in field names MUST be converted to lowercase prior
    /// to their encoding. A request or response containing uppercase characters in field names
    /// MUST be treated as malformed."</remarks>
    RegularFieldNameNotLowercase,

    /// <summary>A member of <see cref="TlsQuicHttp3Request.Fields"/> has an empty or
    /// <see langword="null"/> name.</summary>
    /// <remarks>Not a sentence of s4.2 - RFC 9110 s5.1's field-name grammar requires at least
    /// one token character, and RFC 9110 is not among this project's captures. So this member
    /// exists to keep the encoder TOTAL rather than to enforce a quoted MUST: a zero-length
    /// name would otherwise reach the QPACK literal writer and be emitted, and an empty name is
    /// not a field. Stated here rather than dressed up with a citation nobody can
    /// resolve.</remarks>
    RegularFieldNameEmpty,

    /// <summary>A member of <see cref="TlsQuicHttp3Request.Fields"/> is a connection-specific
    /// field, which RFC 9114 s4.2 forbids outright - or is a <c>te</c> carrying a value other
    /// than <c>"trailers"</c>, which is the one exception s4.2 grants and the bound it puts on
    /// it.</summary>
    /// <remarks>
    /// <para>s4.2: "An endpoint MUST NOT generate an HTTP/3 field section containing
    /// connection-specific fields; any message containing connection-specific fields MUST be
    /// treated as malformed." And immediately after: "The only exception to this is the TE
    /// header field, which MAY be present in an HTTP/3 request header; when it is, it MUST NOT
    /// contain any value other than \"trailers\"."</para>
    /// <para>ONE MEMBER FOR BOTH HALVES ON PURPOSE. A <c>te: gzip</c> is refused by the same
    /// sentence pair that refuses an <c>upgrade</c>, and splitting them would suggest the TE
    /// carve-out is a separate rule rather than the tail of this one. See
    /// <see cref="TlsQuicHttp3Request"/>'s CONNECTION-SPECIFIC FIELDS banner for why the set is
    /// six names and not RFC 9110 s7.6.1's dynamic one.</para>
    /// </remarks>
    ConnectionSpecificField,

    /// <summary>A <c>content-length</c> in <see cref="TlsQuicHttp3Request.Fields"/> does not
    /// truthfully describe <see cref="TlsQuicHttp3Request.Body"/>.</summary>
    /// <remarks>
    /// <para>RFC 9114 s4.1.2: "A request or response that is defined as having content when it
    /// contains a Content-Length header field (Section 8.6 of [HTTP]) is malformed if the value
    /// of the Content-Length header field does not equal the sum of the DATA frame lengths
    /// received." The sum of the DATA frame lengths this encoder writes is exactly
    /// <c>Body.Length</c> - see TryEncode's ONE DATA FRAME note - so the rule is decidable here,
    /// before a byte is sent, rather than only at the peer that would answer it with
    /// H3_MESSAGE_ERROR.</para>
    /// <para>NO REQUEST-SIDE ESCAPE, AND s4.1.2'S NEXT SENTENCE IS WHY IT IS NOT AN OVERSIGHT.
    /// The escape reads "A RESPONSE that is defined as never having content, even when a
    /// Content-Length is present, can have a non-zero Content-Length header field even though no
    /// content is included in DATA frames" - a response, in as many words, and
    /// TlsQuicHttp3Response.IsDefinedAsNeverHavingContent is where this repository implements it.
    /// A request has no counterpart, so equality is unconditional on this side.</para>
    /// <para>ONE MEMBER FOR TWO ARMS. A value that is not a non-negative decimal integer refuses
    /// through this member too, and not through a separate one: s4.1.2's own bullet list already
    /// makes "the inclusion of invalid characters in field names or values" malformed, so both
    /// arms are the same verdict, and both mean the same thing to the caller - the
    /// content-length we were asked to put on the wire does not describe the body we were asked
    /// to send. REFUSED RATHER THAN CORRECTED, for the reason the uppercase scan gives: silently
    /// rewriting the caller's field would make the bytes differ from what was asked for.</para>
    /// </remarks>
    ContentLengthDisagreesWithBody,

    /// <summary>A member of <see cref="TlsQuicHttp3Request.Trailers"/> has a name beginning with
    /// ':'.</summary>
    /// <remarks>A DIFFERENT SENTENCE FROM
    /// <see cref="PseudoHeaderAmongRegularFields"/>'s, which is why it is a different member.
    /// That one is s4.3's ordering rule, "a pseudo-header field that appears in a header section
    /// after a regular header field"; this one is s4.3's flat ban two sentences earlier,
    /// "Pseudo-header fields MUST NOT appear in trailer sections", which holds however the
    /// trailer section is ordered and would still hold if the trailer carried nothing
    /// else.</remarks>
    PseudoHeaderInTrailerSection,
}

// RFC 9114 s4's request, as the s7.2.2 HEADERS frame that carries it.
//
// ============================================================================
// THE PSEUDO-HEADER ORDER IS A FINGERPRINT, NOT A CONFORMANCE REQUIREMENT.
// ============================================================================
//
// This is the single most important sentence in this file, and it is here because the
// obvious "cleanup" - sorting the four names, or hard-coding some canonical sequence - would
// be invisible to every conformance test and would change `perk_hash`.
//
// rfc9114-section4-expressing-http-semantics.txt, s4.3, in full and verbatim:
//
//     "All pseudo-header fields MUST appear in the header section before regular header
//      fields.  Any request or response that contains a pseudo-header field that appears in
//      a header section after a regular header field MUST be treated as malformed."
//
// That is s4.3's ONLY ordering rule. It constrains the BOUNDARY between the pseudo-headers
// and the regular fields and says nothing whatever about the sequence WITHIN either group.
// s4.3.1 then defines the four request pseudo-headers in the order :method, :scheme,
// :authority, :path - a definition order, in prose, with no MUST attached to it - and the
// client capture observes :method, :authority, :scheme, :path, which is a DIFFERENT
// order. Both conform. The difference is exactly what is fingerprinted:
// the preset that measured it line 70 renders the capture's order `m,a,s,p`
// as the second segment of the `perk` string.
//
// So the order comes from TlsQuicHttp3Spec.PseudoHeaderOrder and from nowhere else. There is
// no sort here, no canonical list, and no fallback ordering. The test that would fail if one
// were added is TlsQuicHttp3RequestTests.ReorderingThePseudoHeadersChangesTheBytes.
//
// ============================================================================
// WHAT IS ENFORCED AND WHAT IS DELIBERATELY NOT
// ============================================================================
//
// Enforced, each quoted at its check below: s4.3.1's "exactly one value for the :method,
// :scheme, and :path pseudo-header fields"; s4.3.1's ":path ... MUST NOT be empty for
// \"http\" or \"https\" URIs"; s4.3.1's :authority-or-Host requirement and its non-empty
// half; s4.3's pseudo-before-regular boundary; s4.2's lowercase field names; and, added by
// C10b, s4.2's connection-specific field ban with its TE carve-out - see the banner below.
//
// NOT enforced, and each for a stated reason rather than by omission:
//
//   - CONNECT, AND THIS IS A DECISION RATHER THAN A GAP. See THE CONNECT LIMITATION below,
//     which is stated at length because the validator's shape actively excludes it.
//   - The scheme-has-no-mandatory-authority arm. s4.3.1 continues: "If the scheme does not
//     have a mandatory authority component and none is provided in the request target, the
//     request MUST NOT contain the :authority pseudo-header or Host header fields." Deciding
//     which schemes those are needs a registry no capture here carries, so only the half
//     s4.3.1 names outright - "including \"http\" and \"https\"" - is checked.
//   - s4.2.2's SETTINGS_MAX_FIELD_SECTION_SIZE. "An implementation that has received this
//     parameter SHOULD NOT send an HTTP message header that exceeds the indicated size". The
//     peer's value arrives on the control stream and is held by
//     TlsQuicHttp3Streams.PeerSettings, which this type has no reference to. It belongs where
//     the request meets the connection - task C11.
//
// ============================================================================
// THE CONNECT LIMITATION. THIS VALIDATOR REJECTS EVERY LEGAL CONNECT REQUEST.
// ============================================================================
//
// Not implemented, deliberately: nothing on the path this subsystem exists to serve sends
// CONNECT, and speculative support was declined. What follows is the named gap, so that the
// next reader finds a decision rather than an omission.
//
// The validator above is written from s4.3.1, and a CONNECT request is s4.3.1's exact
// INVERSE. rfc9114-section4.4-connect.txt, s4.4, verbatim:
//
//     "A CONNECT request MUST be constructed as follows:
//      *  The :method pseudo-header field is set to "CONNECT"
//      *  The :scheme and :path pseudo-header fields are omitted
//      *  The :authority pseudo-header field contains the host and port to connect to"
//
// OMITTED, not empty and not "/". So the mandatory-pseudo-header check - which demands that
// PseudoHeaderOrder contain :method, :scheme AND :path - refuses a conforming CONNECT with
// MandatoryPseudoHeaderOmitted, and a caller who "fixes" that by putting :scheme and :path
// back emits a request s4.4's last sentence calls malformed: "A CONNECT request that does not
// conform to these restrictions is malformed." There is no way to spell a legal CONNECT
// through this type, and there is not meant to be.
//
// TWO FACTS THE IMPLEMENTOR WILL NEED, BOTH ALREADY MISREAD ONCE ELSEWHERE, because they sit
// one line apart in s4.4 and are of DIFFERENT SEVERITIES:
//
//   - H3_CONNECT_ERROR is a STREAM error. s4.4: "A proxy treats any error in the TCP
//     connection, which includes receiving a TCP segment with the RST bit set, as a stream
//     error of type H3_CONNECT_ERROR." One stream is reset; the connection lives.
//   - A non-DATA known frame after CONNECT has completed is a CONNECTION error. s4.4: "Once
//     the CONNECT method has completed, only DATA frames are permitted to be sent on the
//     stream. Extension frames MAY be used if specifically permitted by the definition of the
//     extension. Receipt of any other known frame type MUST be treated as a connection error
//     of type H3_FRAME_UNEXPECTED." The whole connection goes.
//
// Neither code is a member of TlsQuicHttp3ErrorCode, because nothing raises them. s4.4 also
// obliges no client to implement CONNECT at all - every remaining paragraph binds the proxy -
// so this is unimplemented functionality and not a spec violation.
//
// ============================================================================
// CONNECTION-SPECIFIC FIELDS: WHY SIX NAMES, AND WHY TE IS NOT ONE OF THEM.
// ============================================================================
//
// s4.2, verbatim: "HTTP/3 does not use the Connection header field to indicate
// connection-specific fields; in this protocol, connection-specific metadata is conveyed by
// other means. An endpoint MUST NOT generate an HTTP/3 field section containing
// connection-specific fields; any message containing connection-specific fields MUST be
// treated as malformed." Its only pointer to a list is the next paragraph but one, aimed at
// intermediaries: "MUST remove connection-specific header fields as discussed in Section 7.6.1
// of [HTTP]".
//
// THREE THINGS RFC 9110 s7.6.1 SAYS THAT A FROM-MEMORY LIST GETS WRONG. Read
// rfc9110-section7.6.1-connection-specific-fields.txt, not this summary of it:
//
//   (a) s7.6.1 DEFINES NO CLOSED LIST. Its five names are a bullet list introduced by
//       "Furthermore, intermediaries SHOULD remove or replace fields that are known to require
//       removal before forwarding ... This includes but is not limited to:" - a SHOULD, aimed
//       at intermediaries, and explicitly open-ended. The set s7.6.1 actually defines is
//       DYNAMIC: "for each connection-option in this field, remove any header or trailer
//       field(s) from the message with the same name as the connection-option".
//   (b) "Connection" IS NOT ONE OF THE FIVE BULLETS. It is removed by the separate MUST
//       paragraph above them, which ends "and then remove the Connection header field itself".
//       A list built by copying the bullets alone lets `connection` through.
//   (c) TE IS IN THE BULLET LIST AND s4.2 CARVES IT BACK OUT. A flat ban on the five names
//       refuses a legal request. s4.2's own words are quoted at the check.
//
// SO THE CHECK IS SIX NAMES: the five bullets - proxy-connection, keep-alive, te,
// transfer-encoding, upgrade - plus `connection` from fact (b), with `te` conditional per fact
// (c). Transfer-Encoding is doubly cited: s4.1 says outright "Transfer codings ... are not
// defined for HTTP/3; the Transfer-Encoding header field MUST NOT be used."
//
// AND s7.6.1's DYNAMIC HALF IS UNREACHABLE HERE RATHER THAN UNIMPLEMENTED, which is a
// conclusion and not an excuse. The only mechanism that can widen the set is a Connection
// field's connection-options; `connection` is itself refused by fact (b), so a caller cannot get
// a name into the dynamic set without the request being refused on the Connection field first.
// Walking the options would be code no input can reach. The dynamic half matters on the
// RECEIVE side, where the peer's Connection field is not ours to refuse before reading - and
// that is a message this client, which never sends Connection, will never be sent in reply to
// one. C11 owns it if a receive-side field-validity pass ever exists.
//
// NOT DERIVED FROM THE LIST, and named so nobody thinks it was forgotten: s7.6.1's closing
// paragraphs about a connection option WITHOUT a corresponding field ("A sender MUST NOT send a
// connection option corresponding to a field that is intended for all recipients of the
// content") describe the Connection field's own value, which this encoder never emits.
//
// ============================================================================
// NOTHING HERE THROWS ON A MALFORMED REQUEST.
// ============================================================================
//
// Every rule above is a `false` plus a TlsQuicHttp3RequestError, the shape
// TlsQuicHttp3Frames.TryRead and TlsQuicQpackDecoder.TryDecodeFieldSection already use. The
// reason is not that the input is hostile - it is ours - but that subsystem B populates the
// spec and a caller populates the request from a URI, and a fingerprint library whose request
// builder throws forces every caller into a try/catch to find out that a path was empty. Null
// strings are treated as empty rather than dereferenced, so even a default-constructed
// TlsQuicHttp3Field is answered rather than fatal.
//
// The two ArgumentNullException guards on TryEncode's reference PARAMETERS are the exception,
// and they match TlsQuicHttp3Settings.Encode exactly: a null destination or spec is a caller
// bug with no meaningful error code, not a malformed request.
internal sealed class TlsQuicHttp3Request
{
    // The reserved (GREASE) frame this client puts on a request stream when
    // TlsQuicHttp3Spec.SendReservedFramesOnRequestStreams asks for one.
    //
    // DECLARED PLACEHOLDER, all three of it: the N, the payload, and the position.
    // rfc9114-section7-framing-layer.txt s7.2.8: "Frame types of the format 0x1f * N + 0x21
    // for non-negative integer values of N are reserved ... These frames have no semantics,
    // and they MAY be sent on any stream where frames are allowed to be sent. This enables
    // their use for application-layer padding" and "The payload and length of the frames are
    // selected in any manner the implementation chooses." So every one of the three is free,
    // the capture's `perk` string records the SETTINGS list and the pseudo-header order and
    // nothing about a request stream's frames, and no observation in this repository bounds
    // any of them. N = 0, an empty payload and a position before the HEADERS frame are this
    // project's placeholder; task C12 carries all three in the not-yet-known column, and a
    // packet capture of the browser's first request would settle them.
    //
    // Computed through TlsQuicHttp3Frames.ReservedIdentifier rather than written as 0x21, so
    // that the arithmetic is the codec's answer and not a second transcription of s7.2.8's
    // formula. TlsQuicHttp3RequestTests.TheReservedRequestStreamFrameTypeIsAReservedIdentifier
    // recomputes it rather than asserting the number.
    internal static readonly ulong ReservedRequestStreamFrameType =
        TlsQuicHttp3Frames.ReservedIdentifier(0);

    // The QPACK field section is built into a plain array that DOUBLES until it fits, rather
    // than into a buffer sized by an up-front bound. A bound would have to reason about
    // TlsQuicQpackPrimitives' integer widths and about Huffman EXPANSION - RFC 7541's longest
    // code is 30 bits, so a coded string can be nearly four times its input - and a bound got
    // subtly wrong is a silent truncation. TlsQuicQpackEncoder.TryEncodeFieldLine already
    // answers false without writing when the destination is short, so retrying on a bigger
    // array is total, needs no arithmetic, and has exactly one failure mode left: none.
    private const int InitialFieldSectionLength = 256;

    // The four s4.3.1 names, spelled once. Byte arrays because every QPACK entry point takes
    // ReadOnlySpan<byte>, and UTF-8 because s4.2 says only that field names are "strings
    // containing a subset of ASCII characters" - a subset of ASCII is its own UTF-8.
    private static readonly byte[] MethodName = Encoding.UTF8.GetBytes(":method");
    private static readonly byte[] AuthorityName = Encoding.UTF8.GetBytes(":authority");
    private static readonly byte[] SchemeName = Encoding.UTF8.GetBytes(":scheme");
    private static readonly byte[] PathName = Encoding.UTF8.GetBytes(":path");

    // s4.3.1: "An intermediary that converts an HTTP/3 request to HTTP/1.1 MUST create a Host
    // field if one is not present in a request by copying the value of the :authority
    // pseudo-header field." The reverse direction is why a Host field can stand in for
    // :authority, which is the alternative the authority check honours.
    private const string HostFieldName = "host";

    // RFC 9110 s7.6.1's five bullets - "Proxy-Connection ... Keep-Alive ... TE ...
    // Transfer-Encoding ... Upgrade" - plus `connection` itself, which is NOT one of those
    // bullets and is caught by the separate MUST paragraph above them. Six names, spelled
    // lowercase because the s4.2 uppercase scan runs earlier in the same loop iteration and has
    // already refused anything else. See the CONNECTION-SPECIFIC FIELDS banner above for why
    // s7.6.1's dynamic set collapses to these six on a send path.
    private static readonly string[] ConnectionSpecificFieldNames =
    [
        "connection",
        "proxy-connection",
        "keep-alive",
        TeFieldName,
        "transfer-encoding",
        "upgrade",
    ];

    // s4.2's one exception and the whole of the value it permits.
    private const string TeFieldName = "te";
    private const string TrailersValue = "trailers";

    // s4.1.2's field, spelled lowercase because the s4.2 uppercase scan has already refused
    // every other spelling by the time TryValidateContentLength compares against it.
    private const string ContentLengthFieldName = "content-length";

    /// <summary>Gets the <c>:method</c> value.</summary>
    internal required string Method { get; init; }

    /// <summary>Gets the <c>:authority</c> value.</summary>
    /// <remarks>Emitted only when <see cref="TlsQuicHttp3Spec.PseudoHeaderOrder"/> lists
    /// <see cref="TlsQuicHttp3PseudoHeader.Authority"/>, which is what makes s4.3.1's
    /// "either an :authority pseudo-header field or a Host header field" expressible.</remarks>
    internal required string Authority { get; init; }

    /// <summary>Gets the <c>:scheme</c> value.</summary>
    internal required string Scheme { get; init; }

    /// <summary>Gets the <c>:path</c> value.</summary>
    internal required string Path { get; init; }

    /// <summary>Gets the ordinary field lines, in the order they are emitted - after every
    /// pseudo-header, per RFC 9114 s4.3.</summary>
    internal ImmutableArray<TlsQuicHttp3Field> Fields { get; init; } = [];

    /// <summary>Gets the request content, RFC 9114 s4.1's item 2 - "optionally, the content, if
    /// present, sent as a series of DATA frames".</summary>
    /// <remarks>
    /// <para>EMPTY IS NOT THE SAME AS AN EMPTY DATA FRAME, and the difference is the whole
    /// reason this is checked for length rather than for null. s4.1 makes the content OPTIONAL;
    /// a zero-length body is a message with no content and emits NO DATA frame at all, which is
    /// what keeps a GET's bytes identical to what this encoder produced before bodies existed.
    /// An empty DATA frame would be two extra bytes on the wire that no observation in this
    /// repository puts there, and h3's fingerprint is the thing this library exists to control.
    /// TlsQuicHttp3RequestTests.ARequestWithNoBodyEmitsNoDataFrameAtAll pins it.</para>
    /// <para>A default-valued <see cref="ImmutableArray{T}"/> reads as empty here for the reason
    /// TryValidateFieldSection's own comment gives about <see cref="Fields"/>: this type answers
    /// rather than throws.</para>
    /// </remarks>
    internal ImmutableArray<byte> Body { get; init; } = [];

    /// <summary>Gets the trailer section, RFC 9114 s4.1's item 3 - "optionally, the trailer
    /// section, if present, sent as a single HEADERS frame".</summary>
    /// <remarks>
    /// <para>SUPPORTED RATHER THAN REFUSED, and the reason is that supporting it costs less than
    /// refusing it would. s4.1's item 3 is "a single HEADERS frame", which is the frame this
    /// class already writes; s4.2's rules on the fields inside it are the rules
    /// TryValidateFieldSection already applies to <see cref="Fields"/> - s4.2 governs "an HTTP/3
    /// field section", and a trailer section is one. So the whole feature is one more call to
    /// two methods that exist. A refusal would have needed its own enum member, its own check
    /// and its own test and would still leave a caller with no way to send one.</para>
    /// <para>THE ONE RULE THAT IS NOT SHARED is s4.3's "Pseudo-header fields MUST NOT appear in
    /// trailer sections", which is a different sentence from the ordering rule that governs
    /// <see cref="Fields"/> and gets its own
    /// <see cref="TlsQuicHttp3RequestError.PseudoHeaderInTrailerSection"/>.</para>
    /// <para>EMPTY EMITS NOTHING, for the same reason <see cref="Body"/> empty does.</para>
    /// </remarks>
    internal ImmutableArray<TlsQuicHttp3Field> Trailers { get; init; } = [];

    /// <summary>Appends this request to <paramref name="destination"/> as the frames a request
    /// stream carries: optionally an RFC 9114 s7.2.8 reserved frame, then the s7.2.2 HEADERS
    /// frame whose payload is the QPACK-encoded field section, then s4.1's optional content and
    /// trailer section.</summary>
    /// <remarks>
    /// <para>ALL FOUR SPEC KNOBS ARE READ HERE, and this method is the only reader of any of
    /// them: <see cref="TlsQuicHttp3Spec.PseudoHeaderOrder"/> chooses the sequence,
    /// <see cref="TlsQuicHttp3Spec.QpackHuffmanStringLiterals"/> and
    /// <see cref="TlsQuicHttp3Spec.QpackNameMatchPolicy"/> are handed to
    /// <see cref="TlsQuicQpackEncoder.TryEncodeFieldLine"/>, and
    /// <see cref="TlsQuicHttp3Spec.SendReservedFramesOnRequestStreams"/> decides the reserved
    /// frame. Each has a test that flips it and reads the bytes change.</para>
    /// <para>NOTHING IS APPENDED WHEN THIS RETURNS <see langword="false"/>. Validation runs to
    /// completion before the first byte, so a caller need not undo a partial write.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> or
    /// <paramref name="spec"/> is <see langword="null"/>.</exception>
    internal bool TryEncode(
        List<byte> destination, TlsQuicHttp3Spec spec, out TlsQuicHttp3RequestError error)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(spec);

        if (!TryBuildFieldLines(spec, out var lines, out error))
        {
            return false;
        }

        // BEFORE THE TRAILER SECTION AND BEFORE ANY ENCODING, so the cheapest refusal runs
        // first and so a request that is malformed in two ways reports the header section's
        // fault rather than whichever the writer reached.
        if (!TryValidateContentLength(out error))
        {
            return false;
        }

        // s4.3's "Pseudo-header fields MUST NOT appear in trailer sections" is the one rule
        // that differs between the two sections; everything else s4.2 says about a field
        // section applies to both, which is why this is the same validator.
        List<(byte[] Name, byte[] Value)>? trailerLines = null;
        var trailers = Trailers.IsDefault ? [] : Trailers;
        if (trailers.Length != 0)
        {
            if (!TryValidateFieldSection(
                    trailers, trailerSection: true, out var trailerFields, out _, out error))
            {
                return false;
            }

            trailerLines = [];
            foreach (var field in trailerFields)
            {
                trailerLines.Add((
                    Encoding.UTF8.GetBytes(field.Name),
                    Encoding.UTF8.GetBytes(field.Value ?? string.Empty)));
            }
        }

        var (buffer, length) = EncodeFieldSection(spec, lines);

        // s7.2.8's reserved frame goes FIRST - the placeholder position, see
        // ReservedRequestStreamFrameType. Written through the ordinary frame writer, so it is
        // a well-formed Type/Length/Payload frame that a peer skips by s9's unknown-type rule.
        if (spec.SendReservedFramesOnRequestStreams)
        {
            TlsQuicHttp3Frames.Write(
                destination, ReservedRequestStreamFrameType, ReadOnlySpan<byte>.Empty);
        }

        // rfc9114-section7-framing-layer.txt s7.2.2: "The HEADERS frame (type=0x01) is used to
        // carry an HTTP field section that is encoded using QPACK." Its one payload field is
        // "Encoded Field Section (..)", which is exactly what `buffer` holds.
        TlsQuicHttp3Frames.Write(
            destination, (ulong)TlsQuicHttp3FrameType.Headers, buffer.AsSpan(0, length));

        // s4.1 item 2: "optionally, the content, if present, sent as a series of DATA frames".
        // s7.2.1: "DATA frames (type=0x00) convey arbitrary, variable-length sequences of bytes
        // associated with HTTP request or response content", with the layout "Type (i) = 0x00,
        // Length (i), Data (..)" - which is the ordinary s7.1 frame the writer already writes.
        //
        // ONE DATA FRAME, NOT A SERIES OF SEVERAL, AND THAT IS A CHOICE RATHER THAN A READING.
        // s7.2.1 puts no bound on Length beyond the varint's own, and s4.1's "a series of DATA
        // frames" permits a series of one; nothing in this repository's captures records how
        // many DATA frames the browser splits a body into, so a split point here would be an
        // invented number wearing a citation. A caller that needs a particular split is the
        // thing that knows it, and the knob belongs beside the other s7 fingerprint knobs on
        // TlsQuicHttp3Spec when an observation arrives to set it. What this choice must NOT do
        // is disagree with the Content-Length, and it cannot: one frame's Length is Body.Length,
        // which is the sum TryValidateContentLength compared against.
        //
        // AND IT IS SKIPPED ENTIRELY WHEN THE BODY IS EMPTY. See Body's remarks - an empty DATA
        // frame is two bytes h3's fingerprint has never been observed to carry.
        var body = Body.IsDefault ? [] : Body;
        if (body.Length != 0)
        {
            TlsQuicHttp3Frames.Write(
                destination,
                (ulong)TlsQuicHttp3FrameType.Data,
                body.AsSpan());
        }

        // s4.1 item 3: "optionally, the trailer section, if present, sent as a single HEADERS
        // frame". A SECOND HEADERS FRAME AND NOT A SECOND KIND OF FRAME - the type is the same
        // 0x01, and what makes it a trailer section is that it follows the content. s4.1 also
        // fixes this as the LAST frame of the message: "a HEADERS or DATA frame after the
        // trailing HEADERS frame[] is considered invalid", so nothing may be appended below it.
        //
        // ITS OWN BUFFER AND ITS OWN PREFIX. TryEncodeFieldSection writes RFC 9204 s4.5.1's
        // field section prefix at offset 0 of whatever it is given, and a field section without
        // one is not decodable - so the two sections cannot share a buffer, and this encoder's
        // static-only representations make them otherwise independent.
        if (trailerLines is not null)
        {
            var (trailerBuffer, trailerLength) = EncodeFieldSection(spec, trailerLines);
            TlsQuicHttp3Frames.Write(
                destination,
                (ulong)TlsQuicHttp3FrameType.Headers,
                trailerBuffer.AsSpan(0, trailerLength));
        }

        return true;
    }

    // The doubling loop, spelled once because two field sections now need it. See
    // InitialFieldSectionLength for why the size is retried rather than computed.
    private static (byte[] Buffer, int Length) EncodeFieldSection(
        TlsQuicHttp3Spec spec, List<(byte[] Name, byte[] Value)> lines)
    {
        var buffer = new byte[InitialFieldSectionLength];
        int length;
        while (!TryEncodeFieldSection(spec, lines, buffer, out length))
        {
            buffer = new byte[buffer.Length * 2];
        }

        return (buffer, length);
    }

    // s4.1.2's Content-Length rule, on the side that CHOOSES the number rather than the side
    // that checks one. See TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody for the
    // quotation and for why the response-side escape has no request-side counterpart.
    //
    // EVERY content-length IS CHECKED, not the first. s4.1.2 speaks of "the Content-Length
    // header field" in the singular, but Fields is a list and nothing upstream forbids two of
    // them; checking only the first would let `content-length: 5, content-length: 9` past on the
    // strength of the half that happened to agree.
    //
    // NumberStyles.None FOR THE REASON ReadStatus GIVES: a Content-Length is a count of octets,
    // and long.Parse's default leniency about a leading '+', a leading '-' and surrounding
    // whitespace is not that. A value this rejects refuses the request rather than being
    // ignored, which is the opposite of what TlsQuicHttp3Response.ContentLengthAgreesWithTheBody
    // does with an unparseable one - and the asymmetry is deliberate: there the field is the
    // PEER's and s4.1.2's verdict is about the sum, here the field is OURS and an unparseable
    // one is a byte sequence we cannot defend having sent.
    private bool TryValidateContentLength(out TlsQuicHttp3RequestError error)
    {
        error = TlsQuicHttp3RequestError.None;
        var declared = Fields.IsDefault ? [] : Fields;
        var bodyLength = Body.IsDefault ? 0 : Body.Length;

        for (var i = 0; i < declared.Length; i++)
        {
            if (!string.Equals(declared[i].Name, ContentLengthFieldName, StringComparison.Ordinal))
            {
                continue;
            }

            if (!long.TryParse(
                    declared[i].Value,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var length)
                || length != bodyLength)
            {
                error = TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody;
                return false;
            }
        }

        return true;
    }

    // Validates, then materialises the field lines in wire order. Both halves in one pass so
    // that "validated" and "emitted" cannot be two different lists - the defect where a check
    // reads one collection and the writer walks another.
    private bool TryBuildFieldLines(
        TlsQuicHttp3Spec spec,
        out List<(byte[] Name, byte[] Value)> lines,
        out TlsQuicHttp3RequestError error)
    {
        lines = [];

        var order = spec.PseudoHeaderOrder;
        var method = Method ?? string.Empty;
        var authority = Authority ?? string.Empty;
        var scheme = Scheme ?? string.Empty;
        var path = Path ?? string.Empty;

        // s4.3.1: "All HTTP/3 requests MUST include exactly one value for the :method,
        // :scheme, and :path pseudo-header fields, unless the request is a CONNECT request".
        //
        // "EXACTLY ONE" IS TWO CLAIMS AND BOTH ARE ANSWERED, one here and one by construction.
        // At most one: TlsQuicHttp3Spec.PseudoHeaderOrder's own init accessor rejects a
        // repeated member, this type holds a single string per pseudo-header, and a second
        // :method smuggled in through Fields is PseudoHeaderAmongRegularFields below. At least
        // one: this check. Neither half is where a reader would look for the other, so both
        // are named.
        if (!order.Contains(TlsQuicHttp3PseudoHeader.Method)
            || !order.Contains(TlsQuicHttp3PseudoHeader.Scheme)
            || !order.Contains(TlsQuicHttp3PseudoHeader.Path))
        {
            error = TlsQuicHttp3RequestError.MandatoryPseudoHeaderOmitted;
            return false;
        }

        // s4.3.1 closes with: "An HTTP request that omits mandatory pseudo-header fields or
        // contains invalid values for those pseudo-header fields is malformed." An empty
        // method or scheme is such an invalid value in any scheme.
        if (method.Length == 0 || scheme.Length == 0)
        {
            error = TlsQuicHttp3RequestError.MandatoryPseudoHeaderValueInvalid;
            return false;
        }

        // CASE-INSENSITIVE ON PURPOSE, and the choice is a strictness one rather than a quoted
        // rule. s4.3.1 spells the schemes lowercase - "MUST NOT be empty for \"http\" or
        // \"https\" URIs" - and an ordinal comparison would let a caller who writes "HTTPS"
        // slip past the :path and :authority rules below and emit a malformed request. The
        // failure direction of OrdinalIgnoreCase is to apply a rule where it might not belong;
        // the failure direction of Ordinal is to emit a request the server rejects.
        var mandatoryAuthorityScheme =
            scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
            || scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

        // s4.3.1 on :path: "This pseudo-header field MUST NOT be empty for \"http\" or
        // \"https\" URIs; \"http\" or \"https\" URIs that do not contain a path component MUST
        // include a value of / (ASCII 0x2f)." The condition is the RFC's own - an empty :path
        // under some other scheme is not something s4.3.1 forbids, and inventing a stricter
        // rule than the text would be this file asserting something it cannot cite.
        if (mandatoryAuthorityScheme && path.Length == 0)
        {
            error = TlsQuicHttp3RequestError.MandatoryPseudoHeaderValueInvalid;
            return false;
        }

        if (!TryValidateRegularFields(out var fields, out var hostValue, out error))
        {
            return false;
        }

        if (!TryValidateAuthority(order, authority, hostValue, mandatoryAuthorityScheme, out error))
        {
            return false;
        }

        // s4.3: "All pseudo-header fields MUST appear in the header section before regular
        // header fields." THIS LOOP AND THE ONE AFTER IT ARE THAT SENTENCE - the boundary is
        // structural, which is why no check enforces it and why the two loops must not be
        // merged or reordered.
        for (var i = 0; i < order.Length; i++)
        {
            lines.Add(order[i] switch
            {
                TlsQuicHttp3PseudoHeader.Method => (MethodName, Encoding.UTF8.GetBytes(method)),
                TlsQuicHttp3PseudoHeader.Authority =>
                    (AuthorityName, Encoding.UTF8.GetBytes(authority)),
                TlsQuicHttp3PseudoHeader.Scheme => (SchemeName, Encoding.UTF8.GetBytes(scheme)),

                // The discard arm is Path rather than a throw:
                // TlsQuicHttp3Spec.PseudoHeaderOrder's init accessor runs Enum.IsDefined over
                // every element, so no fifth value can reach here, and a `_ => throw` would be
                // both unreachable and a throw on this deliberately non-throwing path.
                _ => (PathName, Encoding.UTF8.GetBytes(path)),
            });
        }

        for (var i = 0; i < fields.Count; i++)
        {
            lines.Add((
                Encoding.UTF8.GetBytes(fields[i].Name),
                Encoding.UTF8.GetBytes(fields[i].Value ?? string.Empty)));
        }

        error = TlsQuicHttp3RequestError.None;
        return true;
    }

    // s4.2 and s4.3's rules on the ordinary fields, plus the one lookup s4.3.1's authority
    // rule needs. One pass, because a second walk to find `host` would be a second chance to
    // disagree about which fields exist.
    private bool TryValidateRegularFields(
        out List<TlsQuicHttp3Field> fields,
        out string? hostValue,
        out TlsQuicHttp3RequestError error) =>
        // A default-valued ImmutableArray is a null reference wearing a struct - see
        // TlsQuicHttp3Spec.ThrowIfDefault. That type THROWS on one because it is a
        // configuration surface; here it is read as "no fields", because this method's whole
        // contract is that it answers rather than throws.
        TryValidateFieldSection(
            Fields.IsDefault ? ImmutableArray<TlsQuicHttp3Field>.Empty : Fields,
            trailerSection: false,
            out fields,
            out hostValue,
            out error);

    // The same walk for a header section and for a trailer section, because s4.2 governs "an
    // HTTP/3 field section" and a trailer section is one - the empty name, the uppercase scan
    // and the connection-specific ban are word-for-word the same rule in both places. ONE
    // BRANCH SEPARATES THEM, s4.3's pseudo-header sentence, which differs in WHICH sentence
    // applies and therefore in which error is named; see PseudoHeaderInTrailerSection.
    //
    // hostValue IS STILL PRODUCED ON THE TRAILER ARM AND IS DISCARDED BY THE CALLER. s4.3.1's
    // authority rule is about the request's control data, which a trailer section cannot carry
    // - a `host` trailer is an ordinary field with an unhelpful name and must not stand in for
    // :authority. TryEncode passes `out _` for exactly that reason, and this method does not
    // suppress it here, because a validator that behaved differently depending on which caller
    // asked would be two validators wearing one name.
    private static bool TryValidateFieldSection(
        ImmutableArray<TlsQuicHttp3Field> declared,
        bool trailerSection,
        out List<TlsQuicHttp3Field> fields,
        out string? hostValue,
        out TlsQuicHttp3RequestError error)
    {
        fields = new List<TlsQuicHttp3Field>(declared.Length);
        hostValue = null;

        for (var i = 0; i < declared.Length; i++)
        {
            var name = declared[i].Name;
            if (string.IsNullOrEmpty(name))
            {
                error = TlsQuicHttp3RequestError.RegularFieldNameEmpty;
                return false;
            }

            // s4.3: "Any request or response that contains a pseudo-header field that appears
            // in a header section after a regular header field MUST be treated as malformed."
            // Every member of Fields is emitted after the pseudo-headers, so a ':' name here
            // IS that malformed message. s4.3 also bans inventing one: "Endpoints MUST NOT
            // generate pseudo-header fields other than those defined in this document."
            //
            // AND s4.3 TWO SENTENCES EARLIER FOR THE TRAILER ARM: "Pseudo-header fields MUST
            // NOT appear in trailer sections." A flat ban rather than an ordering rule, which
            // is why the two arms name different errors rather than sharing one.
            if (name[0] == ':')
            {
                error = trailerSection
                    ? TlsQuicHttp3RequestError.PseudoHeaderInTrailerSection
                    : TlsQuicHttp3RequestError.PseudoHeaderAmongRegularFields;
                return false;
            }

            // s4.2: "Characters in field names MUST be converted to lowercase prior to their
            // encoding. A request or response containing uppercase characters in field names
            // MUST be treated as malformed." REFUSED RATHER THAN CONVERTED, deliberately.
            // Lowercasing silently would make the bytes on the wire differ from what the
            // caller asked for, and in a library whose entire purpose is byte-exact control
            // over what an observer sees, a silent rewrite is the worse of the two answers.
            for (var c = 0; c < name.Length; c++)
            {
                if (name[c] is >= 'A' and <= 'Z')
                {
                    error = TlsQuicHttp3RequestError.RegularFieldNameNotLowercase;
                    return false;
                }
            }

            // s4.2: "An endpoint MUST NOT generate an HTTP/3 field section containing
            // connection-specific fields; any message containing connection-specific fields
            // MUST be treated as malformed."
            //
            // BELOW THE UPPERCASE SCAN ON PURPOSE, and the placement is load-bearing rather
            // than tidy: that scan has already refused every name carrying an uppercase
            // character, so an Ordinal comparison against six lowercase names cannot be evaded
            // by spelling one "TE" or "Upgrade". It is the same argument C9's row 33 records
            // about the `host` lookup below - and unlike that one, this comparison is WITNESSED
            // rather than unreachable, because the uppercase scan refusing "TE" is itself the
            // observable that would change if the two were ever reordered.
            if (Array.IndexOf(ConnectionSpecificFieldNames, name) >= 0
                && !IsPermittedTe(name, declared[i].Value))
            {
                error = TlsQuicHttp3RequestError.ConnectionSpecificField;
                return false;
            }

            if (string.Equals(name, HostFieldName, StringComparison.Ordinal))
            {
                hostValue = declared[i].Value ?? string.Empty;
            }

            fields.Add(declared[i]);
        }

        error = TlsQuicHttp3RequestError.None;
        return true;
    }

    // s4.2's TE carve-out, in s4.2's own words: "The only exception to this is the TE header
    // field, which MAY be present in an HTTP/3 request header; when it is, it MUST NOT contain
    // any value other than \"trailers\"."
    //
    // BOTH HALVES OF THAT SENTENCE ARE HERE, and reading only the first is how a flat ban on
    // RFC 9110 s7.6.1's five names ends up refusing a legal request: TE MAY be present, and
    // then its value is bounded. So `te: trailers` encodes and `te: gzip`, `te: trailers,
    // deflate` and a bare `te:` do not.
    //
    // ORDINAL, AND THE COMPARER IS A CHOICE. s4.2 writes the permitted value as the literal
    // lowercase "trailers", and nothing in this repository's captures says a TE value is
    // case-insensitive - RFC 9110 s10.1.4, which defines the field, is not among them. The two
    // failure directions are not symmetric: OrdinalIgnoreCase would EMIT `te: TRAILERS` on the
    // strength of a rule this file cannot cite, while Ordinal REFUSES it and the caller lowers
    // the case. Refusing is the direction that cannot put a byte on the wire we cannot defend,
    // which is the same test C9's scheme comparison applied - there the safe arm happened to be
    // the case-insensitive one, here it is the case-sensitive one, and it is the failure
    // direction rather than the comparer that both choices have in common.
    private static bool IsPermittedTe(string name, string? value) =>
        string.Equals(name, TeFieldName, StringComparison.Ordinal)
        && string.Equals(value ?? string.Empty, TrailersValue, StringComparison.Ordinal);

    // s4.3.1's authority rule, both halves.
    private static bool TryValidateAuthority(
        ImmutableArray<TlsQuicHttp3PseudoHeader> order,
        string authority,
        string? hostValue,
        bool mandatoryAuthorityScheme,
        out TlsQuicHttp3RequestError error)
    {
        error = TlsQuicHttp3RequestError.None;
        var authorityEmitted = order.Contains(TlsQuicHttp3PseudoHeader.Authority);

        // "If these fields are present, they MUST NOT be empty." Unconditional on the scheme -
        // the sentence governs whichever of the two is present, not only the http case - so
        // this check sits outside the mandatoryAuthorityScheme branch below.
        if ((authorityEmitted && authority.Length == 0)
            || (hostValue is not null && hostValue.Length == 0))
        {
            error = TlsQuicHttp3RequestError.AuthorityEmpty;
            return false;
        }

        // "If the :scheme pseudo-header field identifies a scheme that has a mandatory
        // authority component (including \"http\" and \"https\"), the request MUST contain
        // either an :authority pseudo-header field or a Host header field." An OR, so a
        // request that drops :authority from the order and carries a `host` field instead is
        // legal and is NOT refused here - s4.3.1's own next sentence, "Clients that generate
        // HTTP/3 requests directly SHOULD use the :authority pseudo-header field instead of
        // the Host header field", is a SHOULD about which to prefer and not a rule about which
        // is permitted.
        if (mandatoryAuthorityScheme && !authorityEmitted && hostValue is null)
        {
            error = TlsQuicHttp3RequestError.AuthorityMissing;
            return false;
        }

        return true;
    }

    // The RFC 9204 s4.5.1 prefix followed by one s4.5 representation per line. Returns false
    // for exactly one reason - `destination` is too small - which is what makes TryEncode's
    // doubling loop terminate.
    private static bool TryEncodeFieldSection(
        TlsQuicHttp3Spec spec,
        List<(byte[] Name, byte[] Value)> lines,
        Span<byte> destination,
        out int written)
    {
        written = 0;
        if (!TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(destination, out int offset))
        {
            return false;
        }

        for (var i = 0; i < lines.Count; i++)
        {
            if (!TlsQuicQpackEncoder.TryEncodeFieldLine(
                    lines[i].Name,
                    lines[i].Value,
                    spec.QpackHuffmanStringLiterals,
                    spec.QpackNameMatchPolicy == TlsQuicQpackNameMatchPolicy.NameReference,
                    destination[offset..],
                    out int count))
            {
                return false;
            }

            offset += count;
        }

        written = offset;
        return true;
    }
}

// ============================================================================
// THE MUTATION LEDGER - TASK C10 (this file, the response half)
// ============================================================================
//
//   ROWS BELOW                   50  = C10-1 to C10-50 with no gaps
//   KILLED WHEN FIRST RUN        46  = 50 rows, less 2 [WAS-SURVIVOR] and 2 [SURVIVED]
//   SURVIVED, THEN WITNESSED      2  = rows C10-5 and C10-50
//   SURVIVING STILL               2  = rows C10-2 and C10-3
//
// THE ROWS ARE PREFIXED `C10-` ON PURPOSE, and it is the one place this ledger diverges from
// C9's format above. C9's header pins three greps over THIS FILE - `grep -cE '^// +[0-9]+\. '`
// must return 45, and two more like it - and a second ledger numbered 1..N in the same style
// would have silently broken all three. The prefix keeps C9's greps returning 45/2/2 and gives
// this ledger three of its own. Run from this file's directory:
//   `grep -cE '^//   C10-[0-9]+\. ' TlsQuicHttp3Request.cs`                  must return 50
//   `grep -cE '^//   C10-[0-9]+\. \[WAS-SURVIVOR\]' TlsQuicHttp3Request.cs`  must return 2
//   `grep -cE '^//   C10-[0-9]+\. \[SURVIVED\]' TlsQuicHttp3Request.cs`      must return 2
//
// Every row was applied to a private `git worktree` of this branch, one edit at a time, each
// restored before the next, against `dotnet test --filter
// FullyQualifiedName~TlsQuicHttp3Request` - the 87-case suite this file's tests now are, C9's
// 42 plus C10's 45, and no test outside it references either type. Counts are per xUnit CASE,
// so a Theory failing in four rows counts four. All 50 counts come from ONE run against the
// FINAL suite AND the final source; the sweep was re-run whole after rows C10-5 and C10-50
// gained their witness, rather than mixing verdicts from two suites. The only edit made to
// this file afterwards is this comment.
//
// THE HARNESS WAS DISTRUSTED FIRST, as C9's was and for the reason C9 records. Before any real
// row ran, a deliberate known-bad mutation - `":status"` spelled `":statusZ"` - was applied and
// the harness reported KILLED with 15 failures. A harness that cannot fail is not a harness.
// The verdict is read from the run's own `Failed: <n>, Passed: <m>` line and nothing else, and
// a build failure is printed as BUILD-ERROR - a non-result - rather than as a survivor. The
// CS0162 shape C9's row 14 hit is avoided the same way it was there: a guard is disabled as
// `COND && false`, never as a deleted clause.
//
// TWO MUTATIONS WERE DELIBERATELY NOT RUN, and saying so is part of the count being honest.
// The converses of rows C10-8 and C10-45 - accepting an Incomplete frame as a whole one, and
// treating every QPACK error as growable - are both infinite loops, because neither advances
// the cursor it spins on. A hung sweep is a non-result rather than a verdict, so each property
// is measured from the other side instead.
//
//   C10-1. The file's one named error constant, FrameUnexpected, changed to H3_FRAME_ERROR -
//        the whole s4.1 rule reported under the wrong s8.1 code. Killed by 11.
//   C10-2. [SURVIVED] InitialDecodeBufferLength 1024 -> 1. VACUOUS, and no test is written,
//        for the reason C9's own row 2 gives about its own InitialFieldSectionLength: the
//        constant is only where the doubling loop STARTS, every positive value decodes the
//        same field section, and a test asserting the literal 1024 would fail against the
//        mutant and become a false witness - it would pin a performance number as though it
//        were wire format. That the loop grows at all is witnessed by
//        .AFieldSectionLargerThanTheInitialDecodeScratchStillDecodes, and that it terminates
//        on a bad section rather than spinning is row C10-45.
//   C10-3. [SURVIVED] InitialDecodeLineCount 32 -> 1. VACUOUS for exactly the same reason as
//        row 2 and witnessed by the same test, which carries 81 field lines.
//   C10-4. StatusName ":status" -> ":status-x". Killed by 15 - every interim case and every
//        Status assertion at once, because s4.3.2's name is what tells a 103 from a 200.
//   C10-5. [WAS-SURVIVOR] The sticky-failure guard never taken, written `_errorCode !=
//        NoError && false`. SURVIVED the first sweep, and the reason is worth more than the
//        row: after every refusal this reader can raise from a FRAME, _pending still holds
//        the offending bytes, so the mutant re-parses them and re-derives the identical error
//        - .OnceRefusedTheReaderKeepsAnsweringWithTheSameCode passed against it. The one
//        refusal that does NOT work that way is s7.1's truncated frame at the FIN, which is
//        raised AFTER _pending has been advanced past every whole frame; the mutant lets the
//        next call complete that frame and answer true. Witnessed by
//        .AFrameErrorAtTheEndOfTheStreamIsNotRevivedByLaterBytes, written for this row. Now
//        killed by 1.
//   C10-6. The post-FIN guard drops its `bytes.Length > 0` half, so a bare second FIN is
//        refused as though it were a frame. Killed by 1.
//   C10-7. The post-FIN guard never taken, so a whole second response after the stream ended
//        is accepted. Killed by 1.
//   C10-8. Incomplete collapsed into an H3_FRAME_ERROR rather than treated as a wait - the
//        defect TlsQuicHttp3FrameReadStatus' own remarks warn about, which would make every
//        response split across two STREAM frames a connection error. Killed by 3.
//   C10-9. The codec's error code overwritten with a fixed H3_FRAME_ERROR instead of
//        propagated. Killed by 1, .AnHttp2ReservedFrameTypeIsRefusedWithTheCodecsCode, which
//        exists for this row.
//   C10-10. The consumed bytes never dropped from _pending, so every frame is re-read on the
//        next call. Killed by 29.
//   C10-11. The end-of-stream leftover check never taken, so a stream ending mid-frame is
//        silently a complete response. Killed by 2.
//   C10-12. End-of-stream leftovers reported as H3_FRAME_UNEXPECTED rather than s7.1's
//        H3_FRAME_ERROR. Killed by 2.
//   C10-13. IsComplete set unconditionally at the FIN, so a stream carrying only interim
//        responses claims a complete message. Killed by 4.
//   C10-14. IsComplete narrowed to require trailers, which s4.1 makes optional. Killed by 13.
//   C10-15. The DATA stage guard never taken, written `&& false` - s4.1's first and third
//        named invalid sequences both unenforced. Killed by 4.
//   C10-16. The DATA guard narrowed to the before-any-HEADERS case alone, so DATA after the
//        trailers is accepted. Killed by 2 including
//        .ADataFrameAfterTheTrailingHeadersFrameIsRefused.
//   C10-17. The DATA guard made to permit content on an interim response. Killed by 1,
//        .ADataFrameAfterOnlyAnInterimResponseIsRefused - the witness for the one rule here
//        that is NOT in s4.1's 'In particular' list.
//   C10-18. The DATA payload never appended to the body. Killed by 9.
//   C10-19. The DATA payload appended in reverse. Killed by 9, and it is a different 9 from
//        row C10-18's only because the body assertions compare BYTES IN ORDER; a length-only
//        check would have passed this mutant.
//   C10-20. The four control-stream-only frames dropped to the skip arm, which is the
//        'unknown means ignore' misreading of s9 applied to frames that are not unknown.
//        Killed by 4 - all four rows of .AControlStreamOnlyFrameIsRefusedOnARequestStream.
//   C10-21. CANCEL_PUSH alone dropped from that arm. Killed by 1.
//   C10-22. SETTINGS alone dropped from that arm. Killed by 1.
//   C10-23. GOAWAY alone dropped from that arm. Killed by 1.
//   C10-24. MAX_PUSH_ID alone dropped from that arm. Killed by 1. Rows 21-24 exist separately
//        from row C10-20 because a single `case` deleted from a four-way arm is the edit a
//        careless merge actually makes.
//   C10-25. The skip arm refuses every other frame type instead of ignoring it - s9's
//        'Implementations MUST ignore unknown or unsupported values' inverted. Killed by 2,
//        including the PUSH_PROMISE case.
//   C10-26. The after-trailers HEADERS guard never taken. Killed by 2.
//   C10-27. The after-trailers guard moved BELOW the decode, so a misplaced HEADERS frame
//        with an unreadable field section reports QPACK_DECOMPRESSION_FAILED instead of the
//        sequence violation. Killed by 1,
//        .AnUndecodableHeadersFrameAfterTheTrailersIsRefusedForItsPositionFirst, written for
//        this row - the source claims the order in words, so the order needed a witness.
//   C10-28. The trailers branch condition inverted. Killed by 31.
//   C10-29. The trailers branch does not move to AfterTrailers, so s4.1's 'a single HEADERS
//        frame' trailer section becomes any number of them. Killed by 3.
//   C10-30. The trailer section decoded and then discarded. Killed by 2.
//   C10-31. The trailer section stored as the header section, so the trailers overwrite the
//        response's own fields. Killed by 2.
//   C10-32. The 1xx range gains 200, making every OK response interim - which loses the body
//        silently rather than loudly. Killed by 16.
//   C10-33. The 1xx range loses 100. Killed by 2, the "100" row.
//   C10-34. The 1xx range loses 199. Killed by 1, the "199" row, which exists for exactly
//        this off-by-one.
//   C10-35. The interim branch never taken, so a 1xx IS the final response. Killed by 5.
//   C10-36. Interim header sections discarded rather than kept. Killed by 4 - the reason
//        InterimHeaderSections is exposed at all rather than counted.
//   C10-37. An interim response advances the stage as a final one does. Killed by 5.
//   C10-38. The final header section discarded. Killed by 16.
//   C10-39. Status never recorded. Killed by 11.
//   C10-40. The final header section does not advance the stage, so the body that follows it
//        is refused as s4.1's DATA-before-HEADERS. Killed by 18.
//   C10-41. The :status lookup's StringComparison.Ordinal -> OrdinalIgnoreCase. Killed by 1,
//        .AnUppercaseStatusNameIsNotReadAsTheStatus. NOTE THE CONTRAST WITH C9's ROW 33,
//        which is the same mutation on the `host` lookup and survives as unreachable: there,
//        the s4.2 uppercase scan refuses the name before the comparison runs. Here there is
//        no such scan - these names are the PEER's, and this file refuses nothing for being
//        malformed - so the comparison is reachable and had to be witnessed.
//   C10-42. The :status lookup never matches. Killed by 15.
//   C10-43. NumberStyles.None -> NumberStyles.Integer, so " 200" and "+200" parse. Killed by
//        4.
//   C10-44. An unparsable :status becomes 0 rather than -1. Killed by 8.
//   C10-45. The QPACK doubling loop treats every error as fatal, written `|| true`. Killed by
//        1, the large-section test. Its converse - treating every error as growable - is
//        deliberately NOT a row: it is an infinite loop, and a hung sweep is a non-result,
//        not a verdict.
//   C10-46. The QPACK error code replaced by a frame-layer one. Killed by 2, including
//        .AnUndecodableFieldSectionIsRefusedWithTheQpackCode's explicit NotEqual.
//   C10-47. The field-section size limit ignored at the decode call. Killed by 1,
//        .TheMaximumFieldSectionSizeIsHonoured - A4's standing rule that a knob is honoured
//        only if setting it changes the answer.
//   C10-48. The constructor throws the limit away instead of storing it. Killed by 1, the
//        same test. Two rows because the knob has two places to be lost.
//   C10-49. Body exposes the unparsed pending bytes instead of the accumulated content.
//        Killed by 9.
//   C10-50. [WAS-SURVIVOR] Fail records NoError instead of the code, so the failure is not
//        sticky. SURVIVED the first sweep for row C10-5's reason and killed by row C10-5's
//        witness. Now killed by 1.
//
// ============================================================================

/// <summary>RFC 9114 s4.1's response message, read off a request stream as the bytes arrive.
/// </summary>
/// <remarks>
/// <para>THE SHAPE IS s4.1's LIST, NOT A GUESS. "An HTTP message (request or response)
/// consists of: 1. the header section ... sent as a single HEADERS frame, 2. optionally, the
/// content, if present, sent as a series of DATA frames, and 3. optionally, the trailer
/// section, if present, sent as a single HEADERS frame." Every state transition below is one
/// of those three numbered items.</para>
/// <para>NOTHING HERE THROWS, FOR ANY INPUT. These bytes are the peer's, so the contract is
/// the one <see cref="TlsQuicHttp3Frames.TryRead"/> and
/// <see cref="TlsQuicQpackDecoder.TryDecodeFieldSection"/> already keep: every rejection is a
/// <see langword="false"/> plus an error code, and a truncated frame is a wait rather than a
/// failure. <c>TlsQuicHttp3RequestTests.NothingOnTheResponsePathThrowsForAnyInput</c> proves
/// it over every prefix of a real response and over pseudo-random noise, rather than asserting
/// it.</para>
/// </remarks>
internal sealed class TlsQuicHttp3Response
{
    // ========================================================================
    // WHY THE ERROR IS A ulong AND NOT A TlsQuicHttp3ErrorCode.
    // ========================================================================
    //
    // C10 GAVE TWO REASONS AND C10b KEPT ONE OF THEM. The widening was justified by two codes
    // then absent from TlsQuicHttp3ErrorCode; only one of the two ever belonged there.
    //
    //   - H3_MESSAGE_ERROR did belong, and is now TlsQuicHttp3ErrorCode.H3MessageError. It is
    //     an s8.1 code like every other member, so the enum was simply missing a row.
    //   - QPACK_DECOMPRESSION_FAILED did NOT, and adding it would have been the mistake this
    //     comment nearly asked for. It is RFC 9204 s6's code, 0x0200, outside s8.1's
    //     0x0100..0x0110 run entirely, and it already exists once as
    //     TlsQuicQpackDecoder.QpackDecompressionFailed. It is obtained here by CALLING
    //     TlsQuicQpackDecoder.TryGetHttp3ErrorCode rather than by transcribing the number a
    //     second time.
    //
    // SO THE ulong STAYS, for the second reason alone: this out-parameter carries codes from
    // TWO REGISTRIES, and the only type both share is the varint they are on the wire. An enum
    // return would force either a fictitious RFC 9114 member for an RFC 9204 code or a second
    // out-parameter saying which registry the first one meant. The three RFC 9114 codes are
    // cast from the enum at their use sites, so this file still spells no error number itself.
    private const ulong NoError = (ulong)TlsQuicHttp3ErrorCode.None;
    private const ulong FrameUnexpected = (ulong)TlsQuicHttp3ErrorCode.H3FrameUnexpected;

    // s4.1.2: "Malformed requests or responses that are detected MUST be treated as a stream
    // error of type H3_MESSAGE_ERROR." A STREAM error, and this type still has no stream to
    // reset - so the code is returned and the reset is the caller's, exactly as every other
    // code here is. What changed in C10b is that the code exists to return.
    private const ulong MessageError = (ulong)TlsQuicHttp3ErrorCode.H3MessageError;

    // s8.1: "The endpoint detected that its peer is exhibiting a behavior that might be
    // generating excessive load." A CONNECTION error and not a stream one, which is why it is
    // spelled beside FrameUnexpected rather than beside MessageError: a peer feeding one stream
    // past this reader's ceiling has shown what it will do to the next stream too, and s8's own
    // grant - "An endpoint MAY choose to treat a stream error as a connection error under
    // certain circumstances" - runs the other way and is not needed here. The caller decides
    // what to do with the code, as it does with every other code this file returns.
    private const ulong ExcessiveLoad = (ulong)TlsQuicHttp3ErrorCode.H3ExcessiveLoad;

    // ========================================================================
    // WHAT IS DELIBERATELY NOT ENFORCED, each with its reason.
    // ========================================================================
    //
    //   - s4.3.2's :status and s4.1.2's Content-Length rule ARE NOW ENFORCED, and as of task
    //     C10c the Content-Length rule is enforced WHOLE. C10b left the zero-DATA half carved
    //     out - a 200 declaring content-length: 1234 and carrying no DATA frame was accepted -
    //     because deciding it needed RFC 9110's "defined as never having content" set and
    //     s6.4.1 was not among this repository's captures. It is now, as
    //     rfc9110-section6.4.1-content-semantics.txt, and reading it CLOSED the carve-out
    //     rather than widening it: s6.4.1's last sentence is "All other responses do include
    //     content, although that content might be of zero length", so that 200 is a response
    //     "defined as having content" whose DATA sum is 0, and s4.1.2 calls it malformed. See
    //     IsDefinedAsNeverHavingContent and the banner over ContentLengthAgreesWithTheBody.
    //   - THE HEAD AND CONNECT ARMS OF THAT SET WHEN THE CALLER NAMES NO METHOD, which is a
    //     limitation of this type's CALLERS rather than of this type. Two of s6.4.1's five
    //     cases are properties of the REQUEST - "Responses to the HEAD request method ... never
    //     include content" and "2xx (Successful) responses to a CONNECT request method ...
    //     switch the connection to tunnel mode instead of having content" - so C10c took the
    //     method as a constructor argument, which C10b declined to do for the general case and
    //     was right to decline. It defaults to null and null is read as neither, so a HEAD
    //     response declaring a non-zero Content-Length with no DATA is refused unless the
    //     caller says it was a HEAD. TlsQuicHttp3Connection DOES say now, as of cf96c89: it
    //     constructs this type two lines after encoding the very request it holds and passes
    //     `request.Method` through, so a HEAD response through the connection is read against
    //     s6.4.1's escaping set rather than strictly. A caller constructing this type directly
    //     still owes the argument, which is why the parameter is not defaulted to "GET".
    //   - s4.2.2's SETTINGS_MAX_FIELD_SECTION_SIZE is honoured but not sourced here: the limit
    //     arrives as this type's constructor argument and defaults to no limit. OUR advertised
    //     value lives in TlsQuicHttp3Spec's settings list and the peer's in
    //     TlsQuicHttp3Streams.PeerSettings, and reaching into either from here would be this
    //     type growing a connection. C9 left the SEND half to C11 for the same reason; this is
    //     the RECEIVE half of the same knob and it goes to the same place.
    //   - s4.6's push. A PUSH_PROMISE frame is legal on a request stream (s7.2.5, and the s7
    //     Table 1 row) and s4.1 says outright that "these PUSH_PROMISE frames are not part of
    //     the response", so it is skipped like any other frame that is not this message's.
    //     Acting on one is s4.6's work and no task before C12 claims it.

    // s4.3.2: "For responses, a single \":status\" pseudo-header field is defined that carries
    // the HTTP status code."
    private const string StatusName = ":status";

    // s4.1.2 names the field as "a Content-Length header field (Section 8.6 of [HTTP])"; s4.2
    // requires the lowercase spelling on the wire. RFC 9110 s8.6 - NOT s6.4.1, which is
    // "Content Semantics" - is where the field is defined, and s4.1.2 cites s8.6 by name.
    private const string ContentLengthName = "content-length";

    // The two request methods RFC 9110 s6.4.1 makes a response's content-ness depend on, spelled
    // once. UPPERCASE AND COMPARED Ordinal, because a method is a case-sensitive token: a caller
    // that sent :method "head" sent a request no server reads as HEAD, and the failure direction
    // of Ordinal is to apply s4.1.2's rule where s6.4.1's escape might have applied rather than
    // to skip it where it does not.
    private const string HeadMethod = "HEAD";
    private const string ConnectMethod = "CONNECT";

    // The decode scratch, sized by the same argument C9's InitialFieldSectionLength carries and
    // grown the same way: neither number is a bound, both are only where the doubling starts,
    // and the loop retries until TlsQuicQpackDecoder stops answering DestinationTooSmall. A
    // computed bound would have to reason about Huffman EXPANSION and about the 32-byte
    // per-field overhead, and a bound got subtly wrong is a silent truncation.
    //
    // WHAT STOPS THE LOOP GROWING WITHOUT LIMIT IS NOT TlsQuicStream.ReceiveLimit, which is
    // what this paragraph used to claim and what audit finding #6 disproved: that limit is
    // re-credited as bytes are delivered, so it rises for as long as a peer keeps sending and
    // caps nothing. Two real bounds stand in its place. The doubling here cannot outrun the
    // field section it is decoding, which is itself bounded by _maximumFieldSectionSize; and
    // the bytes that reach this type at all are bounded by _maximumBufferedBytes, checked in
    // TryRead as they arrive.
    private const int InitialDecodeBufferLength = 1024;
    private const int InitialDecodeLineCount = 32;

    // s4.1's three numbered items, as the only three states a response can be in.
    private enum Stage
    {
        // No final header section yet. Zero or more INTERIM ones may have gone by: "A server
        // sends zero or more interim HTTP responses on the same stream as the request,
        // followed by a single final HTTP response."
        BeforeFinalHeaders = 0,

        // Item 1 seen, so item 2 - "the content ... sent as a series of DATA frames" - is what
        // DATA frames now are, and the next HEADERS frame is item 3.
        Content = 1,

        // Item 3 seen. s4.1: "a DATA frame before any HEADERS frame, or a HEADERS or DATA
        // frame after the trailing HEADERS frame, is considered invalid."
        AfterTrailers = 2,
    }

    private readonly long _maximumFieldSectionSize;

    // The ceiling on _pending + _body + _interimBytes, audit finding #6's third buffer. NOT THE
    // SAME LIMIT AS _maximumFieldSectionSize AND NOT A SUBSTITUTE FOR IT: s4.2.2's limit is on
    // the UNCOMPRESSED size of one field section and is applied by the QPACK decoder after a
    // HEADERS frame is whole, which is too late to stop a peer that never finishes one. This
    // one is on the compressed bytes as they arrive and stops exactly that.
    private readonly int _maximumBufferedBytes;

    // The :method of the request this stream carries, or null when the caller did not say. Read
    // only by IsDefinedAsNeverHavingContent, which is where null's meaning is argued.
    private readonly string? _requestMethod;

    // The bytes handed over that did not yet form a whole frame. s7: "unlike QUIC frames,
    // HTTP/3 frames can span multiple packets", and a DATA frame split across two STREAM
    // frames is the ordinary case rather than the exotic one - which is why this is a buffer
    // and not an assumption that a call arrives frame-aligned.
    private readonly List<byte> _pending = [];

    // s7.2.1's "arbitrary, variable-length sequences of bytes", concatenated. UNBOUNDED UNTIL
    // THE CONSTRUCTOR SAYS OTHERWISE - see _maximumBufferedBytes, which counts this list and
    // _pending together because a byte crosses from one to the other as its frame completes.
    private readonly List<byte> _body = [];
    private readonly List<ImmutableArray<TlsQuicHttp3Field>> _interim = [];

    // What _interim has cost so far, in RFC 9114 s4.2.2's field-list units. A RUNNING TOTAL AND
    // NOT A RECOMPUTATION, because the check that reads it runs once per TryRead and walking
    // every field of every interim section each time would make a peer's 1xx flood quadratic -
    // which is the shape of the very attack the ceiling exists to refuse.
    private long _interimBytes;

    private Stage _stage = Stage.BeforeFinalHeaders;

    // The sticky failure. No separate bool: TlsQuicHttp3ErrorCode.None is 0 and every real
    // s8.1 or RFC 9204 code is non-zero, which is the same argument that enum's None member
    // rests on. Once set, every later call answers with it rather than parsing on into a state
    // machine that already lost.
    private ulong _errorCode;

    // C16. The peer's dynamic table, or null for C8's static-only arm. READ AND NEVER WRITTEN
    // here - TlsQuicHttp3Streams drives it from the peer's encoder stream, and this reader only
    // resolves against whatever it holds at the instant a field section is presented.
    private readonly TlsQuicQpackDynamicTable? _table;

    // RFC 9204 s2.2.2.1: "After the decoder finishes decoding a field section encoded using
    // representations containing dynamic table references, it MUST emit a Section
    // Acknowledgment instruction." One entry per SECTION, appended in decode order and never
    // removed, so a caller that has sent the first n knows the rest are new - which is what
    // makes "once per section" hold across pumps rather than "once per pump".
    private readonly List<ulong> _sectionAcknowledgments = [];

    /// <summary>Creates a reader.</summary>
    /// <param name="maximumFieldSectionSize">RFC 9114 s4.2.2's limit, applied by
    /// <see cref="TlsQuicQpackDecoder.TryDecodeFieldSection"/> to the UNCOMPRESSED size of each
    /// field section. <see cref="long.MaxValue"/>, the default, is no limit; a connection
    /// passes what it advertised. See WHAT IS DELIBERATELY NOT ENFORCED on why the value is not
    /// read from the spec here.</param>
    /// <param name="requestMethod">The <c>:method</c> of the request this stream carries, which
    /// is what decides two of RFC 9110 s6.4.1's five never-having-content cases.
    /// <see langword="null"/>, the default, is read as neither a HEAD nor a CONNECT - see
    /// <c>IsDefinedAsNeverHavingContent</c> for why that direction and not the other, and WHAT
    /// IS DELIBERATELY NOT ENFORCED for who still has to pass it.</param>
    /// <param name="table">The dynamic table the peer's encoder stream drives, or
    /// <see langword="null"/> - the default - for the static-only arm. A null table cannot
    /// block: <see cref="TlsQuicQpackDecoder"/> refuses a non-zero Required Insert Count
    /// outright on that arm, which is what keeps every zero-capacity caller unchanged.</param>
    /// <param name="maximumBufferedBytes">How many bytes of this response - the unparsed tail
    /// and the accumulated content together - to hold before answering RFC 9114 s8.1's
    /// H3_EXCESSIVE_LOAD. <see cref="int.MaxValue"/>, the default, is effectively no ceiling and
    /// is the SAME SHAPE AND THE SAME ARGUMENT AS <paramref name="maximumFieldSectionSize"/>'s
    /// default: a limit this type is told, never one it reaches out for. A connection passes
    /// <see cref="TlsQuicHttp3Spec.MaximumBufferedResponseBytes"/>; a caller constructing this
    /// type directly owes the argument, which is why the default is permissive rather than the
    /// spec's number copied here - a second copy of a default is a second thing to keep in
    /// step.</param>
    internal TlsQuicHttp3Response(
        long maximumFieldSectionSize = long.MaxValue,
        string? requestMethod = null,
        TlsQuicQpackDynamicTable? table = null,
        int maximumBufferedBytes = int.MaxValue)
    {
        _maximumFieldSectionSize = maximumFieldSectionSize;
        _requestMethod = requestMethod;
        _table = table;
        _maximumBufferedBytes = maximumBufferedBytes;
    }

    /// <summary>Gets whether a field section on this stream is parked on RFC 9204 s2.2.1's
    /// block, waiting for the peer's encoder stream to catch up.</summary>
    /// <remarks>
    /// <para>NOT AN ERROR AND NOT A FAILURE. <see cref="TryRead"/> answers
    /// <see langword="true"/> with an error code of 0 while this is set; the blocked frame's
    /// bytes stay in this reader and the SAME bytes are re-read on the next call. s2.1.2 is why
    /// there is a state here at all: "Because QUIC does not guarantee order between data on
    /// different streams, a decoder might encounter a representation that references a dynamic
    /// table entry that it has not yet received."</para>
    /// <para>It clears when the section decodes. Nothing in this class makes it clear on its
    /// own, because what unblocks it arrives on a DIFFERENT stream.</para>
    /// </remarks>
    internal bool IsBlocked { get; private set; }

    /// <summary>Gets the Required Insert Count the parked section declared, or 0 when
    /// <see cref="IsBlocked"/> is <see langword="false"/>.</summary>
    /// <remarks>s2.2.1: "A stream becomes unblocked when the Insert Count becomes greater than
    /// or equal to the Required Insert Count". This is the value reconstructed ON RECEIPT -
    /// s4.5.1.1's reconstruction reads the live Insert Count, so recomputing it later can give
    /// a different answer for the same bytes.</remarks>
    internal ulong BlockedRequiredInsertCount { get; private set; }

    /// <summary>Gets the Required Insert Count of every field section decoded on this stream
    /// that RFC 9204 s2.2.2.1 requires a Section Acknowledgment for, in decode order.</summary>
    /// <remarks>s4.4.1 acknowledges only "an encoded field section whose declared Required
    /// Insert Count is not zero", so a section that used no dynamic entry appends nothing and
    /// the list stays empty for the whole static-only arm.</remarks>
    internal IReadOnlyList<ulong> SectionAcknowledgments => _sectionAcknowledgments;

    /// <summary>Gets the final response's header section, <c>:status</c> included, empty until
    /// one has been read.</summary>
    internal ImmutableArray<TlsQuicHttp3Field> HeaderFields { get; private set; } = [];

    /// <summary>Gets RFC 9114 s4.1's item 3, the trailer section, empty when there was
    /// none.</summary>
    internal ImmutableArray<TlsQuicHttp3Field> TrailerFields { get; private set; } = [];

    /// <summary>Gets each interim (1xx) header section that preceded the final response, in
    /// arrival order.</summary>
    /// <remarks>KEPT RATHER THAN COUNTED. s4.1 permits "zero or more interim HTTP responses",
    /// and a 103 Early Hints carries link fields a caller may want. Discarding them would also
    /// make "interim responses are tolerated" untestable beyond "no error was raised", which
    /// any implementation that silently dropped them would pass.</remarks>
    internal IReadOnlyList<ImmutableArray<TlsQuicHttp3Field>> InterimHeaderSections => _interim;

    /// <summary>Gets the concatenated payloads of every DATA frame, in order.</summary>
    /// <remarks>s7.2.1: "DATA frames (type=0x00) convey arbitrary, variable-length sequences of
    /// bytes associated with HTTP request or response content." A span over the reader's own
    /// storage rather than a copy, matching <see cref="TlsQuicHttp3Frames.TryRead"/>'s payload.
    /// </remarks>
    internal ReadOnlySpan<byte> Body => CollectionsMarshal.AsSpan(_body);

    /// <summary>Gets the final response's status code, or -1 when no final response has been
    /// read.</summary>
    /// <remarks>-1 NO LONGER MEANS "read, but malformed". C10 left an absent or unparsable
    /// <c>:status</c> reported through this property because H3_MESSAGE_ERROR had no enum
    /// member; C10b refuses it instead, so -1 now means only that no final header section has
    /// arrived yet. A caller that sees <see cref="TryRead"/> answer <see langword="true"/> and
    /// this still -1 is looking at a stream carrying interim responses, or none.</remarks>
    internal int Status { get; private set; } = -1;

    /// <summary>Gets whether a final response was read and the stream then ended.</summary>
    /// <remarks>
    /// <para><see langword="false"/> after a stream that ended carrying only interim
    /// responses: s4.1 requires "a single final HTTP response" to follow them.</para>
    /// <para>AND <see langword="false"/> AFTER A RESET, WHICH IS THE POINT OF
    /// <see cref="ResetErrorCode"/>. RFC 9000 s4.5 leaves the bytes below a reset stream's
    /// final size undelivered forever, so a response cut short by RESET_STREAM has a
    /// <see cref="Body"/> that is a PREFIX of the real one - and this property saying yes
    /// over it would hand a caller a truncated message it has no way to distinguish from a
    /// whole one. That was not a hypothetical: <see cref="TlsQuicStream.ReceiveComplete"/>
    /// briefly folded a reset in, on the true-but-wrong reasoning that such a stream also
    /// delivers nothing further, and this reader's completion rule is end-of-stream plus an
    /// empty buffer - which a reset landing on a frame boundary satisfies exactly. That
    /// property no longer folds it in and the conjunct below is the second lock.</para>
    /// </remarks>
    internal bool IsComplete { get; private set; }

    /// <summary>Gets the RFC 9000 s19.4 Application Protocol Error Code the peer reset this
    /// request stream with, or <see langword="null"/> if it has not.</summary>
    /// <remarks>
    /// <para>THE CODE AND NOT A FLAG, because RFC 9114 s4.1.1 makes the number the whole
    /// decision. "The server SHOULD abort its response stream with the error code
    /// H3_REQUEST_REJECTED" when it did no application processing, and "The client can treat
    /// requests rejected by the server as though they had never been sent at all, thereby
    /// allowing them to be retried later" - whereas H3_REQUEST_CANCELLED means the server
    /// "abandons a response after partial processing", which a client may not silently retry.
    /// A caller told only that the stream was reset cannot tell those apart.</para>
    /// <para>REPORTED, NOT INTERPRETED. The value is the varint the peer sent, whatever it is;
    /// s8.1's codes are not exhaustive of what may legally arrive - s8's reserved
    /// <c>0x1f * N + 0x21</c> space is expressly for codes an endpoint sends in place of
    /// H3_NO_ERROR. Nothing here maps it onto <see cref="TlsQuicHttp3ErrorCode"/>, whose own
    /// summary says its members are the codes THIS subsystem raises.</para>
    /// <para>NULL RATHER THAN 0, for the reason <see cref="TlsQuicStream.ResetErrorCode"/>
    /// gives: 0 is H3_NO_ERROR and a legal thing for a peer to reset with, so a
    /// <see cref="ulong"/> defaulting to zero would read "no reset" and "reset, deliberately"
    /// identically.</para>
    /// </remarks>
    internal ulong? ResetErrorCode { get; private set; }

    /// <summary>Gets whether the peer abandoned this response with an RFC 9000 s19.4
    /// RESET_STREAM.</summary>
    /// <remarks>A STREAM ERROR AND NOT A CONNECTION ERROR, which is why it is a property here
    /// rather than a code out of <see cref="TryRead"/>. RFC 9114 s8 draws the line - "This is
    /// referred to as a 'stream error'" against "This is referred to as a 'connection error'" -
    /// and s4.1.1 makes cancelling one request an ordinary thing for a server to do: "servers
    /// cancel requests if they are unable to or choose not to respond". A connection closed over
    /// it would take every other exchange down with it.</remarks>
    internal bool IsReset => ResetErrorCode is not null;

    /// <summary>Records that the peer reset this request stream, RFC 9000 s19.4.</summary>
    /// <returns><see langword="true"/> the first time only.</returns>
    /// <remarks>
    /// <para>IDEMPOTENT, AND THE FIRST CODE STANDS. The connection calls this once per pump
    /// for as long as the exchange is held, and s19.4 admits only one RESET_STREAM per stream
    /// - the stream layer refuses a second with a different final size as s20.1's
    /// FINAL_SIZE_ERROR - so a later call carries the same number. Keeping the first is what
    /// makes that guaranteed rather than merely true today.</para>
    /// <para>THE RETURN IS WHAT MAKES ONCE-PER-STREAM WORK ONE LAYER UP. RFC 9204 s2.2.2.2's
    /// Stream Cancellation is emitted per abandoned stream, not per pump, and a caller that
    /// tested <see cref="IsReset"/> itself would be keeping a second copy of the same fact.
    /// </para>
    /// <para>IT DOES NOT CLEAR <see cref="HeaderFields"/>, <see cref="Status"/> OR
    /// <see cref="Body"/>. RFC 9114 s4.1 tells a client to "begin processing partial HTTP
    /// messages once enough of the message has been received to make progress", so what did
    /// arrive is worth keeping and reading; what must not happen is it being presented as the
    /// WHOLE message, which is <see cref="IsComplete"/>'s job and not this data's.</para>
    /// </remarks>
    internal bool OnPeerReset(ulong applicationErrorCode)
    {
        if (IsReset)
        {
            return false;
        }

        ResetErrorCode = applicationErrorCode;
        return true;
    }

    /// <summary>Consumes the next bytes of the response stream.</summary>
    /// <remarks>
    /// <para>NEVER THROWS AND NEVER PARTIALLY CONSUMES. Bytes that do not yet form a whole
    /// frame are held for the next call, so a caller may hand over a QUIC STREAM frame's
    /// payload exactly as it arrived, one byte at a time, or the whole response at once, and
    /// get the same answer.</para>
    /// <para>ONCE IT ANSWERS <see langword="false"/> IT KEEPS ANSWERING <see langword="false"/>
    /// with the same code. The error is a connection error in every case s4.1 and s7.2 name,
    /// so there is no state left to parse into.</para>
    /// </remarks>
    /// <param name="bytes">The bytes just received.</param>
    /// <param name="endOfStream">Whether the QUIC stream's FIN accompanied them.</param>
    /// <param name="errorCode">The RFC 9114 s8.1 code to close with, or 0.</param>
    internal bool TryRead(ReadOnlySpan<byte> bytes, bool endOfStream, out ulong errorCode)
    {
        errorCode = _errorCode;
        if (_errorCode != NoError)
        {
            return false;
        }

        // s8.1 defines H3_FRAME_UNEXPECTED as "A frame was received that was not permitted in
        // the current state or on the current stream", and after the stream has ended there is
        // no state in which any frame is permitted. s4.1 reaches the same place from the
        // message side: "receipt of ... an additional HTTP response following a final HTTP
        // response".
        if (IsComplete && bytes.Length > 0)
        {
            return Fail(FrameUnexpected, out errorCode);
        }

        // AddRange RATHER THAN A PER-BYTE Add LOOP. This is the response body's
        // arrival path - every byte of every download passes through here once - and
        // AddRange grows the backing array once and memcpys where Add re-checks
        // capacity per byte. The list's contents are identical either way, which is
        // what the span taken immediately below is parsed from and what
        // TlsQuicHttp3RequestTests.EveryPossibleSplitPointYieldsTheSameResponse
        // reads back at every arrival boundary.
        _pending.AddRange(bytes);

        var buffer = CollectionsMarshal.AsSpan(_pending);
        var offset = 0;
        while (offset < buffer.Length)
        {
            // C16 PARKS BY NOT ADVANCING THE OFFSET, which is the shape this loop already had
            // for a partial frame two statements down. A blocked HEADERS frame is a COMPLETE
            // frame whose processing cannot proceed, so the offset has to be wound back
            // explicitly rather than simply left alone.
            var frameStart = offset;
            var status = TlsQuicHttp3Frames.TryRead(
                buffer, ref offset, out var type, out var payload, out var frameError);

            // Incomplete is s7's "HTTP/3 frames can span multiple packets" and is not an
            // error: the offset did not move, so the frame's first byte stays in _pending.
            if (status == TlsQuicHttp3FrameReadStatus.Incomplete)
            {
                break;
            }

            if (status == TlsQuicHttp3FrameReadStatus.Error)
            {
                return Fail((ulong)frameError, out errorCode);
            }

            if (!TryAcceptFrame(type, payload, out var acceptError))
            {
                // s2.2.1's block, and the ONE false from TryAcceptFrame that is not a failure.
                // It rides on IsBlocked rather than on a third return value because the flag is
                // state this reader has to keep anyway, and because `false` meaning two things
                // is exactly the confusion an extra out-parameter would have buried. The offset
                // goes back to the frame's first byte, so _pending keeps the WHOLE frame and
                // the next call re-presents the same bytes; _stage, _body and HeaderFields are
                // untouched, which is what makes re-presenting idempotent.
                if (IsBlocked)
                {
                    offset = frameStart;
                    break;
                }

                return Fail(acceptError, out errorCode);
            }
        }

        _pending.RemoveRange(0, offset);

        // AUDIT FINDING #6'S THIRD BUFFER, MEASURED AS A RESIDUE AND COVERING A FOURTH THE
        // FINDING DID NOT NAME. Three lists here grow from the peer and nothing else shrinks
        // them, so the ceiling is on their SUM:
        //
        //   * _pending, the tail of a frame that has not finished arriving. The RemoveRange
        //     above has just dropped everything the loop could read, so what is counted is the
        //     part no parse could take - which is the quantity the finding was about, and not
        //     the same thing as how much arrived in this call.
        //   * _body, s7.2.1's DATA payloads concatenated. Its bytes were in _pending a moment
        //     ago, so the two are one quantity moving between two lists.
        //   * _interim, one field section per s4.1 interim (1xx) response. THE FIRST VERSION OF
        //     THIS CHECK ASSERTED THAT _pending AND _body WERE "the only two lists here that a
        //     peer can grow", AND THAT WAS FALSE. s4.1 permits "zero or more interim HTTP
        //     responses" with no bound on the count, and their bytes pass through _pending, are
        //     consumed, and never reach _body - so a peer emitting 1xx responses forever grew
        //     this reader without moving either of the other two numbers.
        //
        // AFTER THE LOOP AND NOWHERE ELSE, WHICH IS WHAT MAKES IT ONE CHECK RATHER THAN THREE.
        // Parsing only moves bytes between these lists and drops frame headers, so the sum
        // never rises during the loop above what it was when the loop began; measuring once at
        // the end therefore bounds every path into all three. The transient peak inside one
        // call is this ceiling plus the delivery that crossed it, which is the same bound
        // TlsQuicHttp3Streams accepts for the same reason.
        //
        // A long ACCUMULATOR AND A long COMPARISON, because three int-shaped quantities added
        // together can leave int's range even when none of them does, and a wrapped negative
        // total would pass a check the peer had already broken.
        //
        // NOT s7.1's H3_FRAME_ERROR. Nothing about the peer's framing is wrong here - the
        // frames may be legal and simply more than we chose to hold - and s8.1 gives
        // H3_EXCESSIVE_LOAD to exactly that: "The endpoint detected that its peer is exhibiting
        // a behavior that might be generating excessive load."
        if ((long)_pending.Count + _body.Count + _interimBytes > _maximumBufferedBytes)
        {
            return Fail(ExcessiveLoad, out errorCode);
        }

        // s7.1's leftover-at-FIN rule does NOT apply to a parked section, and neither does
        // s4.1's completeness. A peer may legally FIN its response stream while the encoder
        // instructions the section needs are still in flight on the encoder stream - that is
        // s2.1.2's whole premise - so what is left in _pending is a frame a LATER pump
        // completes, not one no further byte will ever complete. Both questions are asked again
        // on the pump that unblocks it.
        if (endOfStream && !IsBlocked)
        {
            // s7.1: "a frame payload that terminates before the end of the identified fields
            // MUST be treated as a connection error of type H3_FRAME_ERROR". The stream is
            // over, so what is left is a frame that no further byte will ever complete - which
            // is why this is an error here and Incomplete two statements above.
            if (_pending.Count > 0)
            {
                return Fail((ulong)TlsQuicHttp3ErrorCode.H3FrameError, out errorCode);
            }

            // AT THE FIN AND NOWHERE ELSE, because "the sum of the DATA frame lengths
            // received" is not known until there are no more of them. A body that has already
            // overrun its declared Content-Length could be refused a frame earlier, and
            // deliberately is not: that would be a second copy of the same rule, in a second
            // place, disagreeing with this one the first time either is edited.
            if (!ContentLengthAgreesWithTheBody())
            {
                return Fail(MessageError, out errorCode);
            }

            // `!IsReset` IS THE SILENT-CORRUPTION GUARD, and it is here rather than only at the
            // caller because THIS property is what a caller reads. RFC 9114 s4.1 is unambiguous
            // that a response its stream was reset under is a FAILED response and not a short
            // one, and s4.1.1's retry rules only mean anything if the two are distinguishable.
            //
            // IT IS NOT DEAD CODE JUST BECAUSE TlsQuicStream.ReceiveComplete NOW EXCLUDES A
            // RESET. Callers that drive this type with no connection above them - the fuzz
            // targets, TlsQuicHttp3RequestTests - pass `endOfStream` themselves and may pair it
            // with OnPeerReset in either order. This conjunct is what makes the invariant a
            // property of the reader rather than of one caller's sequencing, and
            // TlsQuicHttp3RequestTests.AResetResponseIsNeverCompleteEvenAtEndOfStream drives
            // exactly that pairing.
            IsComplete = !IsReset && _stage != Stage.BeforeFinalHeaders;
        }

        errorCode = NoError;
        return true;
    }

    // One whole frame, against s4.1's sequence rules and the s7.2 per-frame stream rules.
    private bool TryAcceptFrame(
        ulong frameType, ReadOnlySpan<byte> payload, out ulong errorCode)
    {
        errorCode = NoError;
        switch (frameType)
        {
            case (ulong)TlsQuicHttp3FrameType.Data:
                // s4.1's first named invalid sequence, "a DATA frame before any HEADERS
                // frame", and its third, "a ... DATA frame after the trailing HEADERS frame",
                // are the two stages that are not Content. The interim case falls here too and
                // s4.1 says why in its own words: "Interim responses do not contain content or
                // trailer sections." That sentence is not one of the three the "In particular"
                // list names - but that list is examples of an "invalid sequence of frames",
                // not the whole of it, and content on an interim response is one.
                if (_stage != Stage.Content)
                {
                    errorCode = FrameUnexpected;
                    return false;
                }

                // AddRange RATHER THAN A PER-BYTE Add LOOP: the accumulated content
                // of every DATA frame, appended in the same order, one bulk copy per
                // frame instead of one capacity check per byte. Read back whole by
                // TlsQuicHttp3RequestTests.ALargeBodyRoundTripsThroughTheFrameParser
                // ByteForByte.
                _body.AddRange(payload);

                return true;

            case (ulong)TlsQuicHttp3FrameType.Headers:
                return TryAcceptHeaders(payload, out errorCode);

            // The four frames the s7 Table 1 marks "No" for the Request column, each of which
            // says the same thing in its own subsection: s7.2.3 "Receiving a CANCEL_PUSH frame
            // on a stream other than the control stream MUST be treated as a connection error
            // of type H3_FRAME_UNEXPECTED"; s7.2.4 "If an endpoint receives a SETTINGS frame on
            // a different stream, the endpoint MUST respond with a connection error of type
            // H3_FRAME_UNEXPECTED"; and s7.2.6 and s7.2.7 the same for GOAWAY and MAX_PUSH_ID.
            //
            // THESE ARE WHY THE DEFAULT ARM BELOW IS NOT SIMPLY "SKIP EVERYTHING ELSE". s9's
            // ignore rule is about types an implementation does not KNOW - "Implementations
            // MUST ignore unknown or unsupported values" - and a SETTINGS frame on a request
            // stream is not unknown, it is misplaced.
            case (ulong)TlsQuicHttp3FrameType.CancelPush:
            case (ulong)TlsQuicHttp3FrameType.Settings:
            case (ulong)TlsQuicHttp3FrameType.Goaway:
            case (ulong)TlsQuicHttp3FrameType.MaxPushId:
                errorCode = FrameUnexpected;
                return false;

            // s7.2.5: "A client MUST treat receipt of a PUSH_PROMISE frame that contains a
            // larger push ID than the client has advertised as a connection error of
            // H3_ID_ERROR."
            //
            // THIS RULE BINDS *BECAUSE* SERVER PUSH IS UNIMPLEMENTED, which is the opposite of
            // how it reads. This client never sends MAX_PUSH_ID, so the advertised maximum does
            // not exist; s7.2.5's own preceding sentence - "A server MUST NOT use a push ID
            // that is larger than the client has provided in a MAX_PUSH_ID frame" - leaves a
            // server with no usable push ID at all. Every push ID is therefore larger than what
            // was advertised, and every PUSH_PROMISE is H3_ID_ERROR.
            //
            // s4.1's "These PUSH_PROMISE frames are not part of the response" is why this used
            // to fall to the default arm and be ignored. Not part of the response is not the
            // same as permitted: s7.2.5 still has a push ID to check, and here it always fails.
            //
            // The push ID is READ FIRST so a truncated payload is reported as the framing
            // failure it is. s7.2.5 gives PUSH_PROMISE a "Push ID (i)" field, so a payload
            // without a readable varint is not a push ID this client can find too large - it is
            // H3_FRAME_ERROR, and s7.1 makes that a check on receipt rather than on use.
            case (ulong)TlsQuicHttp3FrameType.PushPromise:
            {
                var pushIdCursor = 0;
                if (!QuicVariableLengthInteger.TryRead(payload, ref pushIdCursor, out _))
                {
                    errorCode = (ulong)TlsQuicHttp3ErrorCode.H3FrameError;
                    return false;
                }

                errorCode = (ulong)TlsQuicHttp3ErrorCode.H3IdError;
                return false;
            }

            default:
                // s4.1: "Frames of unknown types (Section 9), including reserved frames
                // (Section 7.2.8) MAY be sent on a request or push stream before, after, or
                // interleaved with other frames described in this section."
                //
                // The HTTP/2-inherited reserved types - 0x02, 0x06, 0x08, 0x09 - never reach
                // this arm. TlsQuicHttp3Frames.TryRead refuses them with H3_FRAME_UNEXPECTED
                // before returning, which is s7.2.8's rule enforced once, in the codec, rather
                // than twice.
                return true;
        }
    }

    private bool TryAcceptHeaders(ReadOnlySpan<byte> payload, out ulong errorCode)
    {
        // s4.1's second named invalid sequence: "a HEADERS ... frame after the trailing
        // HEADERS frame". Checked BEFORE the decode, so a well-formed field section in the
        // wrong place is still refused for being in the wrong place.
        if (_stage == Stage.AfterTrailers)
        {
            errorCode = FrameUnexpected;
            return false;
        }

        if (!TryDecodeFieldSection(payload, out var fields, out errorCode))
        {
            return false;
        }

        // POSITION DECIDES WHAT A HEADERS FRAME IS, not its contents. s4.1's item 3 is "the
        // trailer section, if present, sent as a single HEADERS frame", and it is the frame
        // that follows the header section - a trailer section has no :status and nothing in
        // s4.3.2 makes one legal there. So a 1xx arriving after the final response is read as
        // the trailers it is positioned as, rather than as a second response; s4.1 already
        // calls that "an additional HTTP response following a final HTTP response" and makes
        // it malformed, which is C11's H3_MESSAGE_ERROR to raise.
        if (_stage == Stage.Content)
        {
            TrailerFields = fields;
            _stage = Stage.AfterTrailers;
            return true;
        }

        // s4.1: "A response MAY consist of multiple messages when and only when one or more
        // interim responses (1xx; see Section 15.2 of [HTTP]) precede a final response to the
        // same request." An interim response is therefore NOT item 1 - the message has not
        // started - so the stage does not move and the next HEADERS frame is judged afresh.
        var status = ReadStatus(fields);
        if (status is >= 100 and <= 199)
        {
            _interim.Add(fields);

            // WHAT THIS SECTION COSTS, IN RFC 9114 s4.2.2's OWN UNITS: "the length of the name
            // and value in bytes plus an overhead of 32 bytes for each field". The same
            // arithmetic TlsQuicQpackDecoder applies to SETTINGS_MAX_FIELD_SECTION_SIZE, and
            // the 32 is taken from TlsQuicQpackDynamicTable.EntrySizeOverhead rather than
            // spelled a third time. It is a proxy for the managed cost rather than the cost
            // itself, and the proxy UNDER-COUNTS BY ROUGHLY TWO TO THREE TIMES: .NET strings
            // are UTF-16, so a byte of an ASCII field name costs two on the heap, and each
            // string carries an object header and a length while each section carries an
            // ImmutableArray and its slots. So MaximumBufferedResponseBytes bounds s4.2.2
            // units and not resident bytes - its own remarks say the same of the body, whose
            // real high water mark is a multiple of the ceiling once the QUIC stream's own
            // delivered copy is counted. The factor is bounded and constant, which is what
            // makes a ceiling in these units a ceiling on memory at all; it is stated here so
            // that 64 MiB is not read as 64 MiB resident.
            //
            // IT IS THE RIGHT PROXY DESPITE THAT, because it is the number s4.2.2 already
            // makes a peer's field sections answerable for - the same arithmetic the decoder
            // applies to SETTINGS_MAX_FIELD_SECTION_SIZE - so one peer cannot be charged two
            // different prices for the same field section depending on which limit it meets.
            //
            // RUNNING AND NEVER DECREMENTED, because _interim is never trimmed: s4.1's interim
            // sections are kept for the caller ("A 103 Early Hints carries link fields a caller
            // may want", as InterimHeaderSections argues), so every one that arrives is one this
            // reader holds until the exchange is dropped.
            foreach (var field in fields)
            {
                _interimBytes += field.Name.Length + field.Value.Length
                    + TlsQuicQpackDynamicTable.EntrySizeOverhead;
            }

            return true;
        }

        // s4.3.2: "For responses, a single \":status\" pseudo-header field is defined that
        // carries the HTTP status code ... This pseudo-header field MUST be included in all
        // responses; otherwise, the response is malformed (see Section 4.1.2)." And s4.1.2
        // makes malformed a code rather than a description: "Malformed requests or responses
        // that are detected MUST be treated as a stream error of type H3_MESSAGE_ERROR." Its
        // last paragraph makes refusing this one mandatory in exactly this direction: "Clients
        // MUST NOT accept a malformed response."
        //
        // ReadStatus answers -1 for BOTH of s4.1.2's applicable bullets - "the absence of
        // mandatory pseudo-header fields" and "invalid values for pseudo-header fields" - and
        // both are malformed, so one check covers both. THE CHECK IS HERE AND NOT IN
        // ReadStatus, because ReadStatus also feeds the interim test above, where -1 must fall
        // through to this line rather than short-circuit into it.
        //
        // A TRAILER SECTION NEVER REACHES THIS LINE, which is why "a HEADERS frame with no
        // :status" is not a blanket refusal: the Stage.Content branch above has already claimed
        // it, and s4.3 forbids a :status there anyway ("Pseudo-header fields MUST NOT appear in
        // trailer sections").
        if (status < 0)
        {
            errorCode = MessageError;
            return false;
        }

        HeaderFields = fields;
        Status = status;
        _stage = Stage.Content;
        return true;
    }

    // s4.1.2's Content-Length rule, verbatim: "A request or response that is defined as having
    // content when it contains a Content-Length header field (Section 8.6 of [HTTP]) is
    // malformed if the value of the Content-Length header field does not equal the sum of the
    // DATA frame lengths received."
    //
    // THE ESCAPE IS THE NEXT SENTENCE AND IT HAS TWO HALVES: "A response that is defined as
    // never having content, even when a Content-Length is present, can have a non-zero
    // Content-Length header field even though no content is included in DATA frames." The
    // response must BE one of RFC 9110 s6.4.1's never-having-content cases AND no content may
    // have arrived in DATA frames. C10b had only the second half - every zero-DATA response
    // escaped - and s6.4.1's closing sentence is what shows that was too wide: "All other
    // responses do include content, although that content might be of zero length." A 200
    // declaring content-length: 1234 with no DATA frame IS "defined as having content", its
    // DATA sum is 0, 0 is not 1234, and s4.1.2 calls it malformed. So the two halves are
    // conjoined here, and IsDefinedAsNeverHavingContent is the first of them.
    //
    // EVERY content-length FIELD IS CHECKED, not the first. That is not a rule invented here -
    // it falls out of applying s4.1.2's sentence to each field line that is one - and it means
    // two content-length lines disagreeing with each other cannot both equal the sum, so the
    // pair is refused without this file needing a duplicate-value rule of its own. RFC 9110
    // s8.6 is captured now and gives none that would help: its one licence is for a
    // comma-separated repeat of ONE value inside a SINGLE field line ("Content-Length: 42, 42"),
    // which a recipient "MAY either reject ... or replace ... with a single instance" - a MAY,
    // about one line rather than two. s8.6 binds senders and forwarders and imposes nothing on
    // a recipient that sees a mismatch; the receiver-side rule is s4.1.2's, and it is this one.
    //
    // Ordinal, and unparsable values skipped, for ReadStatus' two reasons: an uppercase
    // "Content-Length" is not the field s4.2 permits, and NumberStyles.None is what makes
    // " 12" and "+12" not "the value of the Content-Length header field".
    private bool ContentLengthAgreesWithTheBody()
    {
        if (_body.Count == 0 && IsDefinedAsNeverHavingContent())
        {
            return true;
        }

        for (var i = 0; i < HeaderFields.Length; i++)
        {
            if (!string.Equals(HeaderFields[i].Name, ContentLengthName, StringComparison.Ordinal))
            {
                continue;
            }

            if (long.TryParse(
                    HeaderFields[i].Value,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var declared)
                && declared != _body.Count)
            {
                return false;
            }
        }

        return true;
    }

    // RFC 9110 s6.4.1's never-having-content set, which is what s4.1.2 means by a response
    // "defined as never having content".
    //
    // FIVE CASES AND NOT FOUR. The four-case list is the one a reader writes from memory, and it
    // is what stood in this file's own WHAT IS DELIBERATELY NOT ENFORCED until task C10c - "the
    // response to a HEAD, a 204, a 304, a 2xx to a CONNECT" - which drops 1xx. s6.4.1, verbatim
    // and in its own order:
    //
    //     "Responses to the HEAD request method (Section 9.3.2) never include content"
    //     "2xx (Successful) responses to a CONNECT request method (Section 9.3.6) switch the
    //      connection to tunnel mode instead of having content."
    //     "All 1xx (Informational), 204 (No Content), and 304 (Not Modified) responses do not
    //      include content."
    //
    // s6.4.1 CARRIES NO CONFORMANCE KEYWORD AT ALL - not one MUST, SHOULD or MAY in the whole
    // section, only flat declaratives - so nothing here is cited to s6.4.1 as a requirement. It
    // supplies the SET; RFC 9114 s4.1.2 supplies the strength, both halves of it: "Malformed
    // requests or responses that are detected MUST be treated as a stream error of type
    // H3_MESSAGE_ERROR" and "Clients MUST NOT accept a malformed response."
    //
    // THE TWO METHOD ARMS ARE NOT SYMMETRIC WITH THE OTHER THREE, and RFC 9110 s8.6 is why. It
    // makes most of this set moot on the wire: "A server MUST NOT send a Content-Length header
    // field in any response with a status code of 1xx (Informational) or 204 (No Content). A
    // server MUST NOT send a Content-Length header field in any 2xx (Successful) response to a
    // CONNECT request." Only a HEAD response and a 304 MAY carry one at all. 304 is decidable
    // from :status; A HEAD RESPONSE IS THE ONE CASE THAT IS NOT, and it is the whole reason this
    // type now takes a request method. C10b wrote "no request method is taken here and none is
    // needed" and was right about the case it faced - a response that DID carry DATA is not one
    // of these whatever the method - but the zero-DATA case is decidable only with it.
    //
    // A NULL METHOD IS READ AS NEITHER, and that direction is chosen rather than defaulted. The
    // two failure directions are not symmetric: reading null as "might have been a HEAD"
    // restores C10b's blanket escape and accepts the malformed 200 above, which s4.1.2 forbids
    // in as many words; reading it as "was not a HEAD" refuses a legal HEAD response from a
    // caller that did not say, and that caller fixes it by saying - it sent the request and
    // knows the method. Refusing is the direction that cannot accept a message the RFC calls
    // malformed, which is the same test this file's other comparer choices are made by.
    //
    // THE 1xx ARM CANNOT FIRE FROM HERE AND IS WRITTEN ANYWAY. TryAcceptHeaders routes every
    // 100..199 section into _interim without advancing the stage, so Status - which is the FINAL
    // response's - is never 1xx, and a 1xx escapes this rule by never reaching it rather than by
    // this arm. It stays for the reason C9's row 33 keeps its Ordinal `host` lookup: it is one
    // reordering of TryAcceptHeaders away from being reachable, and a list that silently dropped
    // a case s6.4.1 states outright is the exact defect C10c was written to fix. No test
    // witnesses this arm, because none can without being a false witness; C10c's ledger records
    // it as a survivor, unreachable by construction.
    //
    // The CONNECT arm is reachable through the constructor argument and is witnessed, but not by
    // anything this client can send: see THE CONNECT LIMITATION above, which refuses every legal
    // CONNECT request at the encoder.
    private bool IsDefinedAsNeverHavingContent() =>
        string.Equals(_requestMethod, HeadMethod, StringComparison.Ordinal)
        || (string.Equals(_requestMethod, ConnectMethod, StringComparison.Ordinal)
            && Status is >= 200 and <= 299)
        || Status is (>= 100 and <= 199) or 204 or 304;

    // s4.3.2's :status, as an integer. NumberStyles.None so that "+200" and " 200" are the -1
    // they should be: s4.3.2 says the field "carries the HTTP status code", and int.Parse's
    // default leniency about signs and surrounding whitespace is not that.
    private static int ReadStatus(ImmutableArray<TlsQuicHttp3Field> fields)
    {
        for (var i = 0; i < fields.Length; i++)
        {
            if (!string.Equals(fields[i].Name, StatusName, StringComparison.Ordinal))
            {
                continue;
            }

            return int.TryParse(
                fields[i].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var status)
                ? status
                : -1;
        }

        return -1;
    }

    // Task C8's decoder, into scratch that doubles until it fits. See the two Initial...
    // constants on why there is no computed bound.
    private bool TryDecodeFieldSection(
        ReadOnlySpan<byte> payload,
        out ImmutableArray<TlsQuicHttp3Field> fields,
        out ulong errorCode)
    {
        fields = [];
        errorCode = NoError;

        var buffer = new byte[InitialDecodeBufferLength];
        var lines = new TlsQuicQpackDecodedFieldLine[InitialDecodeLineCount];
        int count;
        ulong requiredInsertCount;

        while (!TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                   payload, buffer, lines, _maximumFieldSectionSize, _table,
                   out count, out _, out requiredInsertCount, out var qpackError))
        {
            // C16, AND IT MUST COME BEFORE THE MAPPING BELOW. s2.2.1's Blocked is not a
            // rejection - the same bytes decode once the encoder stream catches up - and
            // TryGetHttp3ErrorCode answers false for it precisely so that it is never mapped.
            // The call below IGNORES that answer and writes QPACK_DECOMPRESSION_FAILED
            // regardless, so a Blocked reaching it closes a healthy connection over ordinary
            // QUIC stream reordering. Nothing is consumed and no field is emitted here; the
            // caller re-presents the same payload.
            if (qpackError == TlsQuicQpackError.Blocked)
            {
                IsBlocked = true;
                BlockedRequiredInsertCount = requiredInsertCount;
                return false;
            }

            // DestinationTooSmall is the ONLY error that says the scratch was short rather
            // than the peer wrong - TryGetHttp3ErrorCode draws that same line, and it is the
            // line that makes this loop terminate instead of spinning on a bad field section.
            if (qpackError != TlsQuicQpackError.DestinationTooSmall)
            {
                TlsQuicQpackDecoder.TryGetHttp3ErrorCode(qpackError, out errorCode);
                return false;
            }

            buffer = new byte[buffer.Length * 2];
            lines = new TlsQuicQpackDecodedFieldLine[lines.Length * 2];
        }

        // s2.2.2.1's MUST, recorded rather than sent: this class has no decoder stream. s4.4.1
        // bounds it to a non-zero declared Required Insert Count, which on the static-only arm
        // is never.
        if (requiredInsertCount != 0)
        {
            _sectionAcknowledgments.Add(requiredInsertCount);
        }

        IsBlocked = false;
        BlockedRequiredInsertCount = 0;

        var decoded = ImmutableArray.CreateBuilder<TlsQuicHttp3Field>(count);
        for (var i = 0; i < count; i++)
        {
            decoded.Add(new TlsQuicHttp3Field(
                Encoding.UTF8.GetString(buffer, lines[i].NameOffset, lines[i].NameLength),
                Encoding.UTF8.GetString(buffer, lines[i].ValueOffset, lines[i].ValueLength)));
        }

        fields = decoded.MoveToImmutable();
        return true;
    }

    private bool Fail(ulong code, out ulong errorCode)
    {
        _errorCode = code;
        errorCode = code;
        return false;
    }
}

// ============================================================================
// THE MUTATION LEDGER - TASK C10b (both halves of this file, and the enum in
// TlsQuicHttp3Frames.cs that rows C10b-1 to C10b-4 mutate)
// ============================================================================
//
//   ROWS BELOW                   39  = C10b-1 to C10b-39 with no gaps
//   KILLED WHEN FIRST RUN        37  = 39 rows, less 2 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      2  = rows C10b-37 and C10b-39
//   SURVIVING STILL               0
//
// THE PREFIX IS `C10b-`, WHICH KEEPS THREE LEDGERS APART IN TWO FILES. C9's header pins
// `grep -cE '^// +[0-9]+\. '` at 45 and C10's pins `grep -cE '^//   C10-[0-9]+\. '` at 50;
// `C10b-` matches neither, because C9's needs a digit where this has a `C` and C10's needs a
// `-` where this has a `b`. Both were re-run after this ledger landed and still return 45/2/2
// and 50/2/2. This ledger's own three, from this file's directory:
//   `grep -cE '^//   C10b-[0-9]+\. ' TlsQuicHttp3Request.cs`                  must return 39
//   `grep -cE '^//   C10b-[0-9]+\. \[WAS-SURVIVOR\]' TlsQuicHttp3Request.cs`  must return 2
//   `grep -cE '^//   C10b-[0-9]+\. \[SURVIVED\]' TlsQuicHttp3Request.cs`      must return 0
//
// Every row was applied to a PRIVATE `git worktree` of this branch, one edit at a time, each
// restored before the next, against `dotnet test --filter
// "FullyQualifiedName~TlsQuicHttp3Request|FullyQualifiedName~TlsQuicHttp3Frames"` - a 192-case
// suite. The worktree is not the usual hygiene here but a necessity: a concurrent task was
// editing TlsQuicHttp3Streams.cs and adding TlsQuicHttp3Connection.cs in the shared tree
// throughout, and a sweep that mutates one file while another agent saves a second cannot tell
// a survivor from a race. Counts are per xUnit CASE, so a Theory failing in seven rows counts
// seven. All 39 counts come from ONE run against the FINAL suite AND the final source; the
// sweep was re-run whole twice - once after rows C10b-37 and C10b-39 gained witnesses, once
// after row C10b-33's theory was corrected - rather than mixing verdicts from three suites.
//
// THE HARNESS WAS DISTRUSTED FIRST, as C9's and C10's were and for the reason C9 records.
// Before any real row ran, a deliberate known-bad - `":status"` spelled `":statusQ"` - was
// applied and the harness reported KILLED with 47 failures. A harness that cannot fail is not a
// harness. The verdict is read from the run's own `Failed: <n>, Passed: <m>` line and nothing
// else; a build failure prints BUILD-ERROR, a non-result, and a pattern matching other than
// exactly once prints NO-MATCH rather than a verdict. The CS0162 shape C9's row 14 hit is
// avoided as both earlier ledgers avoid it: a guard is disabled as `COND && false`, never as a
// deleted clause.
//
// NO MUTATION HERE HAD A CONVERSE THAT WOULD HANG. C10 recorded two it declined to run for
// that reason; neither of this task's three checks sits on a loop, so the question does not
// arise and no row is omitted on those grounds.
//
// ROW C10b-33 IS THE ONE THAT CAUGHT A TEST RATHER THAN THE SOURCE, and it is the reason the
// sweep was worth running twice. FirstBodyPart is 17 bytes long, and the theory that pins
// NumberStyles.None originally read `" 17"` and `"+17"` - which under the relaxed-to-Integer
// mutant parse to exactly the body's length, AGREE with the sum, and pass. Two of six rows were
// witnessing nothing while looking like witnesses. The digits are now ones no body length can
// equal, and the row's count went 1 -> 3.
//
// THE CONNECT LIMITATION HAS NO ROWS, and that is a statement rather than an omission: nothing
// implements CONNECT, so there is no code to mutate. Its two tests pin the CONSEQUENCE of the
// s4.3.1 validator's shape, and the validator itself is C9's rows 12-15.
//
//   C10b-1. H3MessageError 0x010e -> 0x010f, which is H3_CONNECT_ERROR. Killed by 1,
//        TlsQuicHttp3FramesTests.TheErrorCodesAddedByC10bAreTheValuesSection81States.
//   C10b-2. H3MessageError 0x010e -> 0x0200, which is QPACK_DECOMPRESSION_FAILED - the exact
//        registry confusion the enum's own remarks warn about. Killed by 2: the value test and
//        .EveryErrorCodeExceptNoneLiesInsideSection81sContiguousRange, which fails because
//        0x0200 is outside s8.1's 0x0100..0x0110 run. Two independent kills for one mutant, and
//        deliberately so - the second is the one that catches a WRONG NEW member, not just a
//        wrong existing one.
//   C10b-3. H3NoError 0x0100 -> 0x0101. Killed by 1.
//   C10b-4. H3IdError 0x0108 -> 0x0107. Killed by 1. Rows 3 and 4 exist because C10b added
//        those two members to unblock the concurrent connection task, and a member added for
//        someone else is still a member something must check.
//   C10b-5. The connection-specific ban's `Array.IndexOf(...) >= 0` weakened to `> 0`, which
//        drops index 0 - and index 0 is `connection`. THE s7.6.1 TRAP, reproduced exactly: the
//        one name that is not in the extract's bullet list is the one an off-by-one loses.
//        Killed by 4, all of .TheConnectionFieldItselfIsRefusedThoughItIsNotOneOfTheFiveBullets
//        plus the `connection` row of the trailers-value theory.
//   C10b-6. The whole ban never taken, written `>= 0 && false`. THIS ROW IS THE PRE-CHANGE
//        BEHAVIOUR, so its 19 failures are the demonstration that the new cases fail against
//        the code as it stood before this task rather than an assertion that they would.
//   C10b-7. The TE carve-out removed, `&& !IsPermittedTe(...)` -> `&& true`, so s4.2's one
//        exception is refused. Killed by 1, .ATeFieldCarryingTrailersIsAcceptedAndEmitted -
//        which is the case a flat ban on s7.6.1's five names would break, and the reason the
//        capture task flagged it.
//   C10b-8. The carve-out keyed on the VALUE alone, so any of the six is permitted when it says
//        "trailers". Killed by 5 - every row of
//        .AConnectionSpecificFieldIsRefusedEvenWhenItsValueIsTrailers, which was written for
//        this row after it was spotted during planning. s4.2 says "The only exception to this
//        is the TE header field": only.
//   C10b-9. The TE value comparison Ordinal -> OrdinalIgnoreCase. Killed by 2, the "TRAILERS"
//        and "Trailers" rows. The comparer is a stated choice and not a default - see
//        IsPermittedTe - so it needed a witness on the side it actually refuses.
//   C10b-10. The carve-out drops its VALUE half, so `te: gzip` encodes. Killed by 7.
//   C10b-11. TrailersValue "trailers" -> "trailer". Killed by 1.
//   C10b-12. TeFieldName "te" -> "tex", which removes `te` from the banned list AND from the
//        exception at once. Killed by 7 - the exception's own cases still pass, which is the
//        point: only the refusals notice.
//   C10b-13. `connection` dropped from the list - the five-bullet misreading, arrived at by
//        deletion rather than by an off-by-one. Killed by 4, the same four as row C10b-5.
//   C10b-14. `proxy-connection` dropped. Killed by 2.
//   C10b-15. `keep-alive` dropped. Killed by 2.
//   C10b-16. `te` dropped from the list, so any TE value encodes. Killed by 7.
//   C10b-17. `transfer-encoding` dropped. Killed by 2. s4.1 bans this one twice over -
//        "Transfer codings ... are not defined for HTTP/3" - so it is the row a reader is most
//        likely to think redundant.
//   C10b-18. `upgrade` dropped. Killed by 2. Rows 13-18 are separate from row C10b-6 because a
//        single name deleted from a six-element list is the edit a careless merge actually
//        makes.
//   C10b-19. `host` ADDED to the list - the over-strict guess, `host` being connection-adjacent
//        in an HTTP/1.1 reader's mind and licensed by nothing in s7.6.1. Killed by 3, including
//        C9's .AnOrderMissingOnlyTheAuthorityIsAccepted, which needs a `host` field to exist.
//   C10b-20. `accept-encoding` ADDED, an ordinary field banned. Killed by 1. Rows 19 and 20 are
//        the direction the other eighteen do not measure: a ban is wrong when it is too WIDE as
//        well as when it is too narrow.
//   C10b-21. The ban reports PseudoHeaderAmongRegularFields instead of its own code. Killed by
//        19 - every ConnectionSpecificField expectation at once.
//   C10b-22. The :status refusal never taken, `status < 0` -> `status < -1`. THE OTHER
//        PRE-CHANGE ROW: 10 failures, which is the demonstration for item 1.
//   C10b-23. The :status refusal widened to `status <= 0`, refusing a status of 0. Killed by 1,
//        the "0" row of .APlainDecimalStatusIsAcceptedWhateverItsValue - which exists because
//        s4.3.2 bounds :status NOWHERE and an invented 100..599 range would refuse a response
//        the RFC permits.
//   C10b-24. The :status refusal reports H3_FRAME_UNEXPECTED. Killed by 10, including the
//        explicit NotEqual in .AResponseWithoutAStatusIsRefusedAsAMessageError: the frame
//        sequence in that script is perfectly legal and only the MESSAGE is malformed.
//   C10b-25. The trailer branch made conditional on the section carrying a :status, so a real
//        trailer section is refused as a response with none. Killed by 5. This row measures the
//        claim the source makes in words - that POSITION decides what a HEADERS frame is, which
//        is what keeps the new refusal off the trailers.
//   C10b-26. The file's MessageError constant pointed at H3_FRAME_ERROR. Killed by 16.
//   C10b-27. The never-having-content carve-out never applies, written `_body.Count == 0 &&
//        false`. Killed by 1, .ANonZeroContentLengthWithNoDataFrameAtAllIsNotRefused - the case
//        that stops this task refusing every HEAD response and every 304.
//   C10b-28. The Content-Length rule never applies at all, written `_body.Count >= 0`. THE
//        THIRD PRE-CHANGE ROW: 6 failures, the demonstration for item 3.
//   C10b-29. `declared != _body.Count` narrowed to `>`. Killed by 2, the under-declaring rows.
//   C10b-30. The same narrowed to `<`. Killed by 4. Rows 29 and 30 are why the disagreement
//        theory carries deltas of both signs; a single delta would have left one of them alive.
//   C10b-31. ContentLengthName misspelled. Killed by 6.
//   C10b-32. The content-length lookup Ordinal -> OrdinalIgnoreCase. Killed by 1,
//        .AnUppercaseContentLengthNameIsNotReadAsTheContentLength. The same contrast C10's row
//        C10-41 draws for :status holds here: these names are the PEER's and this file refuses
//        nothing for being malformed, so the comparison is reachable and had to be witnessed.
//   C10b-33. NumberStyles.None -> NumberStyles.Integer. Killed by 3. See the note above on why
//        this was 1 before the theory's digits were corrected.
//   C10b-34. Only the first content-length field consulted rather than every one. Killed by 1,
//        .TwoContentLengthFieldsThatDisagreeWithEachOtherAreRefused.
//   C10b-35. The rule reads TrailerFields instead of HeaderFields. Killed by 7.
//   C10b-36. The Content-Length refusal reports H3_FRAME_UNEXPECTED. Killed by 6.
//   C10b-37. [WAS-SURVIVOR] The Content-Length refusal not made sticky - `errorCode = ...;
//        return false;` in place of `Fail(...)`. SURVIVED the first sweep, and for precisely
//        the reason C10's row C10-5 records in a different place: after this refusal the reader
//        still holds every byte it needs, so the mutant RE-DERIVES the identical code on the
//        next call and the test's second, EMPTY call cannot tell them apart. The witness had to
//        hand over the bytes that would have SATISFIED the declared length -
//        .AContentLengthRefusalIsNotRevivedByTheDataThatWouldHaveSatisfiedIt - under which the
//        mutant accepts the very response it has already rejected. Now killed by 1.
//   C10b-38. IsComplete set BEFORE the Content-Length check, so a refused response also claims
//        to be complete. Killed by 1, the same test's IsComplete assertion.
//   C10b-39. [WAS-SURVIVOR] The Content-Length check hoisted ABOVE s7.1's truncated-frame
//        check, so a stream ending mid-frame reports H3_MESSAGE_ERROR instead of H3_FRAME_ERROR.
//        SURVIVED the first sweep because the witness written for it truncated the ONLY DATA
//        frame in its script - which leaves the body empty, hands row C10b-27's carve-out the
//        answer, and makes both orderings agree. A false witness that looked like a real one.
//        The script now carries a whole DATA frame ahead of the truncated one, so the body is
//        non-empty when the leftover check runs. Now killed by 1.
//
// ============================================================================

// ============================================================================
// THE MUTATION LEDGER - TASK C10c (the response half of this file: s4.1.2's
// Content-Length rule, whole)
// ============================================================================
//
//   ROWS BELOW                   23  = C10c-1 to C10c-23 with no gaps
//   KILLED WHEN FIRST RUN        21  = 23 rows, less 1 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVED, THEN WITNESSED      1  = row C10c-23
//   SURVIVING STILL               1  = row C10c-20
//
// THE PREFIX IS `C10c-`, WHICH KEEPS FOUR LEDGERS APART IN THIS ONE FILE. C9's header pins
// `grep -cE '^// +[0-9]+\. '` at 45, C10's pins `^//   C10-[0-9]+\. ` at 50 and C10b's pins
// `^//   C10b-[0-9]+\. ` at 39. `C10c-` matches none of them: C9's needs a digit where this has
// a `C`, C10's needs a `-` where this has a `b`, and C10b's needs a `b` where this has a `c`.
// All three were re-run after this ledger landed and still return 45/2/2, 50/2/2 and 39/2/0.
// This ledger's own three, from this file's directory:
//   `grep -cE '^//   C10c-[0-9]+\. ' TlsQuicHttp3Request.cs`                  must return 23
//   `grep -cE '^//   C10c-[0-9]+\. \[WAS-SURVIVOR\]' TlsQuicHttp3Request.cs`  must return 1
//   `grep -cE '^//   C10c-[0-9]+\. \[SURVIVED\]' TlsQuicHttp3Request.cs`      must return 1
//
// Every row was applied to a PRIVATE `git worktree` of this branch, one edit at a time, each
// restored before the next, against `dotnet test --filter FullyQualifiedName~Quic` - a
// 1748-case suite. The worktree is not hygiene here but a necessity, and for a sharper reason
// than C10b's: TWO other tasks were editing this tree throughout, and the recipe this project's
// handoff recommends - `taskkill /F /IM testhost.exe` before each run - matches EVERY agent's
// test host rather than one's own. Three agents following it abort each other's runs. A
// worktree does not need the kill at all.
//
// AN ABORTED RUN LOOKS LIKE A PASS, AND THAT IS THE TRAP THIS SWEEP ACTUALLY HIT. A test host
// killed mid-run prints a perfectly ordinary `Failed: 0, Passed: <m>` line with a SMALLER m, so
// it reads as "no test noticed the mutant" - a survivor that never ran. The harness therefore
// reads the run's own `Total:` and rejects anything that is not EXACTLY 1748, retrying the row
// up to five times. Twelve runs across the earlier passes were discarded that way, and every
// count below comes from ONE final sweep against the FINAL suite AND the final source.
//
// THE HARNESS WAS DISTRUSTED FIRST, as all three earlier ledgers record, and in BOTH directions
// inside that same final run: a known-bad - `"content-length"` spelled `"content-lengthZ"` -
// reported KILLED with 28 failures, and an inert comment inserted above
// IsDefinedAsNeverHavingContent reported SURVIVED with 0. A harness that cannot fail is not a
// harness, and one that cannot pass is measuring something else. A build failure prints
// BUILD-ERROR, a non-result; a pattern matching other than exactly once prints NO-MATCH. The
// CS0162 shape C9's row 14 hit is avoided as all three earlier ledgers avoid it: a guard is
// disabled as `COND && false`, never as a deleted clause.
//
// THE BUILD IS `--no-incremental`, AND THAT IS ROW C10c-23's DOING. A C# optional-parameter
// default is baked into the CALLING assembly, so a mutation to this type's `requestMethod`
// default is invisible unless the TEST project is recompiled too - an incremental build that
// refreshes only the library reports that row a survivor when it is not one. The same class of
// staleness has a second route worth naming: `Copy-Item` PRESERVES the source file's timestamp,
// so copying an edited file into the worktree can leave MSBuild believing it is up to date and
// skipping the compile outright.
//
//   C10c-1. The escape never applies, `_body.Count == 0 && false && Is...()`, so s4.1.2's rule
//        binds even a 204. Killed by 5.
//   C10c-2. The escape drops its zero-DATA half, `_body.Count >= 0`, so a 304 that carried DATA
//        is excused. Killed by 3 - every row of
//        .AResponseThatNeverHasContentIsStillHeldToItsLengthOnceDataArrives, which exists
//        because s4.1.2 licences the mismatch only "even though no content is included in DATA
//        frames".
//   C10c-3. The escape drops its s6.4.1 half, `(Is...() || true)` - EXACTLY C10b's blanket
//        zero-DATA carve-out restored. THE PRE-CHANGE ROW: 19 failures, which is the
//        demonstration that this task's cases fail against the code as it stood rather than an
//        assertion that they would.
//   C10c-4. The HEAD arm never taken, `(string.Equals(...) && false)`. Killed by 1,
//        .AHeadResponseMayDeclareAContentLengthItSendsNoDataFor.
//   C10c-5. HeadMethod "HEAD" -> "HEADX". Killed by 1.
//   C10c-6. HeadMethod "HEAD" -> "GET" - the escape aimed at the wrong method, which is the
//        direction a narrowing mutation does not measure. Killed by 2.
//   C10c-7. The HEAD comparison Ordinal -> OrdinalIgnoreCase. Killed by 2, the "head" and
//        "Head" rows of .OnlyAMethodSpelledAsRfc9110SpellsItEscapesTheContentLengthRule. The
//        comparer is a stated choice and not a default, so it needed a witness on the side it
//        refuses.
//   C10c-8. The CONNECT arm never taken, `&& Status is >= 200 and <= 299 && false`. Killed by 2.
//   C10c-9. ConnectMethod "CONNECT" -> "CONNECTX". Killed by 2.
//   C10c-10. The CONNECT comparison Ordinal -> OrdinalIgnoreCase. Killed by 2, the "connect" and
//        "Connect" rows - which are in that theory precisely because the status it scripts is a
//        2xx and so reaches this arm.
//   C10c-11. The CONNECT arm ignores the method, `string.Equals(ConnectMethod, ConnectMethod,
//        ...)`, so EVERY 2xx escapes. Killed by 13. Written that way rather than by deleting the
//        comparison because an unused private const is an error under this build's
//        TreatWarningsAsErrors, and a build error is a non-result rather than a verdict.
//   C10c-12. The CONNECT range drops its `>= 200` half. Killed by 1, the "0" row of
//        .OnlyATwoHundredLevelResponseToAConnectEscapesTheRule - which exists for this row,
//        since s4.3.2 bounds :status nowhere and a sub-100 status is a legal one to parse.
//   C10c-13. The same drops its `<= 299` half. Killed by 2, the "300" and "502" rows.
//   C10c-14. The same widened to `<= 300`. Killed by 1, the "300" row.
//   C10c-15. The same narrowed to `>= 201`. Killed by 1, the "200" row. Rows 12-15 are four
//        separate edits because s6.4.1 says "2xx (Successful) responses to a CONNECT request
//        method", and a range has four ways to be wrong.
//   C10c-16. The 204 arm dropped. Killed by 1.
//   C10c-17. The 304 arm dropped. Killed by 1.
//   C10c-18. 204 -> 205. Killed by 2 - the "204" row of the acceptance theory and the "205" row
//        of the refusal theory, which is why both theories carry the neighbours.
//   C10c-19. 304 -> 305. Killed by 2, symmetrically.
//   C10c-20. [SURVIVED] The 1xx arm dropped, `|| Status is 204 or 304` - THE FOUR-CASE LIST this
//        file's own comment carried until C10c, arrived at by deletion. UNREACHABLE BY
//        CONSTRUCTION, and no test is written. TryAcceptHeaders routes every 100..199 field
//        section into _interim and returns WITHOUT advancing the stage, so Status - which is the
//        FINAL response's - is never 1xx and this arm cannot fire. A 1xx escapes s4.1.2's rule
//        by never reaching the check rather than by this arm, which is what
//        .AnInterimResponseDeclaringAContentLengthIsNotRefused pins and what that case says in
//        its own comment that it does NOT witness. A test written to "witness" this arm would
//        have to make a 1xx the final response, which no input can do; it would pass against the
//        mutant and be a false witness. The arm stays for the reason C9's row 33 keeps its
//        Ordinal `host` lookup: it is one reordering of TryAcceptHeaders away from being
//        reachable, and s6.4.1 states the case outright - "All 1xx (Informational), 204 (No
//        Content), and 304 (Not Modified) responses do not include content."
//   C10c-21. The 1xx range widened to `>= 100 and <= 299`, so every 2xx escapes without any
//        method. Killed by 13. Rows 20 and 21 are the two directions of the same arm and only
//        one of them is reachable - which is itself the evidence that row 20's verdict is about
//        reachability and not about the tests being thin.
//   C10c-22. The constructor discards the method it is handed. Killed by 3.
//   C10c-23. [WAS-SURVIVOR] The constructor's DEFAULT changed from null to HeadMethod, so every
//        caller that names no method escapes the rule. SURVIVED the first sweep, and the reason
//        is a general defect in a suite with helpers: ReadWhole and Refuse pass requestMethod
//        EXPLICITLY - null is still an argument - so the C# default was never once exercised,
//        and all twenty-seven of this task's other cases passed against the mutant. The default
//        is not a formality: TlsQuicHttp3Connection constructs this type with the field-section
//        limit alone, so what the default MEANS is what the connection DOES. Witnessed by
//        .TheDefaultConstructorNamesNoMethodAndSoExcusesNoContentLength, which constructs
//        `new TlsQuicHttp3Response()` and nothing else. Now killed by 1.
//
// ============================================================================


// ============================================================================
// THE MUTATION LEDGER - TASK C16 (this file: parking a blocked field section
// and re-presenting the same bytes)
// ============================================================================
//
//   ROWS BELOW                    7  = C16-14 to C16-20 with no gaps
//   KILLED WHEN FIRST RUN         7  = 7 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVING STILL               0
//
//   The task's other 28 rows are in TlsQuicQpackDecoder.cs (11), TlsQuicQpackPrimitives.cs
//   (2), TlsQuicHttp3Streams.cs (7), TlsQuicHttp3Connection.cs (6) and TlsQuicHttp3Frames.cs
//   (2). 7 + 28 = 35 rows for the task.
//
// A UNIQUE ROW PREFIX, because this file already carries FOUR ledgers whose greps must keep
// returning 45, 50, 39 and 23. These rows carry `C16-` so none of them sees these. Their own
// three:
//   `grep -cE '^// +C16-[0-9]+\. ' TlsQuicHttp3Request.cs`                  must return 7
//   `grep -cE '^// +C16-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicHttp3Request.cs` must return 0
//   `grep -cE '^// +C16-[0-9]+\..*\[SURVIVED\]' TlsQuicHttp3Request.cs`     must return 0
//
// Same harness, same gate and the same three harness defects as TlsQuicQpackDecoder.cs's C16
// block, which records them in full.
//
//  C16-14. The Blocked arm deleted from TryDecodeFieldSection, so Blocked reaches
//        TryGetHttp3ErrorCode and its DISCARDED return value leaves 0x0200 in `errorCode`.
//        Killed by 10. THIS IS THE LIVE BUG, from the caller's side - the half that was
//        already in the tree before C16 and was unreachable only because nothing could yet
//        return Blocked. IT WAS WITNESSED FAILING BEFORE THE FIX WENT IN: with the arm
//        disabled, the probe read `accepted=False error=0x200 blocked=False`.
//  C16-15. `offset = frameStart` deleted, so a blocked frame is CONSUMED and the section is
//        silently swallowed rather than parked. Killed by 6, including
//        .FramesBehindAParkedSectionAreNotReadPastIt - the row that says s2.2.1 blocks the
//        STREAM and not the frame, so a DATA frame behind a parked HEADERS must not be read
//        past it and a body must not be assembled for a response with no header section.
//  C16-16. IsBlocked never cleared on a successful decode, so a section that unblocked is
//        re-presented forever and the response never completes. Killed by 5.
//  C16-17. The FIN guard left unqualified, so leftover bytes at the FIN become s7.1's
//        H3_FRAME_ERROR. Killed by 5. A peer may LEGALLY FIN while the encoder instructions
//        its section needs are still in flight - that is s2.1.2's whole premise - so what is
//        left here is a frame a later pump completes, not one no further byte ever will.
//  C16-18. s4.4.1's non-zero condition inverted, so a section that used no dynamic entry is
//        acknowledged and one that did is not. Killed by 2. Acknowledging a zero-count section
//        is a QPACK_DECODER_STREAM_ERROR at the peer's encoder, so both halves are faults.
//  C16-19. The parked Required Insert Count recorded as zero, so a caller cannot tell the
//        stream apart from an unblocked one. Killed by 2.
//  C16-20. The table dropped at the decode call, so every response takes C8's static-only arm
//        however much capacity was advertised - which IS the shipped-defaults defect this
//        whole arm exists to close. Killed by 12.
//
// ============================================================================


// ============================================================================
// THE MUTATION LEDGER - TASK H3B (this file: RFC 9114 s4.1's content and
// trailer section, and s4.1.2's Content-Length rule on the SEND side)
// ============================================================================
//
//   ROWS BELOW                   15  = 2 calibration + H3B-01..H3B-11 + H3B-16 + H3B-17
//   KILLED BY A FAILING CASE     14  = 15 rows, less the 1 deliberate compiler row
//   KILLED-BY-COMPILER            1  = H3B-00-CAL-COMPILER, which is what that row is for
//   SURVIVED                      0
//
//   14 + 1 = 15. The task's other 4 rows are in TlsQuicHttp3Connection.cs (H3B-12 to
//   H3B-15). 15 + 4 = 19 rows for the task, 0 survivors.
//
// A UNIQUE ROW PREFIX, because this file already counts `C9-`, `C10-` and `C16-`. Its own
// three:
//   `grep -cE '^// +H3B-[0-9A-Z-]+\. ' TlsQuicHttp3Request.cs`                  must return 15
//   `grep -cE '^// +H3B-[0-9A-Z-]+\..*\[RESTATED\]' TlsQuicHttp3Request.cs`     must return 1
//   `grep -cE '^// +H3B-[0-9A-Z-]+\..*\[SURVIVED\]' TlsQuicHttp3Request.cs`     must return 0
//
// THE HARNESS: scratchpad/h3body-ws/mutate-h3body.py, run in a PRIVATE COPY of the tree
// rather than in a git worktree - `dotnet restore` fails inside a worktree in this
// repository (NuGet.targets(789,5), path1 null), which is pre-existing and reproduces at
// pristine HEAD. Verdicts are STRUCTURAL: the build's own exit code is KILLED-BY-COMPILER,
// and the failure count comes from the runner's summary line. NO PIPELINES, so no exit code
// read is some tail's rather than the compiler's. A CASE-COUNT FLOOR of 2372 makes a run
// that silently matched fewer cases HARNESS-BROKEN rather than a clean sheet.
//
// GATE: `dotnet test --filter "FullyQualifiedName~Quic"`. 2334 passing at pristine HEAD
// (3d1fbef), 2367 passing after, 0 failing both times. Not the full suite, which has 3
// pre-existing failures unrelated to this file.
//
// BOTH CALIBRATION ROWS MUTATE SOMETHING REAL, which is the point of having two. `if (true)`
// and `if (false)` both come back KILLED-BY-COMPILER here (CS0162 is an error in this tree),
// so neither would be evidence of anything.
//
//  H3B-00-CAL-LIVE. Killed by 27. The body guard compared against 1_000_000_007, so no body
//        is ever emitted. A legal comparison and a wrong one - which is what says the
//        harness's edit reaches the compiled assembly rather than a stale binary.
//  H3B-00-CAL-COMPILER. KILLED-BY-COMPILER, deliberately. An undeclared identifier in the
//        same guard. This is the row that says a non-zero build exit is read as a verdict and
//        not silently as a passing gate.
//  H3B-01. Killed by 37. `body.Length != 0` inverted, so an empty DATA frame rides every GET
//        and no request that has content carries one.
//  H3B-02. Killed by 27. The guard made unconditional, so a body-less GET grows the two
//        octets 00 00. THE FINGERPRINT DEFECT THIS TASK WAS MOST LIKELY TO SHIP, and 27 cases
//        separate it - among them the recorded transcript in
//        TlsQuicConnectionTests.AGetsBytesOnTheWireAreUnchangedByTheBodyPath, whose value was
//        measured at pristine HEAD and not regenerated from the code it checks.
//  H3B-03. Killed by 7. s7.2.1's DATA type written as s7.2.2's HEADERS type.
//  H3B-04. Killed by 6. The last body octet dropped, so the DATA length stops matching the
//        Content-Length that was already validated against it.
//  H3B-05. Killed by 5. The whole trailing-HEADERS block deleted: a trailer section is
//        validated, accepted, and silently never sent.
//  H3B-06. [RESTATED] Killed by 5. s4.1.2's comparison made vacuous - `length < 0` is never
//        true of a parsed non-negative count, so every parseable Content-Length agrees with
//        every body. As first written it compared `length` with itself, which CS1718 makes an
//        ERROR here; KILLED-BY-COMPILER is weaker evidence than a failing case, so the same
//        defect was restated in a form that compiles. The same reason C15-44, C15-45 and
//        C16-31 were restated.
//  H3B-07. Killed by 5. An unparseable Content-Length ignored rather than refused - the
//        RECEIVE side's leniency applied to the side that CHOOSES the number. The asymmetry
//        is deliberate and TryValidateContentLength's comment argues it; this row is what
//        says the argument is load-bearing rather than decorative.
//  H3B-08. Killed by 1. Only a content-length in the first field position is checked, so a
//        second one that disagrees is sent. Killed by exactly one case,
//        .ASecondContentLengthThatDisagreesIsStillCaught, which is the only test in the tree
//        that puts two of that field in one request.
//  H3B-09. Killed by 1. s4.3's two sentences collapsed onto
//        PseudoHeaderAmongRegularFields, so a caller cannot tell which section carried the
//        pseudo-header. Killed by exactly one case,
//        .APseudoHeaderInTheTrailerSectionNamesTheTrailerRule, which asserts BOTH members
//        side by side - a test that checked only "it was refused" would let the two swap.
//  H3B-10. Killed by 5. TryValidateFieldSection's answer thrown away on the trailer arm, so
//        s4.2's uppercase rule and connection-specific ban stop reaching trailers. This row
//        is the whole argument for reusing the validator rather than writing a second one.
//  H3B-11. Killed by 10. s4.1.2's whole check computed and discarded.
//  H3B-16. Killed by 10. The whole DATA block deleted: s4.1's item 2 never reaches the wire
//        while the Content-Length that describes it still does.
//  H3B-17. Killed by 2. The trailing HEADERS frame encodes the HEADER section's lines, so the
//        trailer section arrives full of the pseudo-headers s4.3 forbids there.
