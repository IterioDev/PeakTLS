namespace SharpTls.Tests.ClientHello;

/// <summary>
/// Byte-parity between each shipped QUIC profile and one whole captured ClientHello.
/// <para>The sibling <see cref="SpotifyIosQuicProfileWireTests"/> pins two fields. Everything
/// else in the profile - the extension order, the ten signature algorithms with their duplicate,
/// the GREASE class pattern, the status_request and compress_certificate bodies, the transport
/// parameters and their encodings - could be edited and both that test and the live JA4 stayed
/// green, because nothing compared the whole message to a real one.</para>
/// <para>The comparison normalises exactly what a real client redraws per connection: the
/// 32-byte random, the GREASE codepoints (rewritten to their first-seen INDEX, so the class
/// pattern - supported_groups and key_share drawing alike, the other four drawing apart - is
/// still asserted, EXCEPT for iOS 26, where one capture cannot support it and the assertion is
/// withdrawn on purpose), the ECDHE key-share bodies, and the transport-parameter rotation.
/// Nothing else is masked; a one-byte drift anywhere else fails these tests.</para>
/// </summary>
public sealed class SpotifyIosQuicCaptureParityTests
{
    [Fact]
    public void TheProfileReproducesTheCapturedHelloByteForByte()
    {
        var captured = Convert.FromHexString(CapturedHelloHex);
        var built = ClientHelloProfiles.Spotify917602050IOS270Quic
            .BuildDeterministicForTesting("login5.spotify.com", [7, 7, 4, 2]);

        // Length first: it is the one assertion whose failure message is readable, and a profile
        // that gained or lost an extension fails here before the hex diff.
        Assert.Equal(captured.Length, built.Length);
        Assert.Equal(
            Convert.ToHexString(Normalise(captured)),
            Convert.ToHexString(Normalise(built)));
    }

    /// <summary>
    /// The same comparison for the iOS 26 profile, with ONE ASSERTION WITHDRAWN: the GREASE
    /// class pattern. This capture shows cipher_suites and supported_versions drawing the same
    /// value and the second GREASE extension drawing supported_groups', where the iOS 27 profile
    /// - and the policy both profiles share - has five of the six slots drawing apart.
    /// Independent draws land that way about once in 256, so one hello cannot tell a pattern
    /// from a coincidence, and asserting either reading would be inventing a measurement.
    /// Everything else is compared byte for byte.
    /// </summary>
    [Fact]
    public void TheIos26ProfileReproducesItsCapturedHelloByteForByte()
    {
        var captured = Convert.FromHexString(CapturedIos26HelloHex);
        var built = ClientHelloProfiles.Spotify917602050IOS260Quic
            .BuildDeterministicForTesting("login5.spotify.com", [7, 7, 4, 2]);

        Assert.Equal(captured.Length, built.Length);
        Assert.Equal(
            Convert.ToHexString(Normalise(captured, preserveGreaseClasses: false)),
            Convert.ToHexString(Normalise(built, preserveGreaseClasses: false)));
    }

    /// <summary>
    /// The two profiles are ten bytes and one cipher swap apart, and this states which ten. A
    /// change that moved any other field would have to move it in both captures to stay hidden
    /// from the two parity tests above; this one fails if the profiles converge or diverge
    /// anywhere else.
    /// </summary>
    [Fact]
    public void TheTwoProfilesDifferOnlyInCipherOrderAndTheVendorParameter()
    {
        var ios26 = ClientHelloProfiles.Spotify917602050IOS260Quic
            .BuildDeterministicForTesting("login5.spotify.com", [7, 7, 4, 2]);
        var ios27 = ClientHelloProfiles.Spotify917602050IOS270Quic
            .BuildDeterministicForTesting("login5.spotify.com", [7, 7, 4, 2]);

        Assert.Equal(10, ios27.Length - ios26.Length);

        var vendor = Convert.ToHexString(
            [0xC0, 0x00, 0x00, 0x00, 0xFF, 0x08, 0x08, 0x08, 0x01, 0x09]);
        Assert.Contains(vendor, Convert.ToHexString(ios27), StringComparison.Ordinal);
        Assert.DoesNotContain(vendor, Convert.ToHexString(ios26), StringComparison.Ordinal);

        Assert.Contains(
            Convert.ToHexString([0x13, 0x02, 0x13, 0x01, 0x13, 0x03]),
            Convert.ToHexString(ios26),
            StringComparison.Ordinal);
        Assert.Contains(
            Convert.ToHexString([0x13, 0x02, 0x13, 0x03, 0x13, 0x01]),
            Convert.ToHexString(ios27),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The masking above is the whole risk in this file: normalise too much and the comparison
    /// passes on a profile that no longer matches. Offset 127 is the second byte of the first
    /// signature algorithm (0x0403), a field nothing here is supposed to mask.
    /// </summary>
    [Fact]
    public void TheComparisonDoesNotMaskAwayADriftedField()
    {
        var mutated = Convert.FromHexString(CapturedHelloHex);
        mutated[127] ^= 0xFF;

        Assert.NotEqual(
            Convert.ToHexString(Normalise(Convert.FromHexString(CapturedHelloHex))),
            Convert.ToHexString(Normalise(mutated)));
    }

    /// <summary>Rewrites the per-connection draws to fixed stand-ins, on a copy.</summary>
    /// <param name="hello">The ClientHello handshake message.</param>
    /// <param name="preserveGreaseClasses">Whether two slots drawing the SAME GREASE value must
    /// still compare equal afterwards and two drawing apart must still compare different. False
    /// flattens every GREASE codepoint to one stand-in, which withdraws the class assertion
    /// entirely - correct only where the capture cannot support it.</param>
    private static byte[] Normalise(byte[] hello, bool preserveGreaseClasses = true)
    {
        var buffer = (byte[])hello.Clone();
        var grease = preserveGreaseClasses ? new List<ushort>() : null;
        var i = 4;                                  // handshake header
        i += 2;                                     // legacy_version
        buffer.AsSpan(i, 32).Clear();               // random
        i += 32;
        i += 1 + buffer[i];                         // legacy_session_id
        var cipherLength = Read16(buffer, i);
        i += 2;
        for (var c = 0; c < cipherLength; c += 2)
        {
            MaskGrease(buffer, i + c, grease);
        }

        i += cipherLength;
        i += 1 + buffer[i];                         // legacy_compression_methods
        var extensionsEnd = i + 2 + Read16(buffer, i);
        i += 2;
        while (i < extensionsEnd)
        {
            var type = Read16(buffer, i);
            var length = Read16(buffer, i + 2);
            MaskGrease(buffer, i, grease);
            NormaliseExtension(type, buffer.AsSpan(i + 4, length), grease);
            i += 4 + length;
        }

        return buffer;
    }

    private static void NormaliseExtension(ushort type, Span<byte> body, List<ushort>? grease)
    {
        switch (type)
        {
            case 10:                                // supported_groups
                for (var g = 2; g + 1 < body.Length; g += 2)
                {
                    MaskGrease(body, g, grease);
                }

                break;

            case 43:                                // supported_versions
                for (var v = 1; v + 1 < body.Length; v += 2)
                {
                    MaskGrease(body, v, grease);
                }

                break;

            case 51:                                // key_share
                MaskKeyShares(body[2..], grease);
                break;

            case 57:                                // quic_transport_parameters
                RotateTransportParametersToCanonicalStart(body);
                break;

            default:
                break;
        }
    }

    /// <summary>Keeps every share group and length, zeroing the ephemeral public key.</summary>
    private static void MaskKeyShares(Span<byte> shares, List<ushort>? grease)
    {
        var i = 0;
        while (i + 4 <= shares.Length)
        {
            MaskGrease(shares, i, grease);
            var length = Read16(shares, i + 2);
            shares.Slice(i + 4, length).Clear();
            i += 4 + length;
        }
    }

    /// <summary>
    /// Undoes the per-connection cyclic rotation by rotating the block back to the one that
    /// leads with initial_max_data (0x04). The trailing vendor parameter does not rotate and is
    /// left where it is. Raw varint encodings are MOVED, never re-encoded, so a change to any
    /// parameter encoding width still fails the comparison.
    /// </summary>
    private static void RotateTransportParametersToCanonicalStart(Span<byte> parameters)
    {
        var entries = new List<(int Offset, int Length, ulong Id)>();
        var i = 0;
        while (i < parameters.Length)
        {
            var start = i;
            var id = ReadVarint(parameters, ref i);
            var length = (int)ReadVarint(parameters, ref i);
            i += length;
            entries.Add((start, i - start, id));
        }

        // The vendor parameter trails and stays put WHEN IT IS THERE. iOS 26 sends only the
        // seven, and treating its last entry as pinned would leave 0x0f out of the rotation and
        // quietly compare a different block than the one the client rotates.
        var rotating = entries[^1].Id == 0xFF08_0808 ? entries.Count - 1 : entries.Count;
        var lead = entries.FindIndex(e => e.Id == 0x04);
        if (rotating < 2 || lead <= 0 || lead >= rotating)
        {
            return;
        }

        var blockLength = 0;
        for (var k = 0; k < rotating; k++)
        {
            blockLength += entries[k].Length;
        }

        var rotated = new byte[blockLength];
        var written = 0;
        for (var k = 0; k < rotating; k++)
        {
            var entry = entries[(k + lead) % rotating];
            parameters.Slice(entry.Offset, entry.Length).CopyTo(rotated.AsSpan(written));
            written += entry.Length;
        }

        rotated.CopyTo(parameters[..blockLength]);
    }

    /// <summary>
    /// Rewrites a GREASE codepoint to its first-seen index. Two slots that drew the same value
    /// keep the same stand-in and two that drew apart keep different ones, so the class pattern
    /// survives the masking - which is the part of the GREASE that is a fingerprint rather than
    /// noise.
    /// </summary>
    private static void MaskGrease(Span<byte> buffer, int offset, List<ushort>? grease)
    {
        var value = Read16(buffer, offset);
        if ((value & 0x0F0F) != 0x0A0A || (value >> 8) != (value & 0xFF))
        {
            return;
        }

        if (grease is null)
        {
            buffer[offset] = 0xEE;
            buffer[offset + 1] = 0xFF;
            return;
        }

        var index = grease.IndexOf(value);
        if (index < 0)
        {
            index = grease.Count;
            grease.Add(value);
        }

        buffer[offset] = 0xEE;
        buffer[offset + 1] = (byte)index;
    }

    private static ushort Read16(ReadOnlySpan<byte> buffer, int offset) =>
        (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

    private static ulong ReadVarint(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var width = 1 << (buffer[offset] >> 6);
        var value = (ulong)(buffer[offset] & 0x3F);
        for (var k = 1; k < width; k++)
        {
            value = (value << 8) | buffer[offset + k];
        }

        offset += width;
        return value;
    }

    /// <summary>
    /// The QUIC Initial ClientHello of Spotify 9.1.76.2050 / iOS 27.0 to
    /// <c>login5.spotify.com</c>, reassembled from the two Initial CRYPTO frames of one
    /// first-party capture. JA3 <c>48d08f334704479db85d91df80039756</c>, JA4
    /// <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c>. A handshake message, so it starts at the
    /// 4-byte handshake header and carries no TLS record header.
    /// </summary>
    private const string CapturedHelloHex = ""
        + "010005CF03039AB17A8E9DA25117FADDAAF9FC08A99659DFDB6875BA55639A49AB63BB53A6D80000082A2A130213"
        + "0313010100059EBABA00000000001700150000126C6F67696E352E73706F746966792E636F6D000A000E000C5A5A"
        + "11EC001D001700180019001000050003026833000500050100000000000D00160014040308040401050308050805"
        + "050108060601020100120000003304EF04ED5A5A00010011EC04C035A05F4B46062DA681F0B20640956A1A91AD40"
        + "62C989F00637E2349C765BF80289DC4229DD23A51FF2755276347F1B8CF13A78853B74BDE096B402A12EDB2B41D8"
        + "CED34B48DFA5533A558D25927FDA68B4809657DA836BA052911E6AC269C5A364A66627D89D4B6C8BE164038D196B"
        + "400B8594F4A97744B0E4944F1AFC2366C14770C213B57908F0D5C879010D7A0839301174AE4A7F0C8113863683C3"
        + "F6B47A267E3B2C3E2728C8AAA081E8833A49742AEF8301B5402FAF14445AA6A970701D0F8345CDCAACBE01146305"
        + "104E094DE4A133DB370F9DC90274C0C01B95039E548FED3C06A8E81A35253FCE8C9162C08572D888EB15BEE44565"
        + "6ED35E292493F2F014CCC11A6E348E174673FF944591943C92B8081AC1141789CC3E8B5364263ADDF28C0CA22C32"
        + "293B22D054FF8C8942F76AC2507CEB584D2F59A1BF3798E5544226F4345AF61AC4874F67578DB77255F025A79AC5"
        + "3667E12040204AA8E99F4DDCA16DA0384F59208F825538E08069558573B09B778730FF65957FCB099888BB4D724F"
        + "3AC86810D803A39863FF457E96C81BCED9B4DB018A9A439DFA1A835180162C79816BE5C75556663085A6A59ABE68"
        + "E5485909C2CAFB8FF7C24B4E60AB585B530D8B8EFCCBAB0FD4A7442025AB20C0DB5512DA5B4370E8692D933D7D70"
        + "9278A25D56B1A5F52AB3E19BB477E4AACB11B77DD34C3AB87D93FCB60833C88704B572069315C9C992D85124C38D"
        + "2C71C57B4B58FA2425DFA9575F1785A3172B9F5CAA337A31B1167DF1F5B4EBDA6E57512A02337B9FB6CC37D6BB91"
        + "E10BFC525A94D42044924BF69416C240A036F32B039B14057835559C90A2770F477C88B2C6961220ABF47499ED60"
        + "9746E856B3517DF9013451F4467E6056643429BA129A968777CEC99B9C926AAC3531772BB7D47A44E3AB7763BA8F"
        + "9F1C256B5B0A114974C08270F57706EF4A987D317995828C96BB9F7F78814BA56A1025BD55FB612CD28F2FF45164"
        + "8C4157E35C2B856280766EAA967DF0D0250FA7ABE4E95AE58C5E3262AB2844881D61BB49C0145C888926F65EC674"
        + "828F4378C6310C8EA3781E5C8894F71DEDC40DB7F19AC8C9BE346B295A855BB2057185176C116015D1638BCE9464"
        + "288A5F05B0741B23C120A007F630BDFC475111B6C4DF7C5BBF3AAB4C943551CC3A917C45D1F274CB13B59D1A78EB"
        + "03C9A801947B8A4816CAC1F9CA5900E527AC552BBB13CA95864630B36979B3CDD9483438878D4E105AC966A795F4"
        + "4F4F39470CA9614C298003F94E85E71F2E20080B53A6CF48840B8B535F4096493CA827CC164A33653A6168B50875"
        + "B2C02DB2BA9DF0358BD53407C179649233BE2D13A080E73FDB74807570A2B5C3BDE8DA94952308592741751C0482"
        + "854B6EBB6B5C13B69D7B280AA3C6BE834EEE6212100368B51C23BF017A3CE15BB0B51C544228EB18C7707ABFB920"
        + "77588C7C2C6498C4082FA88093A1D9459C366D96D85623F3BF9455B599079862F68C6F5946E84821547737EF7880"
        + "2119AD0319B0D42A20F71166BA67B53DC311676A6F39890B92B68EC52172E9BB3F1BDA47F06521890B136CCBA28E"
        + "C53A06817E679292C0346010981EFA8218CEA0815BC38F11020391C76E029122156506E06EEE1CCDBAFC1F4BD116"
        + "E587DDC011B59DE4AC332CCB56464B3DFFBB5BAFDA30C81A7A08D3616D0F769E98BC92A59B27478910E4DA10582A"
        + "4A001D0020C5FAE1F221C6DBD291815E46AA32910A49BCFE291E65AB0A180D0E3BA078813B002D00020101002B00"
        + "05048A8A03040039002B0E0240400F00040481000000050480200000060480200000070480200000090108C00000"
        + "00FF0808080109001B00030200019A9A000100";
    /// <summary>
    /// The QUIC Initial ClientHello of the same Spotify build on iOS 26 to
    /// <c>login5.spotify.com</c>, reassembled from its two Initial CRYPTO frames. JA3
    /// <c>2f9431e877b01e163774ae4ae0df9ded</c>, JA4 <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c>
    /// - the same JA4 as the capture above, which is why JA4 alone cannot pin either profile.
    /// </summary>
    private const string CapturedIos26HelloHex = ""
        + "010005C5030394FC6D36E2BEA57461EE202EFDB4232B4FB84DFC499DA88CEC3503EBB3B1E5FD0000088A8A130213"
        + "01130301000594DADA00000000001700150000126C6F67696E352E73706F746966792E636F6D000A000E000CAAAA"
        + "11EC001D001700180019001000050003026833000500050100000000000D00160014040308040401050308050805"
        + "050108060601020100120000003304EF04EDAAAA00010011EC04C0FC2980CB0148F3A8536052794BA877F01282EA"
        + "099B83F3CA745084A0CA7714A574EDF53BB20CA2A7DB032B0C57E43151303225EEDA91AEC0CF4A5A14C39A41D770"
        + "BBA03BAEB1037B2855774B520C4311BE1BF7028BC37E93304ACCC4BDC2EAA8D5B43954714D10919B76DBA9113A32"
        + "0F4556C767A31674AFE4A17C0239561C4C25591A1557282BF333BCFD8129394406A75BAC9FE82AE87855B26500D6"
        + "341C28D973BBA8AA2C349F8CE5BE6CCBBB37D7AC7A3B62DF824191D711F8C148BD795E49D69AC819B7BDA8829210"
        + "3A2396B6465BAFAFB22C66B5287CB031362BB33295389DD57C2E1C0C20F4454748729F834A5187817914785F8104"
        + "FE40044291396C562D24029741E4AFE765A4F55490B5BB3A6C118FA4595924B7C3C7F2C5B536842428B6C6C15038"
        + "C4CD2C860B95231A090413071CB49BBB0BAAC1AF7C0918849C708B948A3A9342E1BC4DF1820878F6CA93895C6BF9"
        + "9CBF9210A321991870251CDCA82065AED46AA3F3F28C90F245FA46B44BA2BB8F424B60A543927A7CEC479BAAD26E"
        + "96B30B6FA825A8A04CE0DC21903473F706332BC2BD7A4C49A2B8C4C5C42AE4F58D8E506ADAFBBF69B62685223630"
        + "A6B5EDA55D431A78BCCA67CE1155B4585553E8AAB2D07EC1802C95833547F074E6FA492A66C3F067167487CD3BCB"
        + "979BC7454F290DC9337015694411779DDEB5B9BC471742637356F05CE5A315FD51B173AA1F5B39346B0B0144F463"
        + "8BC19E75F841A14C2683E1314FBB0DE537570F86A271810FFB848E176ABA5105BCA1F03F4A7404AFC60F0DF0CB3D"
        + "951C59A69463AB41F4BB0B6F11327AEA91E47B86E727A214F50423EC1938D2C8DC7A71EE7705707B7DB6AA16E292"
        + "7F12BCA926740CA8D925D8753468F1B76C2C8157480085615EE1F3C4F62BB71BF81019822622C048B099A2A2FC85"
        + "2CF894FCF56BC099ADF48A2698220798E831488B6022CB9687E9816D08A840C77B6B930CA2FBB9472C80E6C995B4"
        + "96C6341A0DBE582EC4772C557C5CE84417839A3B9A58345770BD09C471D10105B9A959EF17CD5A656C14E01F8769"
        + "3405734444C9432E9BBF0CD5B68159181771C54DF27C138B94CEC771E7EA8851D0BAF78484A5D1352EA309B03673"
        + "A5D7A69EBA1098C62809755B261A47A9076E4558A0BA5B7D202195C220050CEC47CDD5C200D8BF8E947EA9053550"
        + "030C249883B5726E33AA20DD143E126BAAD43B2AD9A65A11E831AF8A6B95B59015A1963DB75C97CB2A9E02088440"
        + "CE4CFA3440ACC83C837CA607CE072A083C5B138B9B1067E3983725AC8C83CC7F182BCBC1A6E0493F62B6A6010A56"
        + "9019A1C9C5364FDA3728D04B6122B56C829963D2B25E018F1C241E9C9007252148FA56794B046D42694AF33748C9"
        + "89743CBC52B688ABE3C4421D8743E2A8AFA48B2A242AB7B3E29DF1292999B79098534E06075CF3E8735D515D9A4C"
        + "BBA3C863A1218EDD333CCE513664F9341FB584B3F66671E12AA9841E5EC32A3896BF82E4AD62F5135A6A2F560B1C"
        + "2F0A29DA74486381C3FFCB6253D204F97A13C5FACDB13BA1354109EF48C62BC11481E862837A57B7DA924BD85404"
        + "44BAD69C60A3E05C6F5947797BB111B135EE362673F9B85A1902DE426B2ED48EC3689FE903E2215156E0A40D18B7"
        + "2BBA84003E0F705DA31F18F63A6E55F218D2F4123D55E113A77C032B3FC761BDA56163FFB4705B1E80411D7B0B5F"
        + "7F001D00205EE1B3D6073195623C4090B9465C55B6B3F06CC21724788097C3735F2C6D632D002D00020101002B00"
        + "05048A8A0304003900210404810000000504802000000604802000000704802000000901080E0240400F00001B00"
        + "03020001AAAA000100";
}
