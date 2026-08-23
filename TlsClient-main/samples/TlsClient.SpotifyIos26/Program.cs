// One HTTP/3 request carrying the measured Spotify iOS fingerprint.
//
//   dotnet run --project samples/TlsClient.SpotifyIos26
//   dotnet run --project samples/TlsClient.SpotifyIos26 -- https://your-endpoint/api/http3
//
// Kept byte-identical to the snippet in docs/USAGE.md section 3c.
#pragma warning disable TLSCLIENT3

using TlsClient;

var options = TlsPresets.Spotify.CreateOptions();   // Spotify917602050IOS270Http3
await using var session = new TlsSession(options);

var request = new HttpRequestMessage(HttpMethod.Get, "https://fp.impersonate.pro/api/http3");

// ORDER MATTERS HERE. The preset declares no header order, so these reach the wire in the order
// they are added - which is why the credential fields are added in their captured slots rather
// than at the end. Leave one unset and the rest keep their relative order.
request.Headers.TryAddWithoutValidation("accept", "*/*");
if (Environment.GetEnvironmentVariable("SPOTIFY_CLIENT_ID") is { } clientId)
{
    request.Headers.TryAddWithoutValidation("x-client-id", clientId);
}

request.Headers.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");
request.Headers.TryAddWithoutValidation("priority", "u=3, i");
request.Headers.TryAddWithoutValidation("app-platform", "iOS");
request.Headers.TryAddWithoutValidation("user-agent", "Spotify/9.1.76 iOS/27.0 (iPhone17,2)");
if (Environment.GetEnvironmentVariable("SPOTIFY_BEARER") is { } bearer)
{
    request.Headers.TryAddWithoutValidation("authorization", "Bearer " + bearer);
}

request.Headers.TryAddWithoutValidation("accept-language", "en-US,en;q=0.9");
request.Headers.TryAddWithoutValidation("spotify-app-version", "9.1.76.2050");

var response = await session.SendAsync(request);
Console.WriteLine($"{response.HttpVersion} {(int)response.StatusCode}");
Console.WriteLine(response.Text);

#pragma warning restore TLSCLIENT3
