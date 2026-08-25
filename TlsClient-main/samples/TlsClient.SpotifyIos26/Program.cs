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

// ORDER MATTERS HERE. A field reaches the wire only when AddHeader put it there, in the order
// they were added — which is why the credential fields are added in their captured slots rather
// than at the end. Leave one unset and the rest keep their relative order.
request.AddHeader("accept", "*/*");
if (Environment.GetEnvironmentVariable("SPOTIFY_CLIENT_ID") is { } clientId)
{
    request.AddHeader("x-client-id", clientId);
}

request.AddHeader("accept-encoding", "gzip, deflate, br");
request.AddHeader("priority", "u=3, i");
request.AddHeader("app-platform", "iOS");
request.AddHeader("user-agent", "Spotify/9.1.76 iOS/27.0 (iPhone17,2)");
if (Environment.GetEnvironmentVariable("SPOTIFY_BEARER") is { } bearer)
{
    request.AddHeader("authorization", "Bearer " + bearer);
}

request.AddHeader("accept-language", "en-US,en;q=0.9");
request.AddHeader("spotify-app-version", "9.1.76.2050");

var response = await session.SendAsync(request);
Console.WriteLine($"{response.HttpVersion} {(int)response.StatusCode}");
Console.WriteLine(response.Text);

#pragma warning restore TLSCLIENT3
