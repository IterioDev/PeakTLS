// One HTTP/3 request carrying the measured Spotify iOS fingerprint.
//
//   dotnet run --project samples/TlsClient.SpotifyIos26
//   dotnet run --project samples/TlsClient.SpotifyIos26 -- https://your-endpoint/api/http3
//
// Kept byte-identical to the snippet in docs/USAGE.md section 3c.
#pragma warning disable TLSCLIENT3

using TlsClient;

var options = TlsPresets.Spotify.CreateOptions();   // Spotify918602428IOS270Http3
await using var session = new TlsSession(options);

var request = new HttpRequestMessage(HttpMethod.Get, "https://fp.impersonate.pro/api/http3");

// ORDER MATTERS HERE. The preset declares no header order, so these reach the wire in the order
// they are added - which is why the credential fields are added in their captured slots rather
// than at the end. Leave one unset and the rest keep their relative order. This is the
// spclient GET image of Spotify 9.1.86.2428 on iOS 27.0, captured 2026-09-26.
request.AddHeader("spotify-app-version", "9.1.86.2428");
request.AddHeader("accept", "*/*");
if (Environment.GetEnvironmentVariable("SPOTIFY_BEARER") is { } bearer)
{
    request.AddHeader("authorization", "Bearer " + bearer);
}

request.AddHeader("time-zone", "Europe/Athens");
request.AddHeader("app-platform", "iOS");
request.AddHeader("priority", "u=3, i");
request.AddHeader("accept-language", "en-US,en;q=0.9");
request.AddHeader("accept-encoding", "gzip, deflate, br");
request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
if (Environment.GetEnvironmentVariable("SPOTIFY_CLIENT_ID") is { } clientId)
{
    request.AddHeader("x-client-id", clientId);
}

if (Environment.GetEnvironmentVariable("SPOTIFY_CLIENT_TOKEN") is { } clientToken)
{
    request.AddHeader("client-token", clientToken);
}

var response = await session.SendAsync(request);
Console.WriteLine($"{response.HttpVersion} {(int)response.StatusCode}");
Console.WriteLine(response.Text);

#pragma warning restore TLSCLIENT3
