# Wire

Byte-level HTTP/2 wire-capture harness: runs a real `TlsSession` against a scripted
loopback server (or parses a manually captured hex dump) and lets tests assert on the
exact frames and bytes produced, so a future rewrite of the HTTP/2 stack can prove
byte-identical output for the built-in presets.

Two hazards worth knowing before touching this directory:

- `CapturedFrame` (`Http2WireServer.cs`) is a record struct with a `byte[]` payload, so
  its generated equality compares `Payload` by reference, not by value. `Assert.Equal`
  on two frame lists will not do what you expect. Use `Http2WireAssert.EqualFrames`.
- The byte-accounting equality asserted in `Http2WireCaptureTests` is exact only
  because `RecordingStream` never returns more bytes than requested, and
  `Http2WireServer` reads exactly 9 header bytes then exactly the declared payload
  length, appending to `ClientFrames` only after both reads complete. Any future
  buffered or speculative read added to either file would make that equality flaky.
