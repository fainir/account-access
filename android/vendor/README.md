# ZXing Core 3.5.3

This is the unchanged Maven Central release already used by Account Access for
local QR decoding. Keeping the dependency in source avoids repeated downloads
and HTTP 429 failures during publisher and CI builds. Builds verify the original
SHA-256 before copying it into their own output directory:

`8d8064c1636fdaef7189dd9055c7d59950a8940a12f2293956446ec3c109fd82`

Original artifact: [Maven Central](https://repo.maven.apache.org/maven2/com/google/zxing/core/3.5.3/core-3.5.3.jar).
Source: [ZXing 3.5.3 Core](https://github.com/zxing/zxing/tree/zxing-3.5.3/core).
License: Apache-2.0. The unchanged upstream license and notices are included in
[`THIRD_PARTY_NOTICES.txt`](../app/assets/THIRD_PARTY_NOTICES.txt), which is also
bundled into the APK. The release builder includes the JAR in its checked source
inputs; no key or credential is stored in this directory.
