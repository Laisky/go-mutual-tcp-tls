The candidate preserves its module identity and existing API major. Go1.26.0 is required by patched x/net v0.60.0; qualification uses Go1.26.9. Imported-package advisories are fixed with versioned JWT v4.5.2, patched Logrus and protobuf/Gin where required. Module verification, vet, build and full race tests pass without assertion removal or security suppression.

Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call these
vulnerabilities.
Use '-show verbose' for more details.

The remaining unused required-module advisory is GO-2026-5932 for the unmaintained x/crypto/openpgp package, with no upstream fixed version. The repository source does not call or import the vulnerable package. This does not qualify arbitrary downstream consumers of the module graph.
