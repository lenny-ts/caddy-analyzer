#!/usr/bin/env bash
set -euo pipefail

# Export the same keyless signature and certificate for older updaters.
jq -er '.messageSignature.signature | strings | select(length > 0)' checksums.txt.bundle > checksums.txt.sig
jq -er '(.verificationMaterial.certificate.rawBytes // .verificationMaterial.x509CertificateChain.certificates[0].rawBytes)
    | strings | select(length > 0)' checksums.txt.bundle |
    base64 -d | openssl x509 -inform DER -out checksums.txt.pem
