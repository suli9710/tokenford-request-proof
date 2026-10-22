# License evidence bundle

Apache-2.0.txt is the unmodified official standard text from apache.org. Root LICENSE applies only to original project work, as scoped by root NOTICE; it does not relicense dependencies.

license-inventory.json contains pinned source origins, locked archive comparisons, all vendored Noir text checks, all TLSNotary crate declarations, and the remaining unresolved components. upstream/ contains the exact license/notice files from the inspected source archives. provenance/ contains archive member hashes, declaration scans, and the exact public README/manifest evidence needed where a license text is missing. It contains no private-key files or executable upstream source.

TLSNotary-LICENSE-NOTE.md records the Apache-2.0 option explicitly offered by its pinned all-crates README. Three Noir dependencies have no exact-version license grant in the locked upstream archive; they remain unresolved, and this bundle does not invent permission to distribute them. See ../THIRD_PARTY_LICENSE_STATUS.md.
