# Detecting Ransomware Through File Entropy

Project for CS453 at the University of Waterloo

Members:
- Matthew Au-Yeung
- Jeffrey-Kai Li
- Raymond Mei
- Alex Serban
- Daniel Cao

## Dataset

The corpus under `data/` is drawn from **NapierOne**, a mixed-file dataset built by the School of Computing at Edinburgh Napier University in 2021.

| Directory | Format | Files | Total | Mean file |
|---|---|---:|---:|---:|
| `data/7ZIP-ENCRYPTED-tiny/` | 7-Zip archive, encrypted | 40 | 187M | 4.7M |
| `data/CSV-tiny/` | CSV | 100 | 23M | 225K |
| `data/DOC-tiny/` | Microsoft DOC | 100 | 29M | 295K |
| `data/PNG-c9-tiny/` | PNG, compression level 9 | 100 | 144M | 1.5M |
| `data/TXT-tiny/` | Plain text | 100 | 2.6M | 24K |

Samples are named `<seq>-<format>.<ext>`, numbered from `0001`. The 7-Zip set was trimmed to `0001`–`0040` to keep its disk footprint in line with the other sets

### Archive password

The 7-Zip archives are encrypted with the password **`napierone`**

Filenames are encrypted too, so the password is needed just to list an archive. Nothing is left in plaintext, so whole-file entropy isn't diluted by readable metadata (unlike a password-protected ZIP).

### Licensing and attribution

NapierOne is covered by the Edinburgh Napier University license and, because the source documents came from `gov.uk`, the [Open Government Licence v3.0](http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/). Both require attribution. Any write-up using this data must carry:

> Contains public sector information licensed under the Open Government Licence v3.0.

and credit Edinburgh Napier University as the source of the dataset.
