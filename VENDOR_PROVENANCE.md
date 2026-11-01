# Source provenance

Private development package for the user-owned cloud bot. Source was read from the existing local xwechat project; that project was not modified.

| Package file | Source SHA256 | Package SHA256 | Changes |
|---|---|---|---|
| vendor/xwechat/key_v4.py | ff7d9aa77c00b612ed78b808e25e5351ab04b490b1122d7bf9b573edfdbfb2de | af4d9520cdbca4d7112ac6f230b22da6403f6a05fc1f083774717e8738d20253 | Sequential verify_keys; remove multiprocessing verification worker to enforce parent timeout |
| vendor/xwechat/dll_key_scan.py | bf6e7e9a7c2cb3567df1ffedd1d2ead810c076c58e72783ec865ae397dbef1f0 | bf6e7e9a7c2cb3567df1ffedd1d2ead810c076c58e72783ec865ae397dbef1f0 | Unmodified copy |
| vendor/xwechat/sqlite_wal.py | 580d5ceac1ee681991b91dfc1f2b4161287fb829658de872a96ebc7dc1cc4f0c | 171fa33b7d0bdea5ec0cc846e2fa31c1ea671458ba58dc2dce99bdf6be3b0080 | Final-commit coverage and authenticated logical page-count resolver; retain frame/HMAC checks |
| vendor/xwechat/windows_wal_capture.py | 6d63533792e572fb3dc0681deb8eea5775fa8284a7e7877bd5ee6703b4f22918 | 6d63533792e572fb3dc0681deb8eea5775fa8284a7e7877bd5ee6703b4f22918 | Unmodified copy |

Original source root: `xwechat/src/wechat_decrypt_tool (local source checkout)`.

Five crypto functions in `cloud_db_reader.py` are copied verbatim from `wechat_decrypt.py`: `_derive_mac_key`, `_derive_sqlcipher_enc_key`, `_compute_page_hmac`, `_resolve_page1_key_material`, `_decrypt_page`.
Original crypto source SHA256: `6ad9b68590c5d498f9afaa04a0bbd86aced26fa47ac4a2603c455c68e17e36a3`.

`key_v4.py` intentionally verifies candidates sequentially on this 2-vCPU server. It retains the original signature, transform, PBKDF2/HMAC and deadline checks; no child verification processes can retain worker output pipes after timeout. Its source hash therefore differs from the upstream local file.

No historical messages, keys, source project configurations, logs, database files, tests or local virtual environments are packaged. Original source files are retained in the user-owned source project.

`sqlite_wal.py` in bot2 checks extension completeness only after the last valid commit is determined. SQLite checkpoint/truncation can retain larger obsolete historical commits in the same WAL; replay need not reconstruct those earlier snapshots. Genuine final gaps, invalid checksums/HMAC, uncommitted and recycled tails remain rejected or excluded as before. Original source remains unchanged. See https://www.sqlite.org/fileformat2.html#reader_algorithm .

In bot3 the encrypted reader supplies a callback for the latest committed page1 logical size. Generic callers retain strict commit-size behavior. WAL pager capacity is recorded separately; source/frame authentication and logical coverage remain mandatory. Physical zero tails are diagnostic evidence only. See SQLite lockBtree and Tencent SQLCipher btree.c fixed revision445e1dbe066ee917e4475b028f90ff37efb04541.
