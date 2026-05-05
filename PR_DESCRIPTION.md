# fix: companion EXPORT_CONTACT format and FIRMWARE_VER_CODE for MeshMapper wardrive registration

## Summary

Two bugs that together prevent a pyMC companion from completing MeshMapper wardrive Stage 2 registration.

- **`FIRMWARE_VER_CODE` bumped 10 → 11** — MeshMapper uses this value to decide whether the companion supports the full protocol suite. With `10`, certain paths are skipped.

- **`_cmd_export_contact` rewritten to emit a real MeshCore advert packet** — The previous implementation returned a custom binary struct (pubkey + adv\_type + padded name + lat + lon). Real MeshCore firmware instead returns the raw bytes of a self-advertisement packet (`Packet::writeTo()`), which has a different wire format:

  ```
  header(1)    = 0x11  [(PAYLOAD_TYPE_ADVERT << 2) | ROUTE_TYPE_FLOOD]
  path_len(1)  = 0x00
  pubkey(32)
  timestamp(4)
  signature(64) over (pubkey + timestamp + appdata)
  appdata(≤32) = flags(1) + [lat(4) + lon(4) if GPS] + name_bytes
  ```

  The wardrive API receives this blob (via MeshMapper) and verifies the Ed25519 signature using the standard advert format. With the old custom struct, signature verification always failed, returning HTTP 400 "Data string too short".

## How we got here

Tested against a factory-reset Heltec V4 OLED companion (unknown pubkey, same MeshMapper build). That device completed Stage 2 in one attempt. Capturing and comparing the raw EXPORT\_CONTACT frames revealed the format mismatch — real firmware calls `createSelfAdvert()` + `pkt->writeTo()`, pyMC used a hand-rolled struct. Cross-referencing `MeshCore/src/Mesh.cpp` (`createAdvert`) and `Packet.cpp` (`writeTo`) confirmed the expected layout.

## Files changed

- `src/pymc_core/companion/constants.py` — `FIRMWARE_VER_CODE` 10 → 11
- `src/pymc_core/companion/frame_server.py` — `_cmd_export_contact` self-export path rebuilt to emit a signed advert packet
