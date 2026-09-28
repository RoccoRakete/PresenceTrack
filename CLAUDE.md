# PresenceTrack

## Language

The entire project is in English: commit messages, tag annotations (release notes), PR titles/descriptions, GitHub Actions workflows (job/step names, comments, log output), issue/PR templates, all other `.github/` files, the README, internal firmware comments (C++/headers), and all of the device's own log/error output.

No German text anywhere in the project, whether in code comments, docs, UI text, or log output.

## Release process

Cutting a release (e.g. after bumping `FIRMWARE_VERSION` in `include/firmware.h`, committing, and creating the annotated `vX.Y.Z` tag locally) does not publish anything by itself. The GitHub Release is only created by `.github/workflows/firmware.yml` when the tag is pushed, and that push must be confirmed by the human first — never push automatically.

Once the human confirms, publishing the release requires exactly:

```
git push origin main
git push origin vX.Y.Z
```

(or `git push origin main vX.Y.Z` in one step). Push `main` before or together with the tag, not after — the `release` job runs `gh release create ... --verify-tag`, which requires the tag to already be reachable/visible on the remote.

The tag must be annotated (`git tag -a`): its message becomes the GitHub release notes via the `gh api` tag-object lookup in the "Assemble release notes" step, and the tag name must be exactly `v<FIRMWARE_VERSION>` as read from `include/firmware.h`, or the `release` job fails its version check.
