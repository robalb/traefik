# Fork maintenance

This fork carries the TCP/TLS fingerprint feature on top of stable upstream Traefik releases and publishes a container image to `ghcr.io/robalb/traefik`.

## Branches

- `master`, `v3.7`, `v3.8`, ...: mirrors of upstream. Only fast-forward them from `origin`, never commit to them.
- `tcp-tls-fingerprint`: the fingerprint feature, based on upstream `master`.
- `fp/v3.7`: a stable upstream release tag, plus the fingerprint commits, plus one fork-only commit (this file and the image workflow). Images are built from tags on this branch.

Why not commit to `v3.7` directly:

- Syncing from upstream would need a merge every time, and the fork commits would get mixed with upstream ones. On `fp/v3.7` the patch stays a small stack: `git log v3.7.18..fp/v3.7`.
- The tip of `v3.7` contains unreleased fixes. `fp/v3.7` starts from a release tag, so the image is exactly a released Traefik plus the patch.
- Pushes to `master` and `v*` branches trigger upstream CI in the fork. Pushes to `fp/*` don't.

## Publishing an image

```bash
git push fork fp/v3.7
git tag v3.7.18-fp.1 fp/v3.7
git push fork v3.7.18-fp.1
```

That produces:

- Image: `ghcr.io/robalb/traefik:v3.7.18-fp.1`, for `linux/amd64` and `linux/arm64`.
- Version: `traefik version` inside it reports `v3.7.18-fp.1`.

A few rules for the tag:

- Format: it has to match `v*-fp.*` or `.github/workflows/fork-image.yaml` won't run. The part before `-fp` is the upstream release, the number after it counts fork builds on that release.
- Commit: it has to point at a commit on `fp/v3.7` that contains the pipeline file. Tagging `fp/v3.7` itself, as above, does that.
- Image tags: the pipeline publishes only that tag, not `latest`. Reference the exact tag in docker-compose: `image: "ghcr.io/robalb/traefik:v3.7.18-fp.1"`.
- Visibility: the first image is private. Make the package public on GitHub, or run `docker login ghcr.io` on the servers that pull it.

## Updating to a new upstream release

When upstream tags `v3.7.19`:

```bash
git fetch origin --tags
git rebase --onto v3.7.19 v3.7.18 fp/v3.7
go test ./pkg/tcp/... ./pkg/server/...
git push --force-with-lease fork fp/v3.7
git tag v3.7.19-fp.1 fp/v3.7
git push fork v3.7.19-fp.1
```

- `--onto v3.7.19 v3.7.18` takes only the commits after `v3.7.18` (the fork commits) and replays them on top of `v3.7.19`.
- The rebase rewrites `fp/v3.7`, hence `--force-with-lease`. Old tags keep pointing at the old commits, so previous images stay reproducible.
- For fork-only changes on the same upstream release, bump the suffix: `v3.7.19-fp.2`.

## Moving to v3.8

When `v3.8.0` is released (not a release candidate), replace `v3.7.19` with the release `fp/v3.7` is currently on:

```bash
git switch -c fp/v3.8 fp/v3.7
git rebase --onto v3.8.0 v3.7.19 fp/v3.8
```

Then test, tag and push as above, with `v3.8.0-fp.1`. The fingerprint commits were written on `master`, so the rebase should be clean.

## Upstream workflows

- The ones that release or publish images are guarded by `github.repository == 'traefik/traefik'` and never run in the fork.
- The rest only run on PRs and on pushes to `master`/`v*`. Disable them in the fork's Actions settings to save minutes when syncing the mirrors.
- Don't delete the upstream workflow files: that causes rebase conflicts every time upstream edits them.

## Using the image

Enable fingerprints per entrypoint in the install configuration (`traefik.yml`):

```yaml
entryPoints:
  websecure:
    address: ":443"
    fingerprint: {}
```

- Use `fingerprint: {tcp: false}` to keep only the TLS fingerprints.
- Backends receive `X-Tcp-Fingerprint` and `X-Tcp-Ttl` (from the client's TCP SYN, Linux only), and `X-Tls-Ja4` and `X-Tls-Tlsfp` (from the TLS ClientHello). Values sent by clients are removed.
- Ports published through the Docker bridge decrement the TTL, and Docker's userland proxy replaces the client SYN. Use `network_mode: host` when the TCP fingerprint must reflect real clients.
