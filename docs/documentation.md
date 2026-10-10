# Maintain this documentation

Edit prose in `docs/` and imported documents at their original repository paths.
`zensical.toml` owns navigation and source-file imports. Add each new page to
navigation once and preserve existing URLs and section anchors when moving text.

## Build and preview

Use Python 3.11+, Bash, Git, and a running Docker engine:

```sh
bash scripts/docs.sh check
bash scripts/docs.sh build
bash scripts/docs.sh serve
```

The preview opens at `http://127.0.0.1:8000/`; rebuild after editing. Generated
files stay under `target/`. Build a released edition with
`bash scripts/docs.sh build vX.Y.Z`. The normal build uses the working tree.

## Release documentation

Follow the shared [publishing and release-verification policy](https://github.com/hubuum/.github/blob/main/docs-tooling/README.md#ci-and-publishing).
It covers edition URLs, immutable release archives, manual backfills, deployment
recovery, and checking the public site before a release is complete.

<!-- markdownlint-disable-next-line MD033 -->
<span id="shared-examples"></span>

## Make changes

Follow the shared [content and tooling policy](https://github.com/hubuum/.github/blob/main/docs-tooling/README.md#content-policy).
Keep interface-specific examples here and link to a matching server edition for
shared concepts and the [Atlas dataset](example-dataset.md). Update the tooling
SHA in `.github/docs-tools.env` and both reusable-workflow pins together when
adopting shared build changes.
