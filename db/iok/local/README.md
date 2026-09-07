# Local IOK rules

Rules we wrote ourselves, in the same format as the upstream
[IOK](https://github.com/phish-report/IOK) corpus. See the
[IOK rule reference](https://phish.report/docs/iok-rule-reference).

`IokSyncJob` loads every `*.yml` here into `iok_indicators` with
`source: "local"`, alongside the upstream rules it downloads. The two are kept
apart so the retire step, which discards indicators withdrawn upstream, never
touches a rule that lives in this directory.

## Adding a rule

1. Write `<slug>.yml` here. The file name becomes the indicator slug, so keep
   it lowercase and hyphenated.
2. Run `bin/rails test test/services/iok/local_rules_test.rb`. It compiles
   every file in this directory, so a rule that cannot compile fails the build
   rather than the next sync.
3. The rule reaches production on the next daily sync, or immediately from
   `/admin/iok_indicators` with "Sync Now".

Before writing a rule, check it is not already upstream. Most kits are: search
`indicators/` in phish-report/IOK, or [iok.dev](https://iok.dev). A rule that
duplicates an upstream one is two rows to maintain instead of one, and the
upstream copy is the one that keeps getting fixed.

Prefer contributing genuinely new rules upstream as well. This directory is for
rules we need before an upstream pull request lands, and for rules too specific
to us to belong there.

## One trap

A YAML mapping cannot repeat a key. This looks like four conditions but is one,
because Psych keeps only the last:

```yaml
images:
  requests|endswith: "pinnedBookmark.png"
  requests|endswith: "butt.png"
  requests|endswith: "header-slide-1.png"   # only this one
  requests|endswith: "header-slide-2.png"   # ...no, only this one
```

Write it as a list instead. `all` requires every value, and without it any one
value is enough:

```yaml
images:
  requests|endswith|all:
    - "pinnedBookmark.png"
    - "butt.png"
    - "header-slide-1.png"
    - "header-slide-2.png"
```
