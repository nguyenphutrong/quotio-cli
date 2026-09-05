# Amp API response fix

CLI code revision: 9132df6. Swift code revision: a0010107 in the main Quotio project.

## Root cause

The live userDisplayBalanceInfo API returned HTTP 200 with only
`{ok, result: {displayText}}`. displayText uses plain labels; the CLI formatter uses
Markdown labels. Rust had tested the API with Markdown text and rejected the actual
plain text. Its default local Amp route also always executed the CLI.

The Swift parser accepted plain labels but expected the old subscription form
`N% agent usage and M% orb usage remaining`. Current API output instead supplies
`agent usage $remaining of $limit ... orb usage remainingHours of limitHours ...`.
The two subscription metrics were consequently omitted in Swift.

Credit wallet balances contain no total allowance. Unknown percentage is correct
in the data model, but showing an unknown-usage row above a known balance was
misleading in terminal output.

## Fix

- Rust accepts plain API labels and Markdown CLI labels.
- Local public-host Amp keys now use the same API route as managed accounts.
  Environment keys take precedence; local files are read-only, bounded and do not
  send a public-host key to a custom AMP_URL.
- Text output shows subscription amounts used and credit balances directly.
  No percentage or reset timestamp is fabricated for balance-only rows.
- Swift parses current amount-based subscription output and preserves old-format
  support. Agent usage has USD progress; orb percentage uses the hour ratio rather
  than the rounded percentage displayed by the API.
- Date-only billing periods remain without an invented exact reset timestamp.

## Evidence

- Rust plain-response regression failed before the fix, then passed.
- Swift current-format regression failed with missing QuotaMetric, then passed.
- Rust full suite: 64 passed, one opt-in native Keychain test skipped.
- Rust fmt/Clippy: PASS. Signed debug build: PASS.
- Independent reviewer: no blocking issue found; independently ran 7 Amp tests.
- Swift OpenRouterAmpQuotaFetcherTests: 11 passed.
- Swift app xcodebuild Debug: PASS, with only the matching-destination warning.
- Original live CLI request returned exit 0, source amp_api, five windows including
  both subscription metrics and both balances. The text form was also verified.

No API key or raw account identity was saved as a fixture. Tests use synthetic
accounts and values. The initial Python probe failed certificate validation, while
system curl and Rust TLS succeeded; certificate validation was never disabled and
no TLS dependency/configuration change was made.

The Swift app was built but not relaunched or visually inspected. Its parser fix
is verified by tests using the observed API shape; GUI acceptance is separate.
