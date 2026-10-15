# GOPEL v0.6.5: changes

Version 0.6.5 (`haia_agent.gopel_v065.__version__`). Built on GOPEL v0.6.4 (`haia_agent/gopel_v064/`, unchanged) for item 1 of Basil's fix round (October 14, 2026), after a seven-platform CAIPR review of the Team Gate. Pushed files are never rewritten; every change is in this new folder.

1. **The Dispatch record before the call (G-1).** `channel.py` writes the Dispatch record, then calls the adapter, then writes a Response record whatever the call did. An adapter that raises is recorded as a failed call.
2. **Text UTF-8 cannot hold.** `models.escape_unencodable` writes each lone surrogate as `\uXXXX` and lists its position and code point. `ChannelResponseRecord` carries `text_escaped`, `escapes`, `error_escapes`, `api_confirmation`, and `redaction_applied`; `ChannelNavigationRecord` carries `text_escaped` and `escapes`. The adapters' response hash uses `surrogatepass`, so it never fails.
3. **Redaction inside the adapters.** `adapters/message_adapter.redact_secrets` and `failure_response`; `CallableMessageAdapter` and `MessageMockAdapter` take `secret_env_names`.
4. **Withdraw.** `GOPELChannel.withdraw(group, platform_id, reason)`; a group closes when every platform has answered or been withdrawn. The `channel_group_closed` detail keeps its four keys; its reason reads `withdrawn: ...` when a platform was withdrawn.
5. **Analyzer.** Unchanged (SHA-256 `4b4951692ff0c376248d50bef64e8f890d5a62f57d91436b30f084f7612794c5`). A planted-violation test proves it catches what it searches for.

## A correction to the record

The message of commit `afa82f1` (GOPEL v0.6.4) quotes `ModuleNotFoundError: No module named 'haia_agent.gopel_v064.channel'` as an example from its before run. The saved before-run file kept only the names of the failing tests, not their error text, so the evidence cannot confirm that quotation. The counts it gives (20 failed, 1 passed) are confirmed by that file.
