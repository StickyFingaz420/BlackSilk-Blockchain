# G8 final table (227 cargo-mutants mutants, then the hand mutants)

| id | class | final status | caught by / reason | mutant |
|---|---|---|---|---|
| G8-001 | SC2 | unviable | error[E0277]: the trait bound `Info: Default` is not satisfied | tools/supply-audit/src/lib.rs:91:9: replace <impl NodeApi for Pinned<'_>>::info -> Result<rpc::Info, String> with Ok(Default::default()) |
| G8-002 | SC2 | caught (existing test) | a_wallet_that_cannot_reach_the_audit_block_is_refused,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewin | tools/supply-audit/src/lib.rs:92:21: replace < with == in <impl NodeApi for Pinned<'_>>::info |
| G8-003 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:92:21: replace < with > in <impl NodeApi for Pinned<'_>>::info |
| G8-004 | SC2 | caught (existing test) | a_wallet_that_cannot_reach_the_audit_block_is_refused,audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_sh | tools/supply-audit/src/lib.rs:92:21: replace < with <= in <impl NodeApi for Pinned<'_>>::info |
| G8-005 | SC2 | unviable | error[E0277]: the trait bound `blacksilk_rpc::Blocks: Default` is not satisfied | tools/supply-audit/src/lib.rs:104:9: replace <impl NodeApi for Pinned<'_>>::blocks -> Result<rpc::Blocks, String> with Ok(Default::default()) |
| G8-006 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height,pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:104:31: replace \|\| with && in <impl NodeApi for Pinned<'_>>::blocks |
| G8-007 | SC2 | caught (new test, at f14a690) | pinned_never_requests_above_the_audit_height,pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:104:17: replace > with == in <impl NodeApi for Pinned<'_>>::blocks |
| G8-008 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:104:17: replace > with < in <impl NodeApi for Pinned<'_>>::blocks |
| G8-009 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:104:17: replace > with >= in <impl NodeApi for Pinned<'_>>::blocks |
| G8-010 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:104:40: replace == with != in <impl NodeApi for Pinned<'_>>::blocks |
| G8-011 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:107:74: replace + with - in <impl NodeApi for Pinned<'_>>::blocks |
| G8-012 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:107:74: replace + with * in <impl NodeApi for Pinned<'_>>::blocks |
| G8-013 | SC2 | caught (new test, at f14a690) | pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:107:67: replace - with + in <impl NodeApi for Pinned<'_>>::blocks |
| G8-014 | SC2 | caught (new test, at f14a690) | pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:107:67: replace - with / in <impl NodeApi for Pinned<'_>>::blocks |
| G8-015 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:108:38: replace <= with > in <impl NodeApi for Pinned<'_>>::blocks |
| G8-016 | SC2 | unviable | error[E0277]: the trait bound `blacksilk_rpc::Headers: Default` is not satisfied | tools/supply-audit/src/lib.rs:115:9: replace <impl NodeApi for Pinned<'_>>::headers -> Result<rpc::Headers, String> with Ok(Default::default()) |
| G8-017 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height,pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:120:31: replace \|\| with && in <impl NodeApi for Pinned<'_>>::headers |
| G8-018 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height,pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:120:17: replace > with == in <impl NodeApi for Pinned<'_>>::headers |
| G8-019 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height,pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:120:17: replace > with < in <impl NodeApi for Pinned<'_>>::headers |
| G8-020 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:120:17: replace > with >= in <impl NodeApi for Pinned<'_>>::headers |
| G8-021 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height,pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:120:40: replace == with != in <impl NodeApi for Pinned<'_>>::headers |
| G8-022 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:125:57: replace + with - in <impl NodeApi for Pinned<'_>>::headers |
| G8-023 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:125:57: replace + with * in <impl NodeApi for Pinned<'_>>::headers |
| G8-024 | SC2 | caught (new test, at f14a690) | pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:125:50: replace - with + in <impl NodeApi for Pinned<'_>>::headers |
| G8-025 | SC2 | caught (new test, at f14a690) | pinned_never_requests_above_the_audit_height | tools/supply-audit/src/lib.rs:125:50: replace - with / in <impl NodeApi for Pinned<'_>>::headers |
| G8-026 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:126:76: replace * with + in <impl NodeApi for Pinned<'_>>::headers |
| G8-027 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:126:76: replace * with / in <impl NodeApi for Pinned<'_>>::headers |
| G8-028 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:126:56: replace * with + in <impl NodeApi for Pinned<'_>>::headers |
| G8-029 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:126:56: replace * with / in <impl NodeApi for Pinned<'_>>::headers |
| G8-030 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:126:41: replace + with - in <impl NodeApi for Pinned<'_>>::headers |
| G8-031 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:126:41: replace + with * in <impl NodeApi for Pinned<'_>>::headers |
| G8-032 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:126:34: replace - with + in <impl NodeApi for Pinned<'_>>::headers |
| G8-033 | SC2 | caught (new test, at f14a690) | pinned_serves_exactly_the_audit_height | tools/supply-audit/src/lib.rs:126:34: replace - with / in <impl NodeApi for Pinned<'_>>::headers |
| G8-034 | SC2 | unviable | error[E0277]: the trait bound `blacksilk_rpc::Distribution: Default` is not satisfied | tools/supply-audit/src/lib.rs:132:9: replace <impl NodeApi for Pinned<'_>>::distribution -> Result<rpc::Distribution, String> with Ok(Default::default()) |
| G8-035 | SC2 | unviable | error[E0277]: the trait bound `Outputs: Default` is not satisfied | tools/supply-audit/src/lib.rs:135:9: replace <impl NodeApi for Pinned<'_>>::outputs -> Result<rpc::Outputs, String> with Ok(Default::default()) |
| G8-036 | SC2 | unviable | error[E0277]: the trait bound `SubmitResult: Default` is not satisfied | tools/supply-audit/src/lib.rs:138:9: replace <impl NodeApi for Pinned<'_>>::submit_tx -> Result<rpc::SubmitResult, String> with Ok(Default::default()) |
| G8-037 | SC2 | unviable | error[E0277]: the trait bound `PxCommitments: Default` is not satisfied | tools/supply-audit/src/lib.rs:141:9: replace <impl NodeApi for Pinned<'_>>::px_commitments -> Result<rpc::PxCommitments, String> with Ok(Default::default()) |
| G8-038 | SC2 | unviable | error[E0277]: the trait bound `PxContracts: Default` is not satisfied | tools/supply-audit/src/lib.rs:144:9: replace <impl NodeApi for Pinned<'_>>::px_contracts -> Result<rpc::PxContracts, String> with Ok(Default::default()) |
| G8-039 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:236:9: replace Report::complete -> bool with true |
| G8-040 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:236:9: replace Report::complete -> bool with false |
| G8-041 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:236:67: replace && with \|\| in Report::complete |
| G8-042 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:236:40: replace && with \|\| in Report::complete |
| G8-043 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:236:62: replace == with != in Report::complete |
| G8-044 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:236:89: replace == with != in Report::complete |
| G8-045 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:9: replace Report::alarm -> bool with true |
| G8-046 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:9: replace Report::alarm -> bool with false |
| G8-047 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:67: replace \|\| with && in Report::alarm |
| G8-048 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:41: replace \|\| with && in Report::alarm |
| G8-049 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:9: delete ! in Report::alarm |
| G8-050 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:63: replace < with == in Report::alarm |
| G8-051 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:63: replace < with > in Report::alarm |
| G8-052 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:63: replace < with <= in Report::alarm |
| G8-053 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:89: replace < with == in Report::alarm |
| G8-054 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:89: replace < with > in Report::alarm |
| G8-055 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:242:89: replace < with <= in Report::alarm |
| G8-056 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:248:9: replace Report::exit_code -> i32 with 0 |
| G8-057 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:248:9: replace Report::exit_code -> i32 with 1 |
| G8-058 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:248:9: replace Report::exit_code -> i32 with -1 |
| G8-059 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:250:35: replace && with \|\| in Report::exit_code |
| G8-060 | SC1 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:250:38: delete ! in Report::exit_code |
| G8-061 | SC3 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:259:9: replace Report::text -> String with String::new() |
| G8-062 | SC3 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:259:9: replace Report::text -> String with "xyzzy".into() |
| G8-063 | SC3 | caught (new test, at f14a690) | report_tests::the_text_names_duplicates_only_when_there_are_some | tools/supply-audit/src/lib.rs:325:46: replace > with == in Report::text |
| G8-064 | SC3 | caught (new test, at f14a690) | report_tests::the_text_names_duplicates_only_when_there_are_some | tools/supply-audit/src/lib.rs:325:46: replace > with < in Report::text |
| G8-065 | SC3 | caught (new test, at f14a690) | report_tests::the_text_names_duplicates_only_when_there_are_some | tools/supply-audit/src/lib.rs:325:46: replace > with >= in Report::text |
| G8-066 | SC3 | caught (new test, at f14a690) | report_tests::the_text_names_duplicates_only_when_there_are_some | tools/supply-audit/src/lib.rs:325:28: replace + with - in Report::text |
| G8-067 | SC3 | caught (new test, at f14a690) | report_tests::the_text_names_duplicates_only_when_there_are_some | tools/supply-audit/src/lib.rs:325:28: replace + with * in Report::text |
| G8-068 | SC3 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:366:5: replace amt -> String with String::new() |
| G8-069 | SC3 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:366:5: replace amt -> String with "xyzzy".into() |
| G8-070 | SC3 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:366:21: replace < with == in amt |
| G8-071 | SC3 | caught (existing test) | tests::exit_codes | tools/supply-audit/src/lib.rs:366:21: replace < with > in amt |
| G8-072 | SC3 | caught (new test, at f14a690) | report_tests::amounts_of_zero_and_one_have_no_sign | tools/supply-audit/src/lib.rs:366:21: replace < with <= in amt |
| G8-073 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:382:5: replace scan_chain -> Result<(ChainSummary, Vec<String>), String> with Ok((Default::default(), vec![])) |
| G8-074 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:382:5: replace scan_chain -> Result<(ChainSummary, Vec<String>), String> with Ok((Default::default(), vec![String::new()])) |
| G8-075 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:382:5: replace scan_chain -> Result<(ChainSummary, Vec<String>), String> with Ok((Default::default(), vec!["xyzzy".into()])) |
| G8-076 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:388:16: replace <= with > in scan_chain |
| G8-077 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:389:67: replace + with - in scan_chain |
| G8-078 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:389:67: replace + with * in scan_chain |
| G8-079 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:389:60: replace - with + in scan_chain |
| G8-080 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:389:60: replace - with / in scan_chain |
| G8-081 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:395:25: replace != with == in scan_chain |
| G8-082 | SC2 | caught (new test, at f14a690) | the_scan_refuses_a_block_whose_transactions_or_id_do_not_match | tools/supply-audit/src/lib.rs:401:40: replace \|\| with && in scan_chain |
| G8-083 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:401:32: replace != with == in scan_chain |
| G8-084 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:401:63: replace != with == in scan_chain |
| G8-085 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:404:33: replace != with == in scan_chain |
| G8-086 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:415:30: replace += with -= in scan_chain |
| G8-087 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:415:30: replace += with *= in scan_chain |
| G8-088 | SC3 | caught (existing test) | a_wallet_that_cannot_reach_the_audit_block_is_refused,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewin | tools/supply-audit/src/lib.rs:418:37: replace += with -= in scan_chain |
| G8-089 | SC3 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:418:37: replace += with *= in scan_chain |
| G8-090 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:419:30: replace += with -= in scan_chain |
| G8-091 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:419:30: replace += with *= in scan_chain |
| G8-092 | SC3 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:422:34: replace += with -= in scan_chain |
| G8-093 | SC3 | caught (existing test) | the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:422:34: replace += with *= in scan_chain |
| G8-094 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:423:30: replace += with -= in scan_chain |
| G8-095 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:423:30: replace += with *= in scan_chain |
| G8-096 | SC1 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:424:37: replace += with -= in scan_chain |
| G8-097 | SC1 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:424:37: replace += with *= in scan_chain |
| G8-098 | SC1 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:425:38: replace += with -= in scan_chain |
| G8-099 | SC1 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:425:38: replace += with *= in scan_chain |
| G8-100 | SC1 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:426:30: replace += with -= in scan_chain |
| G8-101 | SC1 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:426:30: replace += with *= in scan_chain |
| G8-102 | SC3 | caught (new test, at f14a690) | a_deploy_is_counted_and_its_fee_is_owed_by_the_coinbase | tools/supply-audit/src/lib.rs:436:38: replace += with -= in scan_chain |
| G8-103 | SC3 | caught (new test, at f14a690) | a_deploy_is_counted_and_its_fee_is_owed_by_the_coinbase | tools/supply-audit/src/lib.rs:436:38: replace += with *= in scan_chain |
| G8-104 | SC2 | caught (new test, at f14a690) | a_deploy_is_counted_and_its_fee_is_owed_by_the_coinbase | tools/supply-audit/src/lib.rs:437:30: replace += with -= in scan_chain |
| G8-105 | SC2 | caught (new test, at f14a690) | a_deploy_is_counted_and_its_fee_is_owed_by_the_coinbase | tools/supply-audit/src/lib.rs:437:30: replace += with *= in scan_chain |
| G8-106 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:441:21: replace != with == in scan_chain |
| G8-107 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:441:39: replace + with - in scan_chain |
| G8-108 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:441:39: replace + with * in scan_chain |
| G8-109 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:446:29: replace += with -= in scan_chain |
| G8-110 | SC2 | caught (existing test) | the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:446:29: replace += with *= in scan_chain |
| G8-111 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:447:20: replace += with -= in scan_chain |
| G8-112 | SC2 | caught (existing test) | the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:447:20: replace += with *= in scan_chain |
| G8-113 | SC3 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:448:22: replace += with -= in scan_chain |
| G8-114 | SC3 | caught (existing test) | the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:448:22: replace += with *= in scan_chain |
| G8-115 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:450:18: replace += with -= in scan_chain |
| G8-116 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:450:18: replace += with *= in scan_chain |
| G8-117 | SC2 | caught (existing test) | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain | tools/supply-audit/src/lib.rs:453:14: replace != with == in scan_chain |
| G8-118 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_audit_block_is_refused,audit_at_an_earlier_height_rewin | tools/supply-audit/src/lib.rs:467:5: replace block_id -> Result<Hash, String> with Ok(Default::default()) |
| G8-119 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_audit_block_is_refused,audit_at_an_earlier_height_rewin | tools/supply-audit/src/lib.rs:471:30: replace == with != in block_id |
| G8-120 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:478:5: replace summarize -> WalletSummary with Default::default() |
| G8-121 | SC3 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:478:23: replace + with - in summarize |
| G8-122 | SC3 | caught (new test, at f14a690) | report_tests::maturity_is_judged_at_the_next_block | tools/supply-audit/src/lib.rs:478:23: replace + with * in summarize |
| G8-123 | SC3 | caught (new test, at 29284c2) | report_tests::maturity_is_judged_at_the_next_block | tools/supply-audit/src/lib.rs:480:9: delete field name from struct WalletSummary expression in summarize |
| G8-124 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:481:9: delete field pending_txs from struct WalletSummary expression in summarize |
| G8-125 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:486:22: replace += with -= in summarize |
| G8-126 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:486:22: replace += with *= in summarize |
| G8-127 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:487:22: replace += with -= in summarize |
| G8-128 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:487:22: replace += with *= in summarize |
| G8-129 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:488:23: replace && with \|\| in summarize |
| G8-130 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:488:31: replace < with == in summarize |
| G8-131 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:488:31: replace < with > in summarize |
| G8-132 | SC3 | caught (new test, at f14a690) | report_tests::maturity_is_judged_at_the_next_block | tools/supply-audit/src/lib.rs:488:31: replace < with <= in summarize |
| G8-133 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:488:42: replace + with - in summarize |
| G8-134 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:488:42: replace + with * in summarize |
| G8-135 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:489:36: replace += with -= in summarize |
| G8-136 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:489:36: replace += with *= in summarize |
| G8-137 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:490:31: replace && with \|\| in summarize |
| G8-138 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:490:19: delete ! in summarize |
| G8-139 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:490:39: replace < with == in summarize |
| G8-140 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:490:39: replace < with > in summarize |
| G8-141 | SC3 | caught (new test, at f14a690) | report_tests::maturity_is_judged_at_the_next_block | tools/supply-audit/src/lib.rs:490:39: replace < with <= in summarize |
| G8-142 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:490:50: replace + with - in summarize |
| G8-143 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:490:50: replace + with * in summarize |
| G8-144 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:491:25: replace += with -= in summarize |
| G8-145 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:491:25: replace += with *= in summarize |
| G8-146 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:494:27: replace += with -= in summarize |
| G8-147 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:494:27: replace += with *= in summarize |
| G8-148 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:499:22: replace += with -= in summarize |
| G8-149 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:499:22: replace += with *= in summarize |
| G8-150 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:500:22: replace += with -= in summarize |
| G8-151 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:500:22: replace += with *= in summarize |
| G8-152 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:502:27: replace += with -= in summarize |
| G8-153 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:502:27: replace += with *= in summarize |
| G8-154 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:505:27: replace += with -= in summarize |
| G8-155 | SC3 | caught (existing test) | tests::summary_counts_on_chain_state_and_classifies_it | tools/supply-audit/src/lib.rs:505:27: replace += with *= in summarize |
| G8-156 | SC2 | unviable | error[E0277]: the trait bound `ChainParams: Default` is not satisfied | tools/supply-audit/src/lib.rs:529:5: replace node_params -> Result<ChainParams, String> with Ok(Default::default()) |
| G8-157 | SC2 | caught (existing test) | tests::only_a_final_genesis_is_audited | tools/supply-audit/src/lib.rs:532:8: delete ! in node_params |
| G8-158 | SC2 | caught (existing test) | tests::only_a_final_genesis_is_audited | tools/supply-audit/src/lib.rs:539:26: replace != with == in node_params |
| G8-159 | SC2 | unviable | error[E0277]: the trait bound `Report: Default` is not satisfied | tools/supply-audit/src/lib.rs:553:5: replace audit -> Result<Report, String> with Ok(Default::default()) |
| G8-160 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:557:27: replace > with == in audit |
| G8-161 | SC2 | caught (new test, at f14a690) | a_syncing_node_is_refused_and_one_without_a_header_height_is_audited | tools/supply-audit/src/lib.rs:557:27: replace > with < in audit |
| G8-162 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:557:27: replace > with >= in audit |
| G8-163 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:567:15: replace != with == in audit |
| G8-164 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_audit_block_is_refused,audit_at_an_earlier_height_rewin | tools/supply-audit/src/lib.rs:572:10: replace > with == in audit |
| G8-165 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:572:10: replace > with < in audit |
| G8-166 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_audit_block_is_refused,complete_set_balances_to_zero_and_a_missing_wallet_sh | tools/supply-audit/src/lib.rs:572:10: replace > with >= in audit |
| G8-167 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:578:20: replace == with != in audit |
| G8-168 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:581:25: replace && with \|\| in audit |
| G8-169 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:581:10: replace == with != in audit |
| G8-170 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/lib.rs:581:44: replace != with == in audit |
| G8-171 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:587:28: replace != with == in audit |
| G8-172 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:587:55: replace + with - in audit |
| G8-173 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:587:55: replace + with * in audit |
| G8-174 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:600:31: replace != with == in audit |
| G8-175 | SC2 | caught (existing test) | a_wallet_that_cannot_reach_the_audit_block_is_refused,audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:606:38: replace > with == in audit |
| G8-176 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:606:38: replace > with < in audit |
| G8-177 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it | tools/supply-audit/src/lib.rs:606:38: replace > with >= in audit |
| G8-178 | SC2 | caught (new test, at f14a690) | a_wallet_on_another_block_at_the_audit_height_is_refused | tools/supply-audit/src/lib.rs:618:44: replace \|\| with && in audit |
| G8-179 | SC2 | equivalent, pending second review | proof P1 (dispositions-G8.md) | tools/supply-audit/src/lib.rs:618:24: replace \|\| with && in audit |
| G8-180 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:618:19: replace != with == in audit |
| G8-181 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_audit_block_is_refused,audit_at_an_earlier_height_rewin | tools/supply-audit/src/lib.rs:618:39: replace != with == in audit |
| G8-182 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:618:54: replace && with \|\| in audit |
| G8-183 | SC2 | caught (new test, at f14a690) | a_wallet_on_another_block_at_the_audit_height_is_refused | tools/supply-audit/src/lib.rs:618:50: replace > with == in audit |
| G8-184 | SC2 | caught (new test, at f14a690) | a_wallet_on_another_block_at_the_audit_height_is_refused | tools/supply-audit/src/lib.rs:618:50: replace > with < in audit |
| G8-185 | SC2 | caught (new test, at 29284c2) | an_audit_at_the_genesis_after_the_kept_block_ids_moved_past_it | tools/supply-audit/src/lib.rs:618:50: replace > with >= in audit |
| G8-186 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,a_wallet_that_cannot_reach_the_au | tools/supply-audit/src/lib.rs:618:66: replace != with == in audit |
| G8-187 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount | tools/supply-audit/src/lib.rs:632:38: replace += with -= in audit |
| G8-188 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount | tools/supply-audit/src/lib.rs:632:38: replace += with *= in audit |
| G8-189 | SC1 | caught (new test, at f14a690) | px_records_over_two_wallets_account_for_the_pool | tools/supply-audit/src/lib.rs:637:38: replace += with -= in audit |
| G8-190 | SC1 | caught (new test, at f14a690) | px_records_over_two_wallets_account_for_the_pool | tools/supply-audit/src/lib.rs:637:38: replace += with *= in audit |
| G8-191 | SC2 | caught (existing test) | audit_at_an_earlier_height_rewinds_the_wallets_to_it,complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:643:22: replace == with != in audit |
| G8-192 | SC2 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:644:14: replace != with == in audit |
| G8-193 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:655:42: replace - with + in audit |
| G8-194 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:655:42: replace - with / in audit |
| G8-195 | SC1 | caught (new test, at f14a690) | px_records_over_two_wallets_account_for_the_pool | tools/supply-audit/src/lib.rs:655:35: replace - with + in audit |
| G8-196 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:655:35: replace - with / in audit |
| G8-197 | SC1 | caught (new test, at f14a690) | px_records_over_two_wallets_account_for_the_pool,a_px_record_without_a_bridge_in_raises_the_alarm | tools/supply-audit/src/lib.rs:656:30: replace - with + in audit |
| G8-198 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor | tools/supply-audit/src/lib.rs:656:30: replace - with / in audit |
| G8-199 | SC1 | caught (new test, at f14a690) | px_records_over_two_wallets_account_for_the_pool | tools/supply-audit/src/lib.rs:669:41: replace + with - in audit |
| G8-200 | SC1 | caught (existing test) | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount | tools/supply-audit/src/lib.rs:669:41: replace + with * in audit |
| G8-201 | SC4 | unviable | error[E0277]: the trait bound `Args: Default` is not satisfied | tools/supply-audit/src/main.rs:68:5: replace parse_args -> Args with Default::default() |
| G8-202 | SC1 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:82:5: replace main with () |
| G8-203 | SC4 | unviable | error[E0061]: this function takes 1 argument but 0 arguments were supplied | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::new()) |
| G8-204 | SC4 | unviable | error[E0599]: no associated function or constant named `from_iter` found for struct `Zeroizing<_>` in the current scope | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::from_iter([vec![]])) |
| G8-205 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::new(vec![])) |
| G8-206 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::from(vec![])) |
| G8-207 | SC4 | unviable | error[E0599]: no associated function or constant named `from_iter` found for struct `Zeroizing<_>` in the current scope | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::from_iter([vec![0]])) |
| G8-208 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::new(vec![0])) |
| G8-209 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::from(vec![0])) |
| G8-210 | SC4 | unviable | error[E0599]: no associated function or constant named `from_iter` found for struct `Zeroizing<_>` in the current scope | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::from_iter([vec![1]])) |
| G8-211 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::new(vec![1])) |
| G8-212 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:94:5: replace read_password_file -> Result<Zeroizing<Vec<u8>>, String> with Ok(Zeroizing::from(vec![1])) |
| G8-213 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:5: replace file_kdf -> Option<KdfParams> with None |
| G8-214 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:5: replace file_kdf -> Option<KdfParams> with Some(Default::default()) |
| G8-215 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:25: replace \|\| with && in file_kdf |
| G8-216 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:20: replace < with == in file_kdf |
| G8-217 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:20: replace < with > in file_kdf |
| G8-218 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:20: replace < with <= in file_kdf |
| G8-219 | SC4 | caught (new test, at f14a690) | tests::file_kdf_reads_only_a_wallet_file_header | tools/supply-audit/src/main.rs:103:40: replace != with == in file_kdf |
| G8-220 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:106:54: replace + with - in file_kdf |
| G8-221 | SC4 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:106:54: replace + with * in file_kdf |
| G8-222 | SC1 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:117:5: replace run -> Result<i32, String> with Ok(0) |
| G8-223 | SC1 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:117:5: replace run -> Result<i32, String> with Ok(1) |
| G8-224 | SC1 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:117:5: replace run -> Result<i32, String> with Ok(-1) |
| G8-225 | SC1 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:122:40: replace && with \|\| in run |
| G8-226 | SC4 | caught (new test, at f14a690) | a_password_file_count_that_does_not_match_the_wallets_is_refused | tools/supply-audit/src/main.rs:122:8: delete ! in run |
| G8-227 | SC1 | caught (existing test) | the_binary_is_read_only_and_reports_json_and_exit_codes | tools/supply-audit/src/main.rs:122:69: replace != with == in run |

| hand mutant | commit | exit | failing tests |
|---|---|---|---|
| H1 | e21eb4a | exit 101 | complete_set_balances_to_zero_and_a_missing_wallet_shows_its_exact_amount,audit_at_an_earlier_height_rewinds_the_wallets_to_it,the_binary_is_read_only_and_repor |
| H2 | f14a690 | exit 101 | px_records_over_two_wallets_account_for_the_pool,a_px_record_without_a_bridge_in_raises_the_alarm |
| H3 | f14a690 | exit 101 | equal_amounts_in_distinct_outputs_are_each_counted |
| H4 | f14a690 | exit 101 | px_records_over_two_wallets_account_for_the_pool,a_px_record_without_a_bridge_in_raises_the_alarm |
| H5 | e21eb4a | exit 101 | the_scan_sums_the_px_half_of_the_chain |
| H5b | e21eb4a | exit 101 | the_scan_sums_the_px_half_of_the_chain |
| H6 | e21eb4a | exit 101 | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported,the_scan_sums_the_px_half_of_the_chain,complete_set_balances_to_zero_and_a_missing_wa |
| H7 | e21eb4a | exit 101 | the_pool_may_return_to_exactly_zero_and_an_overpaying_coinbase_is_reported |
| H8 | f14a690 | exit 101 | pinned_serves_exactly_the_audit_height |
| H9 | f14a690 | exit 101 | pinned_serves_exactly_the_audit_height |
| H10 | f14a690 | exit 101 | pinned_serves_exactly_the_audit_height |
| H10b | f14a690 | exit 101 | pinned_serves_exactly_the_audit_height |
| H10c | e21eb4a | exit 101 | audit_at_an_earlier_height_rewinds_the_wallets_to_it |
| H11 | f14a690 | exit 101 | pinned_serves_exactly_the_audit_height |
| H12 | f14a690 | exit 101 | pinned_serves_exactly_the_audit_height |

Totals: caught 211, equivalent, pending second review 1, unviable 15
