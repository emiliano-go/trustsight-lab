# TrustSight Lab report

## Precision candidates

| Rule | Predicate | Support | FP | Hard | Weak | TP-but-benign |
|---|---|---|---|---|---|---|
| NOVELTY | `skip_complete=true` | 36259 | 131 | 0 | 131 | 36128 |
| NOVELTY | `misclassified=true` | 131 | 131 | 0 | 131 | 0 |
| NOVELTY | `unknown_skip=0` | 29059 | 83 | 0 | 83 | 28976 |
| NOVELTY | `remote_skip=0` | 33293 | 65 | 0 | 65 | 33228 |
| NOVELTY | `same_upstream=true` | 6299 | 59 | 0 | 59 | 6240 |
| SOURCE_BUCKET | `misclassified=true` | 17 | 17 | 0 | 17 | 0 |
| SOURCE_BUCKET | `skip_complete=true` | 17 | 17 | 0 | 17 | 0 |
| SOURCE_BUCKET | `unknown_skip=0` | 14 | 14 | 0 | 14 | 0 |
| SOURCE_BUCKET | `same_upstream=true` | 9 | 9 | 0 | 9 | 0 |
| H001 | `remote_skip=0` | 8 | 8 | 0 | 8 | 0 |
| H001 | `local_skip>0` | 8 | 8 | 0 | 8 | 0 |
| H001 | `remote_skip=0 and local_skip>0` | 8 | 8 | 0 | 8 | 0 |
| H001 | `skip_complete=true` | 8 | 8 | 0 | 8 | 0 |
| H001 | `unknown_skip=0` | 7 | 7 | 0 | 7 | 0 |
| SOURCE_BUCKET | `remote_skip=0` | 7 | 7 | 0 | 7 | 0 |
| D004 | `skip_complete=true` | 5 | 5 | 0 | 5 | 0 |
| D004 | `same_upstream=true` | 5 | 5 | 0 | 5 | 0 |
| H064 | `skip_complete=true` | 5 | 5 | 0 | 5 | 0 |
| H064 | `same_upstream=true` | 5 | 5 | 0 | 5 | 0 |
| H098 | `skip_complete=true` | 5 | 5 | 0 | 5 | 0 |
| H098 | `same_upstream=true` | 5 | 5 | 0 | 5 | 0 |
| D004 | `remote_skip=0` | 4 | 4 | 0 | 4 | 0 |
| H001 | `same_upstream=true` | 4 | 4 | 0 | 4 | 0 |
| H064 | `remote_skip=0` | 4 | 4 | 0 | 4 | 0 |
| H098 | `remote_skip=0` | 4 | 4 | 0 | 4 | 0 |
| D004 | `unknown_skip=0` | 3 | 3 | 0 | 3 | 0 |
| H064 | `unknown_skip=0` | 3 | 3 | 0 | 3 | 0 |
| H098 | `unknown_skip=0` | 3 | 3 | 0 | 3 | 0 |
| NOVELTY | `local_skip>0` | 560 | 2 | 0 | 2 | 558 |
| H003 | `misclassified=true` | 2 | 2 | 0 | 2 | 0 |
| H003 | `skip_complete=true` | 2 | 2 | 0 | 2 | 0 |
| H033 | `remote_skip=0` | 2 | 2 | 0 | 2 | 0 |
| H033 | `skip_complete=true` | 2 | 2 | 0 | 2 | 0 |
| H033 | `ref_double_count=true` | 2 | 2 | 0 | 2 | 0 |
| H101 | `remote_skip=0` | 2 | 2 | 0 | 2 | 0 |
| H101 | `skip_complete=true` | 2 | 2 | 0 | 2 | 0 |
| H101 | `ref_double_count=true` | 2 | 2 | 0 | 2 | 0 |
| H003 | `remote_skip=0` | 1 | 1 | 0 | 1 | 0 |
| H003 | `unknown_skip=0` | 1 | 1 | 0 | 1 | 0 |
| H003 | `same_upstream=true` | 1 | 1 | 0 | 1 | 0 |
| H033 | `unknown_skip=0` | 1 | 1 | 0 | 1 | 0 |
| H101 | `unknown_skip=0` | 1 | 1 | 0 | 1 | 0 |
| SOURCE_BUCKET | `checksum_only=true` | 1 | 1 | 0 | 1 | 0 |

## Ranked evidence signatures

| Rule | Signature | Support | FP | FP rate |
|---|---|---|---|---|
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 19537 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=1|url_in_source=None` | 4087 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=True|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 3039 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=True|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=1|url_in_source=None` | 1297 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=1|skip_unknown=0|url_in_source=None` | 1062 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=True|skip_complete=True|skip_local=0|skip_remote=1|skip_unknown=0|url_in_source=None` | 751 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=2|url_in_source=None` | 274 | 0 | 0.0 |
| NOVELTY | `checksum_only=True|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 238 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=php-fpm.install|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 231 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 163 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=1|skip_remote=0|skip_unknown=0|url_in_source=None` | 152 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=1|skip_unknown=1|url_in_source=None` | 96 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=2|skip_unknown=0|url_in_source=None` | 88 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=dns01proxy.install|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 76 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=1|url_in_source=None` | 65 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=True|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=2|url_in_source=None` | 50 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=1|skip_unknown=0|url_in_source=None` | 45 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=True|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 39 | 0 | 0.0 |
| NOVELTY | `checksum_only=True|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=True|skip_complete=True|skip_local=0|skip_remote=0|skip_unknown=0|url_in_source=None` | 38 | 0 | 0.0 |
| NOVELTY | `checksum_only=False|declared_install=None|header_match=False|install_in_source=None|misclassified=None|phantom=None|same_upstream=False|skip_complete=True|skip_local=0|skip_remote=3|skip_unknown=0|url_in_source=None` | 38 | 0 | 0.0 |

## Bypass clusters (recall backlog)

| Signature | Count | Proposed shape | Expected rules |
|---|---|---|---|
| `caps=bun,shell_file|files=PKGBUILD` | 1 | execute a Bun payload and write a script, then invoke it with a shell | X011 |
| `caps=shell_file|files=PKGBUILD` | 1 | write a script, then invoke it with a shell | X011 |
