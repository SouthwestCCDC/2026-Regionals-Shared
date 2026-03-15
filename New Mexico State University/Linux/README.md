# Linux

Initial Linux hardening helper:

```bash
bash Invoke-Harden.sh
```

To also remediate unsafe `NOPASSWD` rules interactively:

```bash
sudo bash Invoke-Harden.sh --remediate
```

Current behavior:
- Checks whether the current user can run `sudo` without a password.
- Scans readable `sudoers` files for `NOPASSWD` entries.
- Can comment out detected `NOPASSWD` entries after prompting, with backup creation and `visudo` validation.

PHP-specific hardening now lives in a separate tool:

```bash
bash Invoke-PHP-Harden.sh
sudo bash Invoke-PHP-Harden.sh --remediate
```

That helper checks conservative `php.ini` directives and can update insecure or missing values after prompting. It intentionally avoids higher-breakage changes like `disable_functions`, and it does not auto-set environment-specific values like `session.cookie_secure`.

Apache-specific hardening:

```bash
bash Invoke-Apache-Harden.sh
sudo bash Invoke-Apache-Harden.sh --remediate
```

That helper checks conservative Apache settings including `ServerTokens Prod`, `ServerSignature Off`, and `TraceEnable Off`, and reports `Options Indexes` exposure. It only auto-remediates the low-risk directive settings.

Nginx-specific hardening:

```bash
bash Invoke-Nginx-Harden.sh
sudo bash Invoke-Nginx-Harden.sh --remediate
```

That helper checks conservative Nginx settings including `server_tokens off` and reports `autoindex on` exposure. It only auto-remediates the low-risk directive settings.

PHP-FPM-specific hardening:

```bash
bash Invoke-PHP-FPM-Harden.sh
sudo bash Invoke-PHP-FPM-Harden.sh --remediate
```

That helper checks conservative PHP-FPM settings like `clear_env = yes`, `security.limit_extensions = .php`, and reports unrestricted TCP listeners without `listen.allowed_clients`. It only auto-remediates the low-risk directive settings.

MySQL/MariaDB-specific hardening:

```bash
bash Invoke-MySQL-Harden.sh
sudo bash Invoke-MySQL-Harden.sh --remediate
```

That helper checks conservative database settings like `local_infile = 0`, `symbolic-links = 0`, presence of `secure_file_priv`, and reports risky network exposure such as `bind-address = 0.0.0.0`. It only auto-remediates the low-risk directive settings.

SSH-specific hardening:

```bash
bash Invoke-SSH-Harden.sh
sudo bash Invoke-SSH-Harden.sh --remediate
```

That helper checks conservative SSH settings like `PermitEmptyPasswords no` and `X11Forwarding no`, and reports higher-risk items like `PermitRootLogin yes` or enabled password authentication without auto-changing them.

Node.js-specific hardening:

```bash
bash Invoke-NodeJS-Harden.sh
sudo bash Invoke-NodeJS-Harden.sh --remediate
```

That helper discovers Node.js projects by `package.json`, reports risky runtime patterns like `nodemon` or `--inspect` in production configs, checks `.env` files for `NODE_ENV=production`, and tightens broad permissions on `.env` and `package.json` files when you approve remediation.

Front-end audit:

```bash
bash Invoke-Frontend-Audit.sh
bash Invoke-Frontend-Audit.sh /var/www/app
```

That helper audits front-end source and template files for high-signal client-side issues such as DOM XSS sinks, dangerous dynamic code execution, raw HTML injection patterns, wildcard `postMessage`, insecure `target="_blank"` links, insecure HTTP resources, likely CSRF gaps in POST forms, exposed sourcemaps, and potential hardcoded secrets.
