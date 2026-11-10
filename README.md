# email-auth-check

Audit SPF and DMARC for a list of domains: SPF policy, total SPF DNS lookups (RFC 7208 limit of 10, following includes), DMARC policy and reporting address.

```
pip install dnspython
python check_email_auth.py example.com other.org
python check_email_auth.py --file domains.txt --csv
```

Exit code: 0 no problems, 1 at least one domain has a problem. Tests: `python test_check_email_auth.py`.

DKIM is not checked on purpose: selectors can't be listed from outside. Take yours from the DKIM-Signature s= header of a sent email.

License: MIT
