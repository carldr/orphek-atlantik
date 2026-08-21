# Working convention

## Keep FINDINGS.md up to date

Keep a chronological record of what we do, whether it worked or not.  We want to write
a blog post or a summary after we've completed things.

## Running commands

The user runs the active network operations themselves (nmap, ssh, live probes) — it's
more interesting that way and keeps live-hardware actions under their control.
Claude does offline analysis (firmware, APKs, hash cracking) and hands over exact
commands to run.
