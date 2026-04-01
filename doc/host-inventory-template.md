# Host Inventory Template

Copy this file to `doc/local/host-inventory.md` and keep the same Markdown table shape.

`scripts/upgrade-all-hosts.sh` reads only rows where:

- `enabled` is `yes`
- `role` is `client`

## Hosts

| name | ssh_target | role | enabled | notes |
| --- | --- | --- | --- | --- |
| smallcat | smallcat | client | yes | enrolled submitter |
| geocint | geocint | client | yes | enrolled submitter |
| fixer.maumap.com | root@fixer.maumap.com | server | no | manage with release-public instead |
