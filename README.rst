Overview
========

This program is very personal and probably not useful to anyone besides me.  It
takes as input a list of malicious domain names.  They are considered so
because they fall into one of these categories:

- tracking
- advertisement
- malware distribution
- porn

This list is converted to an input file ready to be used for the “servers-file”
directive in the configuration file of dnsmasq.  So, the output file will
consist of lines with this format::

  server=/example.com/

For getting there, the following steps are necessary:

1. Make the set of domains unique
2. Remove all domains that are sub-domains of others (they are shadowed anyway,
   so they would just make the dataset bigger)
3. Apply a custom blacklist, i.e. add those entries to the input
4. Apply a whitelist.  This is a little bit trickier and explained in a section
   of its own.


Input file format
-----------------

Each line in the large blacklist must have the form::

  0.0.0.0 example.com

As for the personal black/whitelists, each line contains exactly one domain
name.  Empty lines and lines starting with `#` are ignored.


Hardcoded paths
---------------

Input
  `/etc/hosts-blacklist`

Output
  `/etc/servers-blacklist`

Blacklist
  `/tmp/my_blacklist`

Whitelist
  `/tmp/my_whitelist`


Applying the whitelist
----------------------

Each domain on the whitelist removes itself and all of its subdomains from the
complete list.

If there are superdomains (for a whitelist entry `good.example.com` this would
be `example.com`), an additional entry is added to the output of the form::

  server=/good.example.com/#

Note the `#` at the end of the line.


Todos
-----

- If a whitelisted entry does not start with “``*.``”, do not remove
  blacklisted subdomains.  For instance, I whitelist ``werstreamt.es``,
  however, ``data-c0c484e9be.werstreamt.es`` should still be blacklisted.
