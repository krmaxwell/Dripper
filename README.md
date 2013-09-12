Dripper
=======

Dripper.c is a fast, asynchronous DNS scanner; it can be used for enumerating subdomains and enumerating boxes via reverse DNS. See the [original home page](http://blackhatlibrary.net/Dripper). Redistributing under GPL v3 per the previous v1 permissions.


## How It Works

When Dripper first starts, it forks the process. The child process rapidly sends DNS queries using raw sockets without waiting for replies, while the parent process opens a raw socket sniffer and listens for DNS replies. Dripper cycles through a list of nameservers to help prevent rate limiting.

## Usage

Due to the usage of raw sockets, Dripper requires root priviledges to function properly.
The most basic usage of Dripper is to enumerate subdomains:

```
# ./dripper -d blackhatlibrary.net
---------------------------------
dripper Stateless DNS Scanner 1.0
  (c) jtripper 2013
  http://blackhatlibrary.net/
---------------------------------

www.blackhatlibrary.net -> 141.101.117.55 (A)
www.blackhatlibrary.net -> 141.101.116.55 (A)
```

By default, Dripper uses the file "resolv.conf" to load nameservers and "subs.txt" to load subdomains. These can be changed with the "-r" and "-s" options, respectively.

```
# ./dripper -r resolv.conf.2 -s subs2.txt -d blackhatlibrary.net
```

Dripper also supports reverse DNS record scanning, this feature accepts an IP range to scan and a word (usually a domain) to search for:

```
# ./dripper -d yahoo -i 98.138.253.109/24
---------------------------------
dripper Stateless DNS Scanner 1.0
  (c) jtripper 2013
  http://blackhatlibrary.net/
---------------------------------

9.253.138.98.in-addr.arpa -> hdf39.fp.ne1.yahoo.com (PTR)
46.253.138.98.in-addr.arpa -> fs2.fp.ne1.yahoo.com (PTR)
```

An example subdomain file might look like:

```
www
irc
```

Resolv.conf should be in the same format:

```
8.8.8.8
8.8.4.4
```

## Limitations

Some known limitations are:
- Packets do not get resent, packets that get lost are lost.
- Nameservers tend to ratelimit incoming packets.

**See also [pyTinyDns DNS server](http://www.chokepoint.net/2013/08/pytinydns-part-2.html).**

