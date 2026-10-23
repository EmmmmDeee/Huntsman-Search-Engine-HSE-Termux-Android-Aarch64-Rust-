- A DNS answer read from wire form (DNS over UDP or RFC 8484 DNS over HTTPS) refuses a name
  longer than RFC 1035's 255 octets. A hostile resolver could point every record of one 64 KB
  datagram at a 30 KB name and have it copied, escaped, into each: about 350 MB of text and
  15 seconds of work from one answer. A name in a record's data (`CNAME`, `NS`, `PTR`, `DNAME`,
  `MX`, `SRV`) must also end inside that record; one that ran on into the bytes after it was read
  as the record's value.
