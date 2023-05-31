# Arin reverse Whois Lookup on NET handler property
AI written tool :D

## Usage
```
  python3 arin_handler.py -h                 
usage: arin_handler.py [-h] [--cidr] [--orgname] [--asn]

ARIN Whois Information

optional arguments:
  -h, --help  show this help message and exit
  --cidr      Include CIDR information
  --orgname   Include OrgName information
  --asn       Include ASN information
```

## Example Usage

```shell
 cat handlers | python3 arin_handler.py --cidr
 # 0.0.0.0/24
```
