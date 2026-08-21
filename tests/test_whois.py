from collector.whois import WhoisRecord, _parse_rdap


def test_parse_rdap_ipv4():
    payload = {
        "name": "CLOUDFLARENET",
        "country": "US",
        "startAddress": "1.1.1.0",
        "endAddress": "1.1.1.255",
        "handle": "NET-1-1-1-0-1",
        "links": [{"href": "https://rdap.arin.net/registry/ip/1.1.1.1"}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@cloudflare.com"]]],
            },
        ],
    }
    record = _parse_rdap("1.1.1.1", payload)
    assert isinstance(record, WhoisRecord)
    assert record.network == "CLOUDFLARENET"
    assert record.country == "US"
    assert record.org == "Cloudflare, Inc."
    assert record.abuse == "abuse@cloudflare.com"
    assert record.rir == "ARIN"
