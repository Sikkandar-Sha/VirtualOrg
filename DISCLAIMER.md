# Disclaimer

Read this before pointing anything at VirtualOrg, and before showing anyone what came
out of it.

## Everything in this world is invented

VirtualOrg generates a fictional company. Every person, machine, application, control,
policy, incident, vulnerability and finding in it was produced by
`world/generate.py` from a random seed. None of it describes any real organisation,
and none of it came from one.

- **The people are not real.** Names are drawn from a fixed word list and combined at
  random. Email addresses use `acme.example`, a domain reserved by RFC 2606 precisely
  so it can never resolve. Any resemblance to a living person is coincidental and
  unintended.
- **The CVE identifiers are fabricated, and deliberately impossible.** They are
  constructed with a year in the 9000s, for example `CVE-9024-12176`. CVE years are
  assignment years, so nothing will ever be issued in that range and an identifier
  from this world can never name a real advisory. The CVSS score attached to one says
  nothing whatsoever about the security of anything. This is on purpose: a synthetic
  finding that escapes into a real report should be recognisable as synthetic on
  sight, not only by whoever remembers where it came from.
- **The vulnerabilities, misconfigurations, control failures and incidents are
  fabricated.** They exist to give a risk-posture product something to reason about,
  not because anyone found them anywhere.
- **The vendor names are trademarks of their owners.** ServiceNow, Splunk, Onspring,
  Okta, Tenable, Workday and CrowdStrike are named because the API twins imitate the
  *shape* of their published interfaces. VirtualOrg is not affiliated with, endorsed
  by, sponsored by, or derived from any of them, and no code or data from any of them
  is included here.

## Do not let this data escape

The most likely way VirtualOrg causes harm is not a break-in. It is a screenshot.

A posture report computed from this world looks exactly like a posture report computed
from a real one. Numbers, control references, CVE identifiers and severities all read
as genuine. Put one in front of someone who does not know its provenance and they will
reasonably assume it describes their estate.

So:

- **Label it.** The shipped connector config sets `mode: simulated` for exactly this
  reason. Carry that label through to your output and into anything you present.
- **Never load VirtualOrg output into a real risk register, GRC platform, ticketing
  system or reporting pipeline.** Not even to test the load. Synthetic findings that
  reach a real register are very hard to remove and very easy to act on.
- **Never mix real and synthetic data in one world.** VirtualOrg has no provision for
  handling real customer data, no access controls worth the name, and no data
  retention or deletion story. It is not built to hold anything that matters.

## This is not a security product

VirtualOrg does not scan anything, detect anything, or protect anything. It is a test
fixture. It offers no assurance about the security of any system, including its own,
and nothing it reports constitutes security advice.

The environment ships with working credentials on purpose and binds to localhost for
that reason. See [SECURITY.md](SECURITY.md) before changing either.

## The twins are models, not the vendors

Every API twin here was written from published documentation and our understanding of
each vendor's behaviour. **None was captured from a real tenant, and all seven are derived as
`unverified`** from `twins/provenance.yaml`, which records for each twin what its
shapes were based on and whether anything was ever captured. The status is computed
from those two facts rather than asserted, and served at `/_provenance`.

A connector that passes against VirtualOrg has been shown to agree with *this
environment*. It has not been shown to agree with the vendor. Those are different
claims, and only the first one is supported by anything here. Closing that gap needs
certification against real vendor tenants.

## No warranty

VirtualOrg is provided under the Apache License 2.0, without warranty of any kind. See
[LICENSE](LICENSE) for the full text, including the limitation of liability.
