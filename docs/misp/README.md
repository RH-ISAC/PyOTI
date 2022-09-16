## PyOTI Taxonomy Library

---
### PyOTI automated enrichment schemes and definitions for point in time classification of indicators. 
pyoti namespace available in JSON format at this [location](https://github.com/MISP/misp-taxonomies/blob/main/pyoti/machinetag.json). The JSON format can be freely reused in your application or automatically enabled in [MISP](https://www.github.com/MISP/MISP) taxonomy.

---
A machine tag is composed of a namespace, a predicate and a value. Machine tags are often called triple tag due to their format.

- namespace:predicate=value

---
### checkdmarc
#### pyoti:checkdmarc="spoofable"
  * #### Spoofable
    > The email address can be spoofed (e.g. no strict SPF policy/DMARC is not enforced).

---
### disposable-email
#### pyoti:disposable-email
> The email domain is from a disposable email service.

---
### emailrepio
#### pyoti:emailrepio="spoofable"
  * #### Spoofable
    > The email address can be spoofed (e.g. no strict SPF policy/DMARC is not enforced).


#### pyoti:emailrepio="suspicious"
  * #### Suspicious
    > The email address should be treated as suspicious or risky.

#### pyoti:emailrepio="blacklisted"
  * #### Blacklisted
    > The email address is believed to be malicious or spammy.

#### pyoti:emailrepio="malicious-activity"
  * #### Malicious Activity
    > The email address has exhibited malicious behavior (e.g. phishing/fraud).

#### pyoti:emailrepio="malicious-activity-recent"
  * #### Malicious Activity Recent
    > The email address has exhibited malicious behavior in the last 90 days (e.g. in the case of temporal account takeovers).

#### pyoti:emailrepio="credentials-leaked"
  * #### Credentials Leaked
    > The email address has had credentials leaked at some point in time (e.g. a data breach, pastebin, dark web, etc).

#### pyoti:emailrepio="credentials-leaked-recent"
  * #### Credentials Leaked Recent
    > The email address has had credentials leaked in the last 90 days.

#### pyoti:emailrepio="reputation-high"
  * #### Reputation High
    > The email address has a high reputation.

#### pyoti:emailrepio="reputation-medium"
  * #### Reputation Medium
    > The email address has a medium reputation.

#### pyoti:emailrepio="reputation-low"
  * #### Reputation Low
    > The email address has a low reputation.

#### pyoti:emailrepio="suspicious-tld"
  * #### Suspicious TLD
    > The email address top-level domain is suspicious.

#### pyoti:emailrepio="spam"
  * #### Spam
    > The email address has exhibited spammy behavior (e.g. spam traps, login form abuse, etc).

---
### iris-investigate
#### pyoti:iris-investigate="high"
  * #### High
    > The domain risk score is high (76-100).

#### pyoti:iris-investigate="medium-high"
  * #### Medium High
    > The domain risk score is medium-high (51-75).

#### pyoti:iris-investigate="medium"
  * #### Medium
    > The domain risk score is medium (26-50).

#### pyoti:iris-investigate="low"
  * #### Low
    > The domain risk score is low (0-25).

---
### virustotal
#### pyoti:virustotal="known-distributor"
  * #### Known Distributor
    > The known-distributor entry indicates a file is from a known distributor.

#### pyoti:virustotal="valid-signature"
  * #### Valid Signature
    > The valid-signature entry indicates a file is signed with a valid signature.

#### pyoti:virustotal="invalid-signature"
  * #### Invalid Signature
    > The invalid-signature entry indicates a file is signed with an invalid signature.

---
### circl-hashlookup
#### pyoti:circl-hashlookup="high-trust"
  * #### High Trust
    > The trust level is high (76-100).

#### pyoti:circl-hashlookup="medium-high-trust"
  * #### Medium High Trust
    > The trust level is medium-high (51-75).

#### pyoti:circl-hashlookup="medium-trust"
  * #### Medium Trust
    > The trust level is medium (26-50).

#### pyoti:circl-hashlookup="low-trust"
  * #### Low Trust
    > The trust level is low (0-25).

---
### reputation-block-list
#### pyoti:reputation-block-list="barracudacentral-brbl"
  * #### Barracuda Reputation Block List
    > Barracuda Reputation Block List (BRBL) is a free DNSBL of IP addresses known to send spam. Barracuda Networks fights spam and created the BRBL to help stop the spread of spam.

#### pyoti:reputation-block-list="spamcop-scbl"
  * #### SpamCop Blocking List
    > The SpamCop Blocking List (SCBL) lists IP addresses which have transmitted reported email to SpamCop users. SpamCop, service providers and individual users then use the SCBL to block and filter unwanted email.

#### pyoti:reputation-block-list="spamhaus-sbl"
  * #### Spamhaus Block List
    > The Spamhaus Block List (SBL) Advisory is a database of IP addresses from which Spamhaus does not recommend the acceptance of electronic mail.

#### pyoti:reputation-block-list="spamhaus-xbl"
  * #### Spamhaus Exploits Block List
    > The Spamhaus Exploits Block List (XBL) is a realtime database of IP addresses of hijacked PCs infected by illegal 3rd party exploits, including open proxies (HTTP, socks, AnalogX, wingate, etc), worms/viruses with built-in spam engines, and other types of trojan-horse exploits.

#### pyoti:reputation-block-list="spamhaus-pbl"
  * #### Spamhaus Policy Block List
    > The Spamhaus PBL is a DNSBL database of end-user IP address ranges which should not be delivering unauthenticated SMTP email to any Internet mail server except those provided for specifically by an ISP for that customer’s use.

#### pyoti:reputation-block-list="spamhaus-css"
  * #### Spamhaus CSS
    > The Spamhaus CSS list is an automatically produced dataset of IP addresses that are involved in sending low-reputation email. CSS mostly targets static spam emitters that are not covered in the PBL or XBL, such as snowshoe spam operations, but may also include other senders that display a risk to our users, such as compromised hosts.

#### pyoti:reputation-block-list="spamhaus-drop"
  * #### Spamhaus Don’t Route Or Peer
    > Spamhaus Don’t Route Or Peer (DROP) is an advisory 'drop all traffic' list. DROP is a tiny subset of the SBL which is designed for use by firewalls or routing equipment.

#### pyoti:reputation-block-list="spamhaus-spam"
  * #### Spamhaus Domain Block List Spam Domain
    > Spamhaus Domain Block List (DBL) is a list of domain names with poor reputations used for spam.

#### pyoti:reputation-block-list="spamhaus-phish"
  * #### Spamhaus Domain Block List Phish Domain
    > Spamhaus Domain Block List (DBL) is a list of domain names with poor reputations used for phishing.

#### pyoti:reputation-block-list="spamhaus-malware"
  * #### Spamhaus Domain Block List Malware Domain
    > Spamhaus Domain Block List (DBL) is a list of domain names with poor reputations used to serve malware.

#### pyoti:reputation-block-list="spamhaus-botnet-c2"
  * #### Spamhaus Domain Block List Botnet C2 Domain
    > Spamhaus Domain Block List (DBL) is a list of domain names with poor reputations used for botnet command and control.

#### pyoti:reputation-block-list="spamhaus-abused-legit-spam"
  * #### Spamhaus Domain Block List Abused Legit Spam Domain
    > Spamhaus Domain Block List (DBL) is a list of abused legitimate domain names with poor reputations used for spam.

#### pyoti:reputation-block-list="spamhaus-abused-spammed-redirector"
  * #### Spamhaus Domain Block List Abused Spammed Redirector Domain
    > Spamhaus Domain Block List (DBL) is a list of abused legitimate spammed domain names with poor reputations used as redirector domains.

#### pyoti:reputation-block-list="spamhaus-abused-legit-phish"
  * #### Spamhaus Domain Block List Abused Legit Phish Domain
    > Spamhaus Domain Block List (DBL) is a list of abused legitimate domain names with poor reputations used for phishing.

#### pyoti:reputation-block-list="spamhaus-abused-legit-malware"
  * #### Spamhaus Domain Block List Abused Legit Malware Domain
    > Spamhaus Domain Block List (DBL) is a list of abused legitimate domain names with poor reputations used to serve malware.

#### pyoti:reputation-block-list="spamhaus-abused-legit-botnet-c2"
  * #### Spamhaus Domain Block List Abused Legit Botnet C2 Domain
    > Spamhaus Domain Block List (DBL) is a list of abused legitimate domain names with poor reputations used for botnet command and control.

#### pyoti:reputation-block-list="surbl-phish"
  * #### SURBL Phishing Sites
    > Phishing data from multiple sources is included in this list. Data includes PhishTank, OITC, PhishLabs, Malware Domains and several other sources, including proprietary research by SURBL.

#### pyoti:reputation-block-list="surbl-malware"
  * #### SURBL Malware Sites
    > This list contains data from multiple sources that cover sites hosting malware. This includes OITC, abuse.ch, The DNS blackhole malicious site data from malwaredomains.com and others. Malware data also includes significant proprietary research by SURBL.

#### pyoti:reputation-block-list="surbl-spam"
  * #### SURBL Spam Sites
    > This list contains mainly general spam sites. It combines data from the formerly separate JP, WS, SC and AB lists. It also includes data from Internet security, anti-abuse, ISP, ESP and other communities, such as Telenor. Most of the data in this list comes from internal, proprietary research by SURBL.

#### pyoti:reputation-block-list="surbl-abused-legit"
  * #### SURBL Abused Legit Sites
    > This list contains data from multiple sources that cover cracked sites, including SURBL internal ones. Criminals steal credentials or abuse vulnerabilities to break into websites and add malicious content. Often cracked pages will redirect to spam sites or to other cracked sites. Cracked sites usually still contain the original legitimate content and may still be mentioned in legitimate emails, besides the malicious pages referenced in spam.

#### pyoti:reputation-block-list="uribl-black"
  * #### URIBL Black
    > URIBL Black list contains domain names belonging to and used by spammers, including but not restricted to those that appear in URIs found in Unsolicited Bulk and/or Commercial Email (UBE/UCE). This list has a goal of zero False Positives.

#### pyoti:reputation-block-list="uribl-grey"
  * #### URIBL Grey
    > URIBL Grey list contains domains found in UBE/UCE, and possibly honour opt-out requests. It may include ESPs which allow customers to import their recipient lists and may have no control over the subscription methods. This list can and probably will cause False Positives depending on your definition of UBE/UCE.

#### pyoti:reputation-block-list="uribl-red"
  * #### URIBL Red
    > URIBL Red list contains domains that actively show up in mail flow, are not listed on URIBL black, and are either: being monitored, very young (domain age via whois), or use whois privacy features to protect their identity. This list is automated in nature, so please use at your own risk.

#### pyoti:reputation-block-list="uribl-multi"
  * #### URIBL Multi
    > URIBL Multi list contains all of the public URIBL lists.

---
### abuseipdb
#### pyoti:abuseipdb="high"
  * #### High
    > The IP abuse confidence score is high (76-100).

#### pyoti:abuseipdb="medium-high"
  * #### Medium High
    > The IP abuse confidence score is medium-high (51-75).

#### pyoti:abuseipdb="medium"
  * #### Medium
    > The IP abuse confidence score is medium (26-50).

#### pyoti:abuseipdb="low"
  * #### Low
    > The IP abuse confidence score is low (0-25).

---
### greynoise-riot
#### pyoti:greynoise-riot="trust-level-1"
  * #### Trust Level 1
    > These IPs are trustworthy because the companies or services assigned are generally responsible for the interactions with this IP. Adding these ranges to an allow-list may make sense.

#### pyoti:greynoise-riot="trust-level-2"
  * #### Trust Level 2
    > These IPs are somewhat trustworthy because they are necessary for regular and common business internet use. Companies that own these IPs typically do not claim responsibility or have accountability for interactions with these IPs. Malicious actions may be associated with these IPs but adding this entire range to a block-list does not make sense.

---
### googlesafebrowsing
#### pyoti:googlesafebrowsing="malware"
  * #### MALWARE
    > Malware threat type.

#### pyoti:googlesafebrowsing="social-engineering"
  * #### SOCIAL_ENGINEERING
    > Social engineering threat type.

#### pyoti:googlesafebrowsing="unwanted-software"
  * #### UNWANTED_SOFTWARE
    > Unwanted software threat type.

#### pyoti:googlesafebrowsing="potentially-harmful-application"
  * #### POTENTIALLY_HARMFUL_APPLICATION
    > Potentially harmful application threat type.

#### pyoti:googlesafebrowsing="unspecified"
  * #### THREAT_TYPE_UNSPECIFIED
    > Unknown threat type.