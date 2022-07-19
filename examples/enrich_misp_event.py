from argparse import ArgumentParser
from pymisp import ExpandedPyMISP, MISPAttribute, MISPObjectAttribute
from typing import Dict, List, Union

from pyoti.domains import CheckDMARC, IrisInvestigate
from pyoti.emails import DisposableEmails, EmailRepIO
from pyoti.hashes import CIRCLHashLookup
from pyoti.ips import AbuseIPDB, GreyNoise
from pyoti.multis import DNSBlockList, VirusTotalV3
from pyoti.urls import GoogleSafeBrowsing

from keys import abuseipdb, domaintools, googlesafebrowsing, greynoise, misp_pre, sublime, virustotal


def enrich_hashes(file_hash: str) -> Dict:
    enrichment = {}

    hl = CIRCLHashLookup()
    hl.file_hash = file_hash
    enrichment['hashlookup'] = hl.check_hash()

    vt = VirusTotalV3(api_key=virustotal)
    vt.file_hash = file_hash
    enrichment['virustotal'] = vt.check_hash()

    return enrichment


def get_hashlookup_tags(hltrust: int) -> str:
    lt = 'pyoti:circl-hashlookup="low-trust"'
    mt = 'pyoti:circl-hashlookup="medium-trust"'
    mht = 'pyoti:circl-hashlookup="medium-high-trust"'
    ht = 'pyoti:circl-hashlookup="high-trust"'

    if hltrust <= 25:
        return lt
    elif 25 < hltrust <= 50:
        return mt
    elif 50 < hltrust <= 75:
        return mht
    elif hltrust > 75:
        return ht


def enrich_domains(domain: str) -> Dict:
    enrichment = {}

    iris = IrisInvestigate(api_key=domaintools)
    iris.domain = domain
    i_domain = iris.check_domain()
    enrichment['iris'] = i_domain

    dbl = DNSBlockList()
    dbl.domain = domain
    enrichment['dbl'] = dbl.check_domain()

    return enrichment


def get_domainrisk_tags(risk_score: int) -> str:
    hr = 'pyoti:iris-investigate="high"'
    mhr = 'pyoti:iris-investigate="medium-high"'
    mr = 'pyoti:iris-investigate="medium"'
    lr = 'pyoti:iris-investigate="low"'

    if risk_score <= 25:
        return lr
    elif 25 < risk_score <= 50:
        return mr
    elif 50 < risk_score <= 75:
        return mhr
    elif risk_score > 75:
        return hr


def enrich_emails(email: str) -> Dict:
    enrichment = {}
    domain = email.split("@")[1]

    dmarc = CheckDMARC()
    dmarc.domain = domain
    enrichment['checkdmarc'] = dmarc.check_domain()

    disposable = DisposableEmails()
    disposable.email = email
    enrichment['disposable'] = disposable.check_email()

    erep = EmailRepIO(api_key=sublime)
    erep.email = email
    enrichment['emailrep'] = erep.check_email()

    return enrichment


def get_emailrep_tags(reputation: str) -> str:
    hr = 'pyoti:emailrepio="reputation-high"'
    mr = 'pyoti:emailrepio="reputation-medium"'
    lr = 'pyoti:emailrepio="reputation-low"'

    if reputation == "high":
        return hr
    elif reputation == "medium":
        return mr
    elif reputation == "low":
        return lr


def enrich_ips(ip: str) -> Dict:
    enrichment = {}

    abuse = AbuseIPDB(api_key=abuseipdb)
    abuse.ip = ip
    enrichment['abuseipdb'] = abuse.check_ip()

    gn = GreyNoise(api_key=greynoise)
    gn.ip = ip
    enrichment['greynoise'] = gn.check_ip_riot()

    rbl = DNSBlockList()
    rbl.ip = ip
    enrichment['rbl'] = rbl.check_ip()

    return enrichment


def get_abuseipdb_tags(abuse_score: int) -> str:
    ha = 'pyoti:abuseipdb="high"'
    mha = 'pyoti:abuseipdb="medium-high"'
    ma = 'pyoti:abuseipdb="medium"'
    la = 'pyoti:abuseipdb="low"'

    if abuse_score <= 25:
        return la
    elif 25 < abuse_score <= 50:
        return ma
    elif 50 < abuse_score <= 75:
        return mha
    elif abuse_score > 75:
        return ha


def enrich_urls(url: str) -> Dict:
    enrichment = {}

    gsb = GoogleSafeBrowsing(api_key=googlesafebrowsing)
    gsb.url = url
    g_url = gsb.check_url()
    enrichment['google'] = g_url

    return enrichment


def get_gsb_tags(threat_type: List[str]) -> List[str]:
    mal = 'pyoti:googlesafebrowsing="malware"'
    se = 'pyoti:googlesafebrowsing="social-engineering"'
    us = 'pyoti:googlesafebrowsing="unwanted-software"'
    pha = 'pyoti:googlesafebrowsing="potentially-harmful-application"'
    un = 'pyoti:googlesafebrowsing="unspecified"'

    for threat in threat_type:
        if threat == "MALWARE":
            yield mal
        elif threat == "SOCIAL_ENGINEERING":
            yield se
        elif threat == "UNWANTED_SOFTWARE":
            yield us
        elif threat == "POTENTIALLY_HARMFUL_APPLICATION":
            yield pha
        elif threat == "THREAT_TYPE_UNSPECIFIED":
            yield un


def run_enrichment(attributes: Union[List[MISPAttribute], List[MISPObjectAttribute]]):
    for attr in attributes:
        # do PyOTI hash enrichment
        if attr.type == "md5" or attr.type == "sha1" or attr.type == "sha256":
            if attr.value in processed_iocs:
                # apply tags from attribute that has already been checked and enriched
                [attr.add_tag(tag) for tag in processed_iocs[attr.value]]
                continue
            processed_iocs[attr.value] = []
            h_enrichment = enrich_hashes(attr.value)

            # get hashlookup trust level and apply pyoti taxonomy tag
            hltrust = h_enrichment['hashlookup'].get('hashlookup:trust')
            if hltrust:
                hl_tag = get_hashlookup_tags(hltrust)
                processed_iocs[attr.value].append(hl_tag)
                attr.add_tag(hl_tag)

            if h_enrichment['virustotal'].get('error'):
                # looking for file not found error and continuing to next attribute
                continue
            else:
                # get virstotal known software distributor and apply pyoti taxonomy tag
                vt_known = h_enrichment['virustotal'].get('data').get('attributes').get('known_distributors')
                if vt_known:
                    vt_known_tag = 'pyoti:virustotal="known-distributor"'
                    processed_iocs[attr.value].append(vt_known_tag)
                    attr.add_tag(vt_known_tag)

                # get virstotal file signature info and apply pyoti taxonomy tag
                vt_sig = h_enrichment['virustotal'].get('data').get('attributes').get('signature_info')
                if vt_sig:
                    vt_sig_tag = 'pyoti:virustotal="valid-signature"'
                    processed_iocs[attr.value].append(vt_sig_tag)
                    attr.add_tag(vt_sig_tag)

                # get virustotal threat classification info and apply pyoti taxonomy tag
                vt_tc = h_enrichment['virustotal'].get('data').get('attributes').get('popular_threat_classification')
                if vt_tc:
                    vt_threat_label = vt_tc.get('suggested_threat_label')
                    processed_iocs[attr.value].append(vt_threat_label)
                    attr.add_tag(vt_threat_label)

        elif attr.type == "domain" or attr.type == "hostname":
            # do PyOTI domain enrichment
            if attr.value in processed_iocs:
                # apply tags from attribute that has already been checked and enriched
                [attr.add_tag(tag) for tag in processed_iocs[attr.value]]
                continue
            processed_iocs[attr.value] = []
            d_enrichment = enrich_domains(attr.value)

            # get iris-investigate domain risk score and apply pyoti taxonomy tag
            risk_score = d_enrichment['iris'][0].get('domain_risk').get('risk_score')
            iris_tag = get_domainrisk_tags(risk_score)
            processed_iocs[attr.value].append(iris_tag)
            attr.add_tag(iris_tag)

            # check if domain is on dns block lists
            dbl_tags = [x.get('blocklist') for x in d_enrichment['dbl']]
            if dbl_tags:
                rep_bl = 'pyoti:reputation-block-list='
                [processed_iocs[attr.value].append(f'{rep_bl}"{tag}"') for tag in dbl_tags if tag is not None]
                [attr.add_tag(f'{rep_bl}"{tag}"') for tag in dbl_tags if tag is not None]

        elif attr.type == "email-src":
            # do PyOTI email enrichment
            if attr.value in processed_iocs:
                # apply tags from attribute that has already been checked and enriched
                [attr.add_tag(tag) for tag in processed_iocs[attr.value]]
                continue
            processed_iocs[attr.value] = []
            e_enrichment = enrich_emails(attr.value)

            # check if email address domain is spoofable and apply pyoti taxonomy tag
            d_spoofable = e_enrichment['checkdmarc'].get('spoofable')
            if d_spoofable:
                dmarc_tag = 'pyoti:checkdmarc="spoofable"'
                processed_iocs[attr.value].append(dmarc_tag)
                attr.add_tag(dmarc_tag)

            # check if email address is disposable
            disposable = e_enrichment['disposable'].get('disposable')
            if disposable:
                dis_tag = 'pyoti:disposable-email'
                processed_iocs[attr.value].append(dis_tag)
                attr.add_tag(dis_tag)

            # get emailrep.io email address reputation
            e_reputation = e_enrichment['emailrep'].get('reputation')
            if e_reputation != "none":
                rep_tag = get_emailrep_tags(e_reputation)
                processed_iocs[attr.value].append(rep_tag)
                attr.add_tag(rep_tag)

            # check emailrep.io if email address is suspicious
            e_sus = e_enrichment['emailrep'].get('suspicious')
            if e_sus:
                sus_tag = 'pyoti:emailrepio="suspicious"'
                processed_iocs[attr.value].append(sus_tag)
                attr.add_tag(sus_tag)

            # check emailrep.io for recent malicious activity
            e_mal = e_enrichment['emailrep'].get('details').get('malicious_activity_recent')
            if e_mal:
                mal_tag = 'pyoti:emailrepio="malicious-activity-recent"'
                processed_iocs[attr.value].append(mal_tag)
                attr.add_tag(mal_tag)

            # check emailrep.io for recent credential leak
            e_creds = e_enrichment['emailrep'].get('details').get('credentials_leaked_recent')
            if e_creds:
                creds_tag = 'pyoti:emailrepio="credentials-leaked-recent"'
                processed_iocs[attr.value].append(creds_tag)
                attr.add_tag(creds_tag)

            # check emailrep.io if email address is blacklisted
            e_bl = e_enrichment['emailrep'].get('details').get('blacklisted')
            if e_bl:
                bl_tag = 'pyoti:emailrepio="blacklisted"'
                processed_iocs[attr.value].append(bl_tag)
                attr.add_tag(bl_tag)

            # check emailrep.io if email address is spammy
            e_spam = e_enrichment['emailrep'].get('details').get('spam')
            if e_spam:
                spam_tag = 'pyoti:emailrepio="spam"'
                processed_iocs[attr.value].append(spam_tag)
                attr.add_tag(spam_tag)

            # check emailrep.io if email address has suspicious tld
            e_tld = e_enrichment['emailrep'].get('details').get('suspicious_tld')
            if e_tld:
                tld_tag = 'pyoti:emailrepio="suspicious-tld"'
                processed_iocs[attr.value].append(tld_tag)
                attr.add_tag(tld_tag)

        elif attr.type == "ip-src" or attr.type == "ip-dst":
            # do PyOTI ip enrichment
            if attr.value in processed_iocs:
                # apply tags from attribute that has already been checked and enriched
                [attr.add_tag(tag) for tag in processed_iocs[attr.value]]
                continue
            processed_iocs[attr.value] = []
            i_enrichment = enrich_ips(attr.value)

            # check abuseipdb for abuse score
            abuse_confidence = i_enrichment['abuseipdb'].get('data').get('abuseConfidenceScore')
            abuse_tag = get_abuseipdb_tags(abuse_confidence)
            processed_iocs[attr.value].append(abuse_tag)
            attr.add_tag(abuse_tag)

            # check greynoise riot for ip trust level
            trust_level = i_enrichment['greynoise'].get('trust_level')
            tl_1 = 'pyoti:greynoise-riot="trust-level-1"'
            tl_2 = 'pyoti:greynoise-riot="trust-level-2"'
            if trust_level == '1':
                processed_iocs[attr.value].append(tl_1)
                attr.add_tag(tl_1)
            elif trust_level == '2':
                processed_iocs[attr.value].append(tl_2)
                attr.add_tag(tl_2)

            # check if ip address is on reputation block lists
            rbl_tags = [x.get('blocklist') for x in i_enrichment['rbl']]
            if rbl_tags:
                rep_bl = 'pyoti:reputation-block-list='
                [processed_iocs[attr.value].append(f'{rep_bl}"{tag}"') for tag in rbl_tags if tag is not None]
                [attr.add_tag(f'{rep_bl}"{tag}"') for tag in rbl_tags if tag is not None]

        elif attr.type == "url":
            # do PyOTI url enrichment
            if attr.value in processed_iocs:
                # apply tags from attribute that has already been checked and enriched
                [attr.add_tag(tag) for tag in processed_iocs[attr.value]]
                continue
            processed_iocs[attr.value] = []
            u_enrichment = enrich_urls(attr.value)

            # check google safe browsing for url threat
            g_threat = [x['threatType'] for x in u_enrichment['google'].get('matches')]
            g_tags = get_gsb_tags(g_threat)
            if g_tags:
                [processed_iocs[attr.value].append(tag) for tag in g_tags]
                [attr.add_tag(tag) for tag in g_tags]


def main():
    parser = ArgumentParser(
        prog="Automated MISP Event Enrichment",
        description="This script will use PyOTI modules to run automated enrichment on all attributes attached to a "
                    "MISP Event and/or attributes attached to MISP Object(s) within a MISP Event and add appropriate "
                    "PyOTI MISP Taxonomy tags. "
    )
    parser.add_argument(
        "-u",
        "--url",
        dest="url",
        required=True,
        help="MISP URL",
        type=str
    )
    parser.add_argument(
        "-s",
        "--ssl",
        dest="ssl",
        required=False,
        help="Verify SSL certificate",
        type=bool,
        nargs="?",
        default=True
    )
    parser.add_argument(
        "-e",
        "--event-id",
        dest="event_id",
        required=True,
        help="MISP Event ID",
        type=int
    )
    parser.add_argument(
        "-p",
        "--publish",
        dest="publish",
        required=False,
        help="Publish MISP Event",
        type=bool,
        nargs="?",
        default=False
    )
    args = parser.parse_args()

    misp = ExpandedPyMISP(url=args.url, key=misp_pre, ssl=args.ssl)

    event = misp.get_event(args.event_id, pythonify=True)

    attrs = event.attributes

    objects = [o.attributes for o in event.objects]

    global processed_iocs
    # use this dict to track processed indicators to ensure we don't query APIs multiple times for the same indicator
    processed_iocs = {}

    if attrs:
        print(f"[*] Found {len(attrs)} attributes in MISP Event: {event.id}. Running enrichment...")
        run_enrichment(attributes=event.attributes)

    if objects:
        print(f"[*] Found {len(objects)} objects attached to MISP Event: {event.id}.")
        for object_attr in objects:
            print(f"[*] Found {len(object_attr)} attributes attached to MISP Object. Running enrichment...")
            run_enrichment(attributes=object_attr)

    misp.update_event(event)
    print(f"[!] Enrichment complete! Updated MISP Event ID: {event.id}!")

    if args.publish:
        misp.publish(args.event_id)
        print(f"[!] Published MISP Event ID: {event.id}!")


if __name__ == "__main__":
    main()
