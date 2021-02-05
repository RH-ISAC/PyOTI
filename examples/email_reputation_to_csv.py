import csv
from argparse import ArgumentParser

from pyoti.emails import EmailRepIO


def run(args):
    eml = EmailRepIO()

    fields = ['Email Address', 'Reputation', 'Suspicious', 'Domain Exists', 'Domain Reputation', 'New Domain', 'Disposable', 'Deliverable']

    with open('email_reputation.csv', 'w') as csvfile:
        csvwriter = csv.writer(csvfile)

        csvwriter.writerow(fields)

        for email in args:
            eml.email = email
            eml_rep = eml.check_email()

            eml_address     = email
            eml_reputation  = eml_rep['reputation']
            eml_sus         = eml_rep['suspicious']
            eml_dmn_exsts   = eml_rep['details']['domain_exists']
            eml_dmn_rep     = eml_rep['details']['domain_reputation']
            eml_dmn_new     = eml_rep['details']['new_domain']
            eml_disposable  = eml_rep['details']['disposable']
            eml_deliverable = eml_rep['details']['deliverable']

            csvwriter.writerow([eml_address,
                                eml_reputation,
                                eml_sus,
                                eml_dmn_exsts,
                                eml_dmn_rep,
                                eml_dmn_new,
                                eml_disposable,
                                eml_deliverable])


def main():
    parser = ArgumentParser(prog='Email Reputation to CSV', description='Check EmailRep.io API for email address reputation outputted to CSV')
    parser.add_argument('-f', '--email_file', dest='email_file', help='txt file of email addresses (one per line)')
    args = parser.parse_args()

    input_file = open(args.email_file)

    run(input_file)
    print("[*] Finished! Check email_reputation.csv for your email address reputations.")


if __name__ == '__main__':
    main()
