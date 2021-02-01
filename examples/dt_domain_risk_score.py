from argparse import ArgumentParser

from pyoti.domains import IrisInvestigate
from pyoti.keys import domaintools

def run(args):
    iris = IrisInvestigate()
    iris.api_key = domaintools
    iris.domain = args
    domain_rep = iris.check_domain()

    try:
        return f"Iris risk score: {domain_rep[0]['domain_risk']['risk_score']}"
    except IndexError:
        return "Iris risk score: N/A"

def main():
    parser = ArgumentParser(prog='IrisInvestigate Domain Risk Score', description='Check Domaintools Iris Investigate for domain risk score of a given domain')
    parser.add_argument('-d', '--domain', dest='domain', help='domain to check reputation')
    args = parser.parse_args()

    print(run(args.domain))

if __name__ == '__main__':
    main()
