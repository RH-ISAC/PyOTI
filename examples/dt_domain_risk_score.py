from argparse import ArgumentParser

from pyoti.domains import IrisInvestigate
from keys import domaintools

def run(args):
    iris = IrisInvestigate()
    iris.api_key = domaintools
    iris.domain = args
    domain_rep = iris.check_domain()

    return domain_rep[0]['domain_risk']

def main():
    parser = ArgumentParser(prog='IrisInvestigate Domain Risk Score', description='Check Domaintools Iris Investigate for domain risk score of a given domain')
    parser.add_argument('-d', '--domain', help='domain to check reputation')
    args = parser.parse_args()

    return run(args)

if __name__ == '__main__':
    main()
