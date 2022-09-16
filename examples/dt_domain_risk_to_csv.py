import csv
from argparse import ArgumentParser
from tld.exceptions import TldDomainNotFound

from pyoti.domains import IrisInvestigate
from pyoti.utils import split_url_domain
from keys import domaintools


def run(args):
    iris = IrisInvestigate(api_key=domaintools)

    fields = ["Domain", "Risk Score"]

    with open("domain_risk.csv", "w") as csvfile:
        csvwriter = csv.writer(csvfile)

        csvwriter.writerow(fields)

        for dmn in args:
            if 'http' in dmn:
                try:
                    iris.domain = split_url_domain(dmn)
                except TldDomainNotFound:
                    continue
            else:
                dmnsplt = dmn.split('.')
                if len(dmnsplt) > 2:
                    iris.domain = '.'.join(dmnsplt[-2:])
                else:
                    iris.domain = dmn

            try:
                domain_rep = iris.check_domain()
                risk_score = domain_rep[0]["domain_risk"]["risk_score"]
            except IndexError:
                risk_score = "N/A"
            except KeyError:
                risk_score = "N/A"
            except AttributeError:
                risk_score = "N/A"

            csvwriter.writerow([dmn, risk_score])


def main():
    parser = ArgumentParser(
        prog="Domain Risk Score to CSV",
        description="Check Domaintools Iris Investigate for risk score outputted to CSV",
    )
    parser.add_argument(
        "-f",
        "--domain_file",
        dest="domain_file",
        help="txt file of domains (one per line)",
    )
    args = parser.parse_args()

    input_file = open(args.domain_file)

    run(input_file)
    print("[*] Finished! Check domain_risk.csv for your domain risk scores.")


if __name__ == "__main__":
    main()
