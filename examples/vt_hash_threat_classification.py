import csv
from argparse import ArgumentParser

from pyoti.multis import VirusTotalV3
from keys import virustotal


def run(args):
    vt = VirusTotalV3(api_key=virustotal)

    fields = ["Hash", "Threat Classification", "Crowdsourced Yara Results"]

    with open("hash_classification.csv", "w") as csvfile:
        csvwriter = csv.writer(csvfile)

        csvwriter.writerow(fields)

        for hash in args:
            vt.file_hash = hash.strip('\n')
            hash_resp = vt.check_hash()

            if hash_resp.get('data'):
                row = ([hash_resp['data']['attributes']['sha256']])
                if hash_resp['data']['attributes'].get('popular_threat_classification'):
                    row += ([hash_resp['data']['attributes']['popular_threat_classification'].get('suggested_threat_label')])
                    if hash_resp['data']['attributes'].get('crowdsourced_yara_results'):
                        for yara_result in hash_resp['data']['attributes']['crowdsourced_yara_results']:
                            row += ([yara_result.get('description')])
                csvwriter.writerow(row)


def main():
    parser = ArgumentParser(
        prog="VT hash reputation to CSV",
        description="Check Virustotal for hash threat classification and any matches on yara rules",
    )
    parser.add_argument(
        "-f",
        "--hash_file",
        dest="hash_file",
        help="txt file of file hashes (one per line)",
    )
    args = parser.parse_args()

    input_file = open(args.hash_file)

    run(input_file)
    print("[*] Finished! Check hash_classification.csv for your file hash reputations.")


if __name__ == "__main__":
    main()
