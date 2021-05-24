from argparse import ArgumentParser

from pyoti.emails import EmailRepIO
from keys import sublime


def run(args):
    eml = EmailRepIO(api_key=sublime)
    eml.email = args
    eml_rep = eml.check_email()

    return eml_rep


def main():
    parser = ArgumentParser(
        prog="EmailRep.io Email Reputation",
        description="Check EmailRep.io's API for email reputation on a given email address.",
    )
    parser.add_argument(
        "-e", "--email", dest="email", help="email address to check reputation"
    )
    args = parser.parse_args()

    print(run(args.email))


if __name__ == "__main__":
    main()
