from disposable_email_domains import blocklist
from typing import Dict

from pyoti.classes import EmailAddress


class DisposableEmails(EmailAddress):
    """DisposableEmails Email Address Reputation

    This class checks if an email address is contained within a set of known disposable email domains.
    """
    def __init__(self, email: str = None):
        EmailAddress.__init__(self, email=email)

    def check_email(self) -> Dict:
        """Checks if email domain is a known disposable email service.

        :return: dict of email address and if it is disposable
        """
        domain = self.email.split("@")[1]
        info = {"email": self.email}
        if domain in blocklist:
            info["disposable"] = True
        else:
            info["disposable"] = False

        return info
