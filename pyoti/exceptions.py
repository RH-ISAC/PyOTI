class PyOTIError(Exception):
    """Base PyOTI exception."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class GSBError(PyOTIError):
    """Exception raised for Google Safe Browsing HTTP Status Errors"""

    pass


class LinkPreviewError(PyOTIError):
    """Exception raised for LinkPreview API."""

    pass


class MaltiverseIOCError(PyOTIError):
    """Exception raised for MaltiverseIOC errors."""

    pass


class OTXError(PyOTIError):
    """Exception raised for AlienVault OTX errors."""


class SpamhausError(PyOTIError):
    """Exception raised for any special codes returned that indicates an error in query."""

    pass


class URLhausHashError(PyOTIError):
    """Exception raised for URLhaus errors."""

    pass


class VirusTotalError(PyOTIError):
    """Exception raised for VirusTotal errors."""
