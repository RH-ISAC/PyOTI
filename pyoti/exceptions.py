class PyOTIError(Exception):
    """Base PyOTI exception."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class CIRCLPDNSError(PyOTIError):
    """Exception raised for CIRCLPDNS errors."""
    pass


class GSBError(PyOTIError):
    """Exception raised for Google Safe Browsing errors."""
    pass


class LinkPreviewError(PyOTIError):
    """Exception raised for LinkPreview errors."""
    pass


class MaltiverseIOCError(PyOTIError):
    """Exception raised for MaltiverseIOC errors."""
    pass


class MalwareHashRegistryError(PyOTIError):
    """Exception raised for MalwareHashRegistry errors."""
    pass


class SpamhausError(PyOTIError):
    """Exception raised for Spamhaus errors."""
    pass


class SpamhausIntelError(PyOTIError):
    """Exception raised for SpamhausIntel errors."""
    pass


class URLhausError(PyOTIError):
    """Exception raised for URLhaus errors."""
    pass


class VirusTotalError(PyOTIError):
    """Exception raised for VirusTotal errors."""
    pass
