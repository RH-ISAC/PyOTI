class PyOTIError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class GSBPermissionDenied(PyOTIError):
    """Exception raised for Google Safe Browsing API permission errors."""
    pass


class GSBInvalidAPIKey(PyOTIError):
    """Exception raised for Google Safe Browsing API invalid API key error."""
    pass

class MaltiverseIOCError(PyOTIError):
    """Exception raised for MaltiverseIOC errors."""
    pass


class OTXError(PyOTIError):
    """Exception raised for AlienVault OTX errors."""


class SpamhausZenError(PyOTIError):
    """Exception raised for any special codes returned that indicates an error in query."""
    pass


class URLhausHashError(PyOTIError):
    """Exception raised for invalid hash type for URLhaus query."""
    pass


class VirusTotalDomainError(PyOTIError):
    """Exception raised for invalid domain for VirusTotal query."""


class VirusTotalHashError(PyOTIError):
    """Exception raised for invalid hash type or scan_id for VirusTotal query."""
    pass


class VirusTotalIPError(PyOTIError):
    """Exception raised for invalid IP address for VirusTotal query."""
    pass


class VirusTotalURLError(PyOTIError):
    """Exception raised for invalid URL for VirusTotal query."""
    pass
