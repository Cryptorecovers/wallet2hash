"""Exception hierarchy for wallet2hash.

Handlers raise these instead of returning ad-hoc sentinel values so that the CLI
can map failures to stable, machine-readable outcomes.
"""


class Wallet2HashError(Exception):
    """Base class for all wallet2hash errors."""


class UnreadableFileError(Wallet2HashError):
    """The supplied artifact could not be read."""


class FormatError(Wallet2HashError):
    """The artifact is malformed or does not match its claimed format."""


class CorruptedFileError(FormatError):
    """The artifact parses but its integrity/authentication data is inconsistent."""


class UnsupportedFormatError(Wallet2HashError):
    """The artifact is understood but this build cannot process that variant."""


class UnsupportedVersionError(UnsupportedFormatError):
    """The format is understood but the specific format version is not supported."""


class HashcatUnavailableError(Wallet2HashError):
    """No Hashcat mode can faithfully represent the extracted verification material."""


class VerificationUnsupportedError(Wallet2HashError):
    """Password verification is possible in principle but unavailable here.

    This usually means an optional crypto backend (or the required wallet material)
    is missing in the current environment.
    """
