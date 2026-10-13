class AccessError(Exception):
    """Only fixed, non-sensitive reason codes cross the agent boundary."""

    def __init__(self, status: str, reason: str, kind: str = "login"):
        self.status = status
        self.reason = reason
        self.kind = kind
        super().__init__(reason)
