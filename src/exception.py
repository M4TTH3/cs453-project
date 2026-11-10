class FileNotInDataError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__("Data directory not found")

