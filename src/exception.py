class FileNotInDataError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__("Data directory not found")



class NotInDockerError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__("Must run inside the docker container (DOCKER_ENV=true), use 'just shell'")
