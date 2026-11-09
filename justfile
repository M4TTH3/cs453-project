compose := "docker compose -f docker/compose.yaml"

default:
    @just --list

# build the testing image
build:
    {{compose}} build

# start the container and sync python deps
up:
    {{compose}} up -d --build
    {{compose}} exec dev uv sync
    @echo "up: 'just shell' to enter"

# stop and remove the container
down:
    {{compose}} down

# interactive shell in the running container
shell:
    {{compose}} exec dev bash

# run a command inside the container; quote the whole thing
# e.g. just run 'python3 -c "import numpy; print(numpy.__version__)"'
run +cmd:
    {{compose}} exec dev sh -c {{quote(cmd)}}
