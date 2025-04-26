# yggdrasil

A secure file transfer system implemented in Python. This project demonstrates concepts in computer networking including encrypted transmission, authentication, and integrity validation.

## Setup

This project uses `uv` for dependency management.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mertbozkir/yggdrasil.git
    cd yggdrasil
    ```
2.  **Install dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    # Create and activate a virtual environment (optional but recommended)
    uv venv
    source .venv/bin/activate # On Windows use: .venv\Scripts\activate

    # Install dependencies
    uv pip sync pyproject.toml
    ```

## Usage

### 1. Generate Keys

Before running the client or server for the first time, generate the necessary RSA key pairs:

```bash
python scripts/generate_keys.py
```
This will create a `.keys/` directory (if it doesn't exist) and populate it with `client_private.pem`, `client_public.pem`, `server_private.pem`, and `server_public.pem`.

### 2. Run the Server

Start the server to listen for incoming connections:

```bash
python -m src.server
```
The server listens on `127.0.0.1:65432` by default (see `src/config.py`). Received files will be saved in the `.files/output/` directory.

### 3. Run the Client

To send a file to the server:

```bash
# Ensure the server is running first
# Create a sample file if needed:
mkdir -p .files/input && echo "Hello Secure World from Host!" > .files/input/sample.txt

python -m src.client --file .files/input/sample.txt
```
*   Replace `.files/input/sample.txt` with the path to the file you want to send.

## Running with Docker (macOS)

Ensure you have Docker Desktop or Colima (a Docker-compatible runtime) installed and running.


### 1. Build the Docker Image

Navigate to the project's root directory (`yggdrasil`) in your terminal and run:

```bash
docker build -t yggdrasil:latest .
```

### 2. Run the Server Container

Open a terminal window and run the server container:

```bash
docker run --rm -p 65432:65432 --name yggdrasil-server yggdrasil:latest python -m src.server
```
*   `--rm`: Automatically removes the container when it exits.
*   `-p 65432:65432`: Maps port 65432 on your host machine to port 65432 inside the container.
*   `--name yggdrasil-server`: Assigns a name to the container for easier reference.
*   The server will log output to this terminal. Received files will be saved inside the container at `/app/.files/output/`.

### 3. Run the Client Container

Open *another* terminal window. First, ensure you have an input file ready on your host machine:

```bash
# Create a sample file if it doesn't exist
mkdir -p .files/input && echo "Hello Secure World from Docker!" > .files/input/sample.txt
```

Now, run the client container, mounting the input directory:

```bash
docker run --rm \
  -v "$(pwd)/.files/input:/app/.files/input" \
  yggdrasil:latest \
  python -m src.client --host host.docker.internal --file /app/.files/input/sample.txt
```
*   `--rm`: Automatically removes the container when it exits.
*   `-v "$(pwd)/.files/input:/app/.files/input"`: Mounts the local `.files/input` directory into the container at `/app/.files/input`. This makes `sample.txt` available inside the container.
*   `--host host.docker.internal`: Tells the client to connect to the server running on your host machine (Docker Desktop provides this special DNS name).
*   `--file /app/.files/input/sample.txt`: Specifies the path *inside the container* to the file being sent.

You should see the client connect to the server (running in the other terminal) and transfer the file. 
