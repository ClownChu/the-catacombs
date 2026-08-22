FROM python:3.11-slim-bookworm

ARG USERNAME="agent"
ARG USER_UID="1000"
ARG USER_GID="1000"

ENV USERNAME="${USERNAME}"
ENV USER_UID="${USER_UID}"
ENV USER_GID="${USER_GID}"

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME

# 1. Install core tools, dev dependencies, and database clients (including mariadb-client)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core HTTP & Network
    git curl wget openssh-client ca-certificates \
    # Repositories & Keys
    gnupg2 apt-transport-https lsb-release \
    # Terminal & Text
    zsh vim less \
    # Build Tools (For native node/python modules)
    build-essential pkg-config python3-dev \
    # Data & Archives
    jq unzip tar \
    # DB Clients
    mariadb-client postgresql-client sqlite3 libsqlite3-dev \
    # Process management
    procps lsof \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/zsh", "-c"]

# 2. Add the Sury PHP PPA securely (Modern Bookworm 'signed-by' method)
RUN mkdir -p /etc/apt/keyrings \
    && wget -qO /etc/apt/keyrings/sury-php.gpg https://packages.sury.org/php/apt.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ bookworm main" > /etc/apt/sources.list.d/php.list

# 3. Install multiple PHP versions side-by-side + extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    # CLI runtimes
    php5.6-cli \
    php7.4-cli \
    php8.1-cli \
    php8.5-cli \
    # Shared dev extensions
    php5.6-xml php5.6-mbstring php5.6-curl php5.6-zip php5.6-gd \
    php7.4-xml php7.4-mbstring php7.4-curl php7.4-zip php7.4-gd php7.4-pcov \
    php8.1-xml php8.1-mbstring php8.1-curl php8.1-zip php8.1-gd php8.1-pcov \
    php8.5-xml php8.5-mbstring php8.5-curl php8.5-zip php8.5-gd php8.5-pcov \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Default for interactive shells
RUN update-alternatives --set php /usr/bin/php8.5

# 4. Copy Composer from official image
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# 5. Global Python Tooling
RUN pip install --no-cache-dir pipx \
    && pipx ensurepath

# Setup SSH directory scaffolding
RUN mkdir -p /home/$USERNAME/.ssh && chmod 700 /home/$USERNAME/.ssh \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh

# Install nvm
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash \
    && echo 'export NVM_DIR="$HOME/.nvm"' >> $HOME/.zshrc \
    \
    && echo '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" # This loads nvm' >> $HOME/.zshrc \
    && echo '[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion" # This loads nvm bash_completion' >> $HOME/.zshrc

ENV NODE_VERSION="22.12.0"
# Install node
RUN source $HOME/.zshrc \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# Set node environment variables
RUN echo 'export NODE_FOLDER="$NVM_DIR/v$NODE_VERSION"' >> $HOME/.zshrc \
    && echo 'export NODE_PATH="$NODE_FOLDER/lib/node_modules"' >> $HOME/.zshrc \
    && echo 'export PATH="$NODE_FOLDER/bin:$PATH"' >> $HOME/.zshrc

RUN source $HOME/.zshrc \
    && npm install -g playwright \
    && npx playwright install-deps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set default user
USER $USERNAME

ENTRYPOINT ["/bin/zsh"]