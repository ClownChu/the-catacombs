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

# 1. Install core tools and PPA prerequisites in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    zsh \
    ca-certificates \
    openssh-client \
    wget \
    gnupg2 \
    apt-transport-https \
    lsb-release \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/zsh", "-c"]

# 2. Add the Sury PHP PPA securely (Modern Bookworm 'signed-by' method)
RUN mkdir -p /etc/apt/keyrings \
    && wget -qO /etc/apt/keyrings/sury-php.gpg https://packages.sury.org/php/apt.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ bookworm main" > /etc/apt/sources.list.d/php.list

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
    && npx playwright install chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/$USERNAME/.ssh && chmod 700 /home/$USERNAME/.ssh

# Set default user
USER $USERNAME

RUN echo '# Start ssh-agent in interactive shells when the bind-mounted key is present' >> /home/$USERNAME/.zshrc \
    && echo '  eval "$(ssh-agent -s)" >/dev/null' >> /home/$USERNAME/.zshrc \
    && echo '  ssh-add "$HOME/.ssh/id_ed25519_github" 2>/dev/null || true' >> /home/$USERNAME/.zshrc 

RUN node -v \
    && python --version

ENTRYPOINT ["/bin/zsh"]