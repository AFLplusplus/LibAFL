# [Choice] Debian version: buster, stretch
ARG VARIANT="bullseye"
FROM buildpack-deps:${VARIANT}-curl

# [Option] Install zsh
ARG INSTALL_ZSH="true"
# [Option] Upgrade OS packages to their latest versions
ARG UPGRADE_PACKAGES="true"
# Install needed packages and setup non-root user. Use a separate RUN statement to add your own dependencies.
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
COPY library-scripts/*.sh library-scripts/*.env /tmp/library-scripts/
RUN bash /tmp/library-scripts/common-debian.sh "${INSTALL_ZSH}" "${USERNAME}" "${USER_UID}" "${USER_GID}" "${UPGRADE_PACKAGES}" "true" "false" \
    && bash /tmp/library-scripts/rust-debian.sh "${CARGO_HOME}" "${RUSTUP_HOME}" "${USERNAME}" "true" "true" \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/library-scripts

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --yes-install-recommends \
    cargo \
    clang \
    cmake \ 
    g++ \
    libfdt-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    libssl-dev \
    llvm-dev \
    ninja-build \
    pkg-config \
    python2 \
    python3-pip \
    zlib1g-dev 

RUN pip3 install lit


# install corrosion for concolic support
RUN cd /tmp \
    && mkdir corrosion \
    && git clone https://github.com/AndrewGaspar/corrosion.git \
    && cmake -Scorrosion -Bbuild -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --config Release \
    && cmake --install build --config Release \
    && rm -rf corrosion \
    && rm -rf build \
    && apt-get remove -y cargo \
    && apt-get autoremove -y

# install cmake from source, because debians version too old
RUN cd /tmp \
    && git clone https://github.com/Kitware/CMake.git \
    && cd CMake \
    && cmake -G Ninja . \
    && ninja \
    && apt-get remove -y cmake \
    && ninja install \
    && cd .. && rm -rf CMake
