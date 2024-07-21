# Use an official Ubuntu base image
FROM ubuntu:22.04

ARG USER=user

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /mnt/share

# Install build essentials and other dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Clone the LIEF project
# RUN git clone --depth 1 https://github.com/lief-project/LIEF.git /LIEF

# Download and install the LIEF release (adjust the version as needed)
RUN wget https://github.com/lief-project/LIEF/releases/download/0.14.1/LIEF-0.14.1-Linux-x86_64.tar.gz \
    && tar -xzf LIEF-0.14.1-Linux-x86_64.tar.gz -C /usr/local \
    && rm LIEF-0.14.1-Linux-x86_64.tar.gz

RUN mv /usr/local/LIEF-0.14.1-Linux-x86_64 /usr/local/LIEF
# https://github.com/lief-project/LIEF/releases/download/0.14.1/LIEF-0.14.1-Linux-x86_64.tar.gz


# Link lib
RUN ln -s /usr/local/LIEF/include/LIEF /usr/local/include/LIEF \
 && ln -s /usr/local/LIEF/lib/libLIEF.so /usr/local/lib/libLIEF.so


# Create a group and user with UID and GID of 1000
RUN groupadd -g 1000 $USER && \
    useradd -rm -d /home/$USER -s /bin/bash -g $USER -G sudo -u 1000 $USER

# Give the new user passwordless sudo privileges
RUN echo $USER ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USER \
 && chmod 0440 /etc/sudoers.d/$USER

# Switch to the new user for subsequent commands
USER $USER



# Reset the working directory
WORKDIR /mnt/share

# Set environment variables to help find LIEF (optional)
ENV LD_LIBRARY_PATH=/usr/local/LIEF/lib:$LD_LIBRARY_PATH

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Command to run when starting the container
#CMD ["/bin/bash"]


