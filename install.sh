
############################################
############# Install LIEF #################
############################################

# (may ask for sudo password)

# Install LIEF
wget https://github.com/lief-project/LIEF/releases/download/0.14.1/LIEF-0.14.1-Linux-x86_64.tar.gz \
    && tar -xzf LIEF-0.14.1-Linux-x86_64.tar.gz -C /usr/local \
    && rm LIEF-0.14.1-Linux-x86_64.tar.gz

# Rename the folder to /usr/local/LIEF
mv /usr/local/LIEF-0.14.1-Linux-x86_64 /usr/local/LIEF


# Create symbolic links
ln -s /usr/local/LIEF/include/LIEF /usr/local/include/LIEF \
 && ln -s /usr/local/LIEF/lib/libLIEF.so /usr/local/lib/libLIEF.so


# Add LIEF to the library path
export LD_LIBRARY_PATH=/usr/local/LIEF/lib:$LD_LIBRARY_PATH