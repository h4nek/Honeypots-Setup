# Use an official Ubuntu distribution as a parent image
FROM ubuntu:18.04

# Install all needed programs
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "python3-dev", "python3-pip"]
RUN ["apt-get", "install", "-y", "nmap"]
RUN ["apt-get", "install", "-y", "iproute2"]
RUN ["apt-get", "install", "-y", "iputils-ping"]
#tzdata tzdata/Areas select Europe
#tzdata tzdata/Zones/Europe select Prague
#RUN ["echo", "8", "39", "|", "apt-get", "install", "-y", "git-all"]
#RUN echo 8 39 | apt-get install -y git-all # git installation has prompts about location
RUN ["apt-get", "install", "-y", "wget"]
RUN ["apt-get", "install", "-y", "unzip"]

# Install and setup Honeycomb framework
RUN ["pip3", "install", "honeycomb-framework"]
RUN ["export", "LC_ALL=C.UTF-8"]
RUN ["export", "LANG=C.UTF-8"]
RUN ["cd", "/home"]
#RUN ["git", "clone", "https://github.com/h4nek/honeycomb_plugins.git"]
RUN ["wget", "https://github.com/h4nek/honeycomb_plugins/archive/master.zip"] # custom plugins repository
RUN ["unzip", "master.zip"]
RUN ["cp", "-r", "honeycomb_plugins-master", "/root/.config/honeycomb/"] # move the plugins into honeycomb home folder -> they'll appear as installed

# Install Honeycomb services libraries
RUN ["pip3", "install" ,"pyftpdlib"]
#RUN ["apt-get", "install", "-y",


# Install any needed Python packages specified in requirements.txt
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt


# Copy the current directory contents into the container at /app
COPY . /app

# Set the working directory to /app
WORKDIR /app

# Run the program
CMD ["python3", "main-beta.py"]
