# Use an official Python runtime as a parent image
FROM ubuntu:18.04

# Copy the current directory contents into the container at /app
COPY . /app

# Set the working directory to /app
WORKDIR /app

# Install all needed programs
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "python3-dev", "python3-pip"]
RUN ["apt-get", "install", "-y", "nmap"]
RUN ["apt-get", "install", "-y", "iproute2"]
RUN ["apt-get", "install", "-y", "iputils-ping"]
# Install any needed Python packages specified in requirements.txt
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# Run the program
CMD ["python3", "main-beta.py"]
