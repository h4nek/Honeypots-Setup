# Use an official Python runtime as a parent image
FROM python:3.6.6-stretch

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME World
# Set proxy server, replace host:port with values for your servers
ENV http_proxy 192.168.1.219:80
ENV https_proxy 192.168.1.219:88

# Run app.py when the container launches
CMD ["python", "app.py"]
