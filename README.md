# collector-docker
Dockerfile for manual installation of Recon collector tools


### BUILD INSTRUCTIONS & README

#######################################################################

Install Docker

```
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# Ubuntu 22.04
curl -k -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Kali
curl -k -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/docker-ce-archive-keyring.gpg
printf '%s\n' "deb https://download.docker.com/linux/debian bullseye stable" |  sudo tee /etc/apt/sources.list.d/docker-ce.list

sudo apt update
sudo groupadd docker
sudo apt install docker-ce -y
sudo usermod -aG docker $USER

# If behind break and inspect add the following to all apt commands
-o "Acquire::https::Verify-Peer=false"

openssl s_client -showcerts -connect google.com:443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ca.crt
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
service docker restart

# Generate ssh key for collector docker instance
ssh-keygen -f id_rsa

# Create collector in Reverge
Create Manual Collector in Reverge.
Enter IP address of extender pivot
Enter custom port for port forward 
Username of docker instance (root)
Add SSH private key generated above

```

```
 docker build --build-arg sshkey="local public key file, e.g. id_rsa.pub" --build-arg apikey="Recon API Key" -t collector:test1 .
 
```
 
 
###########################################################################################

Start docker instance with port forward from docker to host on port 2222


```
docker run --name collector1 -p 2222:22 -d collector:test1
```

#################################################

Create a port forward from Collector to Pivot

edit /etc/ssh/sshd_config on pivot to all for all interfaces to forward traffic

```
GatewayPorts clientspecified
```

restart ssh service

```
service ssh restart
```

```
screen -S ssh_session
ssh -t -t -N -i pivot.pem -R *:2222:localhost:2222 -o ServerAliveCountMax=3 <username>@<IP Address>
```

### Troubleshooting

Ensure firewall port exceptions exist for any ports opened

If there is an error about signal on main thread with luigi

Create "/opt/collector/luigi.cfg" on host volume:

    [worker]
    no_install_shutdown_handler=True
    
Open a shell for debugging

```
docker exec -u 0 -it collector1  /bin/bash
```

