# vesper

## Installation

This is a binary release - the application binary is available for download, as an asset.
 - copy the binary to **/usr/local/vesper**
 - create the appropriate config files in **/usr/local/vesper**
 - copy the service [file](https://github.com/iris-platform/vesper/tree/master/etc/systemd/system) to **/etc/systemd/system/**
 - If this is a fresh install, run this command first
 ```sh
 # systemctl enable vesper.service
 ```
 - To start service
 ```sh
 # systemctl start vesper.service
 ```
 - To stop service
 ```sh
 # systemctl stop vesper.service
 ```

## Configuration

This config file is read **ONCE** at startup only.

The following is the template for configuration file (in JSON format) that is read by the application, at startup.

```sh
{
	"log_file" : "/var/log/vesper/vesper.log",                               <--- RECOMMENDED PATH
	"log_file_max_size" : 50000000,                                          <--- IN BYTES - MAX LOG FILE SIZE BEFORE LOG ROTATION (DEFAULT: 50000000 BYTES)
	"host" : "",                                                             <--- FQDN/IP/HOSTNAME OF THE HOST WHERE THIS APPLICATION IS GOING TO RUN  
	"ssl_cert_file": "",                                                     <--- IF HTTPS IS SUPPORTED, THIS IS ABSOLUTE PATH + FILE NAME
	"ssl_key_file": "",                                                      <--- IF HTTPS IS SUPPORTED, THIS IS ABSOLUTE PATH + FILE NAME
	"http_host_port: "",                                                     <--- (HTTP ONLY) IS APPLICABLE ONLY IF SSL CERT AND KEY FILE IS NOT AVAILABLE
	"root_certs_fetch_interval": 60,                                         <--- INTERVAL IN SECONDS FOR VESPER TO FETCH ROOT CERTS FROM SKS
	"signing_credentials_fetch_interval": 60,                                <--- INTERVAL IN SECONDS FOR VESPER TO FETCH FILENAME AND PRIVATE KEY REQUIRED FOR SIGNING
	"sks_credentials_file": "/usr/local/vesper/sks.json",                    <--- FILE THAT CONTAINS SKS URL + PATH AND TOKEN REQUIRED TO FETCH ROOT CERTS AS WELL AS FILENAME AND PRIVATE KEY REQUIRED FOR SIGNING
	"sks_credentials_file_check_interval" : 60,                              <--- INTERVAL IN SECONDS FOR VESPER TO CHECK DF SKS URL + PATH AND TOKEN HAS CHANGED SINCE LAST READ
	"sticr_host_file" : "/usr/local/vesper/sticr.json",                      <--- FILE THAT CONTAINS STICR HOST URL + PATH
	"verify_root_ca" : true or false                                         <--- IF FALSE, ROOT CERT VALIDATION IS NOT DONE
```