# vesper

## Installation

This is a binary release - the application binary is available for download, as an asset.
 - copy the binary to **/usr/local/vesper**
 - create the appropriate config files in **/usr/local/vesper**
 - copy [this](https://github.com/iris-platform/vesper/tree/master/etc/systemd/system) file to **/etc/systemd/system/**
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

### Main config

This config file is read **ONCE** at startup only.

The following is the template for configuration file (in JSON format) that is read by the application, at startup.

```sh
{
  "log_file" : "/var/log/vesper/vesper.log",                  <--- RECOMMENDED PATH
  "log_file_max_size" : 50000000,                             <--- IN BYTES - MAX LOG FILE SIZE BEFORE LOG ROTATION (DEFAULT: 50000000 BYTES)
  "log_host" : "",                                            <--- HOSTNAME/IP/FQDN/CNAME TO BE ADDED TO EACH LOG LINE
  "http_host" : "",                                           <--- HOST IP TO WHICH HTTP SERVER WILL BIND TO (APPLIES ONLY IF ssl_cert_file and ssl_key_file ARE NOT SPECIFIED)
  "http_port" : "",                                           <--- HTTP PORT; IF NOT SPECIFIED DEFAULT PORT APPLIES - 443 FOR HTTPS OR 80 FOR HTTP
  "ssl_cert_file": "",                                        <--- IF HTTPS IS SUPPORTED, THIS IS ABSOLUTE PATH + FILE NAME
  "ssl_key_file": "",                                         <--- IF HTTPS IS SUPPORTED, THIS IS ABSOLUTE PATH + FILE NAME
  "http_host_port: "",                                        <--- (HTTP ONLY) IS APPLICABLE ONLY IF SSL CERT AND KEY FILE IS NOT AVAILABLE
  "eks_credentials_file": "/usr/local/vesper/eks.json",       <--- FILE THAT CONTAINS SKS URL + PATH AND TOKEN REQUIRED TO FETCH ROOT CERTS AS WELL AS FILENAME AND PRIVATE KEY REQUIRED FOR SIGNING
  "eks_credentials_file_check_interval" : 60,                 <--- (DEFAULT IS 60 MINUTES) INTERVAL IN MINUTES FOR VESPER TO CHECK AUM URL, KEY, SECRET AND/OR EKS URL HAS CHANGED. SERVER JWT TO CALL EKS APIS IS REFRESHED AS WELL
  "sticr_host_file" : "/usr/local/vesper/sticr.json",         <--- FILE THAT CONTAINS STICR HOST URL + PATH
  "sticr_file_check_interval" : 60,                           <--- (DEFAULT IS 60 MINUTES) INTERVAL IN MINUTES FOR VESPER TO CHECK IF STICR URL HAS CHANGED
  "root_certs_fetch_interval": 300,                           <--- (DEFAULT IS 300 SECONDS) INTERVAL IN SECONDS FOR VESPER TO FETCH ROOT CERTS FROM SKS
  "signing_credentials_fetch_interval": 300,                  <--- (DEFAULT IS 300 SECONDS) INTERVAL IN SECONDS FOR VESPER TO FETCH FILENAME AND PRIVATE KEY REQUIRED FOR SIGNING\
  "replay_attack_cache_validation_interval" : 70,             <--- (DEFAULT IS 70 SECONDS) INTERVAL IN SECONDS FOR VESPER TO CLEAR STALE REPLAY ATTACK CACHE. NOTE THAT THIS VALUE MUST BE GREATER THAN VALUE SET AS "valid_iat_period"
  "public_keys_cache_flush_interval" : 300,                   <--- (DEFAULT IS 300 SECONDS) INTERVAL IN SECONDS FOR VESPER TO FLUSH ALL CACHED PUBLIC KEYS
  "verify_root_ca" : true or false,                           <--- (VERIFICATION ONLY) IF FALSE, VERIFICATION, ROOT CERT VALIDATION IS NOT DONE
  "valid_iat_period": 60                                      <--- (DEFAULT IS 60 SECONDS) IN SECONDS - VESPER WILL FAIL VERIFICATION, IF IAT VALUE IN IDENTITY HEADER EXCEEDS CURRENT TIME BY THIS VALUE
}
```

### EKS config

This is the **eks_credentials_file** in main config. This file is read at startup AS WELL AS runtime.

The following is the template for this configuration file (in JSON format)

```sh
{
  "aum": {
  	"url": https://<FQDN/CNAME>/v1.1/login",    <--- CNAME/FQDN FOR IRIS AUTHENTICATION SERVICE - - MUST START WITH SCHEME HTTPS://
  	"key": "",                                  <--- APP KEY FOR IRIS DOMAIN vesper.service.srv
  	"secret": ""                                <--- APP SECRET FOR IRIS DOMAIN vesper.service.srv
  },
  "eks": "https://<FQDN/CNAME>"                 <--- CNAME/FQDN FOR IRIS ENCRYPTED KEYSTORE SERVICE (EKS) - MUST START WITH SCHEME HTTPS://
}
```

### STICR config

This is the **sticr_host_file** in main config. This file is read at startup AS WELL AS runtime.

The following is the template for configuration file (in JSON format)

```sh
{
  "sticrHost": "https://<FQDN/CNAME>"           <--- CNAME/FQDN FOR STICR - MUST START WITH SCHEME HTTPS://
}
```
