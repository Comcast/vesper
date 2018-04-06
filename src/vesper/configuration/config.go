package configuration

import (
	"os"
	"encoding/json"
)


// Configuration -- The first letter of the struct elements must be upper case in order to export them
// The JSON decoder will not use struct elements that are not exported
// This struct will be used to unmarshal the configuration file read at startup
type Configuration struct {
	LogFile							string									`json:"log_file"`
	LogFileMaxSize			int64										`json:"log_file_max_size"`
	Host								string									`json:"host"`
	HttpHostPort				string  								`json:"http_host_port"`
	SslCertFile					string									`json:"ssl_cert_file"`
	SslKeyFile					string									`json:"ssl_key_file"`
	RootCertsFetchInterval					int64				`json:"root_certs_fetch_interval"`
	SigningCredentialsFetchInterval int64				`json:"signing_credentials_fetch_interval"`
	SksCredentialsFile							string			`json:"sks_credentials_file"`
	SticrHostFile										string			`json:"sticr_host_file"`
	SksSticrFilesCheckInterval			int64				`json:"sks_sticr_files_check_interval"`
	VerifyRootCA										bool				`json:"verify_root_ca"`
}

var configurationInstance *Configuration = nil

func ConfigurationInstance() *Configuration {
	if configurationInstance == nil {

		config := &Configuration{
			LogFile														: "/var/log/vesper/vesper.log",
			LogFileMaxSize										: 50000000,
			Host															: "",
			HttpHostPort											: "",
			SslCertFile												: "",
			SslKeyFile												: "",
			RootCertsFetchInterval						:	60,
			SigningCredentialsFetchInterval		:	60,
			SksCredentialsFile								: "",
			SticrHostFile											: "",
			SksSticrFilesCheckInterval				: 60,
			VerifyRootCA											: false,
		}
		configurationInstance = config
	}
	return configurationInstance
}

func (c *Configuration) GetConfiguration(f string) (err error) {
	file, err := os.Open(f)
	if err == nil {
		decoder := json.NewDecoder(file)
		err = decoder.Decode(c)	
	}
	return
}
