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
	EksCredentialsFile							string			`json:"eks_credentials_file"`
	EksCredentialsRefreshInterval		int64				`json:"eks_credentials_refresh_interval"`
	SticrHostFile										string			`json:"sticr_host_file"`
	SticrFileCheckInterval					int64				`json:"sticr_file_check_interval"`
	VerifyRootCA										bool				`json:"verify_root_ca"`
	ValidateStaleDate								bool				`json:"validate_stale_date"`
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
			EksCredentialsFile								: "",
			EksCredentialsRefreshInterval			: 60,
			SticrHostFile											: "",
			SticrFileCheckInterval						: 60,
			VerifyRootCA											: true,
			ValidateStaleDate									: true,
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
