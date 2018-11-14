package publickeys

import (
	"fmt"
	"testing"
	"encoding/pem"
	"crypto/ecdsa"
	"crypto/x509"
	"vesper/publickeys"
)

func TestAdd(t *testing.T) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIICHjCCAaSgAwIBAgIJAPrmQQLa6zLkMAoGCCqGSM49BAMCME0xCzAJBgNVBAYT\nAlVTMRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExFTATBgNVBAcMDFBoaWxhZGVscGhp\nYTEQMA4GA1UECgwHQ29tY2FzdDAeFw0xODA4MDcxNDI5NDdaFw0xOTA4MDcxNDI5\nNDdaME0xCzAJBgNVBAYTAlVTMRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExFTATBgNV\nBAcMDFBoaWxhZGVscGhpYTEQMA4GA1UECgwHQ29tY2FzdDB2MBAGByqGSM49AgEG\nBSuBBAAiA2IABBdpcVNsqZTrZ8mIwScM/t7FakAx4dkOv40WnKrb7aBJ8Rnr0hqc\n1Rwwbv3HxhCmutN519jbekNUHA0NSgMg3/jI4yPu5FxEkcraAnIL4fnkpV4us1Fn\nWR880p7KBrAjjqNQME4wHQYDVR0OBBYEFOwq7vW6O0EwO3VPja7UuUeUId0vMB8G\nA1UdIwQYMBaAFOwq7vW6O0EwO3VPja7UuUeUId0vMAwGA1UdEwQFMAMBAf8wCgYI\nKoZIzj0EAwIDaAAwZQIwCtnzcs2l1wHWb24tH3BrGjErzLYFSoj5QyATTJ2DJ9LW\nFQw5NrSQL61ImgAtwR52AjEAsLL1gp8+ExzQoUVPRzsOfG0wQioNuCV2Z8LpPD8/\nx1M3OURP0muZJqTUDMDOlFwd\n-----END CERTIFICATE-----")))
	if block != nil {
		// alg = ES256
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		publickeys.Add("https://sticr.comcast.com/0.cer", p)
	}
	block, _ = pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIICUTCCAfegAwIBAgIJAIU5HElrC5ISMAoGCCqGSM49BAMCMIGEMQswCQYDVQQG\nEwJVUzEMMAoGA1UECAwDVExWMQwwCgYDVQQHDANUTFYxDDAKBgNVBAoMA0FUVDEP\nMA0GA1UECwwGU0hBS0VOMRswGQYDVQQDDBJTSEFLRU4tQ0VSVElGSUNBVEUxHTAb\nBgkqhkiG9w0BCQEWDmVsNTMydkBhdHQuY29tMB4XDTE4MDIyMjE0MjQ0MloXDTE5\nMDIxMzE0MjQ0MlowgYQxCzAJBgNVBAYTAlVTMQwwCgYDVQQIDANUTFYxDDAKBgNV\nBAcMA1RMVjEMMAoGA1UECgwDQVRUMQ8wDQYDVQQLDAZTSEFLRU4xGzAZBgNVBAMM\nElNIQUtFTi1DRVJUSUZJQ0FURTEdMBsGCSqGSIb3DQEJARYOZWw1MzJ2QGF0dC5j\nb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATyZEVgX0YGc+tAqSrQv2/0b/yZ\nd4z5i7/sAm165IpqxHHZt9fm1mNy1KX2lxU9hj5VwVgEpQEt26aDQ0YbS1Pto1Aw\nTjAdBgNVHQ4EFgQU/znOK+hXkyHYqPalG+Hhzs3dgBgwHwYDVR0jBBgwFoAU/znO\nK+hXkyHYqPalG+Hhzs3dgBgwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBF\nAiEAtlC9ZeZOsy8qer/FNJXC382s6BI/UDUjkXucB+X9URoCIGh0TpYYDurH+OZr\n1PSHSkXDUIfgpwU5ehSgGIOWk58w\n-----END CERTIFICATE-----"))
	if block != nil {
		// alg = ES256
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		publickeys.Add("https://sticr.comcast.com/1.cer", p)
	}
	publickeys.Entries()
	fmt.Println("----------")
}


func TestFetch(t *testing.T) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIICHjCCAaSgAwIBAgIJAPrmQQLa6zLkMAoGCCqGSM49BAMCME0xCzAJBgNVBAYT\nAlVTMRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExFTATBgNVBAcMDFBoaWxhZGVscGhp\nYTEQMA4GA1UECgwHQ29tY2FzdDAeFw0xODA4MDcxNDI5NDdaFw0xOTA4MDcxNDI5\nNDdaME0xCzAJBgNVBAYTAlVTMRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExFTATBgNV\nBAcMDFBoaWxhZGVscGhpYTEQMA4GA1UECgwHQ29tY2FzdDB2MBAGByqGSM49AgEG\nBSuBBAAiA2IABBdpcVNsqZTrZ8mIwScM/t7FakAx4dkOv40WnKrb7aBJ8Rnr0hqc\n1Rwwbv3HxhCmutN519jbekNUHA0NSgMg3/jI4yPu5FxEkcraAnIL4fnkpV4us1Fn\nWR880p7KBrAjjqNQME4wHQYDVR0OBBYEFOwq7vW6O0EwO3VPja7UuUeUId0vMB8G\nA1UdIwQYMBaAFOwq7vW6O0EwO3VPja7UuUeUId0vMAwGA1UdEwQFMAMBAf8wCgYI\nKoZIzj0EAwIDaAAwZQIwCtnzcs2l1wHWb24tH3BrGjErzLYFSoj5QyATTJ2DJ9LW\nFQw5NrSQL61ImgAtwR52AjEAsLL1gp8+ExzQoUVPRzsOfG0wQioNuCV2Z8LpPD8/\nx1M3OURP0muZJqTUDMDOlFwd\n-----END CERTIFICATE-----")))
	if block != nil {
		// alg = ES256
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		publickeys.Add("https://sticr.comcast.com/0.cer", p)
	}
	block, _ = pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIICUTCCAfegAwIBAgIJAIU5HElrC5ISMAoGCCqGSM49BAMCMIGEMQswCQYDVQQG\nEwJVUzEMMAoGA1UECAwDVExWMQwwCgYDVQQHDANUTFYxDDAKBgNVBAoMA0FUVDEP\nMA0GA1UECwwGU0hBS0VOMRswGQYDVQQDDBJTSEFLRU4tQ0VSVElGSUNBVEUxHTAb\nBgkqhkiG9w0BCQEWDmVsNTMydkBhdHQuY29tMB4XDTE4MDIyMjE0MjQ0MloXDTE5\nMDIxMzE0MjQ0MlowgYQxCzAJBgNVBAYTAlVTMQwwCgYDVQQIDANUTFYxDDAKBgNV\nBAcMA1RMVjEMMAoGA1UECgwDQVRUMQ8wDQYDVQQLDAZTSEFLRU4xGzAZBgNVBAMM\nElNIQUtFTi1DRVJUSUZJQ0FURTEdMBsGCSqGSIb3DQEJARYOZWw1MzJ2QGF0dC5j\nb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATyZEVgX0YGc+tAqSrQv2/0b/yZ\nd4z5i7/sAm165IpqxHHZt9fm1mNy1KX2lxU9hj5VwVgEpQEt26aDQ0YbS1Pto1Aw\nTjAdBgNVHQ4EFgQU/znOK+hXkyHYqPalG+Hhzs3dgBgwHwYDVR0jBBgwFoAU/znO\nK+hXkyHYqPalG+Hhzs3dgBgwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBF\nAiEAtlC9ZeZOsy8qer/FNJXC382s6BI/UDUjkXucB+X9URoCIGh0TpYYDurH+OZr\n1PSHSkXDUIfgpwU5ehSgGIOWk58w\n-----END CERTIFICATE-----"))
	if block != nil {
		// alg = ES256
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		publickeys.Add("https://sticr.comcast.com/1.cer", p)
	}
	fmt.Printf("https://sticr.comcast.com/0.cer - %v\n", publickeys.Fetch("https://sticr.comcast.com/0.cer"))
	fmt.Printf("https://sticr.comcast.com/1.cer - %v\n", publickeys.Fetch("https://sticr.comcast.com/1.cer"))
	fmt.Println("----------")
}

func TestFlush(t *testing.T) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIICHjCCAaSgAwIBAgIJAPrmQQLa6zLkMAoGCCqGSM49BAMCME0xCzAJBgNVBAYT\nAlVTMRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExFTATBgNVBAcMDFBoaWxhZGVscGhp\nYTEQMA4GA1UECgwHQ29tY2FzdDAeFw0xODA4MDcxNDI5NDdaFw0xOTA4MDcxNDI5\nNDdaME0xCzAJBgNVBAYTAlVTMRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExFTATBgNV\nBAcMDFBoaWxhZGVscGhpYTEQMA4GA1UECgwHQ29tY2FzdDB2MBAGByqGSM49AgEG\nBSuBBAAiA2IABBdpcVNsqZTrZ8mIwScM/t7FakAx4dkOv40WnKrb7aBJ8Rnr0hqc\n1Rwwbv3HxhCmutN519jbekNUHA0NSgMg3/jI4yPu5FxEkcraAnIL4fnkpV4us1Fn\nWR880p7KBrAjjqNQME4wHQYDVR0OBBYEFOwq7vW6O0EwO3VPja7UuUeUId0vMB8G\nA1UdIwQYMBaAFOwq7vW6O0EwO3VPja7UuUeUId0vMAwGA1UdEwQFMAMBAf8wCgYI\nKoZIzj0EAwIDaAAwZQIwCtnzcs2l1wHWb24tH3BrGjErzLYFSoj5QyATTJ2DJ9LW\nFQw5NrSQL61ImgAtwR52AjEAsLL1gp8+ExzQoUVPRzsOfG0wQioNuCV2Z8LpPD8/\nx1M3OURP0muZJqTUDMDOlFwd\n-----END CERTIFICATE-----")))
	if block != nil {
		// alg = ES256
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		publickeys.Add("https://sticr.comcast.com/0.cer", p)
	}
	block, _ = pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIICUTCCAfegAwIBAgIJAIU5HElrC5ISMAoGCCqGSM49BAMCMIGEMQswCQYDVQQG\nEwJVUzEMMAoGA1UECAwDVExWMQwwCgYDVQQHDANUTFYxDDAKBgNVBAoMA0FUVDEP\nMA0GA1UECwwGU0hBS0VOMRswGQYDVQQDDBJTSEFLRU4tQ0VSVElGSUNBVEUxHTAb\nBgkqhkiG9w0BCQEWDmVsNTMydkBhdHQuY29tMB4XDTE4MDIyMjE0MjQ0MloXDTE5\nMDIxMzE0MjQ0MlowgYQxCzAJBgNVBAYTAlVTMQwwCgYDVQQIDANUTFYxDDAKBgNV\nBAcMA1RMVjEMMAoGA1UECgwDQVRUMQ8wDQYDVQQLDAZTSEFLRU4xGzAZBgNVBAMM\nElNIQUtFTi1DRVJUSUZJQ0FURTEdMBsGCSqGSIb3DQEJARYOZWw1MzJ2QGF0dC5j\nb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATyZEVgX0YGc+tAqSrQv2/0b/yZ\nd4z5i7/sAm165IpqxHHZt9fm1mNy1KX2lxU9hj5VwVgEpQEt26aDQ0YbS1Pto1Aw\nTjAdBgNVHQ4EFgQU/znOK+hXkyHYqPalG+Hhzs3dgBgwHwYDVR0jBBgwFoAU/znO\nK+hXkyHYqPalG+Hhzs3dgBgwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBF\nAiEAtlC9ZeZOsy8qer/FNJXC382s6BI/UDUjkXucB+X9URoCIGh0TpYYDurH+OZr\n1PSHSkXDUIfgpwU5ehSgGIOWk58w\n-----END CERTIFICATE-----"))
	if block != nil {
		// alg = ES256
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		publickeys.Add("https://sticr.comcast.com/1.cer", p)
	}
	publickeys.Entries()
	fmt.Println("----------")
	publickeys.FlushCache()
	publickeys.Entries()
}

