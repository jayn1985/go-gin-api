package sign_rsa

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/xinliangnote/go-util/rsa"
	timeUtil "github.com/xinliangnote/go-util/time"
	"go-gin-api/app/config"
	"go-gin-api/app/util/response"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var AppSecret string

// RSA 非对称加密
func SetUp() gin.HandlerFunc {

	return func(c *gin.Context) {
		utilGin := response.Gin{Ctx: c}

		sign, err := verifySign(c)

		if sign != nil {
			utilGin.Response(-1, "Debug Sign", sign)
			c.Abort()
			return
		}

		if err != nil {
			utilGin.Response(-1, err.Error(), sign)
			c.Abort()
			return
		}

		c.Next()
	}
}

// 创建签名
func CreateSign(params url.Values) (string, error) {
	return rsa.PublicEncrypt(createEncryptStr(params), AppSecret)
}

// 验证签名
func verifySign(c *gin.Context) (map[string]string, error) {
	_ = c.Request.ParseForm()
	req   := c.Request.Form
	debug := strings.Join(c.Request.Form["debug"], "")
	ak    := strings.Join(c.Request.Form["ak"], "")
	sn    := strings.Join(c.Request.Form["sn"], "")
	ts    := strings.Join(c.Request.Form["ts"], "")

	// 验证来源
	value, ok := config.ApiAuthConfig[ak]
	if ok {
		AppSecret = value["rsa"]
	} else {
		return nil, errors.New("ak Error")
	}

	if debug == "1" {
		currentUnix := timeUtil.GetCurrentUnix()
		req.Set("ts", strconv.FormatInt(currentUnix, 10))

		sn, err := CreateSign(req)
		if err != nil {
			return nil, errors.New("sn Exception")
		}

		res := map[string]string{
			"ts": strconv.FormatInt(currentUnix, 10),
			"sn": sn,
		}
		return res, nil
	}

	// 验证过期时间
	timestamp := time.Now().Unix()
	exp, _    := strconv.ParseInt(config.AppSignExpiry, 10, 64)
	tsInt, _  := strconv.ParseInt(ts, 10, 64)
	if tsInt > timestamp || timestamp - tsInt >= exp {
		return nil, errors.New("ts Error")
	}

	// 验证签名
	if sn == "" {
		return nil, errors.New("sn Error")
	}

	decryptStr, decryptErr := rsa.PrivateDecrypt(sn, config.AppRsaPrivateFile)
	if decryptErr != nil {
		return nil, errors.New(decryptErr.Error())
	}
	if decryptStr != createEncryptStr(req) {
		return nil, errors.New("sn Error")
	}
	return nil, nil
}

func createEncryptStr(params url.Values) string {
	var key []string
	var str = ""
	for k := range params {
		if k != "sn" && k != "debug" {
			key = append(key, k)
		}
	}
	sort.Strings(key)
	for i := 0; i < len(key); i++ {
		if i == 0 {
			str = fmt.Sprintf("%v=%v", key[i], params.Get(key[i]))
		} else {
			str = str + fmt.Sprintf("&%v=%v", key[i], params.Get(key[i]))
		}
	}
	return str
}
