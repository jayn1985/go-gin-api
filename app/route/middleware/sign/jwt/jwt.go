package sign_jwt

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go-gin-api/app/config"
	"go-gin-api/app/util/response"
	"strconv"
	"strings"
	"time"
)

type UserSession struct {
	ID int64 `json:"id"`
	Name string `json:"name,omitempty"`
}

type tcClaims struct {
	Sub *UserSession
	jwt.StandardClaims
}

func SetUp() gin.HandlerFunc {

	return func(c *gin.Context) {
		utilGin := response.Gin{Ctx: c}

		err := verifyToken(c)
		if err != nil {
			utilGin.Response(-1, err.Error(), nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

func CreateToken(sub *UserSession) (string, error) {
	now := time.Now()

	exp, _ := strconv.ParseInt(config.AppSignExpiry, 10, 64)
	expireTime := now.Add(time.Duration(exp) * time.Second).Unix()

	claims := tcClaims{
		sub,
		jwt.StandardClaims{
			Issuer: config.AppName,
			IssuedAt: now.Unix(),
			ExpiresAt: expireTime,
			NotBefore: now.Unix(),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return jwtToken.SignedString([]byte(config.JwtSecret))
}

func verifyToken(c *gin.Context) error {
	appToken := strings.TrimSpace(c.Request.Header.Get("X-App-Token"))
	if appToken == "" {
		return errors.New("token empty")
	}

	userInfo, err := decodeToken(appToken)
	if err != nil {
		return err
	}

	c.Set("current_user", userInfo)
	return nil
}

func decodeToken(tokenStr string) (*UserSession, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &tcClaims{}, func(token *jwt.Token) (i interface{}, e error) {
		return []byte(config.JwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := t.Claims.(*tcClaims); ok {
		retSub := claims.Sub

		if retSub == nil || retSub.ID == 0 {
			return nil, errors.New("invalid token - 002")
		}

		return retSub, nil
	} else {
		return nil, errors.New("invalid token - 001")
	}
}
