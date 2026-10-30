package main

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"log"
	"os"
	"strings"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// 读取二维码图片
func readQRCode(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return "", err
	}

	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}

	reader := qrcode.NewQRCodeReader()

	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}

	result, err := reader.Decode(bitmap, hints)
	if err != nil {
		return "", err
	}

	return result.GetText(), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("使用方法：")
		fmt.Println(`  go run . "github-2fa.png"`)
		return
	}

	qrPath := os.Args[1]

	// 1. 识别二维码
	uri, err := readQRCode(qrPath)
	if err != nil {
		log.Fatalf("二维码识别失败: %v", err)
	}

	// GitHub 2FA 正常应该是：
	// otpauth://totp/GitHub:xxx?secret=XXXX...
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		log.Fatal("该二维码不是标准 TOTP 2FA 二维码")
	}

	// 2. 解析 TOTP
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		log.Fatalf("解析 OTP 信息失败: %v", err)
	}

	if key.Secret() == "" {
		log.Fatal("二维码中没有找到 TOTP Secret")
	}

	fmt.Printf("服务: %s\n", key.Issuer())
	fmt.Printf("账户: %s\n", key.AccountName())
	fmt.Printf("周期: %d 秒\n\n", key.Period())

	// 不输出 Secret，避免意外泄漏

	// 3. 持续生成验证码
	for {
		now := time.Now()

		code, err := totp.GenerateCodeCustom(
			key.Secret(),
			now.UTC(),
			totp.ValidateOpts{
				Period:    uint(key.Period()),
				Skew:      0,
				Digits:    key.Digits(),
				Algorithm: key.Algorithm(),
				Encoder:   key.Encoder(),
			},
		)

		if err != nil {
			log.Fatalf("生成验证码失败: %v", err)
		}

		remaining := int64(key.Period()) -
			now.Unix()%int64(key.Period())

		fmt.Printf(
			"\r2FA 验证码: %s    剩余: %2d 秒 ",
			code,
			remaining,
		)

		time.Sleep(time.Second)
	}
}