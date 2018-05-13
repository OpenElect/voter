/* openelect-voter - a cli for the OpenElect voting platform.
 *
 * Copyright (C) 2018  OpenElect
 *     Fin Christensen <fin.christensen@st.ovgu.de>,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"os"
	"fmt"
	"io"
	"regexp"
	"strings"
	"io/ioutil"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
    "crypto/x509"
    "encoding/pem"

	"github.com/urfave/cli"
	"github.com/go-yaml/yaml"
)

var vote = struct {
	PrivateKey string
	Vote int
	Secret string
	Output string
}{}

var check = struct {
	Container string
	Secret string
	PublicKey string
}{}

var rng = rand.Reader

type VoteContainer struct {
	Vote int
	ID int64
}

func GetIDFromAgency() (int64, error) {
	// TODO
	return 42, nil
}

func AgencySign(voteContainer string) (string, error) {
	// TODO
	return voteContainer, nil
}

func encrypt(secret string, text string) (string, error) {
	hashedSecret := sha256.Sum256([]byte(secret))
	bsecret := hashedSecret[:]
	btext := []byte(text)

	block, err := aes.NewCipher(bsecret)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(btext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], btext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(secret string, cryptoText string) (string, error) {
	hashedSecret := sha256.Sum256([]byte(secret))
	bsecret := hashedSecret[:]
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(bsecret)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}

func sign(privateKeyPem []byte, data []byte) (string, error){
	privBlock, _ := pem.Decode(privateKeyPem)
	privateKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return "", cli.NewExitError("Failed to parse your private key!", 6)
	}

	signature, err := rsa.SignPKCS1v15(rng, privateKey, 0, data)
	if err != nil {
		return "", cli.NewExitError("Failed to sign your vote!", 7)
	}
	return base64.URLEncoding.EncodeToString(signature), nil
}

func verify(publicKeyContent string, data string, signature string) (bool, error) {
	tokens := strings.Split(publicKeyContent, " ")

	if len(tokens) < 2 {
		return false, errors.New("Invalid key format - must contain at least two fields")
	}

	decodedSignature, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	publicKeyData, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		return false, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyData)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), 0, []byte(data), decodedSignature)
	return err == nil, nil
}

func Vote(context *cli.Context) error {
	if !context.IsSet("private-key") ||
		!context.IsSet("vote") ||
		!context.IsSet("secret") ||
		!context.IsSet("output") {
		cli.ShowCommandHelpAndExit(context, "vote", 1)
	}

	id, err := GetIDFromAgency()
	if err != nil {
		return cli.NewExitError("Failed to get connection to agency!", 2)
	}

	container, err := yaml.Marshal(
		&VoteContainer{
			Vote: vote.Vote,
			ID: id,
		},
	)
	if err != nil {
		return cli.NewExitError("Failed to serialize your vote!", 3)
	}

	encryptedContainer, err := encrypt(vote.Secret, string(container))
	if err != nil {
		return cli.NewExitError("Failed to encrypt your vote!", 4)
	}
	privateKeyPem, err := ioutil.ReadFile(vote.PrivateKey)
	if err != nil {
		return cli.NewExitError("Failed to open your private key!", 5)
	}

	signature, err := sign(privateKeyPem, []byte(encryptedContainer))
	if err != nil {
		return err
	}

	voteContainer := fmt.Sprintf(`%s
-----BEGIN RSA SIGNATURE-----
%s
-----END RSA SIGNATURE-----
`, encryptedContainer, signature)

	signedVote, err := AgencySign(voteContainer)
	if err != nil {
		return cli.NewExitError("The agency failed to sign your vote!", 8)
	}

	if err := ioutil.WriteFile(vote.Output, []byte(signedVote), 0644); err != nil {
		return cli.NewExitError("Failed to write the signed vote to your filesystem!", 9)
	}

	return nil
}

var re, _ = regexp.Compile(`^(.*)\n-----BEGIN RSA SIGNATURE-----\n(.*)\n-----END RSA SIGNATURE-----\n$`)

func Check(context *cli.Context) error {
	if !context.IsSet("public-key") ||
		!context.IsSet("container") ||
		!context.IsSet("secret") {
		cli.ShowCommandHelpAndExit(context, "check", 1)
	}

	container, err := ioutil.ReadFile(check.Container)
	if err != nil {
		return cli.NewExitError("Failed to open vote file!", 10)
	}

	res := re.FindStringSubmatch(string(container))
	vote := res[1]
	signature := res[2]
	publicKey, err := ioutil.ReadFile(check.PublicKey)
	if err != nil {
		return cli.NewExitError("Failed to open your public key!", 11)
	}

	valid, err := verify(string(publicKey), vote, signature)
	if err != nil {
		fmt.Printf("%s\n", err)
		return cli.NewExitError("Failed to verify signature of vote!", 12)
	}

	if valid {
		fmt.Printf("Signature of vote is: VALID\n")
	} else {
		fmt.Printf("Signature of vote is: INVALID\n")
	}

	decryptedVote, err := decrypt(check.Secret, vote)
	if err != nil {
		return cli.NewExitError("Failed to decrypt vote!", 13)
	}

	fmt.Printf("%s\n", decryptedVote)

	return nil
}

func Commit(context *cli.Context) error {
	return nil
}

func main() {
	cli.AppHelpTemplate = `Usage: {{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
{{.Usage}}
{{if .Commands}}
Commands:
{{range .Commands}}{{if not .HideHelp}}   {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}{{end}}{{if .VisibleFlags}}
Global options:
   {{range .VisibleFlags}}{{.}}
   {{end}}{{end}}{{if len .Authors}}
Authors:
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .Commands}}
{{.Name}} - {{.Copyright}}{{end}}
`

	app := cli.NewApp()
	app.Name = "openelect-voter"
	app.Usage = "This program provides a command line interface to the OpenElect voting platform."
	app.Version = "0.1.0"
	app.Authors = []cli.Author{
		{
			Name: "Fin Christensen",
			Email: "fin.christensen@st.ovgu.de",
		},
	}
	app.Copyright = "Copyright (c) 2018  OpenElect"
	app.Action = cli.ShowAppHelp
	app.Commands = []cli.Command{
		{
			Name: "vote",
			Aliases: []string{"v"},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "private-key, k",
					Usage: "Provide the path to your private key used to sign your vote.",
					Destination: &vote.PrivateKey,
				},
				cli.IntFlag{
					Name: "vote, v",
					Usage: "Provide the ID of the item you would like to vote for.",
					Destination: &vote.Vote,
				},
				cli.StringFlag{
					Name: "secret, s",
					Usage: "Provide a secret with which your vote gets encrypted.",
					Destination: &vote.Secret,
				},
				cli.StringFlag{
					Name: "output, o",
					Usage: "Provide the path where to write the produced voting container.",
					Destination: &vote.Output,
				},
			},
			Usage: "Create a vote that can be committed to a counting server",
			Description: "This action creates a vote container that can be send to a counting server.",
			Action: Vote,
		},
		{
			Name: "check",
			Aliases: []string{"validate", "v"},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "public-key, k",
					Usage: "Provide the path to the public key that was used to sign the vote.",
					Destination: &check.PublicKey,
				},
				cli.StringFlag{
					Name: "container, c",
					Usage: "Provide the path to the vote container file.",
					Destination: &check.Container,
				},
				cli.StringFlag{
					Name: "secret, s",
					Usage: "Provide the secret with which your vote was encrypted.",
					Destination: &check.Secret,
				},
			},
			Usage: "Check the content of a previously made vote",
			Description: "This action checks the content of a previously made vote for validation.",
			Action: Check,
		},
		{
			Name: "commit",
			Aliases: []string{"c"},
			Flags: []cli.Flag{},
			Usage: "Commit a vote to a counting server",
			Description: "This action commits a vote to a counting server.",
			Action: Commit,
		},
	}

	app.Run(os.Args)
}

/*
vote:
--private-key, -k [PATH:string]
--vote, -v [VOTE:number]
--secret, -s [SECRET:string]
--output, -o [CONTAINER_PATH:string]

check:
--container, -c [CONTAINER_PATH:string]
--public-key, -k [PATH:string]
--secret, -s [SECRET:string]

commit:
--container, -c [CONTAINER_PATH:string]
--secret, -s [SECRET:string]
*/
