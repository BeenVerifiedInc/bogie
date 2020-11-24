package bogie

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BeenVerifiedInc/bogie/common"
	bogieio "github.com/BeenVerifiedInc/bogie/io"
	dotaccess "github.com/go-bongo/go-dotaccess"
	"github.com/imdario/mergo"
	yaml "gopkg.in/yaml.v2"

	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type applicationOutput struct {
	outPath  string
	template string
	context  *context
}

type context struct {
	Values map[interface{}]interface{}
}

type config struct {
	appOutputs *[]*applicationOutput
	input      string
	output     string
	context    *context
	bogie      *Bogie
}

func processApplications(b *Bogie) ([]*applicationOutput, error) {
	c, err := genContext(b.EnvFile)
	if err != nil {
		return nil, err
	}

	appOutputs := []*applicationOutput{}
	re := regexp.MustCompile(b.AppRegex)
	//generate list of flagged apps
	flaggedApplicationInputs := make([]*ApplicationInput, 0)
	for _, app := range b.ApplicationInputs {
		if b.AppRegex != "" {
			if !re.MatchString(app.Name) {
				continue
			}
		}

		c, isFlaggedBySecret, err := setValueContext(app, c, b.FlaggedSecret)
		if err != nil {
			return nil, err
		}
		if isFlaggedBySecret {
			flaggedApplicationInputs = append(flaggedApplicationInputs, app)
		}

		releaseDir := filepath.Join(b.OutPath, app.Name)

		conf := config{
			appOutputs: &appOutputs,
			input:      app.Templates,
			output:     releaseDir,
			context:    c,
			bogie:      b,
		}

		err = processApplication(conf)
		if err != nil {
			return nil, err
		}
	}
	flaggedAppJson, err := json.Marshal(flaggedApplicationInputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling json for application inputs. %v\n", err)
	} else {
		fmt.Printf("%s\n", string(flaggedAppJson))
	}

	return appOutputs, nil
}

func genContext(envfile string) (*context, error) {
	c := context{}

	if envfile == "" {
		return &c, nil
	}

	inEnv, err := bogieio.DecryptFile(envfile, "yaml")
	if err != nil {
		return &c, err
	}

	err = yaml.Unmarshal(inEnv, &c.Values)
	if err != nil {
		return &c, err
	}

	return &c, nil
}

func setValueContext(app *ApplicationInput, old *context, flaggedSecret string) (*context, bool, error) {
	c := context{}

	files := []string{}

	if app.Env != "" {
		if defaultRegion, ok := old.Values["default_region"]; ok {
			regionalFileName := fmt.Sprintf("%s/%s.%s.values.yaml", app.Templates, app.Env, defaultRegion)
			if common.FileExists(regionalFileName) {
				files = append(files, regionalFileName)
			}
		}

		files = append(files, fmt.Sprintf("%s/%s.values.yaml", app.Templates, app.Env))
	}

	if len(app.Values) == 0 {
		files = append(files, fmt.Sprintf("%s/values.yaml", app.Templates))
	} else {
		sort.Sort(sort.Reverse(sort.StringSlice(app.Values)))
		files = append(files, app.Values...)
	}

	dontWarn := func(file string) bool {
		return len(app.Values) == 0 &&
			file == fmt.Sprintf("%s/values.yaml", app.Templates)
	}

	isFlaggedBySecret := false

	for _, file := range files {
		b, err := bogieio.DecryptFile(file, "yaml")
		if err != nil {
			if dontWarn(file) {
				continue
			}
			return &c, false, err
		}

		var tmp map[interface{}]interface{}
		err = yaml.Unmarshal(b, &tmp)
		if err != nil {
			return &c, false, err
		}
		lookedUpSecretNames, secretMapErr := processSecretMap(&tmp)
		if secretMapErr != nil {
			return &c, false, err
		} else {
			for _, v := range lookedUpSecretNames {
				if flaggedSecret == v {
					isFlaggedBySecret = true
				}
			}
		}
		mergo.Merge(&c.Values, tmp)
	}

	mergo.Merge(&c.Values, old.Values)

	for _, keyVal := range app.OverrideVars {
		splits := strings.SplitN(keyVal, "=", 2)
		err := dotaccess.Set(c.Values, splits[0], splits[1])
		if err != nil {
			return &c, isFlaggedBySecret, err
		}
	}

	return &c, isFlaggedBySecret, nil
}

func processApplication(conf config) error {
	input := conf.input
	output := conf.output

	entries, err := bogieio.ReadDir(input)
	if err != nil {
		return err
	}

	helper, _ := bogieio.ReadFile(input + "/_helpers.tmpl")

	r := conf.bogie.Rules.Clone()
	r.ParseFile(input + "/.bogieignore")

	for _, entry := range entries {
		if ok := r.Ignore(entry.Name(), entry.IsDir()); ok {
			continue
		}

		nextInPath := fmt.Sprintf("%s/%s", input, entry.Name())
		nextOutPath := filepath.Join(output, entry.Name())

		if entry.IsDir() {
			conf.input = nextInPath
			conf.output = nextOutPath

			err := processApplication(conf)
			if err != nil {
				return err
			}
		} else {
			inString, err := bogieio.ReadFile(nextInPath)
			if err != nil {
				return err
			}

			*conf.appOutputs = append(*conf.appOutputs, &applicationOutput{
				outPath:  nextOutPath,
				template: string(helper) + string(inString),
				context:  conf.context,
			})
		}
	}

	return nil
}

var (
	secretCache = make(map[string]map[string]string, 0)
)

func getSecret(secretName string) (map[string]string, error){
	cachedValue, ok := secretCache[secretName]
	if ok {
		return cachedValue, nil
	}
	region := os.Getenv("AWS_DEFAULT_REGION")

	//Create a Secrets Manager client
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		fmt.Printf("%v\n", err)
		return nil, err
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
		returnValue := make(map[string]string, 0)
		err = json.Unmarshal([]byte(secretString), &returnValue)
		secretCache[secretName] = returnValue
		return returnValue, nil
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
			return nil, err
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		returnValue := make(map[string]string, 0)
		err = json.Unmarshal([]byte(decodedBinarySecret), &returnValue)
		secretCache[secretName] = returnValue
		return returnValue, nil
	}
}

func processSecretMap(sourceMap *map[interface{}]interface{}) ([]string, error) {
	app, ok := (*sourceMap)["app"].(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("received invalid map in processSecretMap")
	}
	secret, ok := app["secret"].(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("no secret sub-section in app section")
	}
	lookedUpSecrets := make([]string, 0)
	for key, value := range secret {
		_, ok = value.(string)
		if ok {
			continue
		}
		mapValue := value.(map[interface{}]interface{})
		secretArn, ok := mapValue["secret_arn"].(string)
		if !ok {
			continue
		}

		keyName, ok := mapValue["key_name"].(string)
		if !ok {
			continue
		}
		secretValue, _ := getSecret(secretArn)
		lookedUpSecrets = append(lookedUpSecrets, secretArn)
		secret[key] = secretValue[keyName]
	}
	return lookedUpSecrets, nil

}
