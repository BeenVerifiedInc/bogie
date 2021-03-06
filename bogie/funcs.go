package bogie

import (
	"io"
	"text/template"

	"github.com/BeenVerifiedInc/bogie/crypto"
	"github.com/BeenVerifiedInc/bogie/ecr"
	"github.com/BeenVerifiedInc/bogie/file"
	"github.com/BeenVerifiedInc/bogie/types"
)

func initFuncs(c *context, b *Bogie) template.FuncMap {
	templater := func(text string, w io.Writer) error {
		hasContent, buff, err := runTemplate(c, b, text)
		if err != nil {
			return err
		}

		if hasContent {
			if _, err := io.Copy(w, buff); err != nil {
				return err
			}
		}

		return nil
	}

	file.SetTemplater(templater)

	return template.FuncMap{
		"latestImage": ecr.LatestImage(b.SkipImageLookup),
		"readDir":     file.ReadDir,
		"readFile":    file.ReadFile,
		"decryptFile": file.DecryptFile,
		"decryptDir":  file.DecryptDir,
		"basicAuth":   crypto.BasicAuth,
		"json":        types.JSON,
		"jsonArray":   types.JSONArray,
		"toJSON":      types.ToJSON,
		"yaml":        types.YAML,
		"yamlArray":   types.YAMLArray,
		"toYAML":      types.ToYAML,
		"toml":        types.TOML,
		"toTOML":      types.ToTOML,
	}
}
