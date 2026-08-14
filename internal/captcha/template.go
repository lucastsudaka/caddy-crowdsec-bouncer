// Copyright 2026 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package captcha

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"os"
)

const scriptNonceBytes = 16

//go:embed default.html
var defaultTemplateFS embed.FS //nolint:gochecknoglobals // immutable embedded asset

// TemplateData is the data available to both the embedded challenge template
// and Config.TemplatePath. ScriptURL and WidgetClass are fixed by Provider;
// SiteKey is public provider configuration. FormAction is a same-origin URI
// carrying the module's internal submission marker. Nonce authorizes trusted
// inline scripts without relaxing the response Content Security Policy.
type TemplateData struct {
	Provider    Provider
	SiteKey     string
	ScriptURL   template.URL
	WidgetClass string
	Action      string
	FormAction  string
	Nonce       string
	Failed      bool
}

func generateScriptNonce() (string, error) {
	random := make([]byte, scriptNonceBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate script nonce: %w", err)
	}

	return base64.RawStdEncoding.EncodeToString(random), nil
}

func loadTemplate(path string) (*template.Template, error) {
	var source []byte
	if path == "" {
		var err error
		source, err = defaultTemplateFS.ReadFile("default.html")
		if err != nil {
			return nil, fmt.Errorf("captcha: read embedded template: %w", err)
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("captcha: open template: %w", err)
		}
		defer func() { _ = file.Close() }()

		source, err = io.ReadAll(io.LimitReader(file, maximumTemplateBytes+1))
		if err != nil {
			return nil, fmt.Errorf("captcha: read template: %w", err)
		}
		if len(source) > maximumTemplateBytes {
			return nil, fmt.Errorf("captcha: template exceeds %d bytes", maximumTemplateBytes)
		}
	}

	tmpl, err := template.New("captcha").Option("missingkey=error").Parse(string(source))
	if err != nil {
		return nil, fmt.Errorf("captcha: parse template: %w", err)
	}
	return tmpl, nil
}
