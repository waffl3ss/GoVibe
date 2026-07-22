package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"govibe/pkg/models"
)

// JSONWriter handles JSON file output
type JSONWriter struct {
	outputDir string
	domain    string
}

// NewJSONWriter creates a new JSON writer
func NewJSONWriter(outputDir, domain string) *JSONWriter {
	return &JSONWriter{
		outputDir: outputDir,
		domain:    domain,
	}
}

// WriteAll writes all domain data to JSON files
func (w *JSONWriter) WriteAll(data *models.DomainData) error {
	if err := os.MkdirAll(w.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write individual files like ldapdomaindump
	if err := w.writeUsers(data.Users); err != nil {
		return err
	}
	if err := w.writeGroups(data.Groups); err != nil {
		return err
	}
	if err := w.writeComputers(data.Computers); err != nil {
		return err
	}
	if err := w.writeSPNs(data.SPNs); err != nil {
		return err
	}
	if err := w.writePasswordPolicy(data.PasswordPolicy); err != nil {
		return err
	}
	if err := w.writeFGPolicies(data.FGPolicies); err != nil {
		return err
	}
	if err := w.writeTrusts(data.Trusts); err != nil {
		return err
	}
	if err := w.writeDomainInfo(data.Domain); err != nil {
		return err
	}

	// Write combined file
	return w.writeCombined(data)
}

func (w *JSONWriter) writeFile(filename string, data interface{}) error {
	path := filepath.Join(w.outputDir, fmt.Sprintf("%s_%s.json", w.domain, filename))

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", path, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	fmt.Printf("[+] Saved: %s\n", path)
	return nil
}

func (w *JSONWriter) writeUsers(users []models.User) error {
	return w.writeFile("users", users)
}

func (w *JSONWriter) writeGroups(groups []models.Group) error {
	return w.writeFile("groups", groups)
}

func (w *JSONWriter) writeComputers(computers []models.Computer) error {
	return w.writeFile("computers", computers)
}

func (w *JSONWriter) writeSPNs(spns []models.SPN) error {
	return w.writeFile("spns", spns)
}

func (w *JSONWriter) writePasswordPolicy(policy models.PasswordPolicy) error {
	return w.writeFile("password_policy", policy)
}

func (w *JSONWriter) writeFGPolicies(policies []models.FineGrainedPasswordPolicy) error {
	if len(policies) == 0 {
		return nil
	}
	return w.writeFile("fgpp", policies)
}

func (w *JSONWriter) writeTrusts(trusts []models.Trust) error {
	if len(trusts) == 0 {
		return nil
	}
	return w.writeFile("trusts", trusts)
}

func (w *JSONWriter) writeDomainInfo(info models.DomainInfo) error {
	return w.writeFile("domain_info", info)
}

func (w *JSONWriter) writeCombined(data *models.DomainData) error {
	return w.writeFile("all", data)
}
