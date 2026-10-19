package capability

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// FromFile decodes a .plumber.yaml `capabilities:` key the strict way (DecodeYAML) and
// checks its bounds (Validate): the one step the provider (CapabilitiesOf) and `config
// view` both run on the file's raw value, so the two can never read the key differently
// (spec 4.2, 4.6). raw is the PlumberConfig.Capabilities field exactly as the YAML loader
// left it. Nil raw (no capabilities key in the file) is nil, no warning. A decode or
// validation failure logs the one-line warning both callers show through l, naming the
// error, and returns nil so the caller falls back to the built-in list alone.
func FromFile(raw interface{}, l *logrus.Entry) []Declaration {
	if raw == nil {
		return nil
	}
	decls, err := decodeFileValue(raw)
	if err == nil {
		err = Validate(decls)
	}
	if err != nil {
		l.WithError(err).Warn("capabilities: the .plumber.yaml declarations are not valid, the built-in list is in force")
		return nil
	}
	return decls
}

// decodeFileValue re-encodes raw (the loosely-typed value a whole-file YAML decode left
// under the capabilities key) under that same key and decodes it strictly through
// DecodeYAML, which refuses an unknown key by name and a wrong type.
func decodeFileValue(raw interface{}) ([]Declaration, error) {
	data, err := yaml.Marshal(map[string]interface{}{"capabilities": raw})
	if err != nil {
		return nil, err
	}
	return DecodeYAML(data)
}

// Effective returns the effective capability list a run uses: the user list first, in its
// own order, then every built-in capability whose name the user list does not declare (spec
// 4.2). A user declaration that names a built-in replaces it whole: there is no merge of
// recognizers inside one name, so a user can narrow a built-in like secret_detection to
// their own tool alone. A nil or empty user list yields Builtin() unchanged.
func Effective(user []Declaration) []Declaration {
	if len(user) == 0 {
		return Builtin()
	}

	declared := make(map[string]bool, len(user))
	for _, d := range user {
		declared[d.Name] = true
	}

	out := append([]Declaration(nil), user...)
	for _, b := range Builtin() {
		if !declared[b.Name] {
			out = append(out, b)
		}
	}
	return out
}
