// internal/security/registry/registry.go
package registry

import (
	"bufio"
	_ "embed"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Platform identifies the host OS family
type Platform string

// Distro indentifies a *Nix distro family *if Windows, unused
type Distro string

// FindingKey formatted <checker>.<finding_id> to join checker detection logic and registry data
type FindingKey string

// Platform constants
const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformUnix    Platform = "unix"
	PlatformUnknown Platform = "unknown"
)

// Distro family constants where derivatives resolve to parent family
const (
	// Linux Families
	DistroDebian  Distro = "debian"
	DistroRHEL    Distro = "rhel"
	DistroFedora  Distro = "fedora"
	DistroArch    Distro = "arch"
	DistroSUSE    Distro = "suse"
	DistroAlpine  Distro = "alpine"
	DistroGeneric Distro = "generic"

	// Unix Families
	DistroFreeBSD Distro = "freebsd"
	DistroOpenBSD Distro = "openbsd"
	DistroNetBSD  Distro = "netbsd"

	// Non-Linux Platforms
	DistroNone    Distro = ""
	DistroUnknown Distro = "uknown"
)

// OSContext obtains full platform and distro info to pass to auditor before registry lookups
type OSContext struct {
	Platform Platform
	Families []Distro
}

// FindingDefinition is a registry map for types.Finding
type FindingDefinition struct {
	Title       string   `yaml:"title"`
	Severity    string   `yaml:"severity"`
	CVSSScore   float64  `yaml:"cvss_score"`
	CVSSVector  string   `yaml:"cvss_vector"`
	CWE         string   `yaml:"cwe"`
	Description string   `yaml:"description"`
	Impact      string   `yaml:"impact"`
	Resolution  string   `yaml:"resolution"`
	References  []string `yaml:"references"`
}

// platformRegistry holds all indexed definitions
type platformRegistry map[Platform]map[FindingKey]FindingDefinition

// Linux family registry holds distro index findings
type linuxFamilyRegistry map[Distro]map[FindingKey]FindingDefinition

var (
	registry      platformRegistry
	linuxRegistry linuxFamilyRegistry
)

//go:embed data/windows.yaml
var windowsData []byte

//go:embed data/linux_common.yaml
var linuxCommonData []byte

//go:embed data/linux_debian.yaml
var linuxDebianData []byte

//go:embed data/linux_rhel.yaml
var linuxRHELData []byte

//go:embed data/linux_arch.yaml
var linuxArchData []byte

//go:embed data/linux_fedora.yaml
var linuxFedoraData []byte

//go:embed data/linux_suse.yaml
var linuxSUSEData []byte

//go:embed data/linux_alpine.yaml
var linuxAlpineData []byte

//go:embed data/darwin.yaml
var darwinData []byte

//go:embed data/unix_freebsd.yaml
var unixFreeBSDData []byte

//go:embed data/unix_openbsd.yaml
var unixOpenBSDData []byte

func init() {
	registry = make(platformRegistry)
	linuxRegistry = make(linuxFamilyRegistry)

	registry[PlatformWindows] = mustLoad(windowsData)
	registry[PlatformDarwin] = mustLoad(darwinData)

	linuxRegistry[DistroGeneric] = mustLoad(linuxCommonData)
	linuxRegistry[DistroDebian] = mustLoad(linuxDebianData)
	linuxRegistry[DistroRHEL] = mustLoad(linuxRHELData)
	linuxRegistry[DistroArch] = mustLoad(linuxArchData)
	linuxRegistry[DistroFedora] = mustLoad(linuxFedoraData)
	linuxRegistry[DistroSUSE] = mustLoad(linuxSUSEData)
	linuxRegistry[DistroAlpine] = mustLoad(linuxAlpineData)

	unixRegistry := make(map[Distro]map[FindingKey]FindingDefinition)
	unixRegistry[DistroFreeBSD] = mustLoad(unixFreeBSDData)
	unixRegistry[DistroOpenBSD] = mustLoad(unixOpenBSDData)
	registry[PlatformUnix] = flattenUnix(unixRegistry)
}

// mustLoad parses a byte slice into a finding map
func mustLoad(data []byte) map[FindingKey]FindingDefinition {
	var raw map[string]FindingDefinition
	if err := yaml.Unmarshal(data, &raw); err != nil {
		panic("registry: failed to parse embedded YAML: " + err.Error())
	}
	out := make(map[FindingKey]FindingDefinition, len(raw))
	for k, v := range raw {
		out[FindingKey(k)] = v
	}
	return out
}

// flattenUnix merges unix family maps into a distro key map
func flattenUnix(families map[Distro]map[FindingKey]FindingDefinition) map[FindingKey]FindingDefinition {
	out := make(map[FindingKey]FindingDefinition)
	for family, findings := range families {
		for key, def := range findings {
			prefixed := FindingKey(string(family) + "." + string(key))
			out[prefixed] = def
		}
	}
	return out
}

// Lookup retrieves a FindingDefinition for the given OSContext and key.
func Lookup(ctx OSContext, key FindingKey) (FindingDefinition, bool) {
	switch ctx.Platform {
	case PlatformLinux:
		for _, family := range ctx.Families {
			if fm, ok := linuxRegistry[family]; ok {
				if def, ok := fm[key]; ok {
					return def, true
				}
			}
		}
		// fall through to common Linux findings
		if def, ok := linuxRegistry[DistroGeneric][key]; ok {
			return def, true
		}
		return FindingDefinition{}, false

	default:
		if pm, ok := registry[ctx.Platform]; ok {
			if def, ok := pm[key]; ok {
				return def, true
			}
		}
		return FindingDefinition{}, false
	}
}

// DetectOS identifies the current platform and, for Linux, resolves
// the full distribution family chain from /etc/os-release.
func DetectOS() OSContext {
	switch platform := detectPlatform(); platform {
	case PlatformLinux:
		return OSContext{
			Platform: PlatformLinux,
			Families: detectLinuxFamilies(),
		}
	default:
		return OSContext{Platform: platform}
	}
}

// detectPlatform returns the Platform either via runtime.GOOS or /etc/os-release
func detectPlatform() Platform {
	// Check for Linux first via os-release presence
	if _, err := os.Stat("/etc/os-release"); err == nil {
		return PlatformLinux
	}
	// macOS
	if _, err := os.Stat("/System/Library/CoreServices/SystemVersion.plist"); err == nil {
		return PlatformDarwin
	}
	// FreeBSD / OpenBSD / NetBSD
	if _, err := os.Stat("/etc/rc.conf"); err == nil {
		return PlatformUnix
	}
	// Windows — none of the above exist
	return PlatformWindows
}

// detectLinuxFamilies parses /etc/os-release and returns the
// distro family chain ordered from most specific to least specific.
func detectLinuxFamilies() []Distro {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return []Distro{DistroGeneric}
	}
	defer file.Close() // nolint:errcheck // read-only file

	var id, idLike string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "ID_LIKE="):
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	if err := scanner.Err(); err != nil {
		return []Distro{DistroGeneric}
	}

	var families []Distro

	// Resolve the specific ID to a known family
	if f := resolveDistro(id); f != DistroUnknown {
		families = append(families, f)
	}

	// Walk ID_LIKE parent families in declared order
	for _, parent := range strings.Fields(idLike) {
		if f := resolveDistro(parent); f != DistroUnknown {
			// avoid duplicates
			if !containsDistro(families, f) {
				families = append(families, f)
			}
		}
	}

	// Always terminate with generic as the final fallback
	if !containsDistro(families, DistroGeneric) {
		families = append(families, DistroGeneric)
	}

	return families
}

// resolveDistro maps a raw os-release ID or ID_LIKE token to a known Distro family constant.
func resolveDistro(id string) Distro {
	switch strings.ToLower(id) {
	case "debian", "ubuntu", "linuxmint", "pop", "kali", "parrot",
		"elementary", "raspbian", "zorin":
		return DistroDebian
	case "rhel", "centos", "rocky", "almalinux", "ol", "amzn":
		return DistroRHEL
	case "fedora":
		return DistroFedora
	case "arch", "manjaro", "endeavouros", "garuda", "artix":
		return DistroArch
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles":
		return DistroSUSE
	case "alpine":
		return DistroAlpine
	case "freebsd":
		return DistroFreeBSD
	case "openbsd":
		return DistroOpenBSD
	case "netbsd":
		return DistroNetBSD
	default:
		return DistroUnknown
	}
}

// containsDistro reports whether d is present in families.
func containsDistro(families []Distro, d Distro) bool {
	for _, f := range families {
		if f == d {
			return true
		}
	}
	return false
}
