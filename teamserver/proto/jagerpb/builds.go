package jagerpb

// PayloadFormat enum
type PayloadFormat int32

const (
	PayloadFormat_FORMAT_EXE       PayloadFormat = 0
	PayloadFormat_FORMAT_DLL       PayloadFormat = 1
	PayloadFormat_FORMAT_SHELLCODE PayloadFormat = 2
)

func (f PayloadFormat) String() string {
	switch f {
	case PayloadFormat_FORMAT_EXE:
		return "EXE"
	case PayloadFormat_FORMAT_DLL:
		return "DLL"
	case PayloadFormat_FORMAT_SHELLCODE:
		return "SHELLCODE"
	default:
		return "UNKNOWN"
	}
}

// ImplantConfig holds build configuration for an implant
type ImplantConfig struct {
	Format     PayloadFormat `json:"format"`
	Arch       string        `json:"arch,omitempty"`
	Os         string        `json:"os,omitempty"`
	C2Url      string        `json:"c2_url"`
	Sleep      uint32        `json:"sleep"`
	Jitter     uint32        `json:"jitter"`
	IocProfile string        `json:"ioc_profile,omitempty"`
}

func (c *ImplantConfig) GetFormat() PayloadFormat {
	if c == nil {
		return PayloadFormat_FORMAT_EXE
	}
	return c.Format
}

func (c *ImplantConfig) GetIocProfile() string {
	if c == nil {
		return ""
	}
	return c.IocProfile
}

// StagerConfig holds build configuration for a stager
type StagerConfig struct {
	StageUrl   string `json:"stage_url"`
	IocProfile string `json:"ioc_profile,omitempty"`
}

func (c *StagerConfig) GetIocProfile() string {
	if c == nil {
		return ""
	}
	return c.IocProfile
}

// Request/Response types for build operations
type GenerateImplantRequest struct {
	Config   *ImplantConfig `json:"config"`
	SavePath string         `json:"save_path,omitempty"`
}

type GenerateStagerRequest struct {
	Config   *StagerConfig `json:"config"`
	SavePath string        `json:"save_path,omitempty"`
}

type GenerateResponse struct {
	BuildId  string  `json:"build_id"`
	SavePath string  `json:"save_path"`
	Status   *Status `json:"status,omitempty"`
}

type ListBuildsRequest struct{}

type BuildsResponse struct {
	Builds []string `json:"builds,omitempty"`
}

type DownloadBuildRequest struct {
	BuildId string `json:"build_id"`
}

type BuildDataResponse struct {
	Data   []byte  `json:"data,omitempty"`
	Status *Status `json:"status,omitempty"`
}
