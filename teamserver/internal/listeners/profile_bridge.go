package listeners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	pb "github.com/0xhackerfren/Jager-C2/teamserver/proto/jagerpb"
	"github.com/0xhackerfren/Jager-C2/teamserver/internal/malleable"
)

// malleableProfileFromPB converts proto profile metadata to a full malleable profile.
// When ProfileJsonPath env or workspace profile.json exists, load full wire transforms.
func malleableProfileFromPB(pbProf *pb.MalleableProfile) (*malleable.Profile, error) {
	if pbProf == nil {
		return nil, fmt.Errorf("nil profile")
	}

	if path := os.Getenv("JAGER_MALLEABLE_PROFILE"); path != "" {
		return malleable.LoadProfile(path)
	}

	candidates := []string{
		"data/builds/profile.json",
		"builds/profile.json",
	}
	ws := os.Getenv("HARNESS_WORKSPACE")
	if ws == "" {
		ws = os.Getenv("JAGER_WORKSPACE")
	}
	for _, rel := range candidates {
		if ws == "" {
			continue
		}
		full := filepath.Join(ws, rel)
		if _, err := os.Stat(full); err == nil {
			p, err := malleable.LoadProfile(full)
			if err != nil {
				return nil, err
			}
			if pbProf.UserAgent != "" {
				p.UserAgent = pbProf.UserAgent
			}
			if pbProf.Name != "" {
				p.Name = pbProf.Name
			}
			return p, nil
		}
	}

	// Minimal profile: metadata only, no wire transforms (plain JSON implant compat)
	p := &malleable.Profile{
		Name:      pbProf.Name,
		UserAgent: pbProf.UserAgent,
	}
	if p.Name == "" {
		p.Name = "inline"
	}
	return p, nil
}

// LoadMalleableProfileJSON loads profile from raw JSON bytes (REST SetProfile extension).
func LoadMalleableProfileJSON(data []byte) (*malleable.Profile, error) {
	var p malleable.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
