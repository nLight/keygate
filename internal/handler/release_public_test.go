package handler

import (
	"testing"
	"time"

	"github.com/tabloy/keygate/internal/model"
)

func TestBuildLatestRelease(t *testing.T) {
	published := time.Date(2026, 9, 15, 7, 46, 8, 0, time.FixedZone("CEST", 2*60*60))
	rel := &model.Release{
		Version:      "1.11.947",
		Channel:      model.ReleaseChannelStable,
		Name:         "release",
		ReleaseNotes: "- Fixes",
		PublishedAt:  &published,
	}
	a := &model.ReleaseArtifact{
		Platform: "darwin-arm64",
		FileKey:  "releases/summit-ai-mac/1.11.947/darwin-arm64.dmg",
		FileSize: 25718427,
		SHA256:   "EC75977F",
	}

	got := buildLatestRelease("https://license.example.com/", "summit-ai-mac", "beta", rel, a)

	want := LatestRelease{
		Version:     "1.11.947",
		Channel:     "stable",
		Platform:    "darwin-arm64",
		Name:        "release",
		Notes:       "- Fixes",
		PublishedAt: "2026-09-15T05:46:08Z",
		Filename:    "release-1.11.947-darwin-arm64.dmg",
		Size:        25718427,
		SHA256:      "ec75977f",
		DownloadURL: "https://license.example.com/api/v1/releases/summit-ai-mac/latest/download?channel=beta&platform=darwin-arm64",
	}
	if got != want {
		t.Errorf("buildLatestRelease() =\n%+v\nwant\n%+v", got, want)
	}
}
