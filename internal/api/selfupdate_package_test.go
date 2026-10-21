package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The name the backend asks for and the name the build publishes have to be
// the same string, and nothing makes them so at compile time.
//
// They were not, for the whole life of this fork: the backend asked for
// "vsay-agent-arm64.dmg" — a leftover from the product this was forked from —
// while `make deploy-binaries` has always published "wxt-agent-arm64.dmg".
// Every self-update fetched a 404 and reported "download failed", which looks
// exactly like a network problem, so it was read as one.
func TestEveryUpdatePackageIsOneTheBuildPublishes(t *testing.T) {
	makefile := readAgentMakefile(t)

	for _, c := range []struct{ osName, arch string }{
		{"windows", "amd64"},
		{"windows", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
	} {
		t.Run(c.osName+"/"+c.arch, func(t *testing.T) {
			pkg := selfUpdatePackage(c.osName, c.arch)
			if pkg == "" {
				t.Fatalf("no package for %s/%s, but the build publishes one", c.osName, c.arch)
			}
			if !strings.Contains(makefile, "agent-binaries/"+pkg) {
				t.Errorf("the backend would fetch %q, which deploy-binaries never writes — "+
					"the agent gets a 404 and reports it as a failed download", pkg)
			}
		})
	}
}

// A platform with no package must produce no URL. Returning a plausible one
// for a file that was never built is precisely how the original bug survived:
// the portal reported the update as dispatched, and only the endpoint knew.
func TestAPlatformWithNoPackageGetsNoURL(t *testing.T) {
	for _, osName := range []string{"debian", "rhel", "linux", "", "freebsd"} {
		if pkg := selfUpdatePackage(osName, "amd64"); pkg != "" {
			t.Errorf("%s offered the package %q, which this product does not build", osName, pkg)
		}
		if url := selfUpdateURL(osName, "amd64"); url != "" {
			t.Errorf("%s produced the URL %q, which would 404 on the endpoint", osName, url)
		}
	}
}

// An unrecognised architecture falls back to amd64 rather than building a name
// from it. "wxt-agent-i386.dmg" is a 404 with extra steps.
func TestAnUnknownArchitectureFallsBackRatherThanInventingAName(t *testing.T) {
	for _, arch := range []string{"i386", "", "riscv64", "armv7"} {
		pkg := selfUpdatePackage("darwin", arch)
		if !strings.Contains(pkg, "amd64") {
			t.Errorf("architecture %q produced %q, which the build does not publish", arch, pkg)
		}
	}
}

// Where the packages are present, check the real directory too — the Makefile
// says what it intends to write, this says what is actually there to serve.
func TestThePublishedPackagesAreOnDisk(t *testing.T) {
	dir := "../../agent-binaries"
	if _, err := os.Stat(dir); err != nil {
		t.Skip("agent-binaries is not populated in this checkout")
	}

	for _, c := range []struct{ osName, arch string }{
		{"windows", "amd64"}, {"windows", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"},
	} {
		pkg := selfUpdatePackage(c.osName, c.arch)
		if _, err := os.Stat(filepath.Join(dir, pkg)); err != nil {
			t.Errorf("%s/%s would fetch %q, which is not in agent-binaries: %v",
				c.osName, c.arch, pkg, err)
		}
	}
}

func readAgentMakefile(t *testing.T) string {
	t.Helper()
	path := filepath.Join("../../../wxt-agent", "Makefile")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Skipf("agent Makefile not available at %s — this contract is unverified here", path)
	}
	return string(data)
}
