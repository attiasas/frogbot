package autopr

import (
	"os"
	"path/filepath"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeComponent(purl string, locations ...string) cyclonedx.Component {
	c := cyclonedx.Component{Type: cyclonedx.ComponentTypeLibrary, PackageURL: purl, BOMRef: purl}
	if len(locations) > 0 {
		occurrences := make([]cyclonedx.EvidenceOccurrence, len(locations))
		for i, loc := range locations {
			occurrences[i] = cyclonedx.EvidenceOccurrence{Location: loc}
		}
		c.Evidence = &cyclonedx.Evidence{Occurrences: &occurrences}
	}
	return c
}

// bomWithDirect wraps components under a root application component and marks the named refs as its direct deps.
func bomWithDirect(directRefs []string, components []cyclonedx.Component) *cyclonedx.BOM {
	const rootRef = "root"
	deps := []cyclonedx.Dependency{{Ref: rootRef, Dependencies: &directRefs}}
	return &cyclonedx.BOM{
		Metadata:     &cyclonedx.Metadata{Component: &cyclonedx.Component{Type: cyclonedx.ComponentTypeApplication, BOMRef: rootRef}},
		Components:   &components,
		Dependencies: &deps,
	}
}

func TestExtractComponentMatch(t *testing.T) {
	tests := []struct {
		name            string
		sbom            *cyclonedx.BOM
		componentName   string
		affectedVersion string
		expectedPaths   []string
		expectedPurl    string
		expectedDirect  bool
		expectError     bool
	}{
		{
			name: "maven match",
			sbom: bomWithDirect([]string{"pkg:maven/com.example/lib@1.0.0"}, []cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
				makeComponent("pkg:maven/com.example/other@2.0.0", "other/pom.xml"),
			}),
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedPurl:    "maven",
			expectedDirect:  true,
		},
		{
			name: "npm match",
			sbom: bomWithDirect([]string{"pkg:npm/lodash@4.17.20"}, []cyclonedx.Component{
				makeComponent("pkg:npm/lodash@4.17.20", "package.json"),
			}),
			componentName:   "lodash",
			affectedVersion: "4.17.20",
			expectedPaths:   []string{"package.json"},
			expectedPurl:    "npm",
			expectedDirect:  true,
		},
		{
			name: "npm names are matched exactly",
			sbom: bomWithDirect([]string{"pkg:npm/foo_bar@1.0.0", "pkg:npm/foo-bar@1.0.0"}, []cyclonedx.Component{
				makeComponent("pkg:npm/foo_bar@1.0.0", "underscore/package.json"),
				makeComponent("pkg:npm/foo-bar@1.0.0", "hyphen/package.json"),
			}),
			componentName:   "foo_bar",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"underscore/package.json"},
			expectedPurl:    "npm",
			expectedDirect:  true,
		},
		{
			name: "golang match",
			sbom: bomWithDirect([]string{"pkg:golang/github.com/foo/bar@v1.2.3"}, []cyclonedx.Component{
				makeComponent("pkg:golang/github.com/foo/bar@v1.2.3", "go.mod"),
			}),
			componentName:   "github.com/foo/bar",
			affectedVersion: "v1.2.3",
			expectedPaths:   []string{"go.mod"},
			expectedPurl:    "golang",
			expectedDirect:  true,
		},
		{
			name: "transitive component",
			sbom: func() *cyclonedx.BOM {
				dummyRoot := techutils.ToPackageRef("root", "", "")
				applicationRef := "pkg:generic/application"
				parentRef := "pkg:maven/com.example/parent@1.0.0"
				targetRef := "pkg:maven/com.example/lib@1.0.0"
				rootDependencies := []string{applicationRef}
				applicationDependencies := []string{parentRef}
				parentDependencies := []string{targetRef}
				emptyDependencies := []string{}
				components := []cyclonedx.Component{
					makeComponent(applicationRef),
					makeComponent(parentRef),
					makeComponent(targetRef, "pom.xml"),
				}
				dependencies := []cyclonedx.Dependency{
					{Ref: dummyRoot, Dependencies: &rootDependencies},
					{Ref: applicationRef, Dependencies: &applicationDependencies},
					{Ref: parentRef, Dependencies: &parentDependencies},
					{Ref: targetRef, Dependencies: &emptyDependencies},
				}
				return &cyclonedx.BOM{
					Metadata:     &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: dummyRoot}},
					Components:   &components,
					Dependencies: &dependencies,
				}
			}(),
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedPurl:    "maven",
			expectedDirect:  false,
		},
		{
			name: "direct component below Xray-Lib dummy root",
			sbom: func() *cyclonedx.BOM {
				dummyRoot := techutils.ToPackageRef("root", "", "")
				applicationRef := "pkg:generic/application"
				targetRef := "pkg:maven/com.example/lib@1.0.0"
				applicationDependencies := []string{targetRef}
				rootDependencies := []string{applicationRef}
				emptyDependencies := []string{}
				components := []cyclonedx.Component{
					makeComponent(applicationRef),
					makeComponent(targetRef, "pom.xml"),
				}
				dependencies := []cyclonedx.Dependency{
					{Ref: dummyRoot, Dependencies: &rootDependencies},
					{Ref: applicationRef, Dependencies: &applicationDependencies},
					{Ref: targetRef, Dependencies: &emptyDependencies},
				}
				return &cyclonedx.BOM{
					Metadata:     &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: dummyRoot}},
					Components:   &components,
					Dependencies: &dependencies,
				}
			}(),
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedPurl:    "maven",
			expectedDirect:  true,
		},
		{
			name: "mixed direct and transitive occurrences include only direct evidence",
			sbom: func() *cyclonedx.BOM {
				directRef := "target-direct"
				transitiveRef := "target-transitive"
				parentRef := "parent"
				rootDependencies := []string{directRef, parentRef}
				parentDependencies := []string{transitiveRef}
				direct := makeComponent("pkg:npm/example@1.0.0", "direct/package.json")
				direct.BOMRef = directRef
				direct.Properties = &[]cyclonedx.Property{{
					Name: cdxutils.JfrogRelationProperty, Value: string(cdxutils.DirectRelation),
				}}
				transitive := makeComponent("pkg:npm/example@1.0.0", "transitive/package.json")
				transitive.BOMRef = transitiveRef
				transitive.Properties = &[]cyclonedx.Property{{
					Name: cdxutils.JfrogRelationProperty, Value: string(cdxutils.TransitiveRelation),
				}}
				components := []cyclonedx.Component{
					direct,
					transitive,
					{Type: cyclonedx.ComponentTypeLibrary, BOMRef: parentRef},
				}
				dependencies := []cyclonedx.Dependency{
					{Ref: "root", Dependencies: &rootDependencies},
					{Ref: parentRef, Dependencies: &parentDependencies},
				}
				return &cyclonedx.BOM{
					Metadata:     &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: "root"}},
					Components:   &components,
					Dependencies: &dependencies,
				}
			}(),
			componentName:   "example",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"direct/package.json"},
			expectedPurl:    "npm",
			expectedDirect:  true,
		},
		{
			name: "component not found",
			sbom: bomWithDirect([]string{}, []cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
			}),
			componentName:   "com.example/other",
			affectedVersion: "1.0.0",
		},
		{
			name: "wrong version",
			sbom: bomWithDirect([]string{}, []cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
			}),
			componentName:   "com.example/lib",
			affectedVersion: "2.0.0",
		},
		{
			name:          "nil SBOM returns error",
			sbom:          nil,
			componentName: "lib",
			expectError:   true,
		},
		{
			name: "duplicate locations deduplicated",
			sbom: bomWithDirect([]string{"pkg:maven/com.example/lib@1.0.0"}, []cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml", "pom.xml"),
			}),
			componentName:   "com.example/lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedPurl:    "maven",
			expectedDirect:  true,
		},
		{
			name: "maven colon vs slash",
			sbom: bomWithDirect([]string{"pkg:maven/com.example/lib@1.0.0"}, []cyclonedx.Component{
				makeComponent("pkg:maven/com.example/lib@1.0.0", "pom.xml"),
			}),
			componentName:   "com.example:lib",
			affectedVersion: "1.0.0",
			expectedPaths:   []string{"pom.xml"},
			expectedPurl:    "maven",
			expectedDirect:  true,
		},
		{
			name: "pip name normalization",
			sbom: bomWithDirect([]string{"pkg:pypi/Py_JWT@2.0.0"}, []cyclonedx.Component{
				makeComponent("pkg:pypi/Py_JWT@2.0.0", "requirements.txt"),
			}),
			componentName:   "py.jwt",
			affectedVersion: "2.0.0",
			expectedPaths:   []string{"requirements.txt"},
			expectedPurl:    "pypi",
			expectedDirect:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, err := extractComponentMatch(tc.sbom, tc.componentName, tc.affectedVersion)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedPaths, match.descriptorPaths)
			assert.Equal(t, tc.expectedPurl, match.purlType)
			assert.Equal(t, tc.expectedDirect, match.isDirectFromRoot)
		})
	}
}

func TestResolveTechnology(t *testing.T) {
	tests := []struct {
		name         string
		purlType     string
		lockfiles    []string
		expectedTech techutils.Technology
	}{
		{name: "golang", purlType: "golang", expectedTech: techutils.Go},
		{name: "maven", purlType: "maven", expectedTech: techutils.Maven},
		{name: "npm plain", purlType: "npm", expectedTech: techutils.Npm},
		{name: "npm with pnpm-lock", purlType: "npm", lockfiles: []string{"pnpm-lock.yaml"}, expectedTech: techutils.Pnpm},
		{name: "npm with pnpm-workspace", purlType: "npm", lockfiles: []string{"pnpm-workspace.yaml"}, expectedTech: techutils.Pnpm},
		{name: "pypi", purlType: "pypi", expectedTech: techutils.Pip},
		{name: "conan", purlType: "conan", expectedTech: techutils.Conan},
		{name: "gibberish", purlType: "unknown-thing", expectedTech: techutils.NoTech},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.lockfiles {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(""), 0o600))
			}
			assert.Equal(t, tc.expectedTech, resolveTechnology(tc.purlType, dir, nil))
		})
	}
}

func TestResolveTechnology_PnpmDetectedFromDescriptor(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "packages", "app")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "pnpm-lock.yaml"), []byte(""), 0o600))

	tech := resolveTechnology("npm", root, []string{"packages/app/package.json"})
	assert.Equal(t, techutils.Pnpm, tech)
}

func TestComponentNamesMatch(t *testing.T) {
	assert.True(t, componentNamesMatch("com.example:lib", "com.example/lib", "maven"))
	assert.True(t, componentNamesMatch("Py_JWT", "py.jwt", "pypi"))
	assert.True(t, componentNamesMatch("foo__bar", "foo-bar", "pypi"))
	assert.False(t, componentNamesMatch("foo_bar", "foo-bar", "npm"))
	assert.False(t, componentNamesMatch("lodash", "underscore", "npm"))
}
