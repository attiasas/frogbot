package outputwriter

import (
	"fmt"
	"strings"

	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
)

const (
	FrogbotTitlePrefix        = "[🐸 Frogbot]"
	CommentGeneratedByFrogbot = "[🐸 JFrog Frogbot](https://github.com/jfrog/frogbot#readme)"
	ReviewCommentId           = "FrogbotReviewComment"

	vulnerableDependenciesTitle                   = "📦 Vulnerable Dependencies"
	vulnerableDependenciesSummarySubTitle         = "✍️ Summary"
	vulnerableDependenciesResearchDetailsSubTitle = "🔬 Research Details"
	violatedLicenseTitle                          = "## ⚖️ Violated Licenses"

	jasFeaturesMsgWhenNotEnabled = "**Frogbot** also supports **Contextual Analysis, Secret Detection, IaC and SAST Vulnerabilities Scanning**. This features are included as part of the [JFrog Advanced Security](https://jfrog.com/xray/) package, which isn't enabled on your system."

	contextualAnalysisTitle = "📦🔍 Contextual Analysis CVE Vulnerability"
	iacTitle                = "🛠️ Infrastructure as Code Vulnerability"
	sastTitle               = "🎯 Static Application Security Testing (SAST) Vulnerability"
)

func GenerateReviewCommentContent(content string, writer OutputWriter) string {
	return MarkdownComment(ReviewCommentId) + content + Footer(writer)
}

func GetFallbackReviewCommentContent(content string, location formats.Location, writer OutputWriter) string {
	return MarkdownComment(ReviewCommentId) + GetLocationDescription(location) + content + Footer(writer)
}

func GetLocationDescription(location formats.Location) string {
	return fmt.Sprintf(`
%s
at %s (line %d)
`,
		MarkAsCodeSnippet(location.Snippet),
		MarkAsQuote(location.File),
		location.StartLine)
}

func NoVulnerabilitiesTitle(vcsProvider vcsutils.VcsProvider) ImageSource {
	if vcsProvider == vcsutils.GitLab {
		return NoVulnerabilityMrBannerSource
	}
	return NoVulnerabilityPrBannerSource
}

func UserPRVulnerabilitiesTitle(vcsProvider vcsutils.VcsProvider) ImageSource {
	if vcsProvider == vcsutils.GitLab {
		return VulnerabilitiesMrBannerSource
	}
	return VulnerabilitiesPrBannerSource
}

func FrogbotPRVulnerabilitiesTitle(vcsProvider vcsutils.VcsProvider) ImageSource {
	if vcsProvider == vcsutils.GitLab {
		return VulnerabilitiesFixMrBannerSource
	}
	return VulnerabilitiesFixPrBannerSource
}

func UntitledForJasMsg(writer OutputWriter) string {
	return fmt.Sprintf("\n%s%s", SectionDivider(), writer.MarkInCenter(jasFeaturesMsgWhenNotEnabled))
}

func Footer(writer OutputWriter) string {
	return fmt.Sprintf("%s%s", SectionDivider(), writer.MarkInCenter(CommentGeneratedByFrogbot))
}

func getVulnerabilitiesTable(showCaColumn bool, vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	columns := []string{"SEVERITY"}
	if showCaColumn {
		columns = append(columns, "CONTEXTUAL ANALYSIS")
	}
	columns = append(columns, "DIRECT DEPENDENCIES", "IMPACTED DEPENDENCY", "FIXED VERSIONS", "CVES")
	table := NewMarkdownTable(columns...)
	// Construct table rows data
	for _, vulnerability := range vulnerabilities {





		
		var directDependenciesBuilder strings.Builder
		for _, component := range vulnerability.Components {
			directDependenciesBuilder.WriteString(fmt.Sprintf("%s %s%s", component.Name, component.Version, writer.Separator()))
		}
		directDependencies := strings.TrimSuffix(directDependenciesBuilder.String(), writer.Separator())
		impactedDependency := fmt.Sprintf("%s %s", vulnerability.ImpactedDependencyName, vulnerability.ImpactedDependencyVersion)
		fixedVersions := strings.Join(vulnerability.FixedVersions, writer.Separator())
		cves := strings.Join(vulnerability.Cves, writer.Separator())
		row := []string{vulnerability.Severity}
		if showCaColumn {
			row = append(row, vulnerability.ContextualAnalysis)
		}
		row = append(row, directDependencies, impactedDependency, fixedVersions, cves)
		table.AddRow(row...)
	}
	return table.Build()
}

func VulnerabilitiesContent(vulnerabilities []formats.VulnerabilityOrViolationRow, showCaColumn bool, writer OutputWriter) string {
	if len(vulnerabilities) == 0 {
		return ""
	}
	var contentBuilder strings.Builder
	// Write summary table part
	contentBuilder.WriteString(fmt.Sprintf("\n%s\n%s\n%s\n",
		writer.MarkAsTitle(vulnerableDependenciesTitle, 2),
		writer.MarkAsTitle(vulnerableDependenciesSummarySubTitle, 3),
		writer.MarkInCenter(fmt.Sprintf(`%s %s`, getVulnerabilitiesTableHeader(showCaColumn), getVulnerabilitiesTableContent(vulnerabilities, writer)))),
	)
	// Write for each vulnerability details part
	detailsContent := getVulnerabilityDetailsContent(vulnerabilities, writer)
	if strings.TrimSpace(detailsContent) != "" {
		if len(vulnerabilities) == 1 {
			contentBuilder.WriteString(fmt.Sprintf("\n%s\n%s\n",
				writer.MarkAsTitle(vulnerableDependenciesResearchDetailsSubTitle, 3),
				detailsContent,
			))
		} else {
			contentBuilder.WriteString(fmt.Sprintf("%s\n",
				writer.MarkAsDetails(vulnerableDependenciesResearchDetailsSubTitle, 3, detailsContent),
			))
		}
	}
	return contentBuilder.String()
}

func getVulnerabilityDetailsContent(vulnerabilities []formats.VulnerabilityOrViolationRow, writer OutputWriter) string {
	var descriptionContentBuilder strings.Builder
	shouldOutputDescriptionSection := false
	for i := range vulnerabilities {
		vulDescriptionContent := createVulnerabilityDescription(&vulnerabilities[i])
		if strings.TrimSpace(vulDescriptionContent) == "" {
			// No content
			continue
		}
		shouldOutputDescriptionSection = true
		if len(vulnerabilities) == 1 {
			descriptionContentBuilder.WriteString(fmt.Sprintf("%s\n", vulDescriptionContent))
			break
		}
		descriptionContentBuilder.WriteString(fmt.Sprintf("%s\n",
			writer.MarkAsDetails(fmt.Sprintf(`%s%s %s`,
				getVulnerabilityDescriptionIdentifier(vulnerabilities[i].Cves, vulnerabilities[i].IssueId),
				vulnerabilities[i].ImpactedDependencyName,
				vulnerabilities[i].ImpactedDependencyVersion,
			), 4, vulDescriptionContent)),
		)
	}
	if !shouldOutputDescriptionSection {
		return ""
	}
	return descriptionContentBuilder.String()
}

func GetApplicabilityMarkdownDescription(severity, cve, impactedDependency, finding string) string {
	headerRow := "| Severity | Impacted Dependency | Finding | CVE |\n"
	separatorRow := "| :--------------: | :---: | :---: | :---: |\n"
	return headerRow + separatorRow + fmt.Sprintf("| %s | %s | %s | %s |", severity, impactedDependency, finding, cve)
}

// Replace 'GetApplicabilityMarkdownDescription' with this
func GetApplicabilityDescriptionTable(severity, cve, impactedDependency, finding string) string {
	return NewMarkdownTable("Severity", "Impacted Dependency", "Finding", "CVE").AddRow(severity, impactedDependency, finding, cve).Build()
}

func ApplicableCveReviewContent(severity, finding, fullDetails, cve, cveDetails, impactedDependency, remediation string, writer OutputWriter) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf("\n%s%s%s%s\n",
		writer.MarkAsTitle(contextualAnalysisTitle, 2),
		writer.MarkInCenter(GetApplicabilityMarkdownDescription(writer.FormattedSeverity(severity, "Applicable"), cve, impactedDependency, finding)),
		writer.MarkAsDetails("Description", 3, fullDetails),
		writer.MarkAsDetails("CVE details", 3, cveDetails)),
	)
	if len(remediation) > 0 {
		contentBuilder.WriteString(fmt.Sprintf("%s\n",
			writer.MarkAsDetails("Remediation", 3, remediation)),
		)
	}
	return contentBuilder.String()
}

func GetJasMarkdownDescription(severity, finding string) string {
	headerRow := "| Severity | Finding |\n"
	separatorRow := "| :--------------: | :---: |\n"
	return headerRow + separatorRow + fmt.Sprintf("| %s | %s |", severity, finding)
}

// Replace 'GetJasMarkdownDescription' with this
func getJasDescriptionTable(severity, finding string, writer OutputWriter) string {
	return NewMarkdownTable("Severity", "Finding").AddRow(writer.FormattedSeverity(severity, "Applicable"), finding).Build()
}

func IacReviewContent(severity, finding, fullDetails string, writer OutputWriter) string {
	return fmt.Sprintf("\n%s%s%s\n",
		writer.MarkAsTitle(iacTitle, 2),
		writer.MarkInCenter(GetJasMarkdownDescription(writer.FormattedSeverity(severity, "Applicable"), finding)),
		writer.MarkAsDetails("Full description", 3, fullDetails))
}

func SastReviewContent(severity, finding, fullDetails string, codeFlows [][]formats.Location, writer OutputWriter) string {
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf("\n%s%s%s\n",
		writer.MarkAsTitle(sastTitle, 2),
		writer.MarkInCenter(GetJasMarkdownDescription(writer.FormattedSeverity(severity, "Applicable"), finding)),
		writer.MarkAsDetails("Full description", 3, fullDetails),
	))

	if len(codeFlows) > 0 {
		contentBuilder.WriteString(fmt.Sprintf("%s\n",
			writer.MarkAsDetails("Code Flows", 3, sastCodeFlowsReviewContent(codeFlows, writer)),
		))
	}
	return contentBuilder.String()
}

func sastCodeFlowsReviewContent(codeFlows [][]formats.Location, writer OutputWriter) string {
	var contentBuilder strings.Builder
	for _, flow := range codeFlows {
		contentBuilder.WriteString(writer.MarkAsDetails("Vulnerable data flow analysis result", 4, sastDataFlowLocationsReviewContent(flow)))
	}
	return contentBuilder.String()
}

func sastDataFlowLocationsReviewContent(flow []formats.Location) string {
	var contentBuilder strings.Builder
	for _, location := range flow {
		contentBuilder.WriteString(fmt.Sprintf(`
%s %s (at %s line %d)
`,
			"↘️",
			MarkAsQuote(location.Snippet),
			location.File,
			location.StartLine,
		))
	}
	return contentBuilder.String()
}

func LicensesContent(licenses []formats.LicenseRow, writer OutputWriter) string {
	if len(licenses) == 0 {
		return ""
	}
	// Title
	var contentBuilder strings.Builder
	contentBuilder.WriteString(fmt.Sprintf("\n%s\n", writer.MarkAsTitle(violatedLicenseTitle, 2)))
	// Content
	table := NewMarkdownTable("LICENSE", "DIRECT DEPENDENCIES", "IMPACTED DEPENDENCY")
	for _, license := range licenses {
		var directDependenciesBuilder strings.Builder
		for _, component := range license.Components {
			directDependenciesBuilder.WriteString(fmt.Sprintf("%s %s%s", component.Name, component.Version, writer.Separator()))
		}
		directDependencies := strings.TrimSuffix(directDependenciesBuilder.String(), writer.Separator())
		impactedDependency := fmt.Sprintf("%s %s", license.ImpactedDependencyName, license.ImpactedDependencyVersion)

		table.AddRow(license.LicenseKey, directDependencies, impactedDependency)
	}
	contentBuilder.WriteString(writer.MarkInCenter(table.Build()))
	return contentBuilder.String()
}
