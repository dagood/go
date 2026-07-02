// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// The User Guide is assembled from static prose (embedded below) and a
// generated table of contents. The package section headers are generated from
// the shared cryptoPackages registry so that the User Guide and
// CrossPlatformCryptography.md stay in sync.

//go:embed userguide_preamble.md
var userGuidePreamble string

//go:embed userguide_using.md
var userGuideUsing string

//go:embed userguide_bodies.md
var userGuideBodies string

// packageBodyMarker matches the delimiter that separates package bodies in
// userguide_bodies.md, e.g. "<!-- PACKAGE crypto/aes -->".
var packageBodyMarker = regexp.MustCompile(`^<!-- PACKAGE (\S+) -->$`)

// headingRE matches a Markdown ATX heading (levels 1-4).
var headingRE = regexp.MustCompile(`^(#{1,4}) (.*)$`)

// linkRE matches an inline Markdown link, e.g. "[text](url)".
var linkRE = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)

func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// parsePackageBodies splits userguide_bodies.md into a map of import path to
// body text.
func parsePackageBodies(bodies string) (map[string]string, error) {
	result := make(map[string]string)
	var current string
	var buf []string
	flush := func() {
		if current != "" {
			result[current] = strings.Trim(strings.Join(buf, "\n"), "\n")
		}
	}
	for _, line := range strings.Split(normalizeNewlines(bodies), "\n") {
		if m := packageBodyMarker.FindStringSubmatch(line); m != nil {
			flush()
			current = m[1]
			buf = buf[:0]
			continue
		}
		if current == "" {
			if strings.TrimSpace(line) == "" {
				continue
			}
			return nil, fmt.Errorf("content before first package marker: %q", line)
		}
		buf = append(buf, line)
	}
	flush()
	return result, nil
}

// tableOfContents generates a Markdown nested list linking to every heading in
// the document, replicating the GitHub anchor slugging (including duplicate
// suffixes) so it matches the anchors used by the rendered page.
func tableOfContents(document string) string {
	seen := make(map[string]int)
	var lines []string
	inFence := false
	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		m := headingRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		level := len(m[1])
		text := strings.TrimSpace(stripLinks(m[2]))
		anchor := slug(text)
		if n, ok := seen[anchor]; ok {
			seen[anchor] = n + 1
			anchor = fmt.Sprintf("%s-%d", anchor, n+1)
		} else {
			seen[anchor] = 0
		}
		indent := strings.Repeat("  ", level-1)
		lines = append(lines, fmt.Sprintf("%s- [%s](#%s)", indent, displayText(text), anchor))
	}
	return strings.Join(lines, "\n")
}

// stripLinks replaces Markdown links with their link text.
func stripLinks(s string) string {
	return linkRE.ReplaceAllString(s, "$1")
}

// displayText escapes characters that Markdown would otherwise interpret when
// the text is used as link text in the table of contents.
func displayText(s string) string {
	return strings.ReplaceAll(s, "_", "\\_")
}

// slug converts heading text into a GitHub-style anchor slug.
func slug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// generateUserGuide assembles the FIPS User Guide document.
func generateUserGuide() (string, error) {
	bodies, err := parsePackageBodies(userGuideBodies)
	if err != nil {
		return "", fmt.Errorf("failed to parse package bodies: %v", err)
	}

	pkgs := userGuidePackages()

	// Validate that the registry and the embedded bodies agree.
	for _, p := range pkgs {
		if _, ok := bodies[p.ImportPath]; !ok {
			return "", fmt.Errorf("package %q is marked InUserGuide but has no body in userguide_bodies.md", p.ImportPath)
		}
	}
	for importPath := range bodies {
		pkg, ok := packagesByImportPath[importPath]
		if !ok {
			return "", fmt.Errorf("package %q has a User Guide body but is not registered in cryptoPackages", importPath)
		}
		if !pkg.InUserGuide {
			return "", fmt.Errorf("package %q has a User Guide body but is not marked InUserGuide", importPath)
		}
	}

	preamble := strings.TrimRight(normalizeNewlines(userGuidePreamble), "\n")
	using := strings.TrimRight(normalizeNewlines(userGuideUsing), "\n")

	// Assemble the package sections. The header is generated from the shared
	// registry; the body comes from the embedded content.
	var sections []string
	for _, p := range pkgs {
		header := fmt.Sprintf("### [%s](%s)", p.ImportPath, packageLink(p.ImportPath))
		sections = append(sections, header+"\n\n"+bodies[p.ImportPath])
	}

	// Build the document once without the table of contents so we can scan its
	// headings, then insert the generated table of contents.
	blocks := append([]string{preamble, using}, sections...)
	body := strings.Join(blocks, "\n\n")
	toc := tableOfContents(body)

	var b strings.Builder
	fmt.Fprintln(&b, "<!-- This file is generated by eng/_util/cmd/updatecryptodocs. DO NOT EDIT. -->")
	fmt.Fprintln(&b)
	fmt.Fprint(&b, strings.Join(append([]string{preamble, toc, using}, sections...), "\n\n"))
	fmt.Fprintln(&b)
	return b.String(), nil
}
