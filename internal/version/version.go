// Package version hält die eine Stelle, an der die Version dieses Projekts steht.
// Der Hygiene-Test erzwingt, dass CHANGELOG.md dieselbe Version nennt.
package version

// Version folgt SemVer (https://semver.org). Bei einem Release wandert sie
// zusammen mit dem CHANGELOG-Eintrag im selben Commit.
const Version = "0.1.0"
