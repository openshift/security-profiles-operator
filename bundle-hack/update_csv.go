package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <manifest_directory> <version>\n", os.Args[0])
		os.Exit(1)
	}

	manifestDirectory := os.Args[1]
	version := os.Args[2]

	buildManifestFilePath, err := getManifestFilePathFromDirectory(manifestDirectory)
	if err != nil {
		fmt.Printf("Failed to find manifest in %s: %v\n", manifestDirectory, err)
		os.Exit(1)
	}

	fmt.Printf("Success to find manifest in %s\n", buildManifestFilePath)

	// Read and parse the YAML
	data, err := ioutil.ReadFile(buildManifestFilePath)
	if err != nil {
		fmt.Printf("Failed to read file %s: %v\n", buildManifestFilePath, err)
		os.Exit(1)
	}

	var manifest map[string]interface{}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		fmt.Printf("Failed to parse YAML %s: %v\n", buildManifestFilePath, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully loaded %s from build.\n", buildManifestFilePath)

	// Execute the updates
	if err := addRequiredAnnotations(manifest); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := addRequiredLabels(manifest); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := replaceVersion(manifest, version); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := replaceIcon(manifest); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := replaceImages(manifest); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := removeContainerImageAnnotations(manifest); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := updateManifestWithRedHatDetails(manifest); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Finally, write the updated manifest
	if err := writeManifest(manifest, manifestDirectory, version); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Successfully updated CSV manifest for %s.\n", version)
}

// getManifestFilePathFromDirectory scans the directory and returns the first file
// ending with "clusterserviceversion.yaml".
func getManifestFilePathFromDirectory(dir string) (string, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), "clusterserviceversion.yaml") {
			return filepath.Join(dir, f.Name()), nil
		}
	}
	return "", errors.New("clusterserviceversion.yaml not found")
}

// addRequiredAnnotations adds required annotations to the CSV file content represented as a map.
func addRequiredAnnotations(m map[string]interface{}) error {
	requiredAnnotations := map[string]string{
		"features.operators.openshift.io/disconnected":     "true",
		"features.operators.openshift.io/fips-compliant":   "true",
		"features.operators.openshift.io/proxy-aware":      "false",
		"features.operators.openshift.io/tls-profiles":     "false",
		"features.operators.openshift.io/token-auth-aws":   "false",
		"features.operators.openshift.io/token-auth-azure": "false",
		"features.operators.openshift.io/token-auth-gcp":   "false",
		"operatorframework.io/suggested-namespace":         "openshift-security-profiles",
	}

	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return errors.New("error: 'metadata' does not exist in the CSV content")
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return errors.New("error: 'annotations' does not exist within 'metadata' in the CSV content")
	}

	for k, v := range requiredAnnotations {
		annotations[k] = v
	}

	fmt.Println("Successfully added required annotations.")
	return nil
}

// addRequiredLabels adds required labels under metadata.labels
func addRequiredLabels(m map[string]interface{}) error {
	requiredLabels := map[string]string{
		"operatorframework.io/arch.amd64":   "supported",
		"operatorframework.io/arch.ppc64le": "supported",
	}

	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return errors.New("error: 'metadata' does not exist in the CSV content")
	}

	labels, found := metadata["labels"].(map[string]interface{})
	if !found {
		labels = make(map[string]interface{})
		metadata["labels"] = labels
	}

	for k, v := range requiredLabels {
		labels[k] = v
	}

	fmt.Println("Successfully added required labels.")
	return nil
}

// recoverFromReplaceImages recovers from any panic in replaceImages.
func recoverFromReplaceImages() {
	if r := recover(); r != nil {
		fmt.Printf("Recovered from panic: %v\n", r)
	}
}

// splitPullSpec extracts the SHA from a Konflux pull spec (e.g.
// "quay.io/...@sha256:...") and returns only the "@sha256:..." suffix.
func splitPullSpec(konfluxPullSpec string) (string, error) {
	const delimiter = "@"
	parts := strings.Split(konfluxPullSpec, delimiter)
	if len(parts) != 2 {
		return "", fmt.Errorf("cannot extract SHA from %s", konfluxPullSpec)
	}
	return delimiter + parts[1], nil
}

// imgDef defines an image definition with environment name, source and target
type imgDef struct {
	EnvName    string
	KonfluxPS  string
	RedHatBase string
	FinalPS    string
}

// replaceImages updates the main container image and all RELATED_IMAGE_*
// env-vars by peeling off the SHA from each Konflux pull spec and
// re-anchoring it to the Red Hat registry.
//
// RBAC proxy is a special case: it uses a static "latest" tag.
func replaceImages(m map[string]interface{}) error {
	defer recoverFromReplaceImages()

	// 1) Define your raw Konflux pull specs (with sha) and the
	//    corresponding Red Hat registry base names.
	defs := []imgDef{
		{
			EnvName:    "RELATED_IMAGE_OPERATOR",
			KonfluxPS:  "quay.io/redhat-user-workloads/ocp-isc-tenant/security-profiles-operator-release@sha256:08c56e9eaa7b5fd66ea9c9a4e1667f8ff3726d7aa3c3b853a2da5d37f948780b",
			RedHatBase: "registry.redhat.io/compliance/openshift-security-profiles-rhel8-operator",
		},
		{
			EnvName:    "RELATED_IMAGE_SELINUXD",
			KonfluxPS:  "quay.io/redhat-user-workloads/ocp-isc-tenant/openshift-selinuxd-rhel8-container-release@sha256:9556b7d523895b1f351f6745a5a62826a9b1f0d0935c46d34f6cc1ddeeb8b252",
			RedHatBase: "registry.redhat.io/compliance/openshift-selinuxd-rhel8",
		},
		{
			EnvName:    "RELATED_IMAGE_SELINUXD_EL9",
			KonfluxPS:  "quay.io/redhat-user-workloads/ocp-isc-tenant/openshift-selinuxd-rhel9-container-release@sha256:48f1e21bab08dab1f1f7b9ad15dd5faba8f2468d45f7df1b61e7338041ad8385",
			RedHatBase: "registry.redhat.io/compliance/openshift-selinuxd-rhel9",
		},
		{
			EnvName:    "RELATED_IMAGE_SELINUXD_FEDORA",
			KonfluxPS:  "quay.io/redhat-user-workloads/ocp-isc-tenant/openshift-selinuxd-rhel9-container-release@sha256:48f1e21bab08dab1f1f7b9ad15dd5faba8f2468d45f7df1b61e7338041ad8385",
			RedHatBase: "registry.redhat.io/compliance/openshift-selinuxd-rhel9",
		},
		{
			EnvName:    "RELATED_IMAGE_SELINUXD_EL8",
			KonfluxPS:  "quay.io/redhat-user-workloads/ocp-isc-tenant/openshift-selinuxd-rhel8-container-release@sha256:9556b7d523895b1f351f6745a5a62826a9b1f0d0935c46d34f6cc1ddeeb8b252",
			RedHatBase: "registry.redhat.io/compliance/openshift-selinuxd-rhel8",
		},
	}

	// 2) Peel the SHA from each KonfluxPS and build FinalPS
	for i := range defs {
		if defs[i].KonfluxPS != "" {
			sha, err := splitPullSpec(defs[i].KonfluxPS)
			if err != nil {
				return err
			}
			defs[i].FinalPS = defs[i].RedHatBase + sha
		}
	}

	// 3) Drill into m to grab the first container’s env slice and its map
	spec, ok := m["spec"].(map[string]interface{})
	if !ok {
		return errors.New("manifest missing 'spec'")
	}
	install, ok := spec["install"].(map[string]interface{})
	if !ok {
		return errors.New("'spec.install' missing or not a map")
	}
	installSpec, ok := install["spec"].(map[string]interface{})
	if !ok {
		return errors.New("'spec.install.spec' missing")
	}
	deps, ok := installSpec["deployments"].([]interface{})
	if !ok || len(deps) == 0 {
		return errors.New("no deployments at 'spec.install.spec.deployments'")
	}
	dep0, ok := deps[0].(map[string]interface{})
	if !ok {
		return errors.New("first deployment is not a map")
	}
	tpl, ok := dep0["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
	if !ok {
		return errors.New("cannot find template.spec")
	}
	containers, ok := tpl["containers"].([]interface{})
	if !ok || len(containers) == 0 {
		return errors.New("no containers in template.spec.containers")
	}
	ctr, ok := containers[0].(map[string]interface{})
	if !ok {
		return errors.New("container[0] not a map")
	}

	// 4) Update the container's image to the operator's FinalPS
	ctr["image"] = defs[0].FinalPS

	// 5) Update each RELATED_IMAGE_* env var
	envSlice, ok := ctr["env"].([]interface{})
	if !ok {
		return errors.New("container env missing or not a list")
	}
	for _, raw := range envSlice {
		envVar, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := envVar["name"].(string)
		for _, def := range defs {
			if name == def.EnvName {
				envVar["value"] = def.FinalPS
				break
			}
		}
	}

	// 6) Update relatedImages section if it exists
	if err := updateRelatedImages(m, defs); err != nil {
		return err
	}

	fmt.Println("Successfully replaced all images and env vars.")
	return nil
}

// updateRelatedImages updates the relatedImages section with the new image references
func updateRelatedImages(m map[string]interface{}, defs []imgDef) error {
	spec, ok := m["spec"].(map[string]interface{})
	if !ok {
		return errors.New("manifest missing 'spec'")
	}

	// Check if relatedImages exists
	relatedImagesRaw, exists := spec["relatedImages"]
	if !exists {
		fmt.Println("No relatedImages section found, skipping update.")
		return nil
	}

	relatedImages, ok := relatedImagesRaw.([]interface{})
	if !ok {
		return errors.New("relatedImages is not an array")
	}

	// Create a mapping from image names to final images for quick lookup
	imageMap := make(map[string]string)

	// Map environment variable names to relatedImages names
	envToRelatedName := map[string]string{
		"RELATED_IMAGE_OPERATOR":        "security-profiles-operator",
		"RELATED_IMAGE_SELINUXD":        "selinuxd",
		"RELATED_IMAGE_SELINUXD_EL8":    "selinuxd-el8",
		"RELATED_IMAGE_SELINUXD_EL9":    "selinuxd-el9",
		"RELATED_IMAGE_SELINUXD_FEDORA": "selinuxd-fedora",
	}

	// Build the image map
	for _, def := range defs {
		if relatedName, exists := envToRelatedName[def.EnvName]; exists {
			imageMap[relatedName] = def.FinalPS
		}
	}

	// Update the relatedImages entries
	updated := 0
	for _, relatedImageRaw := range relatedImages {
		relatedImage, ok := relatedImageRaw.(map[string]interface{})
		if !ok {
			continue
		}

		name, ok := relatedImage["name"].(string)
		if !ok {
			continue
		}

		if newImage, exists := imageMap[name]; exists {
			relatedImage["image"] = newImage
			updated++
			fmt.Printf("Updated relatedImage '%s' to '%s'\n", name, newImage)
		}
	}

	fmt.Printf("Successfully updated %d relatedImages entries.\n", updated)
	return nil
}

// updateManifestWithRedHatDetails updates links, maintainers, and provider with Red Hat details.
func updateManifestWithRedHatDetails(m map[string]interface{}) error {
	spec, ok := m["spec"].(map[string]interface{})
	if !ok {
		return errors.New("manifest has no 'spec' field")
	}

	spec["links"] = []interface{}{
		map[string]interface{}{
			"name": "Security Profiles Operator",
			"url":  "https://github.com/openshift/security-profiles-operator",
		},
	}
	fmt.Println("Successfully replaced the links in manifest.")

	spec["maintainers"] = []interface{}{
		map[string]interface{}{
			"email": "support@redhat.com",
			"name":  "Red Hat support",
		},
	}
	fmt.Println("Successfully replaced the maintainers in manifest.")

	spec["provider"] = map[string]interface{}{
		"name": "Red Hat",
		"url":  "https://www.redhat.com",
	}
	fmt.Println("Successfully updated the provider in manifest.")
	return nil
}

// replaceVersion updates references to the new version inside the manifest.
func replaceVersion(m map[string]interface{}, newVersion string) error {
	spec, ok := m["spec"].(map[string]interface{})
	if !ok {
		return errors.New("manifest has no 'spec' field")
	}

	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return errors.New("manifest has no 'metadata' field")
	}

	oldVersion, ok := spec["version"].(string)
	if !ok {
		return errors.New("could not find spec.version in the manifest")
	}

	fmt.Printf("Updating version references from %s to %s in manifest.\n", oldVersion, newVersion)

	// metadata.name
	if name, ok := metadata["name"].(string); ok {
		metadata["name"] = strings.ReplaceAll(name, oldVersion, newVersion)
	}

	// metadata.annotations.olm.skipRange
	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return errors.New("metadata.annotations not found in the manifest")
	}
	if skipRange, ok := annotations["olm.skipRange"].(string); ok {
		annotations["olm.skipRange"] = strings.ReplaceAll(skipRange, oldVersion, newVersion)
	}

	// spec.replaces
	spec["replaces"] = "security-profiles-operator.v" + oldVersion

	// spec.version
	spec["version"] = newVersion

	fmt.Printf("Successfully updated the operator version references from %s to %s in manifest.\n", oldVersion, newVersion)
	return nil
}

// replaceIcon replaces the icon data with the Red Hat image icon in base64 form.
func replaceIcon(m map[string]interface{}) error {
	iconPath := "icons/icon.png"

	f, err := os.Open(iconPath)
	if err != nil {
		return fmt.Errorf("failed to open icon at %s: %v", iconPath, err)
	}
	defer f.Close()

	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read icon at %s: %v", iconPath, err)
	}

	base64Icon := base64.StdEncoding.EncodeToString(contents)

	spec, ok := m["spec"].(map[string]interface{})
	if !ok {
		return errors.New("manifest has no 'spec' field")
	}

	spec["icon"] = []interface{}{
		map[string]interface{}{
			"base64data": base64Icon,
			"mediatype":  "image/png",
		},
	}
	fmt.Printf("Successfully updated the operator image to use icon in %s.\n", iconPath)
	return nil
}

// removeContainerImageAnnotations removes the containerImage annotation from metadata.annotations if present.
func removeContainerImageAnnotations(m map[string]interface{}) error {
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return nil // no metadata, do nothing
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		return nil // no annotations, do nothing
	}

	if _, found := annotations["containerImage"]; found {
		delete(annotations, "containerImage")
		fmt.Println("Removed container image annotations from operator manifest.")
	}

	return nil
}

// writeManifest renames the old CSV file and writes the updated manifest to the new filename.
func writeManifest(m map[string]interface{}, manifestDirectory, version string) error {
	oldCSVFilename, err := getManifestFilePathFromDirectory(manifestDirectory)
	if err != nil {
		return fmt.Errorf("failed to find manifest in %s: %v", manifestDirectory, err)
	}

	newCSVFilename := filepath.Join(manifestDirectory,
		fmt.Sprintf("security-profiles-operator.v%s.clusterserviceversion.yaml", version))

	if err := os.Rename(oldCSVFilename, newCSVFilename); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %v", oldCSVFilename, newCSVFilename, err)
	}
	fmt.Printf("Successfully moved %s to %s.\n", oldCSVFilename, newCSVFilename)

	out, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}

	if err := os.WriteFile(newCSVFilename, out, 0644); err != nil {
		return fmt.Errorf("failed to write updated manifest %s: %v", newCSVFilename, err)
	}
	fmt.Printf("Successfully wrote updated manifest to %s.\n", newCSVFilename)

	return nil
}
