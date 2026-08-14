package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// runMihomoRoutingSync is the complete-config path. It deliberately enters
// generation publication directly: a Mihomo routing document describes one
// complete runtime graph, so publishing routes, nodes, groups, DATs, and
// provider snapshots separately would leave mixed generations observable.
func runMihomoRoutingSync(ctx context.Context, options SyncOptions) (SyncReport, error) {
	if options.GenerationDir == "" {
		return SyncReport{}, errors.New("-mihomo-routing-config requires -generation-dir")
	}
	if options.RoutesOutput != "" || options.GroupsOutput != "" || options.NodesOutput != "" {
		return SyncReport{}, errors.New("Mihomo routing generation cannot use direct routes, groups, or nodes output")
	}
	if options.GroupsInputPath != "" {
		return SyncReport{}, errors.New("-mihomo-routing-config cannot be combined with -mihomo-config")
	}

	routingBody, err := os.ReadFile(options.MihomoRoutingPath)
	if err != nil {
		return SyncReport{}, fmt.Errorf("read Mihomo routing config: %w", err)
	}
	document, err := ParseMihomoRoutingDocument(routingBody)
	if err != nil {
		return SyncReport{}, err
	}
	if len(document.ScriptRefs) != 0 {
		reference := document.ScriptRefs[0]
		return SyncReport{}, fmt.Errorf("Mihomo script at index %d line %d is active and unsupported", reference.SourceIndex, reference.SourceLine)
	}

	baseDir, err := filepath.Abs(filepath.Dir(options.MihomoRoutingPath))
	if err != nil {
		return SyncReport{}, fmt.Errorf("resolve Mihomo routing config directory: %w", err)
	}
	normalization, err := NormalizeMihomoRuleProviders(document, baseDir)
	if err != nil {
		return SyncReport{}, err
	}
	ir, err := ParseMihomoRuleIR(document)
	if err != nil {
		return SyncReport{}, err
	}
	ir, err = CompileMihomoSubRules(ir, MihomoSubRuleCompilerOptions{})
	if err != nil {
		return SyncReport{}, err
	}
	providerRefs := collectMihomoRuleSetReferences(ir)
	if err := validateMihomoProviderReferences(providerRefs, normalization); err != nil {
		return SyncReport{}, err
	}

	root, lock, previousSnapshots, err := openMihomoGenerationState(ctx, options.GenerationDir)
	if err != nil {
		return SyncReport{}, err
	}
	defer lock.close()

	fetcher := NewProviderFetcher(options.Client, options.CacheDir)
	fetcher.DeferCacheCommit = true
	fetcher.ValidateBody = func(spec ProviderSpec, body []byte) error {
		_, err := ParseProvider(body, spec)
		return err
	}
	if options.AllowPrivate {
		fetcher.ValidateURL = validateTestURL
		fetcher.AllowPrivate = true
	}

	sets := make(map[string]ParsedRuleSet, len(providerRefs))
	snapshots := make(map[string]ProviderSnapshot, len(providerRefs))
	generationReused := true
	report := SyncReport{Providers: make([]ProviderSyncReport, 0, len(normalization.Providers))}
	reportIndex := make(map[string]int, len(normalization.Providers))
	for _, spec := range normalization.Providers {
		originalName := normalization.ReverseNameMap[spec.Name]
		reportIndex[originalName] = len(report.Providers)
		report.Providers = append(report.Providers, ProviderSyncReport{
			Name:    originalName,
			Warning: "unused by reachable RULE-SET; not fetched",
		})
	}

	for _, spec := range normalization.Providers {
		originalName := normalization.ReverseNameMap[spec.Name]
		if _, used := providerRefs[originalName]; !used {
			continue
		}
		fallback := previousSnapshots[spec.Name]
		if fallback.Name == "" {
			// Keep compatibility with any older generation that keyed a snapshot
			// by the original name while the name was already safe.
			fallback = previousSnapshots[originalName]
		}
		snapshot, fetchResult, err := loadMihomoGenerationProvider(ctx, fetcher, spec, baseDir, fallback)
		if err != nil {
			return SyncReport{}, fmt.Errorf("provider %q: %w", originalName, redactProviderError(err))
		}
		parsed, err := parseCompleteMihomoProvider(spec, snapshot.Body)
		if err != nil {
			return SyncReport{}, fmt.Errorf("provider %q: %w", originalName, err)
		}
		snapshot.Behavior = normalizedProviderBehavior(spec)
		snapshot.Format = normalizedProviderFormat(spec)
		snapshots[spec.Name] = snapshot
		sets[originalName] = parsed
		sets[spec.Name] = parsed

		index := reportIndex[originalName]
		report.Providers[index] = ProviderSyncReport{
			Name:        originalName,
			Updated:     fetchResult.Updated,
			UsedCache:   fetchResult.UsedCache,
			SHA256:      snapshot.SHA256,
			RuleCount:   len(parsed.Domains) + len(parsed.Prefixes),
			Unsupported: len(parsed.Unsupported),
		}
		if fetchResult.Warning != nil {
			report.Providers[index].Warning = fetchResult.Warning.Error()
		}
		if !fetchResult.UsedCache || fetchResult.Updated || spec.Type != "http" {
			generationReused = false
		}
	}

	bound, err := BindMihomoProviderData(ir, normalization, sets, MihomoProviderBindingOptions{UseDAT: true})
	if err != nil {
		return SyncReport{}, err
	}
	usedSafeProviders := make(map[string]struct{}, len(bound.UsedProviders))
	for _, provider := range bound.UsedProviders {
		usedSafeProviders[provider] = struct{}{}
		if _, ok := snapshots[provider]; !ok {
			return SyncReport{}, fmt.Errorf("bound provider %q has no fetched snapshot", provider)
		}
	}
	for provider := range snapshots {
		if _, ok := usedSafeProviders[provider]; !ok {
			delete(snapshots, provider)
		}
	}

	mihomoConfig := MihomoConfig{Proxies: document.Proxies, Groups: document.Groups}
	nodesText, nodeReport, err := GenerateMihomoNodes(mihomoConfig)
	if err != nil {
		return SyncReport{}, err
	}
	groupsText, groupReport, err := generateFullMihomoGroups(mihomoConfig, nodeReport.NameMap)
	if err != nil {
		return SyncReport{}, err
	}
	report.Nodes = nodeReport
	report.Groups = groupReport
	if nodeReport.Converted == 0 || strings.TrimSpace(nodesText) == "" {
		return SyncReport{}, errors.New("Mihomo routing generation requires a non-empty node output")
	}
	if groupReport.Converted == 0 || strings.TrimSpace(groupsText) == "" {
		return SyncReport{}, errors.New("Mihomo routing generation requires a non-empty group output")
	}
	if len(groupReport.Unsupported) != 0 || groupReport.Approximated != 0 {
		return SyncReport{}, errors.New("Mihomo routing generation contains unsupported or approximated groups")
	}

	outboundMap, err := mergeMihomoOutboundMaps(nodeReport.NameMap, groupReport.NameMap)
	if err != nil {
		return SyncReport{}, err
	}
	providerBehaviors := make(map[string]string, len(normalization.Providers)*2)
	for _, provider := range normalization.Providers {
		providerBehaviors[provider.Name] = provider.Behavior
		if original := normalization.ReverseNameMap[provider.Name]; original != "" {
			providerBehaviors[original] = provider.Behavior
		}
	}
	lowered, err := LowerMihomoRuleIR(bound.IR, MihomoRuleLowererOptions{
		ProviderNameMap:   normalization.NameMap,
		OutboundNameMap:   outboundMap,
		ProviderBehaviors: providerBehaviors,
	})
	if err != nil {
		return SyncReport{}, err
	}
	routesText, routeReport, err := renderMihomoLoweredRoutes(lowered)
	if err != nil {
		return SyncReport{}, err
	}
	report.Routes = routeReport
	if routeReport.Generated == 0 || strings.TrimSpace(routesText) == "" {
		return SyncReport{}, errors.New("Mihomo routing generation requires a non-empty route output")
	}

	selectedSnapshots := make([]ProviderSnapshot, 0, len(usedSafeProviders))
	for _, spec := range normalization.Providers {
		if _, used := usedSafeProviders[spec.Name]; used {
			selectedSnapshots = append(selectedSnapshots, snapshots[spec.Name])
		}
	}
	mihomoMetadata := &generationMihomoMetadata{
		InputSHA256:  digest(routingBody),
		NodeNameMap:  cloneStringMap(nodeReport.NameMap),
		GroupNameMap: cloneStringMap(groupReport.NameMap),
		NodeTypes:    cloneStringMap(nodeReport.Types),
	}
	for _, provider := range selectedSnapshots {
		if provider.SHA256 == "" {
			return SyncReport{}, fmt.Errorf("provider %q has an empty snapshot checksum", provider.Name)
		}
	}
	if generationReused {
		unchanged, err := generationMatchesCurrentWithNodes(root, []byte(routesText), []byte(nodesText), []byte(groupsText), selectedSnapshots, mihomoMetadata)
		if err != nil {
			return SyncReport{}, fmt.Errorf("compare current Mihomo generation: %w", err)
		}
		if unchanged {
			return report, nil
		}
	}

	datSpecs := bound.GenerationDATSpecs
	publication, err := beginGenerationPublicationAtWithNodes(root, []byte(routesText), []byte(nodesText), []byte(groupsText), selectedSnapshots, mihomoMetadata, datSpecs...)
	if err != nil {
		return SyncReport{}, fmt.Errorf("prepare Mihomo generation: %w", err)
	}
	if err := publication.publish(); err != nil {
		if !publication.published {
			_ = publication.rollback()
		}
		return SyncReport{}, fmt.Errorf("publish Mihomo generation: %w", err)
	}
	if err := publication.finalize(); err != nil {
		return SyncReport{}, fmt.Errorf("retain Mihomo generation: %w", err)
	}
	return report, nil
}

func openMihomoGenerationState(ctx context.Context, path string) (generationRootState, *generationLock, map[string]ProviderSnapshot, error) {
	root, err := openGenerationRoot(path)
	if err != nil {
		return generationRootState{}, nil, nil, fmt.Errorf("prepare generation root: %w", err)
	}
	lock, err := acquireGenerationLock(ctx, root.root)
	if err != nil {
		return generationRootState{}, nil, nil, fmt.Errorf("acquire generation lock: %w", err)
	}
	root, err = resolveGenerationRoot(root)
	if err != nil {
		lock.close()
		return generationRootState{}, nil, nil, fmt.Errorf("resolve current generation: %w", err)
	}
	var snapshots map[string]ProviderSnapshot
	if root.previousID != "" {
		snapshots, err = readGenerationProviderSnapshots(filepath.Join(root.generations, root.previousID))
		if err != nil {
			lock.close()
			return generationRootState{}, nil, nil, fmt.Errorf("read previous generation provider snapshots: %w", err)
		}
	}
	return root, lock, snapshots, nil
}

func loadMihomoGenerationProvider(ctx context.Context, fetcher *ProviderFetcher, spec ProviderSpec, baseDir string, fallback ProviderSnapshot) (ProviderSnapshot, FetchResult, error) {
	switch spec.Type {
	case "http":
		result, err := fetcher.FetchWithFallbackValidated(ctx, spec, fallback, func(spec ProviderSpec, body []byte) error {
			_, err := parseCompleteMihomoProvider(spec, body)
			return err
		})
		return result.Snapshot, result, err
	case "file", "inline":
		return loadProvider(ctx, fetcher, spec, baseDir)
	default:
		return ProviderSnapshot{}, FetchResult{}, fmt.Errorf("provider type %q is unsupported", spec.Type)
	}
}

func parseCompleteMihomoProvider(spec ProviderSpec, body []byte) (ParsedRuleSet, error) {
	parsed, err := ParseProvider(body, spec)
	if err != nil {
		return ParsedRuleSet{}, fmt.Errorf("parse provider: %w", err)
	}
	if len(parsed.Unsupported) != 0 {
		return ParsedRuleSet{}, fmt.Errorf("provider contains %d unsupported rules", len(parsed.Unsupported))
	}
	if len(parsed.Domains)+len(parsed.Prefixes) == 0 {
		return ParsedRuleSet{}, errors.New("provider is empty")
	}
	return parsed, nil
}

func collectMihomoRuleSetReferences(ir MihomoRuleIR) map[string]MihomoRuleSource {
	refs := make(map[string]MihomoRuleSource)
	var visit func(MihomoExpr, MihomoRuleSource)
	visit = func(expr MihomoExpr, source MihomoRuleSource) {
		if expr.Kind == MihomoExprRuleSet && expr.ProviderRef != nil {
			name := strings.TrimSpace(expr.ProviderRef.Provider)
			if name != "" {
				if _, exists := refs[name]; !exists {
					refs[name] = source
				}
			}
		}
		for _, child := range expr.Children {
			visit(child, source)
		}
		if expr.SubRuleRef != nil {
			visit(expr.SubRuleRef.Guard, source)
		}
	}
	for _, rule := range ir.Rules {
		visit(rule.Expr, rule.MihomoRuleSource)
	}
	for _, subRule := range ir.SubRules {
		for _, rule := range subRule.Rules {
			visit(rule.Expr, rule.MihomoRuleSource)
		}
	}
	return refs
}

func validateMihomoProviderReferences(refs map[string]MihomoRuleSource, normalization MihomoProviderNormalization) error {
	names := make([]string, 0, len(refs))
	for name := range refs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		source := refs[name]
		if _, ok := normalization.NameMap[name]; !ok {
			return fmt.Errorf("RULE-SET provider %q at index %d line %d is undeclared", name, source.SourceIndex, source.SourceLine)
		}
	}
	return nil
}

func mergeMihomoOutboundMaps(nodes, groups map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(nodes)+len(groups))
	result["DIRECT"] = "direct"
	result["REJECT"] = "block"
	for original, safe := range nodes {
		result[original] = safe
	}
	for original, safe := range groups {
		if previous, exists := result[original]; exists && previous != safe {
			return nil, fmt.Errorf("Mihomo outbound %q has conflicting safe mappings %q and %q", original, previous, safe)
		}
		for nodeOriginal, nodeSafe := range nodes {
			if nodeSafe == safe && nodeOriginal != original {
				return nil, fmt.Errorf("Mihomo node %q and group %q map to the same outbound %q", nodeOriginal, original, safe)
			}
		}
		result[original] = safe
	}
	return result, nil
}

func renderMihomoLoweredRoutes(rules []MihomoLoweredRoutingRule) (string, ConversionReport, error) {
	var output strings.Builder
	report := ConversionReport{}
	fallback := ""
	for _, lowered := range rules {
		if lowered.Rule == nil {
			return "", report, errors.New("lowered Mihomo route is nil")
		}
		if len(lowered.Rule.AndFunctions) == 0 {
			if fallback == "" {
				fallback = strings.TrimSpace(lowered.Rule.Outbound.Name)
				if fallback == "" || lowered.Rule.Outbound.Not || len(lowered.Rule.Outbound.Params) != 0 {
					return "", report, fmt.Errorf("lowered Mihomo MATCH route has an invalid fallback outbound")
				}
			}
			// A MATCH rule is a first-match catch-all. Any following Mihomo
			// rules are unreachable and must not be emitted as ordinary kdae
			// routes after the fallback.
			continue
		}
		if fallback != "" {
			continue
		}
		line := strings.TrimSpace(lowered.Rule.String(false, false, true))
		if line == "" {
			return "", report, fmt.Errorf("lowered Mihomo route at index %d line %d is empty", lowered.Source.SourceIndex, lowered.Source.SourceLine)
		}
		output.WriteString("    ")
		output.WriteString(line)
		output.WriteByte('\n')
		report.Generated++
	}
	if fallback != "" {
		output.WriteString("    fallback: ")
		output.WriteString(fallback)
		output.WriteByte('\n')
		report.Generated++
	}
	if report.Generated == 0 {
		return "", report, errors.New("Mihomo routing produced no routes")
	}
	return output.String(), report, nil
}

func generatedRoutingSection(routes []byte) string {
	var output strings.Builder
	output.WriteString("routing {\n")
	output.Write(routes)
	if !generatedRoutesContainFallback(routes) {
		output.WriteString("  fallback: direct\n")
	}
	output.WriteString("}\n")
	return output.String()
}

func generatedRoutesContainFallback(routes []byte) bool {
	for _, line := range strings.Split(string(routes), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "fallback:") {
			return true
		}
	}
	return false
}
