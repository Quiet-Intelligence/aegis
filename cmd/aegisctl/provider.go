package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"aegis/pkg/provider"
)

func handleProvider() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: aegisctl provider <list|current|models|set> [args...]")
		fmt.Println("  list                          show presets from providers.json")
		fmt.Println("  current                       show the resolved config (key masked)")
		fmt.Println("  models [name]                 list real model slugs from the provider")
		fmt.Println("  set <name> [--model X] [--cheap Y] [--flagship Z]")
		fmt.Println("                                persist selection to aegis.env (never writes keys)")
		os.Exit(1)
	}

	sub := os.Args[2]

	switch sub {
	case "list":
		providerList()
	case "current":
		providerCurrent()
	case "models":
		name := ""
		if len(os.Args) >= 4 {
			name = os.Args[3]
		}
		providerModels(name)
	case "set":
		if len(os.Args) < 4 {
			fmt.Println("Usage: aegisctl provider set <name> [--model X] [--cheap Y] [--flagship Z]")
			os.Exit(1)
		}
		providerSet(os.Args[3], os.Args[4:])
	default:
		fmt.Printf("Unknown provider command: %s\n", sub)
		os.Exit(1)
	}
}

func mustRegistry() *provider.Registry {
	registry, err := provider.Load()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return registry
}

func providerList() {
	registry := mustRegistry()
	active := os.Getenv("AEGIS_PROVIDER")
	if active == "" {
		active = provider.DefaultProvider
	}

	fmt.Printf("Presets (loaded from %s):\n\n", registry.Source)
	fmt.Printf("%-12s %-48s %-32s %s\n", "NAME", "URL", "CHEAP MODEL", "FLAGSHIP MODEL")
	names := registry.Names()
	for _, name := range names {
		p := registry.Providers[name]
		marker := "  "
		if name == active {
			marker = "* "
		}
		url := p.URL
		if url == "" {
			url = "(set AEGIS_LLM_URL)"
		}
		fmt.Printf("%s%-10s %-48s %-32s %s\n", marker, name, url, modelOrDash(p.CheapModel, p.DefaultModel), modelOrDash(p.FlagshipModel, p.DefaultModel))
	}
	fmt.Printf("\n* = active (AEGIS_PROVIDER or default). Configure with: aegisctl provider set <name>\n")
}

func modelOrDash(model, fallback string) string {
	if model != "" {
		return model
	}
	if fallback != "" {
		return fallback
	}
	return "-"
}

func providerCurrent() {
	registry := mustRegistry()
	cfg, err := registry.Resolve()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Provider:  %s\n", cfg.ProviderName)
	fmt.Printf("URL:       %s\n", cfg.URL)
	fmt.Printf("Cheap:     %s\n", cfg.CheapModel)
	fmt.Printf("Flagship:  %s\n", cfg.FlagshipModel)
	if cfg.Auth == "none" {
		fmt.Printf("API key:   not required\n")
	} else if cfg.Key == "" {
		fmt.Printf("API key:   <not set> (checked: %s)\n", strings.Join(cfg.KeyEnvsTried, ", "))
	} else {
		fmt.Printf("API key:   %s (from %s)\n", cfg.MaskedKey(), cfg.KeySource)
	}
}

func providerModels(name string) {
	registry := mustRegistry()

	if name == "" {
		cfg, err := registry.Resolve()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		name = cfg.ProviderName
	} else {
		if _, ok := registry.Providers[name]; !ok {
			fmt.Printf("Error: unknown provider %q; valid names: %s\n", name, strings.Join(registry.Names(), ", "))
			os.Exit(1)
		}
		os.Setenv("AEGIS_PROVIDER", name)
	}

	cfg, err := registry.Resolve()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	models, err := provider.ListModels(ctx, cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	fmt.Printf("%d model(s) available on %s:\n\n", len(models), name)
	for _, m := range models {
		if m.PromptPrice != "" {
			fmt.Printf("  %-52s in $%s  out $%s\n", m.ID, m.PromptPrice, m.CompletionPrice)
		} else {
			fmt.Printf("  %s\n", m.ID)
		}
	}
}

func providerSet(name string, flagArgs []string) {
	registry := mustRegistry()
	if _, ok := registry.Providers[name]; !ok {
		fmt.Printf("Error: unknown provider %q; valid names: %s\n", name, strings.Join(registry.Names(), ", "))
		os.Exit(1)
	}

	vars := map[string]string{"AEGIS_PROVIDER": name}

	for i := 0; i < len(flagArgs); i++ {
		var key string
		switch flagArgs[i] {
		case "--model":
			key = "AEGIS_LLM_MODEL"
		case "--cheap":
			key = "AEGIS_CHEAP_MODEL"
		case "--flagship":
			key = "AEGIS_FLAGSHIP_MODEL"
		default:
			fmt.Printf("Error: unknown flag %q (allowed: --model, --cheap, --flagship)\n", flagArgs[i])
			os.Exit(1)
		}
		if i+1 >= len(flagArgs) {
			fmt.Printf("Error: %s needs a value\n", flagArgs[i])
			os.Exit(1)
		}
		vars[key] = flagArgs[i+1]
		i++
	}

	changes, err := provider.SetEnvVars("aegis.env", vars)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Updated aegis.env:")
	for _, c := range changes {
		fmt.Println("  " + strings.ReplaceAll(c, "\n", "\n  "))
	}
	fmt.Println("\nKeys are never written by this command. Set your key in the environment or add it to aegis.env manually.")
}
