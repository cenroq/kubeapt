// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
)

const appVersion = "2.1.0"

var (
	rootCmd = &cobra.Command{
		Use:           "kubeapt",
		Short:         "Kubernetes Admission Policy Toolkit",
		Long:          `CLI toolkit for validating Kubernetes admission policies, Pod Security Admission labels, and cluster webhook safeguards.`,
		Version:       appVersion,
		SilenceErrors: true,
	}
	logLevel       string
	kubeconfigPath string
)

// Execute runs the root command and handles errors.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		if initErr := logging.Init("", getLogLevel()); initErr == nil {
			logging.SetOutputWriter(rootCmd.ErrOrStderr())
		}
		if errors.Is(err, kubernetes.ErrKubeconfigNotFound) {
			logging.Warnf("%v", err)
		} else {
			logging.Errorf("%v", err)
		}
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(func() {
		kubernetes.SetKubeconfig(kubeconfigPath)
	})
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Set logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file")
	rootCmd.AddCommand(ValidateCmd(getLogLevel))
	rootCmd.AddCommand(ScanCmd())
	rootCmd.AddCommand(BundleCmd())
	rootCmd.AddCommand(PoliciesCmd())
	rootCmd.AddCommand(ConvertCmd())
	// analyze is implemented and tested but deliberately not registered: its
	// default probe bundle does not exist yet, so the command would fail on
	// first run. Re-add rootCmd.AddCommand(AnalyzeCmd()) once the probe corpus
	// ships inside the policy bundles.
}

func getLogLevel() string {
	return logLevel
}
